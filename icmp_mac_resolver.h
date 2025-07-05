#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <iostream>

#define MAX_PACKETS 200
class ICMPMacResolver {
 public:
  friend void test_checksum_calculation();
  friend void test_socket_initialization();

  ICMPMacResolver(std::string target_ip)
      : recv_sock(-1), send_sock(-1), target_ip_(target_ip) {}
  ~ICMPMacResolver() {
    if (recv_sock != -1) close(recv_sock);
    if (send_sock != -1) close(send_sock);
  }

  bool get_mac(unsigned char* mac) {
    if (!init_receive_socket()) return false;
    if (!init_send_socket()) return false;
    if (!send_icmp_request(target_ip_.c_str())) return false;
    return receive_icmp_reply(mac, target_ip_.c_str());
  }

 private:
  int recv_sock;
  int send_sock;
  std::string target_ip_;

  //   unsigned short checksum(void* b, int len) {
  //     unsigned short* buf = static_cast<unsigned short*>(b);
  //     unsigned int sum = 0;

  //     for (sum = 0; len > 1; len -= 2) {
  //       sum += *buf++;
  //     }
  //     if (len == 1) {
  //       sum += *(unsigned char*)buf;
  //     }
  //     sum = (sum >> 16) + (sum & 0xFFFF);
  //     sum += (sum >> 16);
  //     return static_cast<unsigned short>(~sum);
  //   }

  unsigned short checksum(void* b, int len) {
    unsigned short* buf = static_cast<unsigned short*>(b);
    unsigned int sum = 0;

    // Обрабатываем по 2 байта
    while (len > 1) {
      sum += *buf++;
      len -= 2;
    }

    // Если остался 1 байт
    if (len == 1) {
      sum += *(unsigned char*)buf;
    }

    // Сворачиваем 32-битную сумму в 16 бит
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    return static_cast<unsigned short>(~sum);
  }

  bool init_receive_socket() {
    // Получаем автоматически определенный интерфейс
    std::string iface = find_appropriate_interface(target_ip_.c_str());

    recv_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (recv_sock < 0) {
      perror("receive socket");
      return false;
    }

    struct ifreq ifr;
    std::memset(&ifr, 0, sizeof(ifr));
    std::strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ);

    if (setsockopt(recv_sock, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) <
        0) {
      perror("setsockopt SO_BINDTODEVICE");
      return false;
    }

    // Set timeout
    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    if (setsockopt(recv_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
      perror("setsockopt SO_RCVTIMEO");
      return false;
    }

    return true;
  }

  bool init_send_socket() {
    send_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (send_sock < 0) {
      perror("send socket");
      return false;
    }

    // Set send timeout (2 seconds)
    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    if (setsockopt(send_sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) {
      perror("setsockopt SO_SNDTIMEO");
      close(send_sock);
      return false;
    }

    return true;
  }

  bool send_icmp_request(const char* ip_address) {
    struct icmphdr icmp;
    std::memset(&icmp, 0, sizeof(icmp));
    icmp.type = ICMP_ECHO;
    icmp.code = 0;
    icmp.un.echo.id = htons(getpid());
    icmp.un.echo.sequence = 1;
    icmp.checksum = checksum(&icmp, sizeof(icmp));

    struct sockaddr_in dest;
    std::memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr(ip_address);

    int result =
        sendto(send_sock, &icmp, sizeof(icmp), 0,
               reinterpret_cast<struct sockaddr*>(&dest), sizeof(dest));

    if (result <= 0) {
      if (errno == EWOULDBLOCK || errno == EAGAIN) {
        std::cerr << "Send operation timed out\n";
      } else {
        perror("sendto");
      }
      return false;
    }

    return true;
  }

  std::string find_appropriate_interface(const char* target_ip) {
    struct ifaddrs *ifaddr, *ifa;
    std::string best_interface;
    in_addr_t target = inet_addr(target_ip);
    in_addr_t best_mask = 0;

    if (getifaddrs(&ifaddr) == -1) {
      perror("getifaddrs");
      return "eth0";  // fallback
    }

    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
      if (ifa->ifa_addr == nullptr || ifa->ifa_addr->sa_family != AF_INET)
        continue;

      in_addr_t local = ((struct sockaddr_in*)ifa->ifa_addr)->sin_addr.s_addr;
      in_addr_t mask = ((struct sockaddr_in*)ifa->ifa_netmask)->sin_addr.s_addr;

      if ((local & mask) == (target & mask) && mask > best_mask) {
        best_mask = mask;
        best_interface = ifa->ifa_name;
      }
    }

    freeifaddrs(ifaddr);
    return best_interface.empty() ? "eth0" : best_interface;
  }

  bool receive_icmp_reply(unsigned char* mac, const char* target_ip) {
    char packet[IP_MAXPACKET];
    struct sockaddr saddr;
    socklen_t saddr_size = sizeof(saddr);
    const int expected_id = htons(getpid());
    const unsigned long expected_ip = inet_addr(target_ip);

    unsigned int packets_count = MAX_PACKETS;
    while (packets_count--) {
      int bytes =
          recvfrom(recv_sock, packet, sizeof(packet), 0, &saddr, &saddr_size);

      if (bytes < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
          // Timeout reached
          return false;
        }
        perror("recvfrom");
        return false;
      }

      // Check minimum packet size
      if (bytes <
          static_cast<int>(sizeof(struct ethhdr) + sizeof(struct iphdr) +
                           sizeof(struct icmphdr))) {
        continue;
      }

      struct ethhdr* eth = reinterpret_cast<struct ethhdr*>(packet);
      struct iphdr* ip =
          reinterpret_cast<struct iphdr*>(packet + sizeof(struct ethhdr));
      struct icmphdr* icmp = reinterpret_cast<struct icmphdr*>(
          packet + sizeof(struct ethhdr) + sizeof(struct iphdr));

      // Verify source IP address
      if (ip->saddr != expected_ip) {
        continue;
      }

      // Verify ICMP Destination Unreachable (type 3)
      if (icmp->type == ICMP_DEST_UNREACH) {
        std::cerr << "Host unreachable (ICMP Destination Unreachable)\n";
        return false;
      }

      // Verify ICMP Time Exceeded (type 11)
      if (icmp->type == ICMP_TIME_EXCEEDED) {
        std::cerr << "Host unreachable (ICMP Time Exceeded)\n";
        return false;
      }

      // Verify ICMP type and code
      if (icmp->type != ICMP_ECHOREPLY || icmp->code != 0) {
        continue;
      }

      // Verify ID and sequence number
      if (icmp->un.echo.id != expected_id || icmp->un.echo.sequence != 1) {
        continue;
      }

      // All checks passed - copy MAC address
      std::memcpy(mac, eth->h_source, 6);
      return true;
    }
    std::cerr << "Maximum number of packets reached\n";
    return false;
  }
};
