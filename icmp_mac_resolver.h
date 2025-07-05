#include <arpa/inet.h>
#include <net/if.h>
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

class ICMPMacResolver {
 public:
  friend void test_checksum_calculation();
  friend void test_socket_initialization();

  ICMPMacResolver() : recv_sock(-1), send_sock(-1) {}
  ~ICMPMacResolver() {
    if (recv_sock != -1) close(recv_sock);
    if (send_sock != -1) close(send_sock);
  }

  bool get_mac(const char* ip_address, unsigned char* mac) {
    if (!init_receive_socket()) return false;
    if (!init_send_socket()) return false;
    if (!send_icmp_request(ip_address)) return false;
    return receive_icmp_reply(mac, ip_address);
  }

 private:
  int recv_sock;
  int send_sock;

  unsigned short checksum(void* b, int len) {
    unsigned short* buf = static_cast<unsigned short*>(b);
    unsigned int sum = 0;

    for (sum = 0; len > 1; len -= 2) {
      sum += *buf++;
    }
    if (len == 1) {
      sum += *(unsigned char*)buf;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return static_cast<unsigned short>(~sum);
  }

  bool init_receive_socket() {
    recv_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (recv_sock < 0) {
      perror("receive socket");
      return false;
    }

    struct ifreq ifr;
    std::memset(&ifr, 0, sizeof(ifr));
    std::strncpy(ifr.ifr_name, "enp3s0", IFNAMSIZ);

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

    if (sendto(send_sock, &icmp, sizeof(icmp), 0,
               reinterpret_cast<struct sockaddr*>(&dest), sizeof(dest)) <= 0) {
      perror("sendto");
      return false;
    }

    return true;
  }

  bool receive_icmp_reply(unsigned char* mac, const char* target_ip) {
    char packet[IP_MAXPACKET];
    struct sockaddr saddr;
    socklen_t saddr_size = sizeof(saddr);
    const int expected_id = htons(getpid());
    const unsigned long expected_ip = inet_addr(target_ip);

    while (true) {
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

      // Verify ICMP type and code
      if (icmp->type != ICMP_ECHOREPLY || icmp->code != 0) {
        continue;
      }

      // Verify ID and sequence number
      if (icmp->un.echo.id != expected_id || icmp->un.echo.sequence != 1) {
        continue;
      }

      // Verify source IP address
      if (ip->saddr != expected_ip) {
        continue;
      }

      // All checks passed - copy MAC address
      std::memcpy(mac, eth->h_source, 6);
      return true;
    }
  }
};
