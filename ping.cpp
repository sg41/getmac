#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>

// Класс для работы с ICMP
class ICMPMacResolver {
 public:
  ICMPMacResolver() : sock_raw(-1) {}
  ~ICMPMacResolver() {
    if (sock_raw != -1) close(sock_raw);
  }

  bool get_mac(const char* ip_address, unsigned char* mac) {
    if (!init_socket()) return false;
    if (!send_icmp_request(ip_address)) return false;
    return receive_icmp_reply(mac);
  }

 private:
  int sock_raw;

  // Вычисление контрольной суммы ICMP пакета
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

  bool init_socket() {
    sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_raw < 0) {
      perror("socket");
      return false;
    }

    struct ifreq ifr;
    std::memset(&ifr, 0, sizeof(ifr));
    std::strncpy(ifr.ifr_name, "enp3s0", IFNAMSIZ);

    if (setsockopt(sock_raw, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) <
        0) {
      perror("setsockopt SO_BINDTODEVICE");
      return false;
    }

    return true;
  }

  bool send_icmp_request(const char* ip_address) {
    char packet[IP_MAXPACKET];
    std::memset(packet, 0, sizeof(packet));

    struct icmphdr* icmp =
        reinterpret_cast<struct icmphdr*>(packet + sizeof(struct iphdr));
    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->un.echo.id = getpid();
    icmp->un.echo.sequence = 1;
    icmp->checksum = checksum(icmp, sizeof(struct icmphdr));

    struct sockaddr_in dest;
    std::memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr(ip_address);

    if (sendto(sock_raw, packet, sizeof(struct icmphdr), 0,
               reinterpret_cast<struct sockaddr*>(&dest), sizeof(dest)) < 0) {
      perror("sendto");
      return false;
    }

    return true;
  }

  bool receive_icmp_reply(unsigned char* mac) {
    char packet[IP_MAXPACKET];
    struct sockaddr saddr;
    socklen_t saddr_size = sizeof(saddr);

    std::memset(packet, 0, sizeof(packet));
    int bytes =
        recvfrom(sock_raw, packet, sizeof(packet), 0, &saddr, &saddr_size);
    if (bytes < 0) {
      perror("recvfrom");
      return false;
    }

    struct ethhdr* eth = reinterpret_cast<struct ethhdr*>(packet);
    std::memcpy(mac, eth->h_source, 6);

    return true;
  }
};

int main(int argc, char* argv[]) {
  if (argc != 2) {
    std::fprintf(stderr, "Usage: %s <IPv4 address>\n", argv[0]);
    return 1;
  }

  unsigned char mac[6];
  ICMPMacResolver resolver;

  if (!resolver.get_mac(argv[1], mac)) {
    std::fprintf(stderr, "Failed to get MAC address\n");
    return 1;
  }

  std::printf("%02x:%02x:%02x:%02x:%02x:%02x\n", mac[0], mac[1], mac[2], mac[3],
              mac[4], mac[5]);

  return 0;
}