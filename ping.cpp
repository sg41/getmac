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
    // Используем SOCK_RAW с IPPROTO_ICMP вместо AF_PACKET
    sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock_raw < 0) {
      perror("socket");
      return false;
    }

    // Включаем IP_HDRINCL для ручного контроля над IP заголовком
    int on = 1;
    if (setsockopt(sock_raw, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
      perror("setsockopt IP_HDRINCL");
      return false;
    }

    return true;
  }

  bool send_icmp_request(const char* ip_address) {
    char packet[sizeof(struct iphdr) + sizeof(struct icmphdr)];
    std::memset(packet, 0, sizeof(packet));

    struct iphdr* ip = reinterpret_cast<struct iphdr*>(packet);
    struct icmphdr* icmp =
        reinterpret_cast<struct icmphdr*>(packet + sizeof(struct iphdr));

    // Заполняем IP заголовок
    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 0;
    ip->tot_len = htons(sizeof(packet));
    ip->id = htons(getpid());
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_ICMP;
    ip->check = 0;  // Рассчитается ниже
    ip->saddr = INADDR_ANY;
    ip->daddr = inet_addr(ip_address);

    // Рассчитываем контрольную сумму IP заголовка
    ip->check = checksum(ip, sizeof(struct iphdr));

    // Заполняем ICMP заголовок
    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->un.echo.id = getpid();
    icmp->un.echo.sequence = 1;
    icmp->checksum = 0;
    icmp->checksum = checksum(icmp, sizeof(struct icmphdr));

    struct sockaddr_in dest;
    std::memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr(ip_address);

    if (sendto(sock_raw, packet, sizeof(packet), 0,
               reinterpret_cast<struct sockaddr*>(&dest), sizeof(dest)) < 0) {
      perror("sendto");
      return false;
    }

    return true;
  }

  bool receive_icmp_reply(unsigned char* mac) {
    // Для получения MAC адреса нам все же нужен AF_PACKET сокет
    int sock_packet = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_packet < 0) {
      perror("socket AF_PACKET");
      return false;
    }

    struct ifreq ifr;
    std::memset(&ifr, 0, sizeof(ifr));
    std::strncpy(ifr.ifr_name, "enp3s0", IFNAMSIZ);

    if (setsockopt(sock_packet, SOL_SOCKET, SO_BINDTODEVICE, &ifr,
                   sizeof(ifr)) < 0) {
      perror("setsockopt SO_BINDTODEVICE");
      close(sock_packet);
      return false;
    }

    char packet[IP_MAXPACKET];
    struct sockaddr saddr;
    socklen_t saddr_size = sizeof(saddr);

    std::memset(packet, 0, sizeof(packet));
    int bytes =
        recvfrom(sock_packet, packet, sizeof(packet), 0, &saddr, &saddr_size);
    if (bytes < 0) {
      perror("recvfrom");
      close(sock_packet);
      return false;
    }

    struct ethhdr* eth = reinterpret_cast<struct ethhdr*>(packet);
    std::memcpy(mac, eth->h_source, 6);

    close(sock_packet);
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