#include "icmp_mac_resolver.h"

int main(int argc, char* argv[]) {
  if (argc != 2) {
    std::fprintf(stderr, "Usage: %s <IPv4 address>\n", argv[0]);
    return EXIT_FAILURE;
  }

  unsigned char mac[6];
  ICMPMacResolver resolver;

  if (!resolver.get_mac(argv[1], mac)) {
    std::fprintf(stderr, "Failed to get MAC address\n");
    return EXIT_FAILURE;
  }

  std::printf("%02x:%02x:%02x:%02x:%02x:%02x\n", mac[0], mac[1], mac[2], mac[3],
              mac[4], mac[5]);

  return EXIT_SUCCESS;
}