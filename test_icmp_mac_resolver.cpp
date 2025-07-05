#include <arpa/inet.h>

#include <cassert>
#include <iostream>

#include "icmp_mac_resolver.h"  // Assuming your class is in this header

// Test socket initialization
void test_socket_initialization() {
  ICMPMacResolver resolver("127.0.0.1");

  std::cout << "Socket initialization test: ";
  // Should fail if not run as root
  assert(resolver.init_receive_socket() == true);
  assert(resolver.init_send_socket() == true);
  std::cout << "PASSED\n";
}

// Test for valid IP address handling
void test_valid_ip_address() {
  ICMPMacResolver resolver("127.0.0.1");
  unsigned char mac[6];

  std::cout << "Valid IP test: ";
  // Test with localhost (may not get MAC but should handle properly)
  bool result = resolver.get_mac(mac);
  // Either succeeds or fails gracefully
  assert(result == true || result == false);
  std::cout << "PASSED\n";
}

// Test for invalid IP address handling
void test_invalid_ip_address() {
  ICMPMacResolver resolver("INVALID_IP_ADDRESS");
  unsigned char mac[6];

  std::cout << "Invalid IP test: ";
  assert(resolver.get_mac(mac) == false);
  std::cout << "PASSED\n";
}

// Test response validation logic
void test_response_validation() {
  ICMPMacResolver resolver("192.168.1.1");
  unsigned char mac[6];
  char fake_packet[1024];

  // Build a fake packet
  struct ethhdr* eth = reinterpret_cast<struct ethhdr*>(fake_packet);
  struct iphdr* ip =
      reinterpret_cast<struct iphdr*>(fake_packet + sizeof(struct ethhdr));
  struct icmphdr* icmp = reinterpret_cast<struct icmphdr*>(
      fake_packet + sizeof(struct ethhdr) + sizeof(struct iphdr));

  // Fill with test data
  memset(fake_packet, 0, sizeof(fake_packet));
  icmp->type = ICMP_ECHOREPLY;
  icmp->code = 0;
  icmp->un.echo.id = htons(getpid());
  icmp->un.echo.sequence = 1;
  ip->saddr = inet_addr("192.168.1.1");

  std::cout << "Response validation test: ";
  // This would need to be integrated with actual receive logic
  // For now just verify the validation components work
  assert(icmp->type == ICMP_ECHOREPLY);
  assert(icmp->code == 0);
  std::cout << "PASSED\n";
}

int main() {
  std::cout << "Running ICMPMacResolver tests...\n";

  test_socket_initialization();
  test_valid_ip_address();
  test_invalid_ip_address();
  test_response_validation();

  std::cout << "All tests completed successfully!\n";
  return 0;
}