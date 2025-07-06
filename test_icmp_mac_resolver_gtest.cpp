#include <gtest/gtest.h>

#include "icmp_mac_resolver.h"

class ICMPMacResolverTest : public ::testing::Test {
 protected:
  void SetUp() override { resolver = new ICMPMacResolver("127.0.0.1"); }

  void TearDown() override { delete resolver; }

  ICMPMacResolver* resolver;
};

TEST_F(ICMPMacResolverTest, InvalidIPHandling) {
  ICMPMacResolver* invalid_resolver = new ICMPMacResolver("InvalidIP");
  unsigned char mac[6];
  EXPECT_FALSE(invalid_resolver->get_mac(mac));
}

// Integration test - requires network and root privileges
TEST_F(ICMPMacResolverTest, LiveICMPTest) {
  ICMPMacResolver* real_resolver = new ICMPMacResolver("8.8.8.8");
  unsigned char mac[6];
  EXPECT_TRUE(real_resolver->get_mac(mac));

  // Verify MAC contains valid values (not all zeros)
  bool non_zero = false;
  for (int i = 0; i < 6; ++i) {
    if (mac[i] != 0) {
      non_zero = true;
      break;
    }
  }
  EXPECT_TRUE(non_zero);
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}