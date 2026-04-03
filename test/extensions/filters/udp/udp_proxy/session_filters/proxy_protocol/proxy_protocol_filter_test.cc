#include "envoy/extensions/filters/udp/udp_proxy/session/proxy_protocol/v3/proxy_protocol.pb.h"

#include "source/common/buffer/buffer_impl.h"
#include "source/common/network/address_impl.h"
#include "source/extensions/filters/udp/udp_proxy/session_filters/proxy_protocol/proxy_protocol.h"

#include "test/extensions/filters/udp/udp_proxy/mocks.h"
#include "test/test_common/utility.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

using testing::NiceMock;

namespace Envoy {
namespace Extensions {
namespace UdpFilters {
namespace UdpProxy {
namespace SessionFilters {
namespace ProxyProtocol {
namespace {

using ProxyProtocolVersion =
    envoy::extensions::filters::udp::udp_proxy::session::proxy_protocol::v3::FilterConfig_Version;

constexpr ProxyProtocolVersion V2 =
    envoy::extensions::filters::udp::udp_proxy::session::proxy_protocol::v3::
        FilterConfig_Version_V2;
constexpr ProxyProtocolVersion V1 =
    envoy::extensions::filters::udp::udp_proxy::session::proxy_protocol::v3::
        FilterConfig_Version_V1;

// V2 header size in bytes (signature + version/cmd + af/proto + length + IPv4 addrs + ports)
constexpr size_t kV2IPv4HeaderSize = 28;
// V2 header size for IPv6 (signature + version/cmd + af/proto + length + IPv6 addrs + ports)
constexpr size_t kV2IPv6HeaderSize = 52;

class ProxyProtocolFilterTest : public testing::Test {
public:
  void setup(ProxyProtocolVersion version = V2, bool prepend_once = false) {
    filter_ = std::make_unique<ProxyProtocolFilter>(version, prepend_once);
    filter_->initializeReadFilterCallbacks(read_callbacks_);
  }

  Network::UdpRecvData makeRecvData(Network::Address::InstanceConstSharedPtr peer,
                                    Network::Address::InstanceConstSharedPtr local,
                                    const std::string& payload) {
    Network::UdpRecvData data;
    data.addresses_.peer_ = std::move(peer);
    data.addresses_.local_ = std::move(local);
    data.buffer_ = std::make_unique<Buffer::OwnedImpl>(payload);
    return data;
  }

  std::unique_ptr<ProxyProtocolFilter> filter_;
  NiceMock<MockReadFilterCallbacks> read_callbacks_;
};

// onNewSession should always return Continue.
TEST_F(ProxyProtocolFilterTest, OnNewSessionReturnsContinue) {
  setup();
  EXPECT_EQ(ReadFilterStatus::Continue, filter_->onNewSession());
}

// V2 UDP header (IPv4): the binary header must match the PROXY v2 spec with DGRAM transport.
TEST_F(ProxyProtocolFilterTest, PrependV2IPv4Header) {
  setup();

  auto peer = std::make_shared<Network::Address::Ipv4Instance>("1.2.3.4", 1000);
  auto local = std::make_shared<Network::Address::Ipv4Instance>("10.0.0.1", 8080);
  const std::string payload = "hello";
  auto data = makeRecvData(peer, local, payload);

  EXPECT_EQ(ReadFilterStatus::Continue, filter_->onData(data));

  // Proxy Protocol v2 header for UDP/IPv4:
  //   - 12-byte signature
  //   - 0x21: version=2, cmd=PROXY
  //   - 0x12: AF_INET (1) << 4 | DGRAM (2)
  //   - 0x000c: address block length = 12 (4+4+2+2)
  //   - 4 bytes src IP, 4 bytes dst IP, 2 bytes src port, 2 bytes dst port
  const uint8_t expected_header[] = {
      0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a, // signature
      0x21,                                                                       // ver=2, PROXY
      0x12,                                                                       // AF_INET, DGRAM
      0x00, 0x0c,                                                                 // addr len = 12
      0x01, 0x02, 0x03, 0x04,                                                    // src 1.2.3.4
      0x0a, 0x00, 0x00, 0x01,                                                    // dst 10.0.0.1
      0x03, 0xe8,                                                                 // src port 1000
      0x1f, 0x90,                                                                 // dst port 8080
  };

  Buffer::OwnedImpl expected_buf(expected_header, sizeof(expected_header));
  expected_buf.add(payload);

  ASSERT_EQ(kV2IPv4HeaderSize + payload.size(), data.buffer_->length());
  EXPECT_TRUE(TestUtility::buffersEqual(expected_buf, *data.buffer_));
}

// V2 UDP header (IPv6): address block uses AF_INET6 and 16-byte addresses.
TEST_F(ProxyProtocolFilterTest, PrependV2IPv6Header) {
  setup();

  auto peer = std::make_shared<Network::Address::Ipv6Instance>("::1", 1000);
  auto local = std::make_shared<Network::Address::Ipv6Instance>("::2", 8080);
  const std::string payload = "hello";
  auto data = makeRecvData(peer, local, payload);

  EXPECT_EQ(ReadFilterStatus::Continue, filter_->onData(data));

  // Proxy Protocol v2 header for UDP/IPv6:
  //   - 0x22: AF_INET6 (2) << 4 | DGRAM (2)
  //   - 0x0024: address block length = 36 (16+16+2+2)
  const uint8_t expected_header[] = {
      0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a, // signature
      0x21,                                                                       // ver=2, PROXY
      0x22,                                                                       // AF_INET6, DGRAM
      0x00, 0x24,                                                                 // addr len = 36
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,                           // src ::1 hi
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,                           // src ::1 lo
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,                           // dst ::2 hi
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,                           // dst ::2 lo
      0x03, 0xe8,                                                                 // src port 1000
      0x1f, 0x90,                                                                 // dst port 8080
  };

  Buffer::OwnedImpl expected_buf(expected_header, sizeof(expected_header));
  expected_buf.add(payload);

  ASSERT_EQ(kV2IPv6HeaderSize + payload.size(), data.buffer_->length());
  EXPECT_TRUE(TestUtility::buffersEqual(expected_buf, *data.buffer_));
}

// V1 header (IPv4): uses human-readable "PROXY TCP4 <src> <dst> <sport> <dport>\r\n".
// The v1 spec only defines TCP, so the filter emits TCP4 even for UDP sessions.
TEST_F(ProxyProtocolFilterTest, PrependV1IPv4Header) {
  setup(V1);

  auto peer = std::make_shared<Network::Address::Ipv4Instance>("1.2.3.4", 1000);
  auto local = std::make_shared<Network::Address::Ipv4Instance>("10.0.0.1", 8080);
  const std::string payload = "hello";
  auto data = makeRecvData(peer, local, payload);

  EXPECT_EQ(ReadFilterStatus::Continue, filter_->onData(data));

  const std::string expected = "PROXY TCP4 1.2.3.4 10.0.0.1 1000 8080\r\nhello";
  Buffer::OwnedImpl expected_buf(expected);
  EXPECT_TRUE(TestUtility::buffersEqual(expected_buf, *data.buffer_));
}

// V1 header (IPv6): uses "PROXY TCP6 <src> <dst> <sport> <dport>\r\n".
TEST_F(ProxyProtocolFilterTest, PrependV1IPv6Header) {
  setup(V1);

  auto peer = std::make_shared<Network::Address::Ipv6Instance>("::1", 1000);
  auto local = std::make_shared<Network::Address::Ipv6Instance>("::2", 8080);
  const std::string payload = "hello";
  auto data = makeRecvData(peer, local, payload);

  EXPECT_EQ(ReadFilterStatus::Continue, filter_->onData(data));

  const std::string expected = "PROXY TCP6 ::1 ::2 1000 8080\r\nhello";
  Buffer::OwnedImpl expected_buf(expected);
  EXPECT_TRUE(TestUtility::buffersEqual(expected_buf, *data.buffer_));
}

// With prepend_once=false (default), the header must be prepended to every datagram.
TEST_F(ProxyProtocolFilterTest, HeaderPrependedToEveryDatagramByDefault) {
  setup(); // prepend_once = false

  auto peer = std::make_shared<Network::Address::Ipv4Instance>("1.2.3.4", 1000);
  auto local = std::make_shared<Network::Address::Ipv4Instance>("10.0.0.1", 8080);

  auto data1 = makeRecvData(peer, local, "first");
  EXPECT_EQ(ReadFilterStatus::Continue, filter_->onData(data1));
  EXPECT_EQ(kV2IPv4HeaderSize + 5, data1.buffer_->length());

  auto data2 = makeRecvData(peer, local, "second");
  EXPECT_EQ(ReadFilterStatus::Continue, filter_->onData(data2));
  EXPECT_EQ(kV2IPv4HeaderSize + 6, data2.buffer_->length());

  auto data3 = makeRecvData(peer, local, "third");
  EXPECT_EQ(ReadFilterStatus::Continue, filter_->onData(data3));
  EXPECT_EQ(kV2IPv4HeaderSize + 5, data3.buffer_->length());
}

// With prepend_once=true, only the first datagram should carry the header.
TEST_F(ProxyProtocolFilterTest, HeaderPrependedOnceWhenConfigured) {
  setup(V2, /*prepend_once=*/true);

  auto peer = std::make_shared<Network::Address::Ipv4Instance>("1.2.3.4", 1000);
  auto local = std::make_shared<Network::Address::Ipv4Instance>("10.0.0.1", 8080);

  // First datagram: header + payload.
  auto data1 = makeRecvData(peer, local, "first");
  EXPECT_EQ(ReadFilterStatus::Continue, filter_->onData(data1));
  EXPECT_EQ(kV2IPv4HeaderSize + 5, data1.buffer_->length());

  // Subsequent datagrams: payload only, no header.
  auto data2 = makeRecvData(peer, local, "second");
  EXPECT_EQ(ReadFilterStatus::Continue, filter_->onData(data2));
  EXPECT_EQ(6u, data2.buffer_->length());
  EXPECT_EQ("second", data2.buffer_->toString());

  auto data3 = makeRecvData(peer, local, "third");
  EXPECT_EQ(ReadFilterStatus::Continue, filter_->onData(data3));
  EXPECT_EQ(5u, data3.buffer_->length());
  EXPECT_EQ("third", data3.buffer_->toString());
}

// onNewSession resets the prepended flag so the next session's first datagram gets a header.
TEST_F(ProxyProtocolFilterTest, NewSessionResetsHeaderPrependedFlag) {
  setup(V2, /*prepend_once=*/true);

  auto peer = std::make_shared<Network::Address::Ipv4Instance>("1.2.3.4", 1000);
  auto local = std::make_shared<Network::Address::Ipv4Instance>("10.0.0.1", 8080);

  // Session 1: only first datagram gets header.
  auto s1d1 = makeRecvData(peer, local, "s1d1");
  EXPECT_EQ(ReadFilterStatus::Continue, filter_->onData(s1d1));
  EXPECT_EQ(kV2IPv4HeaderSize + 4, s1d1.buffer_->length());

  auto s1d2 = makeRecvData(peer, local, "s1d2");
  EXPECT_EQ(ReadFilterStatus::Continue, filter_->onData(s1d2));
  EXPECT_EQ(4u, s1d2.buffer_->length()); // no header on second datagram

  // Start a new session.
  EXPECT_EQ(ReadFilterStatus::Continue, filter_->onNewSession());

  // Session 2: first datagram should get header again.
  auto s2d1 = makeRecvData(peer, local, "s2d1");
  EXPECT_EQ(ReadFilterStatus::Continue, filter_->onData(s2d1));
  EXPECT_EQ(kV2IPv4HeaderSize + 4, s2d1.buffer_->length());

  // Second datagram of session 2: no header.
  auto s2d2 = makeRecvData(peer, local, "s2d2");
  EXPECT_EQ(ReadFilterStatus::Continue, filter_->onData(s2d2));
  EXPECT_EQ(4u, s2d2.buffer_->length());
}

// When the peer address is null the filter logs a warning and passes the datagram unmodified.
TEST_F(ProxyProtocolFilterTest, MissingPeerAddressPassesDatagramUnmodified) {
  setup();

  Network::UdpRecvData data;
  data.addresses_.peer_ = nullptr;
  data.addresses_.local_ = std::make_shared<Network::Address::Ipv4Instance>("10.0.0.1", 8080);
  data.buffer_ = std::make_unique<Buffer::OwnedImpl>("payload");

  EXPECT_EQ(ReadFilterStatus::Continue, filter_->onData(data));
  EXPECT_EQ(7u, data.buffer_->length());
  EXPECT_EQ("payload", data.buffer_->toString());
}

// When the local address is null the filter logs a warning and passes the datagram unmodified.
TEST_F(ProxyProtocolFilterTest, MissingLocalAddressPassesDatagramUnmodified) {
  setup();

  Network::UdpRecvData data;
  data.addresses_.peer_ = std::make_shared<Network::Address::Ipv4Instance>("1.2.3.4", 1000);
  data.addresses_.local_ = nullptr;
  data.buffer_ = std::make_unique<Buffer::OwnedImpl>("payload");

  EXPECT_EQ(ReadFilterStatus::Continue, filter_->onData(data));
  EXPECT_EQ(7u, data.buffer_->length());
  EXPECT_EQ("payload", data.buffer_->toString());
}

// An empty payload still gets a full header prepended.
TEST_F(ProxyProtocolFilterTest, EmptyPayloadStillGetsHeader) {
  setup();

  auto peer = std::make_shared<Network::Address::Ipv4Instance>("1.2.3.4", 1000);
  auto local = std::make_shared<Network::Address::Ipv4Instance>("10.0.0.1", 8080);
  auto data = makeRecvData(peer, local, "");

  EXPECT_EQ(ReadFilterStatus::Continue, filter_->onData(data));
  EXPECT_EQ(kV2IPv4HeaderSize, data.buffer_->length());
}

// Verify the V2 header transport byte differs from TCP: DGRAM=0x02 vs STREAM=0x01.
TEST_F(ProxyProtocolFilterTest, V2HeaderUsesDgramTransportByte) {
  setup();

  auto peer = std::make_shared<Network::Address::Ipv4Instance>("1.2.3.4", 1000);
  auto local = std::make_shared<Network::Address::Ipv4Instance>("10.0.0.1", 8080);
  auto data = makeRecvData(peer, local, "test");

  EXPECT_EQ(ReadFilterStatus::Continue, filter_->onData(data));

  // Byte 13 (0-indexed) is the AF/protocol byte. For IPv4 UDP it must be 0x12.
  // TCP would be 0x11; the difference is the lower nibble: DGRAM=2 vs STREAM=1.
  ASSERT_GE(data.buffer_->length(), 14u);
  uint8_t af_proto_byte;
  data.buffer_->copyOut(13, 1, &af_proto_byte);
  EXPECT_EQ(0x12, af_proto_byte);
}

} // namespace
} // namespace ProxyProtocol
} // namespace SessionFilters
} // namespace UdpProxy
} // namespace UdpFilters
} // namespace Extensions
} // namespace Envoy
