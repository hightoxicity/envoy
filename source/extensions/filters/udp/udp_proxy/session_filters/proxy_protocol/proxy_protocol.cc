#include "source/extensions/filters/udp/udp_proxy/session_filters/proxy_protocol/proxy_protocol.h"

#include "source/common/buffer/buffer_impl.h"
#include "source/extensions/common/proxy_protocol/proxy_protocol_header.h"

namespace Envoy {
namespace Extensions {
namespace UdpFilters {
namespace UdpProxy {
namespace SessionFilters {
namespace ProxyProtocol {

namespace PP = Extensions::Common::ProxyProtocol;

ProxyProtocolFilter::ProxyProtocolFilter(ProxyProtocolVersion version, bool prepend_once)
    : version_(version), prepend_once_(prepend_once) {}

ReadFilterStatus ProxyProtocolFilter::onNewSession() {
  header_prepended_ = false;
  return ReadFilterStatus::Continue;
}

ReadFilterStatus ProxyProtocolFilter::onData(Network::UdpRecvData& data) {
  if (prepend_once_ && header_prepended_) {
    return ReadFilterStatus::Continue;
  }

  const auto* src_ip = data.addresses_.peer_ ? data.addresses_.peer_->ip() : nullptr;
  const auto* dst_ip = data.addresses_.local_ ? data.addresses_.local_->ip() : nullptr;

  if (src_ip == nullptr || dst_ip == nullptr) {
    ENVOY_LOG(warn, "udp proxy_protocol: missing peer or local address, skipping header");
    return ReadFilterStatus::Continue;
  }

  Buffer::OwnedImpl header_buf;

  if (version_ == envoy::extensions::filters::udp::udp_proxy::session::proxy_protocol::v3::
                      FilterConfig_Version_V2) {
    PP::generateV2UdpHeader(*src_ip, *dst_ip, header_buf);
  } else {
    PP::generateV1Header(*src_ip, *dst_ip, header_buf);
  }

  // Prepend the proxy protocol header: move original payload after the header, then swap back.
  header_buf.move(*data.buffer_);
  data.buffer_->move(header_buf);

  header_prepended_ = true;
  return ReadFilterStatus::Continue;
}

} // namespace ProxyProtocol
} // namespace SessionFilters
} // namespace UdpProxy
} // namespace UdpFilters
} // namespace Extensions
} // namespace Envoy
