#pragma once

#include "envoy/extensions/filters/udp/udp_proxy/session/proxy_protocol/v3/proxy_protocol.pb.h"
#include "envoy/network/filter.h"
#include "envoy/network/listener.h"

#include "source/common/common/logger.h"
#include "source/extensions/filters/udp/udp_proxy/session_filters/pass_through_filter.h"

namespace Envoy {
namespace Extensions {
namespace UdpFilters {
namespace UdpProxy {
namespace SessionFilters {
namespace ProxyProtocol {

using ReadFilterStatus = Network::UdpSessionReadFilterStatus;
using ReadFilterCallbacks = Network::UdpSessionReadFilterCallbacks;
using ProxyProtocolVersion = envoy::extensions::filters::udp::udp_proxy::session::proxy_protocol::
    v3::FilterConfig_Version;

/**
 * UDP session filter that prepends a PROXY protocol header (v1 or v2) to each upstream datagram.
 * The header carries the original client IP address and port so that cluster members can identify
 * the real source of traffic without relying on the UDP source address of the Envoy endpoint.
 *
 * Only the *read* direction (client → upstream) is modified. Datagrams flowing in the write
 * direction (upstream → client) are passed through unchanged.
 */
class ProxyProtocolFilter : public PassThroughFilter,
                            Logger::Loggable<Logger::Id::filter> {
public:
  ProxyProtocolFilter(ProxyProtocolVersion version, bool prepend_once);

  // UdpSessionReadFilter
  ReadFilterStatus onNewSession() override;
  ReadFilterStatus onData(Network::UdpRecvData& data) override;

private:
  const ProxyProtocolVersion version_;
  const bool prepend_once_;
  bool header_prepended_{false};
};

} // namespace ProxyProtocol
} // namespace SessionFilters
} // namespace UdpProxy
} // namespace UdpFilters
} // namespace Extensions
} // namespace Envoy
