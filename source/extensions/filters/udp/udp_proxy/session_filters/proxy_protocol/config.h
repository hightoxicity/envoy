#pragma once

#include "envoy/extensions/filters/udp/udp_proxy/session/proxy_protocol/v3/proxy_protocol.pb.h"
#include "envoy/extensions/filters/udp/udp_proxy/session/proxy_protocol/v3/proxy_protocol.pb.validate.h"

#include "source/extensions/filters/udp/udp_proxy/session_filters/factory_base.h"

namespace Envoy {
namespace Extensions {
namespace UdpFilters {
namespace UdpProxy {
namespace SessionFilters {
namespace ProxyProtocol {

using FilterConfig = envoy::extensions::filters::udp::udp_proxy::session::proxy_protocol::v3::
    FilterConfig;
using FilterFactoryCb = Network::UdpSessionFilterFactoryCb;

/**
 * Config registration for the UDP proxy_protocol session filter.
 */
class ProxyProtocolFilterConfigFactory : public FactoryBase<FilterConfig> {
public:
  ProxyProtocolFilterConfigFactory()
      : FactoryBase("envoy.filters.udp.session.proxy_protocol"){};

private:
  FilterFactoryCb
  createFilterFactoryFromProtoTyped(const FilterConfig& proto_config,
                                    Server::Configuration::FactoryContext& context) override;
};

} // namespace ProxyProtocol
} // namespace SessionFilters
} // namespace UdpProxy
} // namespace UdpFilters
} // namespace Extensions
} // namespace Envoy
