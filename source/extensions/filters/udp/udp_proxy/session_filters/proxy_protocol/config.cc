#include "source/extensions/filters/udp/udp_proxy/session_filters/proxy_protocol/config.h"

#include "envoy/registry/registry.h"
#include "envoy/server/filter_config.h"

#include "source/extensions/filters/udp/udp_proxy/session_filters/proxy_protocol/proxy_protocol.h"

namespace Envoy {
namespace Extensions {
namespace UdpFilters {
namespace UdpProxy {
namespace SessionFilters {
namespace ProxyProtocol {

FilterFactoryCb ProxyProtocolFilterConfigFactory::createFilterFactoryFromProtoTyped(
    const FilterConfig& proto_config, Server::Configuration::FactoryContext&) {
  const auto version = proto_config.version();
  const bool prepend_once = proto_config.prepend_once();

  return [version, prepend_once](Network::UdpSessionFilterChainFactoryCallbacks& callbacks) {
    callbacks.addFilter(std::make_shared<ProxyProtocolFilter>(version, prepend_once));
  };
}

REGISTER_FACTORY(ProxyProtocolFilterConfigFactory, NamedUdpSessionFilterConfigFactory);

} // namespace ProxyProtocol
} // namespace SessionFilters
} // namespace UdpProxy
} // namespace UdpFilters
} // namespace Extensions
} // namespace Envoy
