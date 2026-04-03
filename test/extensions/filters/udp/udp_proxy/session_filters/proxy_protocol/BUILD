load(
    "//bazel:envoy_build_system.bzl",
    "envoy_package",
)
load(
    "//test/extensions:extensions_build_system.bzl",
    "envoy_extension_cc_test",
)

licenses(["notice"])  # Apache 2

envoy_package()

envoy_extension_cc_test(
    name = "proxy_protocol_filter_test",
    srcs = ["proxy_protocol_filter_test.cc"],
    extension_names = ["envoy.filters.udp.session.proxy_protocol"],
    rbe_pool = "6gig",
    deps = [
        "//source/common/network:address_lib",
        "//source/extensions/filters/udp/udp_proxy/session_filters/proxy_protocol:config",
        "//test/extensions/filters/udp/udp_proxy:mocks",
        "//test/test_common:utility_lib",
        "@envoy_api//envoy/extensions/filters/udp/udp_proxy/session/proxy_protocol/v3:pkg_cc_proto",
    ],
)
