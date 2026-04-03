load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_extension",
    "envoy_cc_library",
    "envoy_extension_package",
)

licenses(["notice"])  # Apache 2

envoy_extension_package()

envoy_cc_library(
    name = "proxy_protocol_filter_lib",
    srcs = ["proxy_protocol.cc"],
    hdrs = ["proxy_protocol.h"],
    deps = [
        "//envoy/network:filter_interface",
        "//envoy/network:listener_interface",
        "//source/common/buffer:buffer_lib",
        "//source/common/common:logger_lib",
        "//source/extensions/common/proxy_protocol:proxy_protocol_header_lib",
        "//source/extensions/filters/udp/udp_proxy/session_filters:pass_through_filter_lib",
        "@envoy_api//envoy/extensions/filters/udp/udp_proxy/session/proxy_protocol/v3:pkg_cc_proto",
    ],
)

envoy_cc_extension(
    name = "config",
    srcs = ["config.cc"],
    hdrs = ["config.h"],
    visibility = ["//visibility:public"],
    deps = [
        ":proxy_protocol_filter_lib",
        "//source/extensions/filters/udp/udp_proxy/session_filters:factory_base_lib",
        "@envoy_api//envoy/extensions/filters/udp/udp_proxy/session/proxy_protocol/v3:pkg_cc_proto",
    ],
)
