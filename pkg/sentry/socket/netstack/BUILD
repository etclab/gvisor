load("//pkg/sync/locking:locking.bzl", "declare_mutex")
load("//tools:defs.bzl", "go_library", "go_test", "proto_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

declare_mutex(
    name = "netstack_link_mutex",
    out = "netstack_link_mutex.go",
    nested_lock_names = ["destStack"],
    package = "netstack",
    prefix = "netstackLink",
)

go_library(
    name = "netstack",
    srcs = [
        "netstack.go",
        "netstack_link_mutex.go",
        "netstack_state.go",
        "provider.go",
        "socketopt_custom.go",
        "stack.go",
        "tun.go",
        "tunnel.go",
        "tunnel_dns.go",
        "tunnel_endpoint.go",
    ],
    imports = [
        "gvisor.dev/gvisor/pkg/tcpip/stack",
    ],
    visibility = [
        "//pkg/sentry:internal",
    ],
    deps = [
        ":events_go_proto",
        "//pkg/abi/linux",
        "//pkg/abi/linux/errno",
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/eventchannel",
        "//pkg/fdnotifier",
        "//pkg/hostarch",
        "//pkg/log",
        "//pkg/marshal",
        "//pkg/marshal/primitive",
        "//pkg/metric",
        "//pkg/refs",
        "//pkg/sentry/arch",
        "//pkg/sentry/fsimpl/sockfs",
        "//pkg/sentry/inet",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/ktime",
        "//pkg/sentry/memmap",
        "//pkg/sentry/seccheck",
        "//pkg/sentry/seccheck/points:points_go_proto",
        "//pkg/sentry/socket",
        "//pkg/sentry/socket/netfilter",
        "//pkg/sentry/socket/netlink/nlmsg",
        "//pkg/sentry/socket/netstack/packetmmap",
        "//pkg/sentry/uniqueid",
        "//pkg/sentry/vfs",
        "//pkg/sync",
        "//pkg/sync/locking",
        "//pkg/syserr",
        "//pkg/tcpip",
        "//pkg/tcpip/header",
        "//pkg/tcpip/link/ethernet",
        "//pkg/tcpip/link/packetsocket",
        "//pkg/tcpip/link/tun",
        "//pkg/tcpip/link/veth",
        "//pkg/tcpip/network/ipv4",
        "//pkg/tcpip/network/ipv6",
        "//pkg/tcpip/stack",
        "//pkg/tcpip/transport",
        "//pkg/tcpip/transport/tcp",
        "//pkg/tcpip/transport/udp",
        "//pkg/usermem",
        "//pkg/waiter",
        "@org_golang_google_protobuf//proto:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "netstack_test",
    srcs = ["stack_test.go"],
    deps = [":netstack"],
)

go_test(
    name = "tunnel_test",
    size = "small",
    srcs = [
        "tunnel_dns_test.go",
        "tunnel_narrow_test.go",
        "tunnel_test.go",
    ],
    library = ":netstack",
    deps = [
        "//pkg/abi/linux",
        "//pkg/tcpip",
        "//pkg/waiter",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

proto_library(
    name = "events",
    srcs = ["events.proto"],
    visibility = ["//visibility:public"],
)
