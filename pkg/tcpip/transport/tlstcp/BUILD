load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "tlstcp",
    srcs = [
        "endpoint.go",
        "protocol.go",
    ],
    visibility = ["//visibility:public"], 
    deps = [
        "//pkg/tcpip/transport/tcp",
        "//pkg/tcpip/header",
        "//pkg/tcpip/header/parse",
        "//pkg/tcpip/transport/raw",
        "//pkg/tcpip",
        "//pkg/tcpip/stack",
	    "//pkg/waiter",
        "//pkg/log", 
        "//pkg/tcpip/adapters/gonet",
    ],
)