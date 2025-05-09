load("@build_bazel_rules_apple//apple:apple.bzl", "apple_static_framework_import")
load(
    "@com_github_buildbuddy_io_rules_xcodeproj//xcodeproj:defs.bzl",
    "project_options",
    "top_level_targets",
    "xcode_schemes",
    "xcodeproj",
)
load("@envoy//tools/python:namespace.bzl", "envoy_py_namespace")
load("@rules_android//android:rules.bzl", "aar_import")
load("@rules_kotlin//kotlin/internal:toolchains.bzl", "define_kt_toolchain")
load("//bazel:framework_imports_extractor.bzl", "framework_imports_extractor")

licenses(["notice"])  # Apache 2

envoy_py_namespace()

exports_files(["VERSION"])

alias(
    name = "ios_xcframework",
    actual = "//library/swift:Envoy",
    visibility = ["//visibility:public"],
)

alias(
    name = "ios_dist",
    actual = "//library/swift:ios_framework",
)

framework_imports_extractor(
    name = "framework_imports",
    framework = "//library/swift:ios_framework",
)

apple_static_framework_import(
    name = "envoy_mobile_ios",
    framework_imports = [":framework_imports"],
    sdk_dylibs = [
        "resolv.9",
        "c++",
    ],
    sdk_frameworks = [
        "Network",
        "SystemConfiguration",
        "UIKit",
    ],
    visibility = ["//visibility:public"],
)

alias(
    name = "android_aar",
    actual = "//library/kotlin/io/envoyproxy/envoymobile:envoy_aar",
    visibility = ["//visibility:public"],
)

aar_import(
    name = "envoy_mobile_android",
    aar = "//library/kotlin/io/envoyproxy/envoymobile:envoy_aar",
    visibility = ["//visibility:public"],
)

alias(
    name = "android_dist",
    actual = "//library/kotlin/io/envoyproxy/envoymobile:envoy_aar_with_artifacts",
)

alias(
    name = "android_xds_dist",
    actual = "//library/kotlin/io/envoyproxy/envoymobile:envoy_xds_aar_with_artifacts",
)

define_kt_toolchain(
    name = "kotlin_toolchain",
    jvm_target = "1.8",
)

filegroup(
    name = "kotlin_lint_config",
    srcs = [".kotlinlint.yml"],
    visibility = ["//visibility:public"],
)

filegroup(
    name = "editor_config",
    srcs = [".editorconfig"],
    visibility = ["//visibility:public"],
)

genrule(
    name = "kotlin_format",
    srcs = ["//:editor_config"],
    outs = ["kotlin_format.txt"],
    cmd = """
    $(location @kotlin_formatter//file) --android "**/*.kt" \
        --reporter=plain --reporter=checkstyle,output=$@ \
        --editorconfig=$(location //:editor_config)
    """,
    tools = ["@kotlin_formatter//file"],
)

genrule(
    name = "kotlin_format_fix",
    srcs = ["//:editor_config"],
    outs = ["kotlin_format_fix.txt"],
    cmd = """
    $(location @kotlin_formatter//file) -F --android "**/*.kt" \
        --reporter=plain --reporter=checkstyle,output=$@ \
        --editorconfig=$(location //:editor_config)
    """,
    tools = ["@kotlin_formatter//file"],
)

xcodeproj(
    name = "xcodeproj",
    bazel_path = "./bazelw",
    build_mode = "bazel",
    project_name = "Envoy",
    project_options = project_options(
        indent_width = 2,
        tab_width = 2,
    ),
    scheme_autogeneration_mode = "auto",  # Switch to "all" to generate schemes for all deps
    schemes = [
        xcode_schemes.scheme(
            name = "Hello World App",
            launch_action = xcode_schemes.launch_action("//examples/swift/hello_world:app"),
        ),
        xcode_schemes.scheme(
            name = "Hello World App (ObjC)",
            launch_action = xcode_schemes.launch_action("//examples/objective-c/hello_world:app"),
        ),
        xcode_schemes.scheme(
            name = "Experimental App",
            launch_action = xcode_schemes.launch_action("//test/swift/apps/experimental:app"),
        ),
        xcode_schemes.scheme(
            name = "Swift Library",
            build_action = xcode_schemes.build_action(["//library/swift:ios_lib"]),
        ),
        xcode_schemes.scheme(
            name = "iOS Tests",
            test_action = xcode_schemes.test_action([
                "//experimental/swift:quic_stream_test",
                "//test/objective-c:envoy_bridge_utility_test",
                "//test/swift/integration:test",
                "//test/swift/stats:test",
                "//test/swift:test",
            ]),
        ),
        xcode_schemes.scheme(
            name = "Objective-C Library",
            build_action = xcode_schemes.build_action(["//library/objective-c:envoy_engine_objc_lib"]),
            test_action = xcode_schemes.test_action(["//test/objective-c:envoy_bridge_utility_test"]),
        ),
    ],
    tags = ["manual"],
    top_level_targets = [
        # Apps
        top_level_targets(
            labels = [
                "//examples/objective-c/hello_world:app",
                "//examples/swift/hello_world:app",
                "//test/swift/apps/experimental:app",
            ],
            target_environments = [
                "device",
                "simulator",
            ],
        ),
        # Tests
        "//experimental/swift:quic_stream_test",
        "//test/objective-c:envoy_bridge_utility_test",
        "//test/swift/cxx:test",
        "//test/swift/integration:test",
        "//test/swift/stats:test",
        "//test/swift:test",
    ],
)

platform(
    name = "android_armv7",
    constraint_values = [
        "@platforms//cpu:armv7",
        "@platforms//os:android",
    ],
)

platform(
    name = "android_arm64",
    constraint_values = [
        "@platforms//cpu:arm64",
        "@platforms//os:android",
    ],
)

platform(
    name = "android_x86_32",
    constraint_values = [
        "@platforms//cpu:x86_32",
        "@platforms//os:android",
    ],
)

platform(
    name = "android_x86_64",
    constraint_values = [
        "@platforms//cpu:x86_64",
        "@platforms//os:android",
    ],
)
