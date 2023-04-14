// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.System.Diagnostics.TraceReporting.0.h"

WINRT_EXPORT namespace winrt::Windows::System::Diagnostics::TraceReporting {

struct WINRT_EBO IPlatformDiagnosticActionsStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPlatformDiagnosticActionsStatics>
{
    IPlatformDiagnosticActionsStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPlatformDiagnosticTraceInfo :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPlatformDiagnosticTraceInfo>
{
    IPlatformDiagnosticTraceInfo(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPlatformDiagnosticTraceRuntimeInfo :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPlatformDiagnosticTraceRuntimeInfo>
{
    IPlatformDiagnosticTraceRuntimeInfo(std::nullptr_t = nullptr) noexcept {}
};

}
