// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Data.Json.1.h"
#include "winrt/impl/Windows.Foundation.Collections.1.h"
#include "winrt/impl/Windows.System.1.h"
#include "winrt/impl/Windows.System.Diagnostics.1.h"

WINRT_EXPORT namespace winrt::Windows::System::Diagnostics {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::System::Diagnostics {

struct WINRT_EBO DiagnosticActionResult :
    Windows::System::Diagnostics::IDiagnosticActionResult
{
    DiagnosticActionResult(std::nullptr_t) noexcept {}
};

struct WINRT_EBO DiagnosticInvoker :
    Windows::System::Diagnostics::IDiagnosticInvoker,
    impl::require<DiagnosticInvoker, Windows::System::Diagnostics::IDiagnosticInvoker2>
{
    DiagnosticInvoker(std::nullptr_t) noexcept {}
    static Windows::System::Diagnostics::DiagnosticInvoker GetDefault();
    static Windows::System::Diagnostics::DiagnosticInvoker GetForUser(Windows::System::User const& user);
    static bool IsSupported();
};

struct WINRT_EBO ProcessCpuUsage :
    Windows::System::Diagnostics::IProcessCpuUsage
{
    ProcessCpuUsage(std::nullptr_t) noexcept {}
};

struct WINRT_EBO ProcessCpuUsageReport :
    Windows::System::Diagnostics::IProcessCpuUsageReport
{
    ProcessCpuUsageReport(std::nullptr_t) noexcept {}
};

struct WINRT_EBO ProcessDiagnosticInfo :
    Windows::System::Diagnostics::IProcessDiagnosticInfo,
    impl::require<ProcessDiagnosticInfo, Windows::System::Diagnostics::IProcessDiagnosticInfo2>
{
    ProcessDiagnosticInfo(std::nullptr_t) noexcept {}
    static Windows::Foundation::Collections::IVectorView<Windows::System::Diagnostics::ProcessDiagnosticInfo> GetForProcesses();
    static Windows::System::Diagnostics::ProcessDiagnosticInfo GetForCurrentProcess();
    static Windows::System::Diagnostics::ProcessDiagnosticInfo TryGetForProcessId(uint32_t processId);
};

struct WINRT_EBO ProcessDiskUsage :
    Windows::System::Diagnostics::IProcessDiskUsage
{
    ProcessDiskUsage(std::nullptr_t) noexcept {}
};

struct WINRT_EBO ProcessDiskUsageReport :
    Windows::System::Diagnostics::IProcessDiskUsageReport
{
    ProcessDiskUsageReport(std::nullptr_t) noexcept {}
};

struct WINRT_EBO ProcessMemoryUsage :
    Windows::System::Diagnostics::IProcessMemoryUsage
{
    ProcessMemoryUsage(std::nullptr_t) noexcept {}
};

struct WINRT_EBO ProcessMemoryUsageReport :
    Windows::System::Diagnostics::IProcessMemoryUsageReport
{
    ProcessMemoryUsageReport(std::nullptr_t) noexcept {}
};

struct WINRT_EBO SystemCpuUsage :
    Windows::System::Diagnostics::ISystemCpuUsage
{
    SystemCpuUsage(std::nullptr_t) noexcept {}
};

struct WINRT_EBO SystemCpuUsageReport :
    Windows::System::Diagnostics::ISystemCpuUsageReport
{
    SystemCpuUsageReport(std::nullptr_t) noexcept {}
};

struct WINRT_EBO SystemDiagnosticInfo :
    Windows::System::Diagnostics::ISystemDiagnosticInfo
{
    SystemDiagnosticInfo(std::nullptr_t) noexcept {}
    static Windows::System::Diagnostics::SystemDiagnosticInfo GetForCurrentSystem();
};

struct WINRT_EBO SystemMemoryUsage :
    Windows::System::Diagnostics::ISystemMemoryUsage
{
    SystemMemoryUsage(std::nullptr_t) noexcept {}
};

struct WINRT_EBO SystemMemoryUsageReport :
    Windows::System::Diagnostics::ISystemMemoryUsageReport
{
    SystemMemoryUsageReport(std::nullptr_t) noexcept {}
};

}
