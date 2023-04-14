// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Data.Json.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.System.Diagnostics.2.h"
#include "winrt/Windows.System.h"

namespace winrt::impl {

template <typename D> winrt::hresult consume_Windows_System_Diagnostics_IDiagnosticActionResult<D>::ExtendedError() const
{
    winrt::hresult value{};
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::IDiagnosticActionResult)->get_ExtendedError(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::ValueSet consume_Windows_System_Diagnostics_IDiagnosticActionResult<D>::Results() const
{
    Windows::Foundation::Collections::ValueSet value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::IDiagnosticActionResult)->get_Results(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::System::Diagnostics::DiagnosticActionResult, Windows::System::Diagnostics::DiagnosticActionState> consume_Windows_System_Diagnostics_IDiagnosticInvoker<D>::RunDiagnosticActionAsync(Windows::Data::Json::JsonObject const& context) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::System::Diagnostics::DiagnosticActionResult, Windows::System::Diagnostics::DiagnosticActionState> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::IDiagnosticInvoker)->RunDiagnosticActionAsync(get_abi(context), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::System::Diagnostics::DiagnosticActionResult, Windows::System::Diagnostics::DiagnosticActionState> consume_Windows_System_Diagnostics_IDiagnosticInvoker2<D>::RunDiagnosticActionFromStringAsync(param::hstring const& context) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::System::Diagnostics::DiagnosticActionResult, Windows::System::Diagnostics::DiagnosticActionState> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::IDiagnosticInvoker2)->RunDiagnosticActionFromStringAsync(get_abi(context), put_abi(operation)));
    return operation;
}

template <typename D> Windows::System::Diagnostics::DiagnosticInvoker consume_Windows_System_Diagnostics_IDiagnosticInvokerStatics<D>::GetDefault() const
{
    Windows::System::Diagnostics::DiagnosticInvoker result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::IDiagnosticInvokerStatics)->GetDefault(put_abi(result)));
    return result;
}

template <typename D> Windows::System::Diagnostics::DiagnosticInvoker consume_Windows_System_Diagnostics_IDiagnosticInvokerStatics<D>::GetForUser(Windows::System::User const& user) const
{
    Windows::System::Diagnostics::DiagnosticInvoker result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::IDiagnosticInvokerStatics)->GetForUser(get_abi(user), put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_System_Diagnostics_IDiagnosticInvokerStatics<D>::IsSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::IDiagnosticInvokerStatics)->get_IsSupported(&value));
    return value;
}

template <typename D> Windows::System::Diagnostics::ProcessCpuUsageReport consume_Windows_System_Diagnostics_IProcessCpuUsage<D>::GetReport() const
{
    Windows::System::Diagnostics::ProcessCpuUsageReport value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::IProcessCpuUsage)->GetReport(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_System_Diagnostics_IProcessCpuUsageReport<D>::KernelTime() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::IProcessCpuUsageReport)->get_KernelTime(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_System_Diagnostics_IProcessCpuUsageReport<D>::UserTime() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::IProcessCpuUsageReport)->get_UserTime(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_System_Diagnostics_IProcessDiagnosticInfo<D>::ProcessId() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::IProcessDiagnosticInfo)->get_ProcessId(&value));
    return value;
}

template <typename D> hstring consume_Windows_System_Diagnostics_IProcessDiagnosticInfo<D>::ExecutableFileName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::IProcessDiagnosticInfo)->get_ExecutableFileName(put_abi(value)));
    return value;
}

template <typename D> Windows::System::Diagnostics::ProcessDiagnosticInfo consume_Windows_System_Diagnostics_IProcessDiagnosticInfo<D>::Parent() const
{
    Windows::System::Diagnostics::ProcessDiagnosticInfo value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::IProcessDiagnosticInfo)->get_Parent(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_System_Diagnostics_IProcessDiagnosticInfo<D>::ProcessStartTime() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::IProcessDiagnosticInfo)->get_ProcessStartTime(put_abi(value)));
    return value;
}

template <typename D> Windows::System::Diagnostics::ProcessDiskUsage consume_Windows_System_Diagnostics_IProcessDiagnosticInfo<D>::DiskUsage() const
{
    Windows::System::Diagnostics::ProcessDiskUsage value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::IProcessDiagnosticInfo)->get_DiskUsage(put_abi(value)));
    return value;
}

template <typename D> Windows::System::Diagnostics::ProcessMemoryUsage consume_Windows_System_Diagnostics_IProcessDiagnosticInfo<D>::MemoryUsage() const
{
    Windows::System::Diagnostics::ProcessMemoryUsage value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::IProcessDiagnosticInfo)->get_MemoryUsage(put_abi(value)));
    return value;
}

template <typename D> Windows::System::Diagnostics::ProcessCpuUsage consume_Windows_System_Diagnostics_IProcessDiagnosticInfo<D>::CpuUsage() const
{
    Windows::System::Diagnostics::ProcessCpuUsage value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::IProcessDiagnosticInfo)->get_CpuUsage(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::System::AppDiagnosticInfo> consume_Windows_System_Diagnostics_IProcessDiagnosticInfo2<D>::GetAppDiagnosticInfos() const
{
    Windows::Foundation::Collections::IVector<Windows::System::AppDiagnosticInfo> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::IProcessDiagnosticInfo2)->GetAppDiagnosticInfos(put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_System_Diagnostics_IProcessDiagnosticInfo2<D>::IsPackaged() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::IProcessDiagnosticInfo2)->get_IsPackaged(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::System::Diagnostics::ProcessDiagnosticInfo> consume_Windows_System_Diagnostics_IProcessDiagnosticInfoStatics<D>::GetForProcesses() const
{
    Windows::Foundation::Collections::IVectorView<Windows::System::Diagnostics::ProcessDiagnosticInfo> processes{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::IProcessDiagnosticInfoStatics)->GetForProcesses(put_abi(processes)));
    return processes;
}

template <typename D> Windows::System::Diagnostics::ProcessDiagnosticInfo consume_Windows_System_Diagnostics_IProcessDiagnosticInfoStatics<D>::GetForCurrentProcess() const
{
    Windows::System::Diagnostics::ProcessDiagnosticInfo processes{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::IProcessDiagnosticInfoStatics)->GetForCurrentProcess(put_abi(processes)));
    return processes;
}

template <typename D> Windows::System::Diagnostics::ProcessDiagnosticInfo consume_Windows_System_Diagnostics_IProcessDiagnosticInfoStatics2<D>::TryGetForProcessId(uint32_t processId) const
{
    Windows::System::Diagnostics::ProcessDiagnosticInfo result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::IProcessDiagnosticInfoStatics2)->TryGetForProcessId(processId, put_abi(result)));
    return result;
}

template <typename D> Windows::System::Diagnostics::ProcessDiskUsageReport consume_Windows_System_Diagnostics_IProcessDiskUsage<D>::GetReport() const
{
    Windows::System::Diagnostics::ProcessDiskUsageReport value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::IProcessDiskUsage)->GetReport(put_abi(value)));
    return value;
}

template <typename D> int64_t consume_Windows_System_Diagnostics_IProcessDiskUsageReport<D>::ReadOperationCount() const
{
    int64_t value{};
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::IProcessDiskUsageReport)->get_ReadOperationCount(&value));
    return value;
}

template <typename D> int64_t consume_Windows_System_Diagnostics_IProcessDiskUsageReport<D>::WriteOperationCount() const
{
    int64_t value{};
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::IProcessDiskUsageReport)->get_WriteOperationCount(&value));
    return value;
}

template <typename D> int64_t consume_Windows_System_Diagnostics_IProcessDiskUsageReport<D>::OtherOperationCount() const
{
    int64_t value{};
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::IProcessDiskUsageReport)->get_OtherOperationCount(&value));
    return value;
}

template <typename D> int64_t consume_Windows_System_Diagnostics_IProcessDiskUsageReport<D>::BytesReadCount() const
{
    int64_t value{};
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::IProcessDiskUsageReport)->get_BytesReadCount(&value));
    return value;
}

template <typename D> int64_t consume_Windows_System_Diagnostics_IProcessDiskUsageReport<D>::BytesWrittenCount() const
{
    int64_t value{};
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::IProcessDiskUsageReport)->get_BytesWrittenCount(&value));
    return value;
}

template <typename D> int64_t consume_Windows_System_Diagnostics_IProcessDiskUsageReport<D>::OtherBytesCount() const
{
    int64_t value{};
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::IProcessDiskUsageReport)->get_OtherBytesCount(&value));
    return value;
}

template <typename D> Windows::System::Diagnostics::ProcessMemoryUsageReport consume_Windows_System_Diagnostics_IProcessMemoryUsage<D>::GetReport() const
{
    Windows::System::Diagnostics::ProcessMemoryUsageReport value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::IProcessMemoryUsage)->GetReport(put_abi(value)));
    return value;
}

template <typename D> uint64_t consume_Windows_System_Diagnostics_IProcessMemoryUsageReport<D>::NonPagedPoolSizeInBytes() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::IProcessMemoryUsageReport)->get_NonPagedPoolSizeInBytes(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_System_Diagnostics_IProcessMemoryUsageReport<D>::PageFaultCount() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::IProcessMemoryUsageReport)->get_PageFaultCount(&value));
    return value;
}

template <typename D> uint64_t consume_Windows_System_Diagnostics_IProcessMemoryUsageReport<D>::PageFileSizeInBytes() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::IProcessMemoryUsageReport)->get_PageFileSizeInBytes(&value));
    return value;
}

template <typename D> uint64_t consume_Windows_System_Diagnostics_IProcessMemoryUsageReport<D>::PagedPoolSizeInBytes() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::IProcessMemoryUsageReport)->get_PagedPoolSizeInBytes(&value));
    return value;
}

template <typename D> uint64_t consume_Windows_System_Diagnostics_IProcessMemoryUsageReport<D>::PeakNonPagedPoolSizeInBytes() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::IProcessMemoryUsageReport)->get_PeakNonPagedPoolSizeInBytes(&value));
    return value;
}

template <typename D> uint64_t consume_Windows_System_Diagnostics_IProcessMemoryUsageReport<D>::PeakPageFileSizeInBytes() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::IProcessMemoryUsageReport)->get_PeakPageFileSizeInBytes(&value));
    return value;
}

template <typename D> uint64_t consume_Windows_System_Diagnostics_IProcessMemoryUsageReport<D>::PeakPagedPoolSizeInBytes() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::IProcessMemoryUsageReport)->get_PeakPagedPoolSizeInBytes(&value));
    return value;
}

template <typename D> uint64_t consume_Windows_System_Diagnostics_IProcessMemoryUsageReport<D>::PeakVirtualMemorySizeInBytes() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::IProcessMemoryUsageReport)->get_PeakVirtualMemorySizeInBytes(&value));
    return value;
}

template <typename D> uint64_t consume_Windows_System_Diagnostics_IProcessMemoryUsageReport<D>::PeakWorkingSetSizeInBytes() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::IProcessMemoryUsageReport)->get_PeakWorkingSetSizeInBytes(&value));
    return value;
}

template <typename D> uint64_t consume_Windows_System_Diagnostics_IProcessMemoryUsageReport<D>::PrivatePageCount() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::IProcessMemoryUsageReport)->get_PrivatePageCount(&value));
    return value;
}

template <typename D> uint64_t consume_Windows_System_Diagnostics_IProcessMemoryUsageReport<D>::VirtualMemorySizeInBytes() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::IProcessMemoryUsageReport)->get_VirtualMemorySizeInBytes(&value));
    return value;
}

template <typename D> uint64_t consume_Windows_System_Diagnostics_IProcessMemoryUsageReport<D>::WorkingSetSizeInBytes() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::IProcessMemoryUsageReport)->get_WorkingSetSizeInBytes(&value));
    return value;
}

template <typename D> Windows::System::Diagnostics::SystemCpuUsageReport consume_Windows_System_Diagnostics_ISystemCpuUsage<D>::GetReport() const
{
    Windows::System::Diagnostics::SystemCpuUsageReport value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::ISystemCpuUsage)->GetReport(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_System_Diagnostics_ISystemCpuUsageReport<D>::KernelTime() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::ISystemCpuUsageReport)->get_KernelTime(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_System_Diagnostics_ISystemCpuUsageReport<D>::UserTime() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::ISystemCpuUsageReport)->get_UserTime(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_System_Diagnostics_ISystemCpuUsageReport<D>::IdleTime() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::ISystemCpuUsageReport)->get_IdleTime(put_abi(value)));
    return value;
}

template <typename D> Windows::System::Diagnostics::SystemMemoryUsage consume_Windows_System_Diagnostics_ISystemDiagnosticInfo<D>::MemoryUsage() const
{
    Windows::System::Diagnostics::SystemMemoryUsage value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::ISystemDiagnosticInfo)->get_MemoryUsage(put_abi(value)));
    return value;
}

template <typename D> Windows::System::Diagnostics::SystemCpuUsage consume_Windows_System_Diagnostics_ISystemDiagnosticInfo<D>::CpuUsage() const
{
    Windows::System::Diagnostics::SystemCpuUsage value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::ISystemDiagnosticInfo)->get_CpuUsage(put_abi(value)));
    return value;
}

template <typename D> Windows::System::Diagnostics::SystemDiagnosticInfo consume_Windows_System_Diagnostics_ISystemDiagnosticInfoStatics<D>::GetForCurrentSystem() const
{
    Windows::System::Diagnostics::SystemDiagnosticInfo value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::ISystemDiagnosticInfoStatics)->GetForCurrentSystem(put_abi(value)));
    return value;
}

template <typename D> Windows::System::Diagnostics::SystemMemoryUsageReport consume_Windows_System_Diagnostics_ISystemMemoryUsage<D>::GetReport() const
{
    Windows::System::Diagnostics::SystemMemoryUsageReport value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::ISystemMemoryUsage)->GetReport(put_abi(value)));
    return value;
}

template <typename D> uint64_t consume_Windows_System_Diagnostics_ISystemMemoryUsageReport<D>::TotalPhysicalSizeInBytes() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::ISystemMemoryUsageReport)->get_TotalPhysicalSizeInBytes(&value));
    return value;
}

template <typename D> uint64_t consume_Windows_System_Diagnostics_ISystemMemoryUsageReport<D>::AvailableSizeInBytes() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::ISystemMemoryUsageReport)->get_AvailableSizeInBytes(&value));
    return value;
}

template <typename D> uint64_t consume_Windows_System_Diagnostics_ISystemMemoryUsageReport<D>::CommittedSizeInBytes() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::System::Diagnostics::ISystemMemoryUsageReport)->get_CommittedSizeInBytes(&value));
    return value;
}

template <typename D>
struct produce<D, Windows::System::Diagnostics::IDiagnosticActionResult> : produce_base<D, Windows::System::Diagnostics::IDiagnosticActionResult>
{
    int32_t WINRT_CALL get_ExtendedError(winrt::hresult* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExtendedError, WINRT_WRAP(winrt::hresult));
            *value = detach_from<winrt::hresult>(this->shim().ExtendedError());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Results(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Results, WINRT_WRAP(Windows::Foundation::Collections::ValueSet));
            *value = detach_from<Windows::Foundation::Collections::ValueSet>(this->shim().Results());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::Diagnostics::IDiagnosticInvoker> : produce_base<D, Windows::System::Diagnostics::IDiagnosticInvoker>
{
    int32_t WINRT_CALL RunDiagnosticActionAsync(void* context, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RunDiagnosticActionAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::System::Diagnostics::DiagnosticActionResult, Windows::System::Diagnostics::DiagnosticActionState>), Windows::Data::Json::JsonObject const);
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::System::Diagnostics::DiagnosticActionResult, Windows::System::Diagnostics::DiagnosticActionState>>(this->shim().RunDiagnosticActionAsync(*reinterpret_cast<Windows::Data::Json::JsonObject const*>(&context)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::Diagnostics::IDiagnosticInvoker2> : produce_base<D, Windows::System::Diagnostics::IDiagnosticInvoker2>
{
    int32_t WINRT_CALL RunDiagnosticActionFromStringAsync(void* context, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RunDiagnosticActionFromStringAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::System::Diagnostics::DiagnosticActionResult, Windows::System::Diagnostics::DiagnosticActionState>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::System::Diagnostics::DiagnosticActionResult, Windows::System::Diagnostics::DiagnosticActionState>>(this->shim().RunDiagnosticActionFromStringAsync(*reinterpret_cast<hstring const*>(&context)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::Diagnostics::IDiagnosticInvokerStatics> : produce_base<D, Windows::System::Diagnostics::IDiagnosticInvokerStatics>
{
    int32_t WINRT_CALL GetDefault(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefault, WINRT_WRAP(Windows::System::Diagnostics::DiagnosticInvoker));
            *result = detach_from<Windows::System::Diagnostics::DiagnosticInvoker>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetForUser(void* user, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForUser, WINRT_WRAP(Windows::System::Diagnostics::DiagnosticInvoker), Windows::System::User const&);
            *result = detach_from<Windows::System::Diagnostics::DiagnosticInvoker>(this->shim().GetForUser(*reinterpret_cast<Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::Diagnostics::IProcessCpuUsage> : produce_base<D, Windows::System::Diagnostics::IProcessCpuUsage>
{
    int32_t WINRT_CALL GetReport(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetReport, WINRT_WRAP(Windows::System::Diagnostics::ProcessCpuUsageReport));
            *value = detach_from<Windows::System::Diagnostics::ProcessCpuUsageReport>(this->shim().GetReport());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::Diagnostics::IProcessCpuUsageReport> : produce_base<D, Windows::System::Diagnostics::IProcessCpuUsageReport>
{
    int32_t WINRT_CALL get_KernelTime(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KernelTime, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().KernelTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UserTime(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UserTime, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().UserTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::Diagnostics::IProcessDiagnosticInfo> : produce_base<D, Windows::System::Diagnostics::IProcessDiagnosticInfo>
{
    int32_t WINRT_CALL get_ProcessId(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProcessId, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().ProcessId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExecutableFileName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExecutableFileName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ExecutableFileName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Parent(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Parent, WINRT_WRAP(Windows::System::Diagnostics::ProcessDiagnosticInfo));
            *value = detach_from<Windows::System::Diagnostics::ProcessDiagnosticInfo>(this->shim().Parent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProcessStartTime(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProcessStartTime, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().ProcessStartTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DiskUsage(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DiskUsage, WINRT_WRAP(Windows::System::Diagnostics::ProcessDiskUsage));
            *value = detach_from<Windows::System::Diagnostics::ProcessDiskUsage>(this->shim().DiskUsage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MemoryUsage(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MemoryUsage, WINRT_WRAP(Windows::System::Diagnostics::ProcessMemoryUsage));
            *value = detach_from<Windows::System::Diagnostics::ProcessMemoryUsage>(this->shim().MemoryUsage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CpuUsage(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CpuUsage, WINRT_WRAP(Windows::System::Diagnostics::ProcessCpuUsage));
            *value = detach_from<Windows::System::Diagnostics::ProcessCpuUsage>(this->shim().CpuUsage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::Diagnostics::IProcessDiagnosticInfo2> : produce_base<D, Windows::System::Diagnostics::IProcessDiagnosticInfo2>
{
    int32_t WINRT_CALL GetAppDiagnosticInfos(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAppDiagnosticInfos, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::System::AppDiagnosticInfo>));
            *result = detach_from<Windows::Foundation::Collections::IVector<Windows::System::AppDiagnosticInfo>>(this->shim().GetAppDiagnosticInfos());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsPackaged(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsPackaged, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsPackaged());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::Diagnostics::IProcessDiagnosticInfoStatics> : produce_base<D, Windows::System::Diagnostics::IProcessDiagnosticInfoStatics>
{
    int32_t WINRT_CALL GetForProcesses(void** processes) noexcept final
    {
        try
        {
            *processes = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForProcesses, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::System::Diagnostics::ProcessDiagnosticInfo>));
            *processes = detach_from<Windows::Foundation::Collections::IVectorView<Windows::System::Diagnostics::ProcessDiagnosticInfo>>(this->shim().GetForProcesses());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetForCurrentProcess(void** processes) noexcept final
    {
        try
        {
            *processes = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForCurrentProcess, WINRT_WRAP(Windows::System::Diagnostics::ProcessDiagnosticInfo));
            *processes = detach_from<Windows::System::Diagnostics::ProcessDiagnosticInfo>(this->shim().GetForCurrentProcess());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::Diagnostics::IProcessDiagnosticInfoStatics2> : produce_base<D, Windows::System::Diagnostics::IProcessDiagnosticInfoStatics2>
{
    int32_t WINRT_CALL TryGetForProcessId(uint32_t processId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryGetForProcessId, WINRT_WRAP(Windows::System::Diagnostics::ProcessDiagnosticInfo), uint32_t);
            *result = detach_from<Windows::System::Diagnostics::ProcessDiagnosticInfo>(this->shim().TryGetForProcessId(processId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::Diagnostics::IProcessDiskUsage> : produce_base<D, Windows::System::Diagnostics::IProcessDiskUsage>
{
    int32_t WINRT_CALL GetReport(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetReport, WINRT_WRAP(Windows::System::Diagnostics::ProcessDiskUsageReport));
            *value = detach_from<Windows::System::Diagnostics::ProcessDiskUsageReport>(this->shim().GetReport());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::Diagnostics::IProcessDiskUsageReport> : produce_base<D, Windows::System::Diagnostics::IProcessDiskUsageReport>
{
    int32_t WINRT_CALL get_ReadOperationCount(int64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadOperationCount, WINRT_WRAP(int64_t));
            *value = detach_from<int64_t>(this->shim().ReadOperationCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WriteOperationCount(int64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WriteOperationCount, WINRT_WRAP(int64_t));
            *value = detach_from<int64_t>(this->shim().WriteOperationCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OtherOperationCount(int64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OtherOperationCount, WINRT_WRAP(int64_t));
            *value = detach_from<int64_t>(this->shim().OtherOperationCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BytesReadCount(int64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BytesReadCount, WINRT_WRAP(int64_t));
            *value = detach_from<int64_t>(this->shim().BytesReadCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BytesWrittenCount(int64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BytesWrittenCount, WINRT_WRAP(int64_t));
            *value = detach_from<int64_t>(this->shim().BytesWrittenCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OtherBytesCount(int64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OtherBytesCount, WINRT_WRAP(int64_t));
            *value = detach_from<int64_t>(this->shim().OtherBytesCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::Diagnostics::IProcessMemoryUsage> : produce_base<D, Windows::System::Diagnostics::IProcessMemoryUsage>
{
    int32_t WINRT_CALL GetReport(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetReport, WINRT_WRAP(Windows::System::Diagnostics::ProcessMemoryUsageReport));
            *value = detach_from<Windows::System::Diagnostics::ProcessMemoryUsageReport>(this->shim().GetReport());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::Diagnostics::IProcessMemoryUsageReport> : produce_base<D, Windows::System::Diagnostics::IProcessMemoryUsageReport>
{
    int32_t WINRT_CALL get_NonPagedPoolSizeInBytes(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NonPagedPoolSizeInBytes, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().NonPagedPoolSizeInBytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PageFaultCount(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PageFaultCount, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().PageFaultCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PageFileSizeInBytes(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PageFileSizeInBytes, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().PageFileSizeInBytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PagedPoolSizeInBytes(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PagedPoolSizeInBytes, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().PagedPoolSizeInBytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PeakNonPagedPoolSizeInBytes(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PeakNonPagedPoolSizeInBytes, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().PeakNonPagedPoolSizeInBytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PeakPageFileSizeInBytes(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PeakPageFileSizeInBytes, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().PeakPageFileSizeInBytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PeakPagedPoolSizeInBytes(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PeakPagedPoolSizeInBytes, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().PeakPagedPoolSizeInBytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PeakVirtualMemorySizeInBytes(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PeakVirtualMemorySizeInBytes, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().PeakVirtualMemorySizeInBytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PeakWorkingSetSizeInBytes(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PeakWorkingSetSizeInBytes, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().PeakWorkingSetSizeInBytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PrivatePageCount(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PrivatePageCount, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().PrivatePageCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VirtualMemorySizeInBytes(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VirtualMemorySizeInBytes, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().VirtualMemorySizeInBytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WorkingSetSizeInBytes(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WorkingSetSizeInBytes, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().WorkingSetSizeInBytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::Diagnostics::ISystemCpuUsage> : produce_base<D, Windows::System::Diagnostics::ISystemCpuUsage>
{
    int32_t WINRT_CALL GetReport(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetReport, WINRT_WRAP(Windows::System::Diagnostics::SystemCpuUsageReport));
            *value = detach_from<Windows::System::Diagnostics::SystemCpuUsageReport>(this->shim().GetReport());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::Diagnostics::ISystemCpuUsageReport> : produce_base<D, Windows::System::Diagnostics::ISystemCpuUsageReport>
{
    int32_t WINRT_CALL get_KernelTime(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KernelTime, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().KernelTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UserTime(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UserTime, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().UserTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IdleTime(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IdleTime, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().IdleTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::Diagnostics::ISystemDiagnosticInfo> : produce_base<D, Windows::System::Diagnostics::ISystemDiagnosticInfo>
{
    int32_t WINRT_CALL get_MemoryUsage(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MemoryUsage, WINRT_WRAP(Windows::System::Diagnostics::SystemMemoryUsage));
            *value = detach_from<Windows::System::Diagnostics::SystemMemoryUsage>(this->shim().MemoryUsage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CpuUsage(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CpuUsage, WINRT_WRAP(Windows::System::Diagnostics::SystemCpuUsage));
            *value = detach_from<Windows::System::Diagnostics::SystemCpuUsage>(this->shim().CpuUsage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::Diagnostics::ISystemDiagnosticInfoStatics> : produce_base<D, Windows::System::Diagnostics::ISystemDiagnosticInfoStatics>
{
    int32_t WINRT_CALL GetForCurrentSystem(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForCurrentSystem, WINRT_WRAP(Windows::System::Diagnostics::SystemDiagnosticInfo));
            *value = detach_from<Windows::System::Diagnostics::SystemDiagnosticInfo>(this->shim().GetForCurrentSystem());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::Diagnostics::ISystemMemoryUsage> : produce_base<D, Windows::System::Diagnostics::ISystemMemoryUsage>
{
    int32_t WINRT_CALL GetReport(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetReport, WINRT_WRAP(Windows::System::Diagnostics::SystemMemoryUsageReport));
            *value = detach_from<Windows::System::Diagnostics::SystemMemoryUsageReport>(this->shim().GetReport());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::Diagnostics::ISystemMemoryUsageReport> : produce_base<D, Windows::System::Diagnostics::ISystemMemoryUsageReport>
{
    int32_t WINRT_CALL get_TotalPhysicalSizeInBytes(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TotalPhysicalSizeInBytes, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().TotalPhysicalSizeInBytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AvailableSizeInBytes(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AvailableSizeInBytes, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().AvailableSizeInBytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CommittedSizeInBytes(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CommittedSizeInBytes, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().CommittedSizeInBytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::System::Diagnostics {

inline Windows::System::Diagnostics::DiagnosticInvoker DiagnosticInvoker::GetDefault()
{
    return impl::call_factory<DiagnosticInvoker, Windows::System::Diagnostics::IDiagnosticInvokerStatics>([&](auto&& f) { return f.GetDefault(); });
}

inline Windows::System::Diagnostics::DiagnosticInvoker DiagnosticInvoker::GetForUser(Windows::System::User const& user)
{
    return impl::call_factory<DiagnosticInvoker, Windows::System::Diagnostics::IDiagnosticInvokerStatics>([&](auto&& f) { return f.GetForUser(user); });
}

inline bool DiagnosticInvoker::IsSupported()
{
    return impl::call_factory<DiagnosticInvoker, Windows::System::Diagnostics::IDiagnosticInvokerStatics>([&](auto&& f) { return f.IsSupported(); });
}

inline Windows::Foundation::Collections::IVectorView<Windows::System::Diagnostics::ProcessDiagnosticInfo> ProcessDiagnosticInfo::GetForProcesses()
{
    return impl::call_factory<ProcessDiagnosticInfo, Windows::System::Diagnostics::IProcessDiagnosticInfoStatics>([&](auto&& f) { return f.GetForProcesses(); });
}

inline Windows::System::Diagnostics::ProcessDiagnosticInfo ProcessDiagnosticInfo::GetForCurrentProcess()
{
    return impl::call_factory<ProcessDiagnosticInfo, Windows::System::Diagnostics::IProcessDiagnosticInfoStatics>([&](auto&& f) { return f.GetForCurrentProcess(); });
}

inline Windows::System::Diagnostics::ProcessDiagnosticInfo ProcessDiagnosticInfo::TryGetForProcessId(uint32_t processId)
{
    return impl::call_factory<ProcessDiagnosticInfo, Windows::System::Diagnostics::IProcessDiagnosticInfoStatics2>([&](auto&& f) { return f.TryGetForProcessId(processId); });
}

inline Windows::System::Diagnostics::SystemDiagnosticInfo SystemDiagnosticInfo::GetForCurrentSystem()
{
    return impl::call_factory<SystemDiagnosticInfo, Windows::System::Diagnostics::ISystemDiagnosticInfoStatics>([&](auto&& f) { return f.GetForCurrentSystem(); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::System::Diagnostics::IDiagnosticActionResult> : winrt::impl::hash_base<winrt::Windows::System::Diagnostics::IDiagnosticActionResult> {};
template<> struct hash<winrt::Windows::System::Diagnostics::IDiagnosticInvoker> : winrt::impl::hash_base<winrt::Windows::System::Diagnostics::IDiagnosticInvoker> {};
template<> struct hash<winrt::Windows::System::Diagnostics::IDiagnosticInvoker2> : winrt::impl::hash_base<winrt::Windows::System::Diagnostics::IDiagnosticInvoker2> {};
template<> struct hash<winrt::Windows::System::Diagnostics::IDiagnosticInvokerStatics> : winrt::impl::hash_base<winrt::Windows::System::Diagnostics::IDiagnosticInvokerStatics> {};
template<> struct hash<winrt::Windows::System::Diagnostics::IProcessCpuUsage> : winrt::impl::hash_base<winrt::Windows::System::Diagnostics::IProcessCpuUsage> {};
template<> struct hash<winrt::Windows::System::Diagnostics::IProcessCpuUsageReport> : winrt::impl::hash_base<winrt::Windows::System::Diagnostics::IProcessCpuUsageReport> {};
template<> struct hash<winrt::Windows::System::Diagnostics::IProcessDiagnosticInfo> : winrt::impl::hash_base<winrt::Windows::System::Diagnostics::IProcessDiagnosticInfo> {};
template<> struct hash<winrt::Windows::System::Diagnostics::IProcessDiagnosticInfo2> : winrt::impl::hash_base<winrt::Windows::System::Diagnostics::IProcessDiagnosticInfo2> {};
template<> struct hash<winrt::Windows::System::Diagnostics::IProcessDiagnosticInfoStatics> : winrt::impl::hash_base<winrt::Windows::System::Diagnostics::IProcessDiagnosticInfoStatics> {};
template<> struct hash<winrt::Windows::System::Diagnostics::IProcessDiagnosticInfoStatics2> : winrt::impl::hash_base<winrt::Windows::System::Diagnostics::IProcessDiagnosticInfoStatics2> {};
template<> struct hash<winrt::Windows::System::Diagnostics::IProcessDiskUsage> : winrt::impl::hash_base<winrt::Windows::System::Diagnostics::IProcessDiskUsage> {};
template<> struct hash<winrt::Windows::System::Diagnostics::IProcessDiskUsageReport> : winrt::impl::hash_base<winrt::Windows::System::Diagnostics::IProcessDiskUsageReport> {};
template<> struct hash<winrt::Windows::System::Diagnostics::IProcessMemoryUsage> : winrt::impl::hash_base<winrt::Windows::System::Diagnostics::IProcessMemoryUsage> {};
template<> struct hash<winrt::Windows::System::Diagnostics::IProcessMemoryUsageReport> : winrt::impl::hash_base<winrt::Windows::System::Diagnostics::IProcessMemoryUsageReport> {};
template<> struct hash<winrt::Windows::System::Diagnostics::ISystemCpuUsage> : winrt::impl::hash_base<winrt::Windows::System::Diagnostics::ISystemCpuUsage> {};
template<> struct hash<winrt::Windows::System::Diagnostics::ISystemCpuUsageReport> : winrt::impl::hash_base<winrt::Windows::System::Diagnostics::ISystemCpuUsageReport> {};
template<> struct hash<winrt::Windows::System::Diagnostics::ISystemDiagnosticInfo> : winrt::impl::hash_base<winrt::Windows::System::Diagnostics::ISystemDiagnosticInfo> {};
template<> struct hash<winrt::Windows::System::Diagnostics::ISystemDiagnosticInfoStatics> : winrt::impl::hash_base<winrt::Windows::System::Diagnostics::ISystemDiagnosticInfoStatics> {};
template<> struct hash<winrt::Windows::System::Diagnostics::ISystemMemoryUsage> : winrt::impl::hash_base<winrt::Windows::System::Diagnostics::ISystemMemoryUsage> {};
template<> struct hash<winrt::Windows::System::Diagnostics::ISystemMemoryUsageReport> : winrt::impl::hash_base<winrt::Windows::System::Diagnostics::ISystemMemoryUsageReport> {};
template<> struct hash<winrt::Windows::System::Diagnostics::DiagnosticActionResult> : winrt::impl::hash_base<winrt::Windows::System::Diagnostics::DiagnosticActionResult> {};
template<> struct hash<winrt::Windows::System::Diagnostics::DiagnosticInvoker> : winrt::impl::hash_base<winrt::Windows::System::Diagnostics::DiagnosticInvoker> {};
template<> struct hash<winrt::Windows::System::Diagnostics::ProcessCpuUsage> : winrt::impl::hash_base<winrt::Windows::System::Diagnostics::ProcessCpuUsage> {};
template<> struct hash<winrt::Windows::System::Diagnostics::ProcessCpuUsageReport> : winrt::impl::hash_base<winrt::Windows::System::Diagnostics::ProcessCpuUsageReport> {};
template<> struct hash<winrt::Windows::System::Diagnostics::ProcessDiagnosticInfo> : winrt::impl::hash_base<winrt::Windows::System::Diagnostics::ProcessDiagnosticInfo> {};
template<> struct hash<winrt::Windows::System::Diagnostics::ProcessDiskUsage> : winrt::impl::hash_base<winrt::Windows::System::Diagnostics::ProcessDiskUsage> {};
template<> struct hash<winrt::Windows::System::Diagnostics::ProcessDiskUsageReport> : winrt::impl::hash_base<winrt::Windows::System::Diagnostics::ProcessDiskUsageReport> {};
template<> struct hash<winrt::Windows::System::Diagnostics::ProcessMemoryUsage> : winrt::impl::hash_base<winrt::Windows::System::Diagnostics::ProcessMemoryUsage> {};
template<> struct hash<winrt::Windows::System::Diagnostics::ProcessMemoryUsageReport> : winrt::impl::hash_base<winrt::Windows::System::Diagnostics::ProcessMemoryUsageReport> {};
template<> struct hash<winrt::Windows::System::Diagnostics::SystemCpuUsage> : winrt::impl::hash_base<winrt::Windows::System::Diagnostics::SystemCpuUsage> {};
template<> struct hash<winrt::Windows::System::Diagnostics::SystemCpuUsageReport> : winrt::impl::hash_base<winrt::Windows::System::Diagnostics::SystemCpuUsageReport> {};
template<> struct hash<winrt::Windows::System::Diagnostics::SystemDiagnosticInfo> : winrt::impl::hash_base<winrt::Windows::System::Diagnostics::SystemDiagnosticInfo> {};
template<> struct hash<winrt::Windows::System::Diagnostics::SystemMemoryUsage> : winrt::impl::hash_base<winrt::Windows::System::Diagnostics::SystemMemoryUsage> {};
template<> struct hash<winrt::Windows::System::Diagnostics::SystemMemoryUsageReport> : winrt::impl::hash_base<winrt::Windows::System::Diagnostics::SystemMemoryUsageReport> {};

}
