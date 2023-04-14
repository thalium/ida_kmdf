// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.ApplicationModel.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Storage.2.h"
#include "winrt/impl/Windows.Storage.Search.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.System.Diagnostics.2.h"
#include "winrt/impl/Windows.System.RemoteSystems.2.h"
#include "winrt/impl/Windows.UI.Popups.2.h"
#include "winrt/impl/Windows.UI.ViewManagement.2.h"
#include "winrt/impl/Windows.System.2.h"

namespace winrt::impl {

template <typename D> winrt::hresult consume_Windows_System_IAppActivationResult<D>::ExtendedError() const
{
    winrt::hresult value{};
    check_hresult(WINRT_SHIM(Windows::System::IAppActivationResult)->get_ExtendedError(put_abi(value)));
    return value;
}

template <typename D> Windows::System::AppResourceGroupInfo consume_Windows_System_IAppActivationResult<D>::AppResourceGroupInfo() const
{
    Windows::System::AppResourceGroupInfo value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::IAppActivationResult)->get_AppResourceGroupInfo(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::AppInfo consume_Windows_System_IAppDiagnosticInfo<D>::AppInfo() const
{
    Windows::ApplicationModel::AppInfo value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::IAppDiagnosticInfo)->get_AppInfo(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::System::AppResourceGroupInfo> consume_Windows_System_IAppDiagnosticInfo2<D>::GetResourceGroups() const
{
    Windows::Foundation::Collections::IVector<Windows::System::AppResourceGroupInfo> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::IAppDiagnosticInfo2)->GetResourceGroups(put_abi(result)));
    return result;
}

template <typename D> Windows::System::AppResourceGroupInfoWatcher consume_Windows_System_IAppDiagnosticInfo2<D>::CreateResourceGroupWatcher() const
{
    Windows::System::AppResourceGroupInfoWatcher result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::IAppDiagnosticInfo2)->CreateResourceGroupWatcher(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::System::AppActivationResult> consume_Windows_System_IAppDiagnosticInfo3<D>::LaunchAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::System::AppActivationResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::IAppDiagnosticInfo3)->LaunchAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<Windows::System::AppDiagnosticInfo>> consume_Windows_System_IAppDiagnosticInfoStatics<D>::RequestInfoAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<Windows::System::AppDiagnosticInfo>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::IAppDiagnosticInfoStatics)->RequestInfoAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::System::AppDiagnosticInfoWatcher consume_Windows_System_IAppDiagnosticInfoStatics2<D>::CreateWatcher() const
{
    Windows::System::AppDiagnosticInfoWatcher watcher{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::IAppDiagnosticInfoStatics2)->CreateWatcher(put_abi(watcher)));
    return watcher;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::System::DiagnosticAccessStatus> consume_Windows_System_IAppDiagnosticInfoStatics2<D>::RequestAccessAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::System::DiagnosticAccessStatus> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::IAppDiagnosticInfoStatics2)->RequestAccessAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<Windows::System::AppDiagnosticInfo>> consume_Windows_System_IAppDiagnosticInfoStatics2<D>::RequestInfoForPackageAsync(param::hstring const& packageFamilyName) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<Windows::System::AppDiagnosticInfo>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::IAppDiagnosticInfoStatics2)->RequestInfoForPackageAsync(get_abi(packageFamilyName), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<Windows::System::AppDiagnosticInfo>> consume_Windows_System_IAppDiagnosticInfoStatics2<D>::RequestInfoForAppAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<Windows::System::AppDiagnosticInfo>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::IAppDiagnosticInfoStatics2)->RequestInfoForAppAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<Windows::System::AppDiagnosticInfo>> consume_Windows_System_IAppDiagnosticInfoStatics2<D>::RequestInfoForAppAsync(param::hstring const& appUserModelId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<Windows::System::AppDiagnosticInfo>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::IAppDiagnosticInfoStatics2)->RequestInfoForAppUserModelId(get_abi(appUserModelId), put_abi(operation)));
    return operation;
}

template <typename D> winrt::event_token consume_Windows_System_IAppDiagnosticInfoWatcher<D>::Added(Windows::Foundation::TypedEventHandler<Windows::System::AppDiagnosticInfoWatcher, Windows::System::AppDiagnosticInfoWatcherEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::System::IAppDiagnosticInfoWatcher)->add_Added(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_System_IAppDiagnosticInfoWatcher<D>::Added_revoker consume_Windows_System_IAppDiagnosticInfoWatcher<D>::Added(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::System::AppDiagnosticInfoWatcher, Windows::System::AppDiagnosticInfoWatcherEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Added_revoker>(this, Added(handler));
}

template <typename D> void consume_Windows_System_IAppDiagnosticInfoWatcher<D>::Added(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::System::IAppDiagnosticInfoWatcher)->remove_Added(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_System_IAppDiagnosticInfoWatcher<D>::Removed(Windows::Foundation::TypedEventHandler<Windows::System::AppDiagnosticInfoWatcher, Windows::System::AppDiagnosticInfoWatcherEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::System::IAppDiagnosticInfoWatcher)->add_Removed(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_System_IAppDiagnosticInfoWatcher<D>::Removed_revoker consume_Windows_System_IAppDiagnosticInfoWatcher<D>::Removed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::System::AppDiagnosticInfoWatcher, Windows::System::AppDiagnosticInfoWatcherEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Removed_revoker>(this, Removed(handler));
}

template <typename D> void consume_Windows_System_IAppDiagnosticInfoWatcher<D>::Removed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::System::IAppDiagnosticInfoWatcher)->remove_Removed(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_System_IAppDiagnosticInfoWatcher<D>::EnumerationCompleted(Windows::Foundation::TypedEventHandler<Windows::System::AppDiagnosticInfoWatcher, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::System::IAppDiagnosticInfoWatcher)->add_EnumerationCompleted(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_System_IAppDiagnosticInfoWatcher<D>::EnumerationCompleted_revoker consume_Windows_System_IAppDiagnosticInfoWatcher<D>::EnumerationCompleted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::System::AppDiagnosticInfoWatcher, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, EnumerationCompleted_revoker>(this, EnumerationCompleted(handler));
}

template <typename D> void consume_Windows_System_IAppDiagnosticInfoWatcher<D>::EnumerationCompleted(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::System::IAppDiagnosticInfoWatcher)->remove_EnumerationCompleted(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_System_IAppDiagnosticInfoWatcher<D>::Stopped(Windows::Foundation::TypedEventHandler<Windows::System::AppDiagnosticInfoWatcher, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::System::IAppDiagnosticInfoWatcher)->add_Stopped(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_System_IAppDiagnosticInfoWatcher<D>::Stopped_revoker consume_Windows_System_IAppDiagnosticInfoWatcher<D>::Stopped(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::System::AppDiagnosticInfoWatcher, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, Stopped_revoker>(this, Stopped(handler));
}

template <typename D> void consume_Windows_System_IAppDiagnosticInfoWatcher<D>::Stopped(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::System::IAppDiagnosticInfoWatcher)->remove_Stopped(get_abi(token)));
}

template <typename D> Windows::System::AppDiagnosticInfoWatcherStatus consume_Windows_System_IAppDiagnosticInfoWatcher<D>::Status() const
{
    Windows::System::AppDiagnosticInfoWatcherStatus value{};
    check_hresult(WINRT_SHIM(Windows::System::IAppDiagnosticInfoWatcher)->get_Status(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_System_IAppDiagnosticInfoWatcher<D>::Start() const
{
    check_hresult(WINRT_SHIM(Windows::System::IAppDiagnosticInfoWatcher)->Start());
}

template <typename D> void consume_Windows_System_IAppDiagnosticInfoWatcher<D>::Stop() const
{
    check_hresult(WINRT_SHIM(Windows::System::IAppDiagnosticInfoWatcher)->Stop());
}

template <typename D> Windows::System::AppDiagnosticInfo consume_Windows_System_IAppDiagnosticInfoWatcherEventArgs<D>::AppDiagnosticInfo() const
{
    Windows::System::AppDiagnosticInfo value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::IAppDiagnosticInfoWatcherEventArgs)->get_AppDiagnosticInfo(put_abi(value)));
    return value;
}

template <typename D> winrt::hresult consume_Windows_System_IAppExecutionStateChangeResult<D>::ExtendedError() const
{
    winrt::hresult value{};
    check_hresult(WINRT_SHIM(Windows::System::IAppExecutionStateChangeResult)->get_ExtendedError(put_abi(value)));
    return value;
}

template <typename D> uint64_t consume_Windows_System_IAppMemoryReport<D>::PrivateCommitUsage() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::System::IAppMemoryReport)->get_PrivateCommitUsage(&value));
    return value;
}

template <typename D> uint64_t consume_Windows_System_IAppMemoryReport<D>::PeakPrivateCommitUsage() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::System::IAppMemoryReport)->get_PeakPrivateCommitUsage(&value));
    return value;
}

template <typename D> uint64_t consume_Windows_System_IAppMemoryReport<D>::TotalCommitUsage() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::System::IAppMemoryReport)->get_TotalCommitUsage(&value));
    return value;
}

template <typename D> uint64_t consume_Windows_System_IAppMemoryReport<D>::TotalCommitLimit() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::System::IAppMemoryReport)->get_TotalCommitLimit(&value));
    return value;
}

template <typename D> uint64_t consume_Windows_System_IAppMemoryReport2<D>::ExpectedTotalCommitLimit() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::System::IAppMemoryReport2)->get_ExpectedTotalCommitLimit(&value));
    return value;
}

template <typename D> uint64_t consume_Windows_System_IAppMemoryUsageLimitChangingEventArgs<D>::OldLimit() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::System::IAppMemoryUsageLimitChangingEventArgs)->get_OldLimit(&value));
    return value;
}

template <typename D> uint64_t consume_Windows_System_IAppMemoryUsageLimitChangingEventArgs<D>::NewLimit() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::System::IAppMemoryUsageLimitChangingEventArgs)->get_NewLimit(&value));
    return value;
}

template <typename D> winrt::guid consume_Windows_System_IAppResourceGroupBackgroundTaskReport<D>::TaskId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::System::IAppResourceGroupBackgroundTaskReport)->get_TaskId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_IAppResourceGroupBackgroundTaskReport<D>::Name() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::IAppResourceGroupBackgroundTaskReport)->get_Name(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_IAppResourceGroupBackgroundTaskReport<D>::Trigger() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::IAppResourceGroupBackgroundTaskReport)->get_Trigger(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_IAppResourceGroupBackgroundTaskReport<D>::EntryPoint() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::IAppResourceGroupBackgroundTaskReport)->get_EntryPoint(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_System_IAppResourceGroupInfo<D>::InstanceId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::System::IAppResourceGroupInfo)->get_InstanceId(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_System_IAppResourceGroupInfo<D>::IsShared() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::System::IAppResourceGroupInfo)->get_IsShared(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::System::AppResourceGroupBackgroundTaskReport> consume_Windows_System_IAppResourceGroupInfo<D>::GetBackgroundTaskReports() const
{
    Windows::Foundation::Collections::IVector<Windows::System::AppResourceGroupBackgroundTaskReport> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::IAppResourceGroupInfo)->GetBackgroundTaskReports(put_abi(result)));
    return result;
}

template <typename D> Windows::System::AppResourceGroupMemoryReport consume_Windows_System_IAppResourceGroupInfo<D>::GetMemoryReport() const
{
    Windows::System::AppResourceGroupMemoryReport result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::IAppResourceGroupInfo)->GetMemoryReport(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::System::Diagnostics::ProcessDiagnosticInfo> consume_Windows_System_IAppResourceGroupInfo<D>::GetProcessDiagnosticInfos() const
{
    Windows::Foundation::Collections::IVector<Windows::System::Diagnostics::ProcessDiagnosticInfo> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::IAppResourceGroupInfo)->GetProcessDiagnosticInfos(put_abi(result)));
    return result;
}

template <typename D> Windows::System::AppResourceGroupStateReport consume_Windows_System_IAppResourceGroupInfo<D>::GetStateReport() const
{
    Windows::System::AppResourceGroupStateReport result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::IAppResourceGroupInfo)->GetStateReport(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::System::AppExecutionStateChangeResult> consume_Windows_System_IAppResourceGroupInfo2<D>::StartSuspendAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::System::AppExecutionStateChangeResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::IAppResourceGroupInfo2)->StartSuspendAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::System::AppExecutionStateChangeResult> consume_Windows_System_IAppResourceGroupInfo2<D>::StartResumeAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::System::AppExecutionStateChangeResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::IAppResourceGroupInfo2)->StartResumeAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::System::AppExecutionStateChangeResult> consume_Windows_System_IAppResourceGroupInfo2<D>::StartTerminateAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::System::AppExecutionStateChangeResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::IAppResourceGroupInfo2)->StartTerminateAsync(put_abi(operation)));
    return operation;
}

template <typename D> winrt::event_token consume_Windows_System_IAppResourceGroupInfoWatcher<D>::Added(Windows::Foundation::TypedEventHandler<Windows::System::AppResourceGroupInfoWatcher, Windows::System::AppResourceGroupInfoWatcherEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::System::IAppResourceGroupInfoWatcher)->add_Added(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_System_IAppResourceGroupInfoWatcher<D>::Added_revoker consume_Windows_System_IAppResourceGroupInfoWatcher<D>::Added(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::System::AppResourceGroupInfoWatcher, Windows::System::AppResourceGroupInfoWatcherEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Added_revoker>(this, Added(handler));
}

template <typename D> void consume_Windows_System_IAppResourceGroupInfoWatcher<D>::Added(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::System::IAppResourceGroupInfoWatcher)->remove_Added(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_System_IAppResourceGroupInfoWatcher<D>::Removed(Windows::Foundation::TypedEventHandler<Windows::System::AppResourceGroupInfoWatcher, Windows::System::AppResourceGroupInfoWatcherEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::System::IAppResourceGroupInfoWatcher)->add_Removed(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_System_IAppResourceGroupInfoWatcher<D>::Removed_revoker consume_Windows_System_IAppResourceGroupInfoWatcher<D>::Removed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::System::AppResourceGroupInfoWatcher, Windows::System::AppResourceGroupInfoWatcherEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Removed_revoker>(this, Removed(handler));
}

template <typename D> void consume_Windows_System_IAppResourceGroupInfoWatcher<D>::Removed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::System::IAppResourceGroupInfoWatcher)->remove_Removed(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_System_IAppResourceGroupInfoWatcher<D>::EnumerationCompleted(Windows::Foundation::TypedEventHandler<Windows::System::AppResourceGroupInfoWatcher, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::System::IAppResourceGroupInfoWatcher)->add_EnumerationCompleted(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_System_IAppResourceGroupInfoWatcher<D>::EnumerationCompleted_revoker consume_Windows_System_IAppResourceGroupInfoWatcher<D>::EnumerationCompleted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::System::AppResourceGroupInfoWatcher, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, EnumerationCompleted_revoker>(this, EnumerationCompleted(handler));
}

template <typename D> void consume_Windows_System_IAppResourceGroupInfoWatcher<D>::EnumerationCompleted(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::System::IAppResourceGroupInfoWatcher)->remove_EnumerationCompleted(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_System_IAppResourceGroupInfoWatcher<D>::Stopped(Windows::Foundation::TypedEventHandler<Windows::System::AppResourceGroupInfoWatcher, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::System::IAppResourceGroupInfoWatcher)->add_Stopped(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_System_IAppResourceGroupInfoWatcher<D>::Stopped_revoker consume_Windows_System_IAppResourceGroupInfoWatcher<D>::Stopped(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::System::AppResourceGroupInfoWatcher, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, Stopped_revoker>(this, Stopped(handler));
}

template <typename D> void consume_Windows_System_IAppResourceGroupInfoWatcher<D>::Stopped(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::System::IAppResourceGroupInfoWatcher)->remove_Stopped(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_System_IAppResourceGroupInfoWatcher<D>::ExecutionStateChanged(Windows::Foundation::TypedEventHandler<Windows::System::AppResourceGroupInfoWatcher, Windows::System::AppResourceGroupInfoWatcherExecutionStateChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::System::IAppResourceGroupInfoWatcher)->add_ExecutionStateChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_System_IAppResourceGroupInfoWatcher<D>::ExecutionStateChanged_revoker consume_Windows_System_IAppResourceGroupInfoWatcher<D>::ExecutionStateChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::System::AppResourceGroupInfoWatcher, Windows::System::AppResourceGroupInfoWatcherExecutionStateChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ExecutionStateChanged_revoker>(this, ExecutionStateChanged(handler));
}

template <typename D> void consume_Windows_System_IAppResourceGroupInfoWatcher<D>::ExecutionStateChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::System::IAppResourceGroupInfoWatcher)->remove_ExecutionStateChanged(get_abi(token)));
}

template <typename D> Windows::System::AppResourceGroupInfoWatcherStatus consume_Windows_System_IAppResourceGroupInfoWatcher<D>::Status() const
{
    Windows::System::AppResourceGroupInfoWatcherStatus status{};
    check_hresult(WINRT_SHIM(Windows::System::IAppResourceGroupInfoWatcher)->get_Status(put_abi(status)));
    return status;
}

template <typename D> void consume_Windows_System_IAppResourceGroupInfoWatcher<D>::Start() const
{
    check_hresult(WINRT_SHIM(Windows::System::IAppResourceGroupInfoWatcher)->Start());
}

template <typename D> void consume_Windows_System_IAppResourceGroupInfoWatcher<D>::Stop() const
{
    check_hresult(WINRT_SHIM(Windows::System::IAppResourceGroupInfoWatcher)->Stop());
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::System::AppDiagnosticInfo> consume_Windows_System_IAppResourceGroupInfoWatcherEventArgs<D>::AppDiagnosticInfos() const
{
    Windows::Foundation::Collections::IVectorView<Windows::System::AppDiagnosticInfo> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::IAppResourceGroupInfoWatcherEventArgs)->get_AppDiagnosticInfos(put_abi(value)));
    return value;
}

template <typename D> Windows::System::AppResourceGroupInfo consume_Windows_System_IAppResourceGroupInfoWatcherEventArgs<D>::AppResourceGroupInfo() const
{
    Windows::System::AppResourceGroupInfo value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::IAppResourceGroupInfoWatcherEventArgs)->get_AppResourceGroupInfo(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::System::AppDiagnosticInfo> consume_Windows_System_IAppResourceGroupInfoWatcherExecutionStateChangedEventArgs<D>::AppDiagnosticInfos() const
{
    Windows::Foundation::Collections::IVectorView<Windows::System::AppDiagnosticInfo> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::IAppResourceGroupInfoWatcherExecutionStateChangedEventArgs)->get_AppDiagnosticInfos(put_abi(value)));
    return value;
}

template <typename D> Windows::System::AppResourceGroupInfo consume_Windows_System_IAppResourceGroupInfoWatcherExecutionStateChangedEventArgs<D>::AppResourceGroupInfo() const
{
    Windows::System::AppResourceGroupInfo value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::IAppResourceGroupInfoWatcherExecutionStateChangedEventArgs)->get_AppResourceGroupInfo(put_abi(value)));
    return value;
}

template <typename D> uint64_t consume_Windows_System_IAppResourceGroupMemoryReport<D>::CommitUsageLimit() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::System::IAppResourceGroupMemoryReport)->get_CommitUsageLimit(&value));
    return value;
}

template <typename D> Windows::System::AppMemoryUsageLevel consume_Windows_System_IAppResourceGroupMemoryReport<D>::CommitUsageLevel() const
{
    Windows::System::AppMemoryUsageLevel value{};
    check_hresult(WINRT_SHIM(Windows::System::IAppResourceGroupMemoryReport)->get_CommitUsageLevel(put_abi(value)));
    return value;
}

template <typename D> uint64_t consume_Windows_System_IAppResourceGroupMemoryReport<D>::PrivateCommitUsage() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::System::IAppResourceGroupMemoryReport)->get_PrivateCommitUsage(&value));
    return value;
}

template <typename D> uint64_t consume_Windows_System_IAppResourceGroupMemoryReport<D>::TotalCommitUsage() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::System::IAppResourceGroupMemoryReport)->get_TotalCommitUsage(&value));
    return value;
}

template <typename D> Windows::System::AppResourceGroupExecutionState consume_Windows_System_IAppResourceGroupStateReport<D>::ExecutionState() const
{
    Windows::System::AppResourceGroupExecutionState value{};
    check_hresult(WINRT_SHIM(Windows::System::IAppResourceGroupStateReport)->get_ExecutionState(put_abi(value)));
    return value;
}

template <typename D> Windows::System::AppResourceGroupEnergyQuotaState consume_Windows_System_IAppResourceGroupStateReport<D>::EnergyQuotaState() const
{
    Windows::System::AppResourceGroupEnergyQuotaState value{};
    check_hresult(WINRT_SHIM(Windows::System::IAppResourceGroupStateReport)->get_EnergyQuotaState(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_IAppUriHandlerHost<D>::Name() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::IAppUriHandlerHost)->get_Name(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_System_IAppUriHandlerHost<D>::Name(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::System::IAppUriHandlerHost)->put_Name(get_abi(value)));
}

template <typename D> Windows::System::AppUriHandlerHost consume_Windows_System_IAppUriHandlerHostFactory<D>::CreateInstance(param::hstring const& name) const
{
    Windows::System::AppUriHandlerHost value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::IAppUriHandlerHostFactory)->CreateInstance(get_abi(name), put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_IAppUriHandlerRegistration<D>::Name() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::IAppUriHandlerRegistration)->get_Name(put_abi(value)));
    return value;
}

template <typename D> Windows::System::User consume_Windows_System_IAppUriHandlerRegistration<D>::User() const
{
    Windows::System::User value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::IAppUriHandlerRegistration)->get_User(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<Windows::System::AppUriHandlerHost>> consume_Windows_System_IAppUriHandlerRegistration<D>::GetAppAddedHostsAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<Windows::System::AppUriHandlerHost>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::IAppUriHandlerRegistration)->GetAppAddedHostsAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_System_IAppUriHandlerRegistration<D>::SetAppAddedHostsAsync(param::async_iterable<Windows::System::AppUriHandlerHost> const& hosts) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::IAppUriHandlerRegistration)->SetAppAddedHostsAsync(get_abi(hosts), put_abi(operation)));
    return operation;
}

template <typename D> Windows::System::User consume_Windows_System_IAppUriHandlerRegistrationManager<D>::User() const
{
    Windows::System::User value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::IAppUriHandlerRegistrationManager)->get_User(put_abi(value)));
    return value;
}

template <typename D> Windows::System::AppUriHandlerRegistration consume_Windows_System_IAppUriHandlerRegistrationManager<D>::TryGetRegistration(param::hstring const& name) const
{
    Windows::System::AppUriHandlerRegistration result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::IAppUriHandlerRegistrationManager)->TryGetRegistration(get_abi(name), put_abi(result)));
    return result;
}

template <typename D> Windows::System::AppUriHandlerRegistrationManager consume_Windows_System_IAppUriHandlerRegistrationManagerStatics<D>::GetDefault() const
{
    Windows::System::AppUriHandlerRegistrationManager result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::IAppUriHandlerRegistrationManagerStatics)->GetDefault(put_abi(result)));
    return result;
}

template <typename D> Windows::System::AppUriHandlerRegistrationManager consume_Windows_System_IAppUriHandlerRegistrationManagerStatics<D>::GetForUser(Windows::System::User const& user) const
{
    Windows::System::AppUriHandlerRegistrationManager result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::IAppUriHandlerRegistrationManagerStatics)->GetForUser(get_abi(user), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_System_IDateTimeSettingsStatics<D>::SetSystemDateTime(Windows::Foundation::DateTime const& utcDateTime) const
{
    check_hresult(WINRT_SHIM(Windows::System::IDateTimeSettingsStatics)->SetSystemDateTime(get_abi(utcDateTime)));
}

template <typename D> Windows::System::DispatcherQueueTimer consume_Windows_System_IDispatcherQueue<D>::CreateTimer() const
{
    Windows::System::DispatcherQueueTimer result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::IDispatcherQueue)->CreateTimer(put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_System_IDispatcherQueue<D>::TryEnqueue(Windows::System::DispatcherQueueHandler const& callback) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::System::IDispatcherQueue)->TryEnqueue(get_abi(callback), &result));
    return result;
}

template <typename D> bool consume_Windows_System_IDispatcherQueue<D>::TryEnqueue(Windows::System::DispatcherQueuePriority const& priority, Windows::System::DispatcherQueueHandler const& callback) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::System::IDispatcherQueue)->TryEnqueueWithPriority(get_abi(priority), get_abi(callback), &result));
    return result;
}

template <typename D> winrt::event_token consume_Windows_System_IDispatcherQueue<D>::ShutdownStarting(Windows::Foundation::TypedEventHandler<Windows::System::DispatcherQueue, Windows::System::DispatcherQueueShutdownStartingEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::System::IDispatcherQueue)->add_ShutdownStarting(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_System_IDispatcherQueue<D>::ShutdownStarting_revoker consume_Windows_System_IDispatcherQueue<D>::ShutdownStarting(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::System::DispatcherQueue, Windows::System::DispatcherQueueShutdownStartingEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ShutdownStarting_revoker>(this, ShutdownStarting(handler));
}

template <typename D> void consume_Windows_System_IDispatcherQueue<D>::ShutdownStarting(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::System::IDispatcherQueue)->remove_ShutdownStarting(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_System_IDispatcherQueue<D>::ShutdownCompleted(Windows::Foundation::TypedEventHandler<Windows::System::DispatcherQueue, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::System::IDispatcherQueue)->add_ShutdownCompleted(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_System_IDispatcherQueue<D>::ShutdownCompleted_revoker consume_Windows_System_IDispatcherQueue<D>::ShutdownCompleted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::System::DispatcherQueue, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, ShutdownCompleted_revoker>(this, ShutdownCompleted(handler));
}

template <typename D> void consume_Windows_System_IDispatcherQueue<D>::ShutdownCompleted(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::System::IDispatcherQueue)->remove_ShutdownCompleted(get_abi(token)));
}

template <typename D> bool consume_Windows_System_IDispatcherQueue2<D>::HasThreadAccess() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::System::IDispatcherQueue2)->get_HasThreadAccess(&value));
    return value;
}

template <typename D> Windows::System::DispatcherQueue consume_Windows_System_IDispatcherQueueController<D>::DispatcherQueue() const
{
    Windows::System::DispatcherQueue value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::IDispatcherQueueController)->get_DispatcherQueue(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_System_IDispatcherQueueController<D>::ShutdownQueueAsync() const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::IDispatcherQueueController)->ShutdownQueueAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::System::DispatcherQueueController consume_Windows_System_IDispatcherQueueControllerStatics<D>::CreateOnDedicatedThread() const
{
    Windows::System::DispatcherQueueController result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::IDispatcherQueueControllerStatics)->CreateOnDedicatedThread(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Deferral consume_Windows_System_IDispatcherQueueShutdownStartingEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::IDispatcherQueueShutdownStartingEventArgs)->GetDeferral(put_abi(result)));
    return result;
}

template <typename D> Windows::System::DispatcherQueue consume_Windows_System_IDispatcherQueueStatics<D>::GetForCurrentThread() const
{
    Windows::System::DispatcherQueue result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::IDispatcherQueueStatics)->GetForCurrentThread(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_System_IDispatcherQueueTimer<D>::Interval() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::System::IDispatcherQueueTimer)->get_Interval(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_System_IDispatcherQueueTimer<D>::Interval(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::System::IDispatcherQueueTimer)->put_Interval(get_abi(value)));
}

template <typename D> bool consume_Windows_System_IDispatcherQueueTimer<D>::IsRunning() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::System::IDispatcherQueueTimer)->get_IsRunning(&value));
    return value;
}

template <typename D> bool consume_Windows_System_IDispatcherQueueTimer<D>::IsRepeating() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::System::IDispatcherQueueTimer)->get_IsRepeating(&value));
    return value;
}

template <typename D> void consume_Windows_System_IDispatcherQueueTimer<D>::IsRepeating(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::System::IDispatcherQueueTimer)->put_IsRepeating(value));
}

template <typename D> void consume_Windows_System_IDispatcherQueueTimer<D>::Start() const
{
    check_hresult(WINRT_SHIM(Windows::System::IDispatcherQueueTimer)->Start());
}

template <typename D> void consume_Windows_System_IDispatcherQueueTimer<D>::Stop() const
{
    check_hresult(WINRT_SHIM(Windows::System::IDispatcherQueueTimer)->Stop());
}

template <typename D> winrt::event_token consume_Windows_System_IDispatcherQueueTimer<D>::Tick(Windows::Foundation::TypedEventHandler<Windows::System::DispatcherQueueTimer, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::System::IDispatcherQueueTimer)->add_Tick(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_System_IDispatcherQueueTimer<D>::Tick_revoker consume_Windows_System_IDispatcherQueueTimer<D>::Tick(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::System::DispatcherQueueTimer, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, Tick_revoker>(this, Tick(handler));
}

template <typename D> void consume_Windows_System_IDispatcherQueueTimer<D>::Tick(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::System::IDispatcherQueueTimer)->remove_Tick(get_abi(token)));
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::Storage::IStorageItem> consume_Windows_System_IFolderLauncherOptions<D>::ItemsToSelect() const
{
    Windows::Foundation::Collections::IVector<Windows::Storage::IStorageItem> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::IFolderLauncherOptions)->get_ItemsToSelect(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_IKnownUserPropertiesStatics<D>::DisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::IKnownUserPropertiesStatics)->get_DisplayName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_IKnownUserPropertiesStatics<D>::FirstName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::IKnownUserPropertiesStatics)->get_FirstName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_IKnownUserPropertiesStatics<D>::LastName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::IKnownUserPropertiesStatics)->get_LastName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_IKnownUserPropertiesStatics<D>::ProviderName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::IKnownUserPropertiesStatics)->get_ProviderName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_IKnownUserPropertiesStatics<D>::AccountName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::IKnownUserPropertiesStatics)->get_AccountName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_IKnownUserPropertiesStatics<D>::GuestHost() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::IKnownUserPropertiesStatics)->get_GuestHost(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_IKnownUserPropertiesStatics<D>::PrincipalName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::IKnownUserPropertiesStatics)->get_PrincipalName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_IKnownUserPropertiesStatics<D>::DomainName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::IKnownUserPropertiesStatics)->get_DomainName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_IKnownUserPropertiesStatics<D>::SessionInitiationProtocolUri() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::IKnownUserPropertiesStatics)->get_SessionInitiationProtocolUri(put_abi(value)));
    return value;
}

template <typename D> Windows::System::LaunchUriStatus consume_Windows_System_ILaunchUriResult<D>::Status() const
{
    Windows::System::LaunchUriStatus value{};
    check_hresult(WINRT_SHIM(Windows::System::ILaunchUriResult)->get_Status(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::ValueSet consume_Windows_System_ILaunchUriResult<D>::Result() const
{
    Windows::Foundation::Collections::ValueSet value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::ILaunchUriResult)->get_Result(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_System_ILauncherOptions<D>::TreatAsUntrusted() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::System::ILauncherOptions)->get_TreatAsUntrusted(&value));
    return value;
}

template <typename D> void consume_Windows_System_ILauncherOptions<D>::TreatAsUntrusted(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::System::ILauncherOptions)->put_TreatAsUntrusted(value));
}

template <typename D> bool consume_Windows_System_ILauncherOptions<D>::DisplayApplicationPicker() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::System::ILauncherOptions)->get_DisplayApplicationPicker(&value));
    return value;
}

template <typename D> void consume_Windows_System_ILauncherOptions<D>::DisplayApplicationPicker(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::System::ILauncherOptions)->put_DisplayApplicationPicker(value));
}

template <typename D> Windows::System::LauncherUIOptions consume_Windows_System_ILauncherOptions<D>::UI() const
{
    Windows::System::LauncherUIOptions value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::ILauncherOptions)->get_UI(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_ILauncherOptions<D>::PreferredApplicationPackageFamilyName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::ILauncherOptions)->get_PreferredApplicationPackageFamilyName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_System_ILauncherOptions<D>::PreferredApplicationPackageFamilyName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::System::ILauncherOptions)->put_PreferredApplicationPackageFamilyName(get_abi(value)));
}

template <typename D> hstring consume_Windows_System_ILauncherOptions<D>::PreferredApplicationDisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::ILauncherOptions)->get_PreferredApplicationDisplayName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_System_ILauncherOptions<D>::PreferredApplicationDisplayName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::System::ILauncherOptions)->put_PreferredApplicationDisplayName(get_abi(value)));
}

template <typename D> Windows::Foundation::Uri consume_Windows_System_ILauncherOptions<D>::FallbackUri() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::ILauncherOptions)->get_FallbackUri(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_System_ILauncherOptions<D>::FallbackUri(Windows::Foundation::Uri const& value) const
{
    check_hresult(WINRT_SHIM(Windows::System::ILauncherOptions)->put_FallbackUri(get_abi(value)));
}

template <typename D> hstring consume_Windows_System_ILauncherOptions<D>::ContentType() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::ILauncherOptions)->get_ContentType(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_System_ILauncherOptions<D>::ContentType(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::System::ILauncherOptions)->put_ContentType(get_abi(value)));
}

template <typename D> hstring consume_Windows_System_ILauncherOptions2<D>::TargetApplicationPackageFamilyName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::ILauncherOptions2)->get_TargetApplicationPackageFamilyName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_System_ILauncherOptions2<D>::TargetApplicationPackageFamilyName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::System::ILauncherOptions2)->put_TargetApplicationPackageFamilyName(get_abi(value)));
}

template <typename D> Windows::Storage::Search::StorageFileQueryResult consume_Windows_System_ILauncherOptions2<D>::NeighboringFilesQuery() const
{
    Windows::Storage::Search::StorageFileQueryResult value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::ILauncherOptions2)->get_NeighboringFilesQuery(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_System_ILauncherOptions2<D>::NeighboringFilesQuery(Windows::Storage::Search::StorageFileQueryResult const& value) const
{
    check_hresult(WINRT_SHIM(Windows::System::ILauncherOptions2)->put_NeighboringFilesQuery(get_abi(value)));
}

template <typename D> bool consume_Windows_System_ILauncherOptions3<D>::IgnoreAppUriHandlers() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::System::ILauncherOptions3)->get_IgnoreAppUriHandlers(&value));
    return value;
}

template <typename D> void consume_Windows_System_ILauncherOptions3<D>::IgnoreAppUriHandlers(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::System::ILauncherOptions3)->put_IgnoreAppUriHandlers(value));
}

template <typename D> bool consume_Windows_System_ILauncherOptions4<D>::LimitPickerToCurrentAppAndAppUriHandlers() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::System::ILauncherOptions4)->get_LimitPickerToCurrentAppAndAppUriHandlers(&value));
    return value;
}

template <typename D> void consume_Windows_System_ILauncherOptions4<D>::LimitPickerToCurrentAppAndAppUriHandlers(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::System::ILauncherOptions4)->put_LimitPickerToCurrentAppAndAppUriHandlers(value));
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_System_ILauncherStatics<D>::LaunchFileAsync(Windows::Storage::IStorageFile const& file) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::ILauncherStatics)->LaunchFileAsync(get_abi(file), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_System_ILauncherStatics<D>::LaunchFileAsync(Windows::Storage::IStorageFile const& file, Windows::System::LauncherOptions const& options) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::ILauncherStatics)->LaunchFileWithOptionsAsync(get_abi(file), get_abi(options), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_System_ILauncherStatics<D>::LaunchUriAsync(Windows::Foundation::Uri const& uri) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::ILauncherStatics)->LaunchUriAsync(get_abi(uri), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_System_ILauncherStatics<D>::LaunchUriAsync(Windows::Foundation::Uri const& uri, Windows::System::LauncherOptions const& options) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::ILauncherStatics)->LaunchUriWithOptionsAsync(get_abi(uri), get_abi(options), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::System::LaunchUriResult> consume_Windows_System_ILauncherStatics2<D>::LaunchUriForResultsAsync(Windows::Foundation::Uri const& uri, Windows::System::LauncherOptions const& options) const
{
    Windows::Foundation::IAsyncOperation<Windows::System::LaunchUriResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::ILauncherStatics2)->LaunchUriForResultsAsync(get_abi(uri), get_abi(options), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::System::LaunchUriResult> consume_Windows_System_ILauncherStatics2<D>::LaunchUriForResultsAsync(Windows::Foundation::Uri const& uri, Windows::System::LauncherOptions const& options, Windows::Foundation::Collections::ValueSet const& inputData) const
{
    Windows::Foundation::IAsyncOperation<Windows::System::LaunchUriResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::ILauncherStatics2)->LaunchUriForResultsWithDataAsync(get_abi(uri), get_abi(options), get_abi(inputData), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_System_ILauncherStatics2<D>::LaunchUriAsync(Windows::Foundation::Uri const& uri, Windows::System::LauncherOptions const& options, Windows::Foundation::Collections::ValueSet const& inputData) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::ILauncherStatics2)->LaunchUriWithDataAsync(get_abi(uri), get_abi(options), get_abi(inputData), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::System::LaunchQuerySupportStatus> consume_Windows_System_ILauncherStatics2<D>::QueryUriSupportAsync(Windows::Foundation::Uri const& uri, Windows::System::LaunchQuerySupportType const& launchQuerySupportType) const
{
    Windows::Foundation::IAsyncOperation<Windows::System::LaunchQuerySupportStatus> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::ILauncherStatics2)->QueryUriSupportAsync(get_abi(uri), get_abi(launchQuerySupportType), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::System::LaunchQuerySupportStatus> consume_Windows_System_ILauncherStatics2<D>::QueryUriSupportAsync(Windows::Foundation::Uri const& uri, Windows::System::LaunchQuerySupportType const& launchQuerySupportType, param::hstring const& packageFamilyName) const
{
    Windows::Foundation::IAsyncOperation<Windows::System::LaunchQuerySupportStatus> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::ILauncherStatics2)->QueryUriSupportWithPackageFamilyNameAsync(get_abi(uri), get_abi(launchQuerySupportType), get_abi(packageFamilyName), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::System::LaunchQuerySupportStatus> consume_Windows_System_ILauncherStatics2<D>::QueryFileSupportAsync(Windows::Storage::StorageFile const& file) const
{
    Windows::Foundation::IAsyncOperation<Windows::System::LaunchQuerySupportStatus> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::ILauncherStatics2)->QueryFileSupportAsync(get_abi(file), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::System::LaunchQuerySupportStatus> consume_Windows_System_ILauncherStatics2<D>::QueryFileSupportAsync(Windows::Storage::StorageFile const& file, param::hstring const& packageFamilyName) const
{
    Windows::Foundation::IAsyncOperation<Windows::System::LaunchQuerySupportStatus> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::ILauncherStatics2)->QueryFileSupportWithPackageFamilyNameAsync(get_abi(file), get_abi(packageFamilyName), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::AppInfo>> consume_Windows_System_ILauncherStatics2<D>::FindUriSchemeHandlersAsync(param::hstring const& scheme) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::AppInfo>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::ILauncherStatics2)->FindUriSchemeHandlersAsync(get_abi(scheme), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::AppInfo>> consume_Windows_System_ILauncherStatics2<D>::FindUriSchemeHandlersAsync(param::hstring const& scheme, Windows::System::LaunchQuerySupportType const& launchQuerySupportType) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::AppInfo>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::ILauncherStatics2)->FindUriSchemeHandlersWithLaunchUriTypeAsync(get_abi(scheme), get_abi(launchQuerySupportType), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::AppInfo>> consume_Windows_System_ILauncherStatics2<D>::FindFileHandlersAsync(param::hstring const& extension) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::AppInfo>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::ILauncherStatics2)->FindFileHandlersAsync(get_abi(extension), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_System_ILauncherStatics3<D>::LaunchFolderAsync(Windows::Storage::IStorageFolder const& folder) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::ILauncherStatics3)->LaunchFolderAsync(get_abi(folder), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_System_ILauncherStatics3<D>::LaunchFolderAsync(Windows::Storage::IStorageFolder const& folder, Windows::System::FolderLauncherOptions const& options) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::ILauncherStatics3)->LaunchFolderWithOptionsAsync(get_abi(folder), get_abi(options), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::System::LaunchQuerySupportStatus> consume_Windows_System_ILauncherStatics4<D>::QueryAppUriSupportAsync(Windows::Foundation::Uri const& uri) const
{
    Windows::Foundation::IAsyncOperation<Windows::System::LaunchQuerySupportStatus> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::ILauncherStatics4)->QueryAppUriSupportAsync(get_abi(uri), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::System::LaunchQuerySupportStatus> consume_Windows_System_ILauncherStatics4<D>::QueryAppUriSupportAsync(Windows::Foundation::Uri const& uri, param::hstring const& packageFamilyName) const
{
    Windows::Foundation::IAsyncOperation<Windows::System::LaunchQuerySupportStatus> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::ILauncherStatics4)->QueryAppUriSupportWithPackageFamilyNameAsync(get_abi(uri), get_abi(packageFamilyName), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::AppInfo>> consume_Windows_System_ILauncherStatics4<D>::FindAppUriHandlersAsync(Windows::Foundation::Uri const& uri) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::AppInfo>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::ILauncherStatics4)->FindAppUriHandlersAsync(get_abi(uri), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::System::LaunchUriStatus> consume_Windows_System_ILauncherStatics4<D>::LaunchUriForUserAsync(Windows::System::User const& user, Windows::Foundation::Uri const& uri) const
{
    Windows::Foundation::IAsyncOperation<Windows::System::LaunchUriStatus> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::ILauncherStatics4)->LaunchUriForUserAsync(get_abi(user), get_abi(uri), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::System::LaunchUriStatus> consume_Windows_System_ILauncherStatics4<D>::LaunchUriForUserAsync(Windows::System::User const& user, Windows::Foundation::Uri const& uri, Windows::System::LauncherOptions const& options) const
{
    Windows::Foundation::IAsyncOperation<Windows::System::LaunchUriStatus> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::ILauncherStatics4)->LaunchUriWithOptionsForUserAsync(get_abi(user), get_abi(uri), get_abi(options), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::System::LaunchUriStatus> consume_Windows_System_ILauncherStatics4<D>::LaunchUriForUserAsync(Windows::System::User const& user, Windows::Foundation::Uri const& uri, Windows::System::LauncherOptions const& options, Windows::Foundation::Collections::ValueSet const& inputData) const
{
    Windows::Foundation::IAsyncOperation<Windows::System::LaunchUriStatus> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::ILauncherStatics4)->LaunchUriWithDataForUserAsync(get_abi(user), get_abi(uri), get_abi(options), get_abi(inputData), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::System::LaunchUriResult> consume_Windows_System_ILauncherStatics4<D>::LaunchUriForResultsForUserAsync(Windows::System::User const& user, Windows::Foundation::Uri const& uri, Windows::System::LauncherOptions const& options) const
{
    Windows::Foundation::IAsyncOperation<Windows::System::LaunchUriResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::ILauncherStatics4)->LaunchUriForResultsForUserAsync(get_abi(user), get_abi(uri), get_abi(options), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::System::LaunchUriResult> consume_Windows_System_ILauncherStatics4<D>::LaunchUriForResultsForUserAsync(Windows::System::User const& user, Windows::Foundation::Uri const& uri, Windows::System::LauncherOptions const& options, Windows::Foundation::Collections::ValueSet const& inputData) const
{
    Windows::Foundation::IAsyncOperation<Windows::System::LaunchUriResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::ILauncherStatics4)->LaunchUriForResultsWithDataForUserAsync(get_abi(user), get_abi(uri), get_abi(options), get_abi(inputData), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_System_ILauncherStatics5<D>::LaunchFolderPathAsync(param::hstring const& path) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::ILauncherStatics5)->LaunchFolderPathAsync(get_abi(path), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_System_ILauncherStatics5<D>::LaunchFolderPathAsync(param::hstring const& path, Windows::System::FolderLauncherOptions const& options) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::ILauncherStatics5)->LaunchFolderPathWithOptionsAsync(get_abi(path), get_abi(options), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_System_ILauncherStatics5<D>::LaunchFolderPathForUserAsync(Windows::System::User const& user, param::hstring const& path) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::ILauncherStatics5)->LaunchFolderPathForUserAsync(get_abi(user), get_abi(path), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_System_ILauncherStatics5<D>::LaunchFolderPathForUserAsync(Windows::System::User const& user, param::hstring const& path, Windows::System::FolderLauncherOptions const& options) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::ILauncherStatics5)->LaunchFolderPathWithOptionsForUserAsync(get_abi(user), get_abi(path), get_abi(options), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::Point> consume_Windows_System_ILauncherUIOptions<D>::InvocationPoint() const
{
    Windows::Foundation::IReference<Windows::Foundation::Point> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::ILauncherUIOptions)->get_InvocationPoint(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_System_ILauncherUIOptions<D>::InvocationPoint(optional<Windows::Foundation::Point> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::System::ILauncherUIOptions)->put_InvocationPoint(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::Rect> consume_Windows_System_ILauncherUIOptions<D>::SelectionRect() const
{
    Windows::Foundation::IReference<Windows::Foundation::Rect> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::ILauncherUIOptions)->get_SelectionRect(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_System_ILauncherUIOptions<D>::SelectionRect(optional<Windows::Foundation::Rect> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::System::ILauncherUIOptions)->put_SelectionRect(get_abi(value)));
}

template <typename D> Windows::UI::Popups::Placement consume_Windows_System_ILauncherUIOptions<D>::PreferredPlacement() const
{
    Windows::UI::Popups::Placement value{};
    check_hresult(WINRT_SHIM(Windows::System::ILauncherUIOptions)->get_PreferredPlacement(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_System_ILauncherUIOptions<D>::PreferredPlacement(Windows::UI::Popups::Placement const& value) const
{
    check_hresult(WINRT_SHIM(Windows::System::ILauncherUIOptions)->put_PreferredPlacement(get_abi(value)));
}

template <typename D> Windows::UI::ViewManagement::ViewSizePreference consume_Windows_System_ILauncherViewOptions<D>::DesiredRemainingView() const
{
    Windows::UI::ViewManagement::ViewSizePreference value{};
    check_hresult(WINRT_SHIM(Windows::System::ILauncherViewOptions)->get_DesiredRemainingView(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_System_ILauncherViewOptions<D>::DesiredRemainingView(Windows::UI::ViewManagement::ViewSizePreference const& value) const
{
    check_hresult(WINRT_SHIM(Windows::System::ILauncherViewOptions)->put_DesiredRemainingView(get_abi(value)));
}

template <typename D> uint64_t consume_Windows_System_IMemoryManagerStatics<D>::AppMemoryUsage() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::System::IMemoryManagerStatics)->get_AppMemoryUsage(&value));
    return value;
}

template <typename D> uint64_t consume_Windows_System_IMemoryManagerStatics<D>::AppMemoryUsageLimit() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::System::IMemoryManagerStatics)->get_AppMemoryUsageLimit(&value));
    return value;
}

template <typename D> Windows::System::AppMemoryUsageLevel consume_Windows_System_IMemoryManagerStatics<D>::AppMemoryUsageLevel() const
{
    Windows::System::AppMemoryUsageLevel value{};
    check_hresult(WINRT_SHIM(Windows::System::IMemoryManagerStatics)->get_AppMemoryUsageLevel(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_System_IMemoryManagerStatics<D>::AppMemoryUsageIncreased(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::System::IMemoryManagerStatics)->add_AppMemoryUsageIncreased(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_System_IMemoryManagerStatics<D>::AppMemoryUsageIncreased_revoker consume_Windows_System_IMemoryManagerStatics<D>::AppMemoryUsageIncreased(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, AppMemoryUsageIncreased_revoker>(this, AppMemoryUsageIncreased(handler));
}

template <typename D> void consume_Windows_System_IMemoryManagerStatics<D>::AppMemoryUsageIncreased(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::System::IMemoryManagerStatics)->remove_AppMemoryUsageIncreased(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_System_IMemoryManagerStatics<D>::AppMemoryUsageDecreased(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::System::IMemoryManagerStatics)->add_AppMemoryUsageDecreased(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_System_IMemoryManagerStatics<D>::AppMemoryUsageDecreased_revoker consume_Windows_System_IMemoryManagerStatics<D>::AppMemoryUsageDecreased(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, AppMemoryUsageDecreased_revoker>(this, AppMemoryUsageDecreased(handler));
}

template <typename D> void consume_Windows_System_IMemoryManagerStatics<D>::AppMemoryUsageDecreased(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::System::IMemoryManagerStatics)->remove_AppMemoryUsageDecreased(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_System_IMemoryManagerStatics<D>::AppMemoryUsageLimitChanging(Windows::Foundation::EventHandler<Windows::System::AppMemoryUsageLimitChangingEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::System::IMemoryManagerStatics)->add_AppMemoryUsageLimitChanging(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_System_IMemoryManagerStatics<D>::AppMemoryUsageLimitChanging_revoker consume_Windows_System_IMemoryManagerStatics<D>::AppMemoryUsageLimitChanging(auto_revoke_t, Windows::Foundation::EventHandler<Windows::System::AppMemoryUsageLimitChangingEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, AppMemoryUsageLimitChanging_revoker>(this, AppMemoryUsageLimitChanging(handler));
}

template <typename D> void consume_Windows_System_IMemoryManagerStatics<D>::AppMemoryUsageLimitChanging(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::System::IMemoryManagerStatics)->remove_AppMemoryUsageLimitChanging(get_abi(token)));
}

template <typename D> Windows::System::AppMemoryReport consume_Windows_System_IMemoryManagerStatics2<D>::GetAppMemoryReport() const
{
    Windows::System::AppMemoryReport memoryReport{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::IMemoryManagerStatics2)->GetAppMemoryReport(put_abi(memoryReport)));
    return memoryReport;
}

template <typename D> Windows::System::ProcessMemoryReport consume_Windows_System_IMemoryManagerStatics2<D>::GetProcessMemoryReport() const
{
    Windows::System::ProcessMemoryReport memoryReport{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::IMemoryManagerStatics2)->GetProcessMemoryReport(put_abi(memoryReport)));
    return memoryReport;
}

template <typename D> bool consume_Windows_System_IMemoryManagerStatics3<D>::TrySetAppMemoryUsageLimit(uint64_t value) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::System::IMemoryManagerStatics3)->TrySetAppMemoryUsageLimit(value, &result));
    return result;
}

template <typename D> uint64_t consume_Windows_System_IMemoryManagerStatics4<D>::ExpectedAppMemoryUsageLimit() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::System::IMemoryManagerStatics4)->get_ExpectedAppMemoryUsageLimit(&value));
    return value;
}

template <typename D> Windows::Storage::Streams::IInputStream consume_Windows_System_IProcessLauncherOptions<D>::StandardInput() const
{
    Windows::Storage::Streams::IInputStream value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::IProcessLauncherOptions)->get_StandardInput(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_System_IProcessLauncherOptions<D>::StandardInput(Windows::Storage::Streams::IInputStream const& value) const
{
    check_hresult(WINRT_SHIM(Windows::System::IProcessLauncherOptions)->put_StandardInput(get_abi(value)));
}

template <typename D> Windows::Storage::Streams::IOutputStream consume_Windows_System_IProcessLauncherOptions<D>::StandardOutput() const
{
    Windows::Storage::Streams::IOutputStream value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::IProcessLauncherOptions)->get_StandardOutput(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_System_IProcessLauncherOptions<D>::StandardOutput(Windows::Storage::Streams::IOutputStream const& value) const
{
    check_hresult(WINRT_SHIM(Windows::System::IProcessLauncherOptions)->put_StandardOutput(get_abi(value)));
}

template <typename D> Windows::Storage::Streams::IOutputStream consume_Windows_System_IProcessLauncherOptions<D>::StandardError() const
{
    Windows::Storage::Streams::IOutputStream value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::IProcessLauncherOptions)->get_StandardError(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_System_IProcessLauncherOptions<D>::StandardError(Windows::Storage::Streams::IOutputStream const& value) const
{
    check_hresult(WINRT_SHIM(Windows::System::IProcessLauncherOptions)->put_StandardError(get_abi(value)));
}

template <typename D> hstring consume_Windows_System_IProcessLauncherOptions<D>::WorkingDirectory() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::IProcessLauncherOptions)->get_WorkingDirectory(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_System_IProcessLauncherOptions<D>::WorkingDirectory(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::System::IProcessLauncherOptions)->put_WorkingDirectory(get_abi(value)));
}

template <typename D> uint32_t consume_Windows_System_IProcessLauncherResult<D>::ExitCode() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::System::IProcessLauncherResult)->get_ExitCode(&value));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::System::ProcessLauncherResult> consume_Windows_System_IProcessLauncherStatics<D>::RunToCompletionAsync(param::hstring const& fileName, param::hstring const& args) const
{
    Windows::Foundation::IAsyncOperation<Windows::System::ProcessLauncherResult> asyncOperationResult{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::IProcessLauncherStatics)->RunToCompletionAsync(get_abi(fileName), get_abi(args), put_abi(asyncOperationResult)));
    return asyncOperationResult;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::System::ProcessLauncherResult> consume_Windows_System_IProcessLauncherStatics<D>::RunToCompletionAsync(param::hstring const& fileName, param::hstring const& args, Windows::System::ProcessLauncherOptions const& options) const
{
    Windows::Foundation::IAsyncOperation<Windows::System::ProcessLauncherResult> asyncOperationResult{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::IProcessLauncherStatics)->RunToCompletionAsyncWithOptions(get_abi(fileName), get_abi(args), get_abi(options), put_abi(asyncOperationResult)));
    return asyncOperationResult;
}

template <typename D> uint64_t consume_Windows_System_IProcessMemoryReport<D>::PrivateWorkingSetUsage() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::System::IProcessMemoryReport)->get_PrivateWorkingSetUsage(&value));
    return value;
}

template <typename D> uint64_t consume_Windows_System_IProcessMemoryReport<D>::TotalWorkingSetUsage() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::System::IProcessMemoryReport)->get_TotalWorkingSetUsage(&value));
    return value;
}

template <typename D> void consume_Windows_System_IProtocolForResultsOperation<D>::ReportCompleted(Windows::Foundation::Collections::ValueSet const& data) const
{
    check_hresult(WINRT_SHIM(Windows::System::IProtocolForResultsOperation)->ReportCompleted(get_abi(data)));
}

template <typename D> Windows::Foundation::Uri consume_Windows_System_IRemoteLauncherOptions<D>::FallbackUri() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::IRemoteLauncherOptions)->get_FallbackUri(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_System_IRemoteLauncherOptions<D>::FallbackUri(Windows::Foundation::Uri const& value) const
{
    check_hresult(WINRT_SHIM(Windows::System::IRemoteLauncherOptions)->put_FallbackUri(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVector<hstring> consume_Windows_System_IRemoteLauncherOptions<D>::PreferredAppIds() const
{
    Windows::Foundation::Collections::IVector<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::IRemoteLauncherOptions)->get_PreferredAppIds(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::System::RemoteLaunchUriStatus> consume_Windows_System_IRemoteLauncherStatics<D>::LaunchUriAsync(Windows::System::RemoteSystems::RemoteSystemConnectionRequest const& remoteSystemConnectionRequest, Windows::Foundation::Uri const& uri) const
{
    Windows::Foundation::IAsyncOperation<Windows::System::RemoteLaunchUriStatus> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::IRemoteLauncherStatics)->LaunchUriAsync(get_abi(remoteSystemConnectionRequest), get_abi(uri), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::System::RemoteLaunchUriStatus> consume_Windows_System_IRemoteLauncherStatics<D>::LaunchUriAsync(Windows::System::RemoteSystems::RemoteSystemConnectionRequest const& remoteSystemConnectionRequest, Windows::Foundation::Uri const& uri, Windows::System::RemoteLauncherOptions const& options) const
{
    Windows::Foundation::IAsyncOperation<Windows::System::RemoteLaunchUriStatus> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::IRemoteLauncherStatics)->LaunchUriWithOptionsAsync(get_abi(remoteSystemConnectionRequest), get_abi(uri), get_abi(options), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::System::RemoteLaunchUriStatus> consume_Windows_System_IRemoteLauncherStatics<D>::LaunchUriAsync(Windows::System::RemoteSystems::RemoteSystemConnectionRequest const& remoteSystemConnectionRequest, Windows::Foundation::Uri const& uri, Windows::System::RemoteLauncherOptions const& options, Windows::Foundation::Collections::ValueSet const& inputData) const
{
    Windows::Foundation::IAsyncOperation<Windows::System::RemoteLaunchUriStatus> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::IRemoteLauncherStatics)->LaunchUriWithDataAsync(get_abi(remoteSystemConnectionRequest), get_abi(uri), get_abi(options), get_abi(inputData), put_abi(operation)));
    return operation;
}

template <typename D> void consume_Windows_System_IShutdownManagerStatics<D>::BeginShutdown(Windows::System::ShutdownKind const& shutdownKind, Windows::Foundation::TimeSpan const& timeout) const
{
    check_hresult(WINRT_SHIM(Windows::System::IShutdownManagerStatics)->BeginShutdown(get_abi(shutdownKind), get_abi(timeout)));
}

template <typename D> void consume_Windows_System_IShutdownManagerStatics<D>::CancelShutdown() const
{
    check_hresult(WINRT_SHIM(Windows::System::IShutdownManagerStatics)->CancelShutdown());
}

template <typename D> bool consume_Windows_System_IShutdownManagerStatics2<D>::IsPowerStateSupported(Windows::System::PowerState const& powerState) const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::System::IShutdownManagerStatics2)->IsPowerStateSupported(get_abi(powerState), &value));
    return value;
}

template <typename D> void consume_Windows_System_IShutdownManagerStatics2<D>::EnterPowerState(Windows::System::PowerState const& powerState) const
{
    check_hresult(WINRT_SHIM(Windows::System::IShutdownManagerStatics2)->EnterPowerState(get_abi(powerState)));
}

template <typename D> void consume_Windows_System_IShutdownManagerStatics2<D>::EnterPowerState(Windows::System::PowerState const& powerState, Windows::Foundation::TimeSpan const& wakeUpAfter) const
{
    check_hresult(WINRT_SHIM(Windows::System::IShutdownManagerStatics2)->EnterPowerStateWithTimeSpan(get_abi(powerState), get_abi(wakeUpAfter)));
}

template <typename D> hstring consume_Windows_System_ITimeZoneSettingsStatics<D>::CurrentTimeZoneDisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::ITimeZoneSettingsStatics)->get_CurrentTimeZoneDisplayName(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<hstring> consume_Windows_System_ITimeZoneSettingsStatics<D>::SupportedTimeZoneDisplayNames() const
{
    Windows::Foundation::Collections::IVectorView<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::ITimeZoneSettingsStatics)->get_SupportedTimeZoneDisplayNames(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_System_ITimeZoneSettingsStatics<D>::CanChangeTimeZone() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::System::ITimeZoneSettingsStatics)->get_CanChangeTimeZone(&value));
    return value;
}

template <typename D> void consume_Windows_System_ITimeZoneSettingsStatics<D>::ChangeTimeZoneByDisplayName(param::hstring const& timeZoneDisplayName) const
{
    check_hresult(WINRT_SHIM(Windows::System::ITimeZoneSettingsStatics)->ChangeTimeZoneByDisplayName(get_abi(timeZoneDisplayName)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::System::AutoUpdateTimeZoneStatus> consume_Windows_System_ITimeZoneSettingsStatics2<D>::AutoUpdateTimeZoneAsync(Windows::Foundation::TimeSpan const& timeout) const
{
    Windows::Foundation::IAsyncOperation<Windows::System::AutoUpdateTimeZoneStatus> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::ITimeZoneSettingsStatics2)->AutoUpdateTimeZoneAsync(get_abi(timeout), put_abi(operation)));
    return operation;
}

template <typename D> hstring consume_Windows_System_IUser<D>::NonRoamableId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::IUser)->get_NonRoamableId(put_abi(value)));
    return value;
}

template <typename D> Windows::System::UserAuthenticationStatus consume_Windows_System_IUser<D>::AuthenticationStatus() const
{
    Windows::System::UserAuthenticationStatus value{};
    check_hresult(WINRT_SHIM(Windows::System::IUser)->get_AuthenticationStatus(put_abi(value)));
    return value;
}

template <typename D> Windows::System::UserType consume_Windows_System_IUser<D>::Type() const
{
    Windows::System::UserType value{};
    check_hresult(WINRT_SHIM(Windows::System::IUser)->get_Type(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::IInspectable> consume_Windows_System_IUser<D>::GetPropertyAsync(param::hstring const& value) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::IInspectable> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::IUser)->GetPropertyAsync(get_abi(value), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IPropertySet> consume_Windows_System_IUser<D>::GetPropertiesAsync(param::async_vector_view<hstring> const& values) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IPropertySet> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::IUser)->GetPropertiesAsync(get_abi(values), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStreamReference> consume_Windows_System_IUser<D>::GetPictureAsync(Windows::System::UserPictureSize const& desiredSize) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStreamReference> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::IUser)->GetPictureAsync(get_abi(desiredSize), put_abi(operation)));
    return operation;
}

template <typename D> void consume_Windows_System_IUserAuthenticationStatusChangeDeferral<D>::Complete() const
{
    check_hresult(WINRT_SHIM(Windows::System::IUserAuthenticationStatusChangeDeferral)->Complete());
}

template <typename D> Windows::System::UserAuthenticationStatusChangeDeferral consume_Windows_System_IUserAuthenticationStatusChangingEventArgs<D>::GetDeferral() const
{
    Windows::System::UserAuthenticationStatusChangeDeferral result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::IUserAuthenticationStatusChangingEventArgs)->GetDeferral(put_abi(result)));
    return result;
}

template <typename D> Windows::System::User consume_Windows_System_IUserAuthenticationStatusChangingEventArgs<D>::User() const
{
    Windows::System::User value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::IUserAuthenticationStatusChangingEventArgs)->get_User(put_abi(value)));
    return value;
}

template <typename D> Windows::System::UserAuthenticationStatus consume_Windows_System_IUserAuthenticationStatusChangingEventArgs<D>::NewStatus() const
{
    Windows::System::UserAuthenticationStatus value{};
    check_hresult(WINRT_SHIM(Windows::System::IUserAuthenticationStatusChangingEventArgs)->get_NewStatus(put_abi(value)));
    return value;
}

template <typename D> Windows::System::UserAuthenticationStatus consume_Windows_System_IUserAuthenticationStatusChangingEventArgs<D>::CurrentStatus() const
{
    Windows::System::UserAuthenticationStatus value{};
    check_hresult(WINRT_SHIM(Windows::System::IUserAuthenticationStatusChangingEventArgs)->get_CurrentStatus(put_abi(value)));
    return value;
}

template <typename D> Windows::System::User consume_Windows_System_IUserChangedEventArgs<D>::User() const
{
    Windows::System::User value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::IUserChangedEventArgs)->get_User(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_IUserDeviceAssociationChangedEventArgs<D>::DeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::IUserDeviceAssociationChangedEventArgs)->get_DeviceId(put_abi(value)));
    return value;
}

template <typename D> Windows::System::User consume_Windows_System_IUserDeviceAssociationChangedEventArgs<D>::NewUser() const
{
    Windows::System::User value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::IUserDeviceAssociationChangedEventArgs)->get_NewUser(put_abi(value)));
    return value;
}

template <typename D> Windows::System::User consume_Windows_System_IUserDeviceAssociationChangedEventArgs<D>::OldUser() const
{
    Windows::System::User value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::IUserDeviceAssociationChangedEventArgs)->get_OldUser(put_abi(value)));
    return value;
}

template <typename D> Windows::System::User consume_Windows_System_IUserDeviceAssociationStatics<D>::FindUserFromDeviceId(param::hstring const& deviceId) const
{
    Windows::System::User user{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::IUserDeviceAssociationStatics)->FindUserFromDeviceId(get_abi(deviceId), put_abi(user)));
    return user;
}

template <typename D> winrt::event_token consume_Windows_System_IUserDeviceAssociationStatics<D>::UserDeviceAssociationChanged(Windows::Foundation::EventHandler<Windows::System::UserDeviceAssociationChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::System::IUserDeviceAssociationStatics)->add_UserDeviceAssociationChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_System_IUserDeviceAssociationStatics<D>::UserDeviceAssociationChanged_revoker consume_Windows_System_IUserDeviceAssociationStatics<D>::UserDeviceAssociationChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::System::UserDeviceAssociationChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, UserDeviceAssociationChanged_revoker>(this, UserDeviceAssociationChanged(handler));
}

template <typename D> void consume_Windows_System_IUserDeviceAssociationStatics<D>::UserDeviceAssociationChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::System::IUserDeviceAssociationStatics)->remove_UserDeviceAssociationChanged(get_abi(token)));
}

template <typename D> bool consume_Windows_System_IUserPicker<D>::AllowGuestAccounts() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::System::IUserPicker)->get_AllowGuestAccounts(&value));
    return value;
}

template <typename D> void consume_Windows_System_IUserPicker<D>::AllowGuestAccounts(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::System::IUserPicker)->put_AllowGuestAccounts(value));
}

template <typename D> Windows::System::User consume_Windows_System_IUserPicker<D>::SuggestedSelectedUser() const
{
    Windows::System::User value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::IUserPicker)->get_SuggestedSelectedUser(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_System_IUserPicker<D>::SuggestedSelectedUser(Windows::System::User const& value) const
{
    check_hresult(WINRT_SHIM(Windows::System::IUserPicker)->put_SuggestedSelectedUser(get_abi(value)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::System::User> consume_Windows_System_IUserPicker<D>::PickSingleUserAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::System::User> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::IUserPicker)->PickSingleUserAsync(put_abi(operation)));
    return operation;
}

template <typename D> bool consume_Windows_System_IUserPickerStatics<D>::IsSupported() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::System::IUserPickerStatics)->IsSupported(&result));
    return result;
}

template <typename D> Windows::System::UserWatcher consume_Windows_System_IUserStatics<D>::CreateWatcher() const
{
    Windows::System::UserWatcher result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::IUserStatics)->CreateWatcher(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::System::User>> consume_Windows_System_IUserStatics<D>::FindAllAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::System::User>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::IUserStatics)->FindAllAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::System::User>> consume_Windows_System_IUserStatics<D>::FindAllAsync(Windows::System::UserType const& type) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::System::User>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::IUserStatics)->FindAllAsyncByType(get_abi(type), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::System::User>> consume_Windows_System_IUserStatics<D>::FindAllAsync(Windows::System::UserType const& type, Windows::System::UserAuthenticationStatus const& status) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::System::User>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::IUserStatics)->FindAllAsyncByTypeAndStatus(get_abi(type), get_abi(status), put_abi(operation)));
    return operation;
}

template <typename D> Windows::System::User consume_Windows_System_IUserStatics<D>::GetFromId(param::hstring const& nonRoamableId) const
{
    Windows::System::User result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::IUserStatics)->GetFromId(get_abi(nonRoamableId), put_abi(result)));
    return result;
}

template <typename D> Windows::System::UserWatcherStatus consume_Windows_System_IUserWatcher<D>::Status() const
{
    Windows::System::UserWatcherStatus value{};
    check_hresult(WINRT_SHIM(Windows::System::IUserWatcher)->get_Status(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_System_IUserWatcher<D>::Start() const
{
    check_hresult(WINRT_SHIM(Windows::System::IUserWatcher)->Start());
}

template <typename D> void consume_Windows_System_IUserWatcher<D>::Stop() const
{
    check_hresult(WINRT_SHIM(Windows::System::IUserWatcher)->Stop());
}

template <typename D> winrt::event_token consume_Windows_System_IUserWatcher<D>::Added(Windows::Foundation::TypedEventHandler<Windows::System::UserWatcher, Windows::System::UserChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::System::IUserWatcher)->add_Added(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_System_IUserWatcher<D>::Added_revoker consume_Windows_System_IUserWatcher<D>::Added(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::System::UserWatcher, Windows::System::UserChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Added_revoker>(this, Added(handler));
}

template <typename D> void consume_Windows_System_IUserWatcher<D>::Added(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::System::IUserWatcher)->remove_Added(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_System_IUserWatcher<D>::Removed(Windows::Foundation::TypedEventHandler<Windows::System::UserWatcher, Windows::System::UserChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::System::IUserWatcher)->add_Removed(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_System_IUserWatcher<D>::Removed_revoker consume_Windows_System_IUserWatcher<D>::Removed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::System::UserWatcher, Windows::System::UserChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Removed_revoker>(this, Removed(handler));
}

template <typename D> void consume_Windows_System_IUserWatcher<D>::Removed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::System::IUserWatcher)->remove_Removed(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_System_IUserWatcher<D>::Updated(Windows::Foundation::TypedEventHandler<Windows::System::UserWatcher, Windows::System::UserChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::System::IUserWatcher)->add_Updated(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_System_IUserWatcher<D>::Updated_revoker consume_Windows_System_IUserWatcher<D>::Updated(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::System::UserWatcher, Windows::System::UserChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Updated_revoker>(this, Updated(handler));
}

template <typename D> void consume_Windows_System_IUserWatcher<D>::Updated(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::System::IUserWatcher)->remove_Updated(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_System_IUserWatcher<D>::AuthenticationStatusChanged(Windows::Foundation::TypedEventHandler<Windows::System::UserWatcher, Windows::System::UserChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::System::IUserWatcher)->add_AuthenticationStatusChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_System_IUserWatcher<D>::AuthenticationStatusChanged_revoker consume_Windows_System_IUserWatcher<D>::AuthenticationStatusChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::System::UserWatcher, Windows::System::UserChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, AuthenticationStatusChanged_revoker>(this, AuthenticationStatusChanged(handler));
}

template <typename D> void consume_Windows_System_IUserWatcher<D>::AuthenticationStatusChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::System::IUserWatcher)->remove_AuthenticationStatusChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_System_IUserWatcher<D>::AuthenticationStatusChanging(Windows::Foundation::TypedEventHandler<Windows::System::UserWatcher, Windows::System::UserAuthenticationStatusChangingEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::System::IUserWatcher)->add_AuthenticationStatusChanging(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_System_IUserWatcher<D>::AuthenticationStatusChanging_revoker consume_Windows_System_IUserWatcher<D>::AuthenticationStatusChanging(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::System::UserWatcher, Windows::System::UserAuthenticationStatusChangingEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, AuthenticationStatusChanging_revoker>(this, AuthenticationStatusChanging(handler));
}

template <typename D> void consume_Windows_System_IUserWatcher<D>::AuthenticationStatusChanging(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::System::IUserWatcher)->remove_AuthenticationStatusChanging(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_System_IUserWatcher<D>::EnumerationCompleted(Windows::Foundation::TypedEventHandler<Windows::System::UserWatcher, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::System::IUserWatcher)->add_EnumerationCompleted(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_System_IUserWatcher<D>::EnumerationCompleted_revoker consume_Windows_System_IUserWatcher<D>::EnumerationCompleted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::System::UserWatcher, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, EnumerationCompleted_revoker>(this, EnumerationCompleted(handler));
}

template <typename D> void consume_Windows_System_IUserWatcher<D>::EnumerationCompleted(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::System::IUserWatcher)->remove_EnumerationCompleted(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_System_IUserWatcher<D>::Stopped(Windows::Foundation::TypedEventHandler<Windows::System::UserWatcher, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::System::IUserWatcher)->add_Stopped(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_System_IUserWatcher<D>::Stopped_revoker consume_Windows_System_IUserWatcher<D>::Stopped(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::System::UserWatcher, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, Stopped_revoker>(this, Stopped(handler));
}

template <typename D> void consume_Windows_System_IUserWatcher<D>::Stopped(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::System::IUserWatcher)->remove_Stopped(get_abi(token)));
}

template <> struct delegate<Windows::System::DispatcherQueueHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::System::DispatcherQueueHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::System::DispatcherQueueHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke() noexcept final
        {
            try
            {
                (*this)();
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <typename D>
struct produce<D, Windows::System::IAppActivationResult> : produce_base<D, Windows::System::IAppActivationResult>
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

    int32_t WINRT_CALL get_AppResourceGroupInfo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppResourceGroupInfo, WINRT_WRAP(Windows::System::AppResourceGroupInfo));
            *value = detach_from<Windows::System::AppResourceGroupInfo>(this->shim().AppResourceGroupInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::IAppDiagnosticInfo> : produce_base<D, Windows::System::IAppDiagnosticInfo>
{
    int32_t WINRT_CALL get_AppInfo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppInfo, WINRT_WRAP(Windows::ApplicationModel::AppInfo));
            *value = detach_from<Windows::ApplicationModel::AppInfo>(this->shim().AppInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::IAppDiagnosticInfo2> : produce_base<D, Windows::System::IAppDiagnosticInfo2>
{
    int32_t WINRT_CALL GetResourceGroups(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetResourceGroups, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::System::AppResourceGroupInfo>));
            *result = detach_from<Windows::Foundation::Collections::IVector<Windows::System::AppResourceGroupInfo>>(this->shim().GetResourceGroups());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateResourceGroupWatcher(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateResourceGroupWatcher, WINRT_WRAP(Windows::System::AppResourceGroupInfoWatcher));
            *result = detach_from<Windows::System::AppResourceGroupInfoWatcher>(this->shim().CreateResourceGroupWatcher());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::IAppDiagnosticInfo3> : produce_base<D, Windows::System::IAppDiagnosticInfo3>
{
    int32_t WINRT_CALL LaunchAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LaunchAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::System::AppActivationResult>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::System::AppActivationResult>>(this->shim().LaunchAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::IAppDiagnosticInfoStatics> : produce_base<D, Windows::System::IAppDiagnosticInfoStatics>
{
    int32_t WINRT_CALL RequestInfoAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestInfoAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<Windows::System::AppDiagnosticInfo>>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<Windows::System::AppDiagnosticInfo>>>(this->shim().RequestInfoAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::IAppDiagnosticInfoStatics2> : produce_base<D, Windows::System::IAppDiagnosticInfoStatics2>
{
    int32_t WINRT_CALL CreateWatcher(void** watcher) noexcept final
    {
        try
        {
            *watcher = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWatcher, WINRT_WRAP(Windows::System::AppDiagnosticInfoWatcher));
            *watcher = detach_from<Windows::System::AppDiagnosticInfoWatcher>(this->shim().CreateWatcher());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestAccessAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestAccessAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::System::DiagnosticAccessStatus>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::System::DiagnosticAccessStatus>>(this->shim().RequestAccessAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestInfoForPackageAsync(void* packageFamilyName, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestInfoForPackageAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<Windows::System::AppDiagnosticInfo>>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<Windows::System::AppDiagnosticInfo>>>(this->shim().RequestInfoForPackageAsync(*reinterpret_cast<hstring const*>(&packageFamilyName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestInfoForAppAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestInfoForAppAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<Windows::System::AppDiagnosticInfo>>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<Windows::System::AppDiagnosticInfo>>>(this->shim().RequestInfoForAppAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestInfoForAppUserModelId(void* appUserModelId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestInfoForAppAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<Windows::System::AppDiagnosticInfo>>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<Windows::System::AppDiagnosticInfo>>>(this->shim().RequestInfoForAppAsync(*reinterpret_cast<hstring const*>(&appUserModelId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::IAppDiagnosticInfoWatcher> : produce_base<D, Windows::System::IAppDiagnosticInfoWatcher>
{
    int32_t WINRT_CALL add_Added(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Added, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::System::AppDiagnosticInfoWatcher, Windows::System::AppDiagnosticInfoWatcherEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Added(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::System::AppDiagnosticInfoWatcher, Windows::System::AppDiagnosticInfoWatcherEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Added(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Added, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Added(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_Removed(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Removed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::System::AppDiagnosticInfoWatcher, Windows::System::AppDiagnosticInfoWatcherEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Removed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::System::AppDiagnosticInfoWatcher, Windows::System::AppDiagnosticInfoWatcherEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Removed(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Removed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Removed(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_EnumerationCompleted(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnumerationCompleted, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::System::AppDiagnosticInfoWatcher, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().EnumerationCompleted(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::System::AppDiagnosticInfoWatcher, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_EnumerationCompleted(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(EnumerationCompleted, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().EnumerationCompleted(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_Stopped(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Stopped, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::System::AppDiagnosticInfoWatcher, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().Stopped(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::System::AppDiagnosticInfoWatcher, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Stopped(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Stopped, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Stopped(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL get_Status(Windows::System::AppDiagnosticInfoWatcherStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::System::AppDiagnosticInfoWatcherStatus));
            *value = detach_from<Windows::System::AppDiagnosticInfoWatcherStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Start() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Start, WINRT_WRAP(void));
            this->shim().Start();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Stop() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Stop, WINRT_WRAP(void));
            this->shim().Stop();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::IAppDiagnosticInfoWatcherEventArgs> : produce_base<D, Windows::System::IAppDiagnosticInfoWatcherEventArgs>
{
    int32_t WINRT_CALL get_AppDiagnosticInfo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppDiagnosticInfo, WINRT_WRAP(Windows::System::AppDiagnosticInfo));
            *value = detach_from<Windows::System::AppDiagnosticInfo>(this->shim().AppDiagnosticInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::IAppExecutionStateChangeResult> : produce_base<D, Windows::System::IAppExecutionStateChangeResult>
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
};

template <typename D>
struct produce<D, Windows::System::IAppMemoryReport> : produce_base<D, Windows::System::IAppMemoryReport>
{
    int32_t WINRT_CALL get_PrivateCommitUsage(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PrivateCommitUsage, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().PrivateCommitUsage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PeakPrivateCommitUsage(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PeakPrivateCommitUsage, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().PeakPrivateCommitUsage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TotalCommitUsage(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TotalCommitUsage, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().TotalCommitUsage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TotalCommitLimit(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TotalCommitLimit, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().TotalCommitLimit());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::IAppMemoryReport2> : produce_base<D, Windows::System::IAppMemoryReport2>
{
    int32_t WINRT_CALL get_ExpectedTotalCommitLimit(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExpectedTotalCommitLimit, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().ExpectedTotalCommitLimit());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::IAppMemoryUsageLimitChangingEventArgs> : produce_base<D, Windows::System::IAppMemoryUsageLimitChangingEventArgs>
{
    int32_t WINRT_CALL get_OldLimit(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OldLimit, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().OldLimit());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NewLimit(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NewLimit, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().NewLimit());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::IAppResourceGroupBackgroundTaskReport> : produce_base<D, Windows::System::IAppResourceGroupBackgroundTaskReport>
{
    int32_t WINRT_CALL get_TaskId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TaskId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().TaskId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Name(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Name, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Trigger(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Trigger, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Trigger());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EntryPoint(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EntryPoint, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().EntryPoint());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::IAppResourceGroupInfo> : produce_base<D, Windows::System::IAppResourceGroupInfo>
{
    int32_t WINRT_CALL get_InstanceId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InstanceId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().InstanceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsShared(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsShared, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsShared());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetBackgroundTaskReports(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetBackgroundTaskReports, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::System::AppResourceGroupBackgroundTaskReport>));
            *result = detach_from<Windows::Foundation::Collections::IVector<Windows::System::AppResourceGroupBackgroundTaskReport>>(this->shim().GetBackgroundTaskReports());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetMemoryReport(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetMemoryReport, WINRT_WRAP(Windows::System::AppResourceGroupMemoryReport));
            *result = detach_from<Windows::System::AppResourceGroupMemoryReport>(this->shim().GetMemoryReport());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetProcessDiagnosticInfos(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetProcessDiagnosticInfos, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::System::Diagnostics::ProcessDiagnosticInfo>));
            *result = detach_from<Windows::Foundation::Collections::IVector<Windows::System::Diagnostics::ProcessDiagnosticInfo>>(this->shim().GetProcessDiagnosticInfos());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetStateReport(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetStateReport, WINRT_WRAP(Windows::System::AppResourceGroupStateReport));
            *result = detach_from<Windows::System::AppResourceGroupStateReport>(this->shim().GetStateReport());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::IAppResourceGroupInfo2> : produce_base<D, Windows::System::IAppResourceGroupInfo2>
{
    int32_t WINRT_CALL StartSuspendAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartSuspendAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::System::AppExecutionStateChangeResult>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::System::AppExecutionStateChangeResult>>(this->shim().StartSuspendAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StartResumeAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartResumeAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::System::AppExecutionStateChangeResult>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::System::AppExecutionStateChangeResult>>(this->shim().StartResumeAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StartTerminateAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartTerminateAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::System::AppExecutionStateChangeResult>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::System::AppExecutionStateChangeResult>>(this->shim().StartTerminateAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::IAppResourceGroupInfoWatcher> : produce_base<D, Windows::System::IAppResourceGroupInfoWatcher>
{
    int32_t WINRT_CALL add_Added(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Added, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::System::AppResourceGroupInfoWatcher, Windows::System::AppResourceGroupInfoWatcherEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Added(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::System::AppResourceGroupInfoWatcher, Windows::System::AppResourceGroupInfoWatcherEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Added(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Added, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Added(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_Removed(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Removed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::System::AppResourceGroupInfoWatcher, Windows::System::AppResourceGroupInfoWatcherEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Removed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::System::AppResourceGroupInfoWatcher, Windows::System::AppResourceGroupInfoWatcherEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Removed(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Removed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Removed(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_EnumerationCompleted(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnumerationCompleted, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::System::AppResourceGroupInfoWatcher, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().EnumerationCompleted(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::System::AppResourceGroupInfoWatcher, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_EnumerationCompleted(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(EnumerationCompleted, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().EnumerationCompleted(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_Stopped(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Stopped, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::System::AppResourceGroupInfoWatcher, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().Stopped(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::System::AppResourceGroupInfoWatcher, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Stopped(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Stopped, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Stopped(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_ExecutionStateChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExecutionStateChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::System::AppResourceGroupInfoWatcher, Windows::System::AppResourceGroupInfoWatcherExecutionStateChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ExecutionStateChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::System::AppResourceGroupInfoWatcher, Windows::System::AppResourceGroupInfoWatcherExecutionStateChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ExecutionStateChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ExecutionStateChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ExecutionStateChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL get_Status(Windows::System::AppResourceGroupInfoWatcherStatus* status) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::System::AppResourceGroupInfoWatcherStatus));
            *status = detach_from<Windows::System::AppResourceGroupInfoWatcherStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Start() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Start, WINRT_WRAP(void));
            this->shim().Start();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Stop() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Stop, WINRT_WRAP(void));
            this->shim().Stop();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::IAppResourceGroupInfoWatcherEventArgs> : produce_base<D, Windows::System::IAppResourceGroupInfoWatcherEventArgs>
{
    int32_t WINRT_CALL get_AppDiagnosticInfos(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppDiagnosticInfos, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::System::AppDiagnosticInfo>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::System::AppDiagnosticInfo>>(this->shim().AppDiagnosticInfos());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AppResourceGroupInfo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppResourceGroupInfo, WINRT_WRAP(Windows::System::AppResourceGroupInfo));
            *value = detach_from<Windows::System::AppResourceGroupInfo>(this->shim().AppResourceGroupInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::IAppResourceGroupInfoWatcherExecutionStateChangedEventArgs> : produce_base<D, Windows::System::IAppResourceGroupInfoWatcherExecutionStateChangedEventArgs>
{
    int32_t WINRT_CALL get_AppDiagnosticInfos(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppDiagnosticInfos, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::System::AppDiagnosticInfo>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::System::AppDiagnosticInfo>>(this->shim().AppDiagnosticInfos());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AppResourceGroupInfo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppResourceGroupInfo, WINRT_WRAP(Windows::System::AppResourceGroupInfo));
            *value = detach_from<Windows::System::AppResourceGroupInfo>(this->shim().AppResourceGroupInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::IAppResourceGroupMemoryReport> : produce_base<D, Windows::System::IAppResourceGroupMemoryReport>
{
    int32_t WINRT_CALL get_CommitUsageLimit(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CommitUsageLimit, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().CommitUsageLimit());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CommitUsageLevel(Windows::System::AppMemoryUsageLevel* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CommitUsageLevel, WINRT_WRAP(Windows::System::AppMemoryUsageLevel));
            *value = detach_from<Windows::System::AppMemoryUsageLevel>(this->shim().CommitUsageLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PrivateCommitUsage(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PrivateCommitUsage, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().PrivateCommitUsage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TotalCommitUsage(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TotalCommitUsage, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().TotalCommitUsage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::IAppResourceGroupStateReport> : produce_base<D, Windows::System::IAppResourceGroupStateReport>
{
    int32_t WINRT_CALL get_ExecutionState(Windows::System::AppResourceGroupExecutionState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExecutionState, WINRT_WRAP(Windows::System::AppResourceGroupExecutionState));
            *value = detach_from<Windows::System::AppResourceGroupExecutionState>(this->shim().ExecutionState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EnergyQuotaState(Windows::System::AppResourceGroupEnergyQuotaState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnergyQuotaState, WINRT_WRAP(Windows::System::AppResourceGroupEnergyQuotaState));
            *value = detach_from<Windows::System::AppResourceGroupEnergyQuotaState>(this->shim().EnergyQuotaState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::IAppUriHandlerHost> : produce_base<D, Windows::System::IAppUriHandlerHost>
{
    int32_t WINRT_CALL get_Name(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Name, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Name(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Name, WINRT_WRAP(void), hstring const&);
            this->shim().Name(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::IAppUriHandlerHostFactory> : produce_base<D, Windows::System::IAppUriHandlerHostFactory>
{
    int32_t WINRT_CALL CreateInstance(void* name, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::System::AppUriHandlerHost), hstring const&);
            *value = detach_from<Windows::System::AppUriHandlerHost>(this->shim().CreateInstance(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::IAppUriHandlerRegistration> : produce_base<D, Windows::System::IAppUriHandlerRegistration>
{
    int32_t WINRT_CALL get_Name(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Name, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_User(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(User, WINRT_WRAP(Windows::System::User));
            *value = detach_from<Windows::System::User>(this->shim().User());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetAppAddedHostsAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAppAddedHostsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<Windows::System::AppUriHandlerHost>>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<Windows::System::AppUriHandlerHost>>>(this->shim().GetAppAddedHostsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetAppAddedHostsAsync(void* hosts, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetAppAddedHostsAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Foundation::Collections::IIterable<Windows::System::AppUriHandlerHost> const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SetAppAddedHostsAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::System::AppUriHandlerHost> const*>(&hosts)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::IAppUriHandlerRegistrationManager> : produce_base<D, Windows::System::IAppUriHandlerRegistrationManager>
{
    int32_t WINRT_CALL get_User(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(User, WINRT_WRAP(Windows::System::User));
            *value = detach_from<Windows::System::User>(this->shim().User());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryGetRegistration(void* name, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryGetRegistration, WINRT_WRAP(Windows::System::AppUriHandlerRegistration), hstring const&);
            *result = detach_from<Windows::System::AppUriHandlerRegistration>(this->shim().TryGetRegistration(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::IAppUriHandlerRegistrationManagerStatics> : produce_base<D, Windows::System::IAppUriHandlerRegistrationManagerStatics>
{
    int32_t WINRT_CALL GetDefault(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefault, WINRT_WRAP(Windows::System::AppUriHandlerRegistrationManager));
            *result = detach_from<Windows::System::AppUriHandlerRegistrationManager>(this->shim().GetDefault());
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
            WINRT_ASSERT_DECLARATION(GetForUser, WINRT_WRAP(Windows::System::AppUriHandlerRegistrationManager), Windows::System::User const&);
            *result = detach_from<Windows::System::AppUriHandlerRegistrationManager>(this->shim().GetForUser(*reinterpret_cast<Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::IDateTimeSettingsStatics> : produce_base<D, Windows::System::IDateTimeSettingsStatics>
{
    int32_t WINRT_CALL SetSystemDateTime(Windows::Foundation::DateTime utcDateTime) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetSystemDateTime, WINRT_WRAP(void), Windows::Foundation::DateTime const&);
            this->shim().SetSystemDateTime(*reinterpret_cast<Windows::Foundation::DateTime const*>(&utcDateTime));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::IDispatcherQueue> : produce_base<D, Windows::System::IDispatcherQueue>
{
    int32_t WINRT_CALL CreateTimer(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateTimer, WINRT_WRAP(Windows::System::DispatcherQueueTimer));
            *result = detach_from<Windows::System::DispatcherQueueTimer>(this->shim().CreateTimer());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryEnqueue(void* callback, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryEnqueue, WINRT_WRAP(bool), Windows::System::DispatcherQueueHandler const&);
            *result = detach_from<bool>(this->shim().TryEnqueue(*reinterpret_cast<Windows::System::DispatcherQueueHandler const*>(&callback)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryEnqueueWithPriority(Windows::System::DispatcherQueuePriority priority, void* callback, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryEnqueue, WINRT_WRAP(bool), Windows::System::DispatcherQueuePriority const&, Windows::System::DispatcherQueueHandler const&);
            *result = detach_from<bool>(this->shim().TryEnqueue(*reinterpret_cast<Windows::System::DispatcherQueuePriority const*>(&priority), *reinterpret_cast<Windows::System::DispatcherQueueHandler const*>(&callback)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_ShutdownStarting(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShutdownStarting, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::System::DispatcherQueue, Windows::System::DispatcherQueueShutdownStartingEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ShutdownStarting(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::System::DispatcherQueue, Windows::System::DispatcherQueueShutdownStartingEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ShutdownStarting(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ShutdownStarting, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ShutdownStarting(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_ShutdownCompleted(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShutdownCompleted, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::System::DispatcherQueue, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().ShutdownCompleted(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::System::DispatcherQueue, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ShutdownCompleted(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ShutdownCompleted, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ShutdownCompleted(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::System::IDispatcherQueue2> : produce_base<D, Windows::System::IDispatcherQueue2>
{
    int32_t WINRT_CALL get_HasThreadAccess(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HasThreadAccess, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().HasThreadAccess());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::IDispatcherQueueController> : produce_base<D, Windows::System::IDispatcherQueueController>
{
    int32_t WINRT_CALL get_DispatcherQueue(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DispatcherQueue, WINRT_WRAP(Windows::System::DispatcherQueue));
            *value = detach_from<Windows::System::DispatcherQueue>(this->shim().DispatcherQueue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ShutdownQueueAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShutdownQueueAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ShutdownQueueAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::IDispatcherQueueControllerStatics> : produce_base<D, Windows::System::IDispatcherQueueControllerStatics>
{
    int32_t WINRT_CALL CreateOnDedicatedThread(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateOnDedicatedThread, WINRT_WRAP(Windows::System::DispatcherQueueController));
            *result = detach_from<Windows::System::DispatcherQueueController>(this->shim().CreateOnDedicatedThread());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::IDispatcherQueueShutdownStartingEventArgs> : produce_base<D, Windows::System::IDispatcherQueueShutdownStartingEventArgs>
{
    int32_t WINRT_CALL GetDeferral(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeferral, WINRT_WRAP(Windows::Foundation::Deferral));
            *result = detach_from<Windows::Foundation::Deferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::IDispatcherQueueStatics> : produce_base<D, Windows::System::IDispatcherQueueStatics>
{
    int32_t WINRT_CALL GetForCurrentThread(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForCurrentThread, WINRT_WRAP(Windows::System::DispatcherQueue));
            *result = detach_from<Windows::System::DispatcherQueue>(this->shim().GetForCurrentThread());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::IDispatcherQueueTimer> : produce_base<D, Windows::System::IDispatcherQueueTimer>
{
    int32_t WINRT_CALL get_Interval(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Interval, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().Interval());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Interval(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Interval, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().Interval(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsRunning(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsRunning, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsRunning());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsRepeating(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsRepeating, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsRepeating());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsRepeating(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsRepeating, WINRT_WRAP(void), bool);
            this->shim().IsRepeating(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Start() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Start, WINRT_WRAP(void));
            this->shim().Start();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Stop() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Stop, WINRT_WRAP(void));
            this->shim().Stop();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_Tick(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Tick, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::System::DispatcherQueueTimer, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().Tick(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::System::DispatcherQueueTimer, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Tick(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Tick, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Tick(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::System::IFolderLauncherOptions> : produce_base<D, Windows::System::IFolderLauncherOptions>
{
    int32_t WINRT_CALL get_ItemsToSelect(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ItemsToSelect, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::Storage::IStorageItem>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::Storage::IStorageItem>>(this->shim().ItemsToSelect());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::IKnownUserPropertiesStatics> : produce_base<D, Windows::System::IKnownUserPropertiesStatics>
{
    int32_t WINRT_CALL get_DisplayName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DisplayName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FirstName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FirstName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().FirstName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LastName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LastName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().LastName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProviderName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProviderName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ProviderName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AccountName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AccountName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AccountName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_GuestHost(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GuestHost, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().GuestHost());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PrincipalName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PrincipalName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().PrincipalName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DomainName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DomainName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DomainName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SessionInitiationProtocolUri(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SessionInitiationProtocolUri, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SessionInitiationProtocolUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::ILaunchUriResult> : produce_base<D, Windows::System::ILaunchUriResult>
{
    int32_t WINRT_CALL get_Status(Windows::System::LaunchUriStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::System::LaunchUriStatus));
            *value = detach_from<Windows::System::LaunchUriStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Result(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Result, WINRT_WRAP(Windows::Foundation::Collections::ValueSet));
            *value = detach_from<Windows::Foundation::Collections::ValueSet>(this->shim().Result());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::ILauncherOptions> : produce_base<D, Windows::System::ILauncherOptions>
{
    int32_t WINRT_CALL get_TreatAsUntrusted(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TreatAsUntrusted, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().TreatAsUntrusted());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TreatAsUntrusted(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TreatAsUntrusted, WINRT_WRAP(void), bool);
            this->shim().TreatAsUntrusted(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DisplayApplicationPicker(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayApplicationPicker, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().DisplayApplicationPicker());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DisplayApplicationPicker(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayApplicationPicker, WINRT_WRAP(void), bool);
            this->shim().DisplayApplicationPicker(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UI(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UI, WINRT_WRAP(Windows::System::LauncherUIOptions));
            *value = detach_from<Windows::System::LauncherUIOptions>(this->shim().UI());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PreferredApplicationPackageFamilyName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PreferredApplicationPackageFamilyName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().PreferredApplicationPackageFamilyName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PreferredApplicationPackageFamilyName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PreferredApplicationPackageFamilyName, WINRT_WRAP(void), hstring const&);
            this->shim().PreferredApplicationPackageFamilyName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PreferredApplicationDisplayName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PreferredApplicationDisplayName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().PreferredApplicationDisplayName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PreferredApplicationDisplayName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PreferredApplicationDisplayName, WINRT_WRAP(void), hstring const&);
            this->shim().PreferredApplicationDisplayName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FallbackUri(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FallbackUri, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().FallbackUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FallbackUri(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FallbackUri, WINRT_WRAP(void), Windows::Foundation::Uri const&);
            this->shim().FallbackUri(*reinterpret_cast<Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ContentType(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentType, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ContentType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ContentType(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentType, WINRT_WRAP(void), hstring const&);
            this->shim().ContentType(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::ILauncherOptions2> : produce_base<D, Windows::System::ILauncherOptions2>
{
    int32_t WINRT_CALL get_TargetApplicationPackageFamilyName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetApplicationPackageFamilyName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().TargetApplicationPackageFamilyName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TargetApplicationPackageFamilyName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetApplicationPackageFamilyName, WINRT_WRAP(void), hstring const&);
            this->shim().TargetApplicationPackageFamilyName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NeighboringFilesQuery(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NeighboringFilesQuery, WINRT_WRAP(Windows::Storage::Search::StorageFileQueryResult));
            *value = detach_from<Windows::Storage::Search::StorageFileQueryResult>(this->shim().NeighboringFilesQuery());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_NeighboringFilesQuery(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NeighboringFilesQuery, WINRT_WRAP(void), Windows::Storage::Search::StorageFileQueryResult const&);
            this->shim().NeighboringFilesQuery(*reinterpret_cast<Windows::Storage::Search::StorageFileQueryResult const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::ILauncherOptions3> : produce_base<D, Windows::System::ILauncherOptions3>
{
    int32_t WINRT_CALL get_IgnoreAppUriHandlers(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IgnoreAppUriHandlers, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IgnoreAppUriHandlers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IgnoreAppUriHandlers(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IgnoreAppUriHandlers, WINRT_WRAP(void), bool);
            this->shim().IgnoreAppUriHandlers(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::ILauncherOptions4> : produce_base<D, Windows::System::ILauncherOptions4>
{
    int32_t WINRT_CALL get_LimitPickerToCurrentAppAndAppUriHandlers(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LimitPickerToCurrentAppAndAppUriHandlers, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().LimitPickerToCurrentAppAndAppUriHandlers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_LimitPickerToCurrentAppAndAppUriHandlers(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LimitPickerToCurrentAppAndAppUriHandlers, WINRT_WRAP(void), bool);
            this->shim().LimitPickerToCurrentAppAndAppUriHandlers(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::ILauncherStatics> : produce_base<D, Windows::System::ILauncherStatics>
{
    int32_t WINRT_CALL LaunchFileAsync(void* file, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LaunchFileAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::Storage::IStorageFile const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().LaunchFileAsync(*reinterpret_cast<Windows::Storage::IStorageFile const*>(&file)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL LaunchFileWithOptionsAsync(void* file, void* options, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LaunchFileAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::Storage::IStorageFile const, Windows::System::LauncherOptions const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().LaunchFileAsync(*reinterpret_cast<Windows::Storage::IStorageFile const*>(&file), *reinterpret_cast<Windows::System::LauncherOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL LaunchUriAsync(void* uri, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LaunchUriAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::Foundation::Uri const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().LaunchUriAsync(*reinterpret_cast<Windows::Foundation::Uri const*>(&uri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL LaunchUriWithOptionsAsync(void* uri, void* options, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LaunchUriAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::Foundation::Uri const, Windows::System::LauncherOptions const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().LaunchUriAsync(*reinterpret_cast<Windows::Foundation::Uri const*>(&uri), *reinterpret_cast<Windows::System::LauncherOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::ILauncherStatics2> : produce_base<D, Windows::System::ILauncherStatics2>
{
    int32_t WINRT_CALL LaunchUriForResultsAsync(void* uri, void* options, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LaunchUriForResultsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::System::LaunchUriResult>), Windows::Foundation::Uri const, Windows::System::LauncherOptions const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::System::LaunchUriResult>>(this->shim().LaunchUriForResultsAsync(*reinterpret_cast<Windows::Foundation::Uri const*>(&uri), *reinterpret_cast<Windows::System::LauncherOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL LaunchUriForResultsWithDataAsync(void* uri, void* options, void* inputData, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LaunchUriForResultsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::System::LaunchUriResult>), Windows::Foundation::Uri const, Windows::System::LauncherOptions const, Windows::Foundation::Collections::ValueSet const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::System::LaunchUriResult>>(this->shim().LaunchUriForResultsAsync(*reinterpret_cast<Windows::Foundation::Uri const*>(&uri), *reinterpret_cast<Windows::System::LauncherOptions const*>(&options), *reinterpret_cast<Windows::Foundation::Collections::ValueSet const*>(&inputData)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL LaunchUriWithDataAsync(void* uri, void* options, void* inputData, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LaunchUriAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::Foundation::Uri const, Windows::System::LauncherOptions const, Windows::Foundation::Collections::ValueSet const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().LaunchUriAsync(*reinterpret_cast<Windows::Foundation::Uri const*>(&uri), *reinterpret_cast<Windows::System::LauncherOptions const*>(&options), *reinterpret_cast<Windows::Foundation::Collections::ValueSet const*>(&inputData)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL QueryUriSupportAsync(void* uri, Windows::System::LaunchQuerySupportType launchQuerySupportType, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(QueryUriSupportAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::System::LaunchQuerySupportStatus>), Windows::Foundation::Uri const, Windows::System::LaunchQuerySupportType const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::System::LaunchQuerySupportStatus>>(this->shim().QueryUriSupportAsync(*reinterpret_cast<Windows::Foundation::Uri const*>(&uri), *reinterpret_cast<Windows::System::LaunchQuerySupportType const*>(&launchQuerySupportType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL QueryUriSupportWithPackageFamilyNameAsync(void* uri, Windows::System::LaunchQuerySupportType launchQuerySupportType, void* packageFamilyName, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(QueryUriSupportAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::System::LaunchQuerySupportStatus>), Windows::Foundation::Uri const, Windows::System::LaunchQuerySupportType const, hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::System::LaunchQuerySupportStatus>>(this->shim().QueryUriSupportAsync(*reinterpret_cast<Windows::Foundation::Uri const*>(&uri), *reinterpret_cast<Windows::System::LaunchQuerySupportType const*>(&launchQuerySupportType), *reinterpret_cast<hstring const*>(&packageFamilyName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL QueryFileSupportAsync(void* file, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(QueryFileSupportAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::System::LaunchQuerySupportStatus>), Windows::Storage::StorageFile const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::System::LaunchQuerySupportStatus>>(this->shim().QueryFileSupportAsync(*reinterpret_cast<Windows::Storage::StorageFile const*>(&file)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL QueryFileSupportWithPackageFamilyNameAsync(void* file, void* packageFamilyName, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(QueryFileSupportAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::System::LaunchQuerySupportStatus>), Windows::Storage::StorageFile const, hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::System::LaunchQuerySupportStatus>>(this->shim().QueryFileSupportAsync(*reinterpret_cast<Windows::Storage::StorageFile const*>(&file), *reinterpret_cast<hstring const*>(&packageFamilyName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindUriSchemeHandlersAsync(void* scheme, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindUriSchemeHandlersAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::AppInfo>>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::AppInfo>>>(this->shim().FindUriSchemeHandlersAsync(*reinterpret_cast<hstring const*>(&scheme)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindUriSchemeHandlersWithLaunchUriTypeAsync(void* scheme, Windows::System::LaunchQuerySupportType launchQuerySupportType, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindUriSchemeHandlersAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::AppInfo>>), hstring const, Windows::System::LaunchQuerySupportType const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::AppInfo>>>(this->shim().FindUriSchemeHandlersAsync(*reinterpret_cast<hstring const*>(&scheme), *reinterpret_cast<Windows::System::LaunchQuerySupportType const*>(&launchQuerySupportType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindFileHandlersAsync(void* extension, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindFileHandlersAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::AppInfo>>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::AppInfo>>>(this->shim().FindFileHandlersAsync(*reinterpret_cast<hstring const*>(&extension)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::ILauncherStatics3> : produce_base<D, Windows::System::ILauncherStatics3>
{
    int32_t WINRT_CALL LaunchFolderAsync(void* folder, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LaunchFolderAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::Storage::IStorageFolder const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().LaunchFolderAsync(*reinterpret_cast<Windows::Storage::IStorageFolder const*>(&folder)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL LaunchFolderWithOptionsAsync(void* folder, void* options, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LaunchFolderAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::Storage::IStorageFolder const, Windows::System::FolderLauncherOptions const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().LaunchFolderAsync(*reinterpret_cast<Windows::Storage::IStorageFolder const*>(&folder), *reinterpret_cast<Windows::System::FolderLauncherOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::ILauncherStatics4> : produce_base<D, Windows::System::ILauncherStatics4>
{
    int32_t WINRT_CALL QueryAppUriSupportAsync(void* uri, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(QueryAppUriSupportAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::System::LaunchQuerySupportStatus>), Windows::Foundation::Uri const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::System::LaunchQuerySupportStatus>>(this->shim().QueryAppUriSupportAsync(*reinterpret_cast<Windows::Foundation::Uri const*>(&uri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL QueryAppUriSupportWithPackageFamilyNameAsync(void* uri, void* packageFamilyName, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(QueryAppUriSupportAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::System::LaunchQuerySupportStatus>), Windows::Foundation::Uri const, hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::System::LaunchQuerySupportStatus>>(this->shim().QueryAppUriSupportAsync(*reinterpret_cast<Windows::Foundation::Uri const*>(&uri), *reinterpret_cast<hstring const*>(&packageFamilyName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindAppUriHandlersAsync(void* uri, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindAppUriHandlersAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::AppInfo>>), Windows::Foundation::Uri const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::AppInfo>>>(this->shim().FindAppUriHandlersAsync(*reinterpret_cast<Windows::Foundation::Uri const*>(&uri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL LaunchUriForUserAsync(void* user, void* uri, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LaunchUriForUserAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::System::LaunchUriStatus>), Windows::System::User const, Windows::Foundation::Uri const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::System::LaunchUriStatus>>(this->shim().LaunchUriForUserAsync(*reinterpret_cast<Windows::System::User const*>(&user), *reinterpret_cast<Windows::Foundation::Uri const*>(&uri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL LaunchUriWithOptionsForUserAsync(void* user, void* uri, void* options, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LaunchUriForUserAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::System::LaunchUriStatus>), Windows::System::User const, Windows::Foundation::Uri const, Windows::System::LauncherOptions const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::System::LaunchUriStatus>>(this->shim().LaunchUriForUserAsync(*reinterpret_cast<Windows::System::User const*>(&user), *reinterpret_cast<Windows::Foundation::Uri const*>(&uri), *reinterpret_cast<Windows::System::LauncherOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL LaunchUriWithDataForUserAsync(void* user, void* uri, void* options, void* inputData, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LaunchUriForUserAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::System::LaunchUriStatus>), Windows::System::User const, Windows::Foundation::Uri const, Windows::System::LauncherOptions const, Windows::Foundation::Collections::ValueSet const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::System::LaunchUriStatus>>(this->shim().LaunchUriForUserAsync(*reinterpret_cast<Windows::System::User const*>(&user), *reinterpret_cast<Windows::Foundation::Uri const*>(&uri), *reinterpret_cast<Windows::System::LauncherOptions const*>(&options), *reinterpret_cast<Windows::Foundation::Collections::ValueSet const*>(&inputData)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL LaunchUriForResultsForUserAsync(void* user, void* uri, void* options, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LaunchUriForResultsForUserAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::System::LaunchUriResult>), Windows::System::User const, Windows::Foundation::Uri const, Windows::System::LauncherOptions const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::System::LaunchUriResult>>(this->shim().LaunchUriForResultsForUserAsync(*reinterpret_cast<Windows::System::User const*>(&user), *reinterpret_cast<Windows::Foundation::Uri const*>(&uri), *reinterpret_cast<Windows::System::LauncherOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL LaunchUriForResultsWithDataForUserAsync(void* user, void* uri, void* options, void* inputData, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LaunchUriForResultsForUserAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::System::LaunchUriResult>), Windows::System::User const, Windows::Foundation::Uri const, Windows::System::LauncherOptions const, Windows::Foundation::Collections::ValueSet const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::System::LaunchUriResult>>(this->shim().LaunchUriForResultsForUserAsync(*reinterpret_cast<Windows::System::User const*>(&user), *reinterpret_cast<Windows::Foundation::Uri const*>(&uri), *reinterpret_cast<Windows::System::LauncherOptions const*>(&options), *reinterpret_cast<Windows::Foundation::Collections::ValueSet const*>(&inputData)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::ILauncherStatics5> : produce_base<D, Windows::System::ILauncherStatics5>
{
    int32_t WINRT_CALL LaunchFolderPathAsync(void* path, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LaunchFolderPathAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().LaunchFolderPathAsync(*reinterpret_cast<hstring const*>(&path)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL LaunchFolderPathWithOptionsAsync(void* path, void* options, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LaunchFolderPathAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), hstring const, Windows::System::FolderLauncherOptions const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().LaunchFolderPathAsync(*reinterpret_cast<hstring const*>(&path), *reinterpret_cast<Windows::System::FolderLauncherOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL LaunchFolderPathForUserAsync(void* user, void* path, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LaunchFolderPathForUserAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::System::User const, hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().LaunchFolderPathForUserAsync(*reinterpret_cast<Windows::System::User const*>(&user), *reinterpret_cast<hstring const*>(&path)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL LaunchFolderPathWithOptionsForUserAsync(void* user, void* path, void* options, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LaunchFolderPathForUserAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::System::User const, hstring const, Windows::System::FolderLauncherOptions const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().LaunchFolderPathForUserAsync(*reinterpret_cast<Windows::System::User const*>(&user), *reinterpret_cast<hstring const*>(&path), *reinterpret_cast<Windows::System::FolderLauncherOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::ILauncherUIOptions> : produce_base<D, Windows::System::ILauncherUIOptions>
{
    int32_t WINRT_CALL get_InvocationPoint(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InvocationPoint, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::Point>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::Point>>(this->shim().InvocationPoint());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_InvocationPoint(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InvocationPoint, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Foundation::Point> const&);
            this->shim().InvocationPoint(*reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::Point> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SelectionRect(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectionRect, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::Rect>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::Rect>>(this->shim().SelectionRect());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SelectionRect(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectionRect, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Foundation::Rect> const&);
            this->shim().SelectionRect(*reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::Rect> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PreferredPlacement(Windows::UI::Popups::Placement* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PreferredPlacement, WINRT_WRAP(Windows::UI::Popups::Placement));
            *value = detach_from<Windows::UI::Popups::Placement>(this->shim().PreferredPlacement());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PreferredPlacement(Windows::UI::Popups::Placement value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PreferredPlacement, WINRT_WRAP(void), Windows::UI::Popups::Placement const&);
            this->shim().PreferredPlacement(*reinterpret_cast<Windows::UI::Popups::Placement const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::ILauncherViewOptions> : produce_base<D, Windows::System::ILauncherViewOptions>
{
    int32_t WINRT_CALL get_DesiredRemainingView(Windows::UI::ViewManagement::ViewSizePreference* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesiredRemainingView, WINRT_WRAP(Windows::UI::ViewManagement::ViewSizePreference));
            *value = detach_from<Windows::UI::ViewManagement::ViewSizePreference>(this->shim().DesiredRemainingView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DesiredRemainingView(Windows::UI::ViewManagement::ViewSizePreference value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesiredRemainingView, WINRT_WRAP(void), Windows::UI::ViewManagement::ViewSizePreference const&);
            this->shim().DesiredRemainingView(*reinterpret_cast<Windows::UI::ViewManagement::ViewSizePreference const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::IMemoryManagerStatics> : produce_base<D, Windows::System::IMemoryManagerStatics>
{
    int32_t WINRT_CALL get_AppMemoryUsage(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppMemoryUsage, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().AppMemoryUsage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AppMemoryUsageLimit(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppMemoryUsageLimit, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().AppMemoryUsageLimit());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AppMemoryUsageLevel(Windows::System::AppMemoryUsageLevel* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppMemoryUsageLevel, WINRT_WRAP(Windows::System::AppMemoryUsageLevel));
            *value = detach_from<Windows::System::AppMemoryUsageLevel>(this->shim().AppMemoryUsageLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_AppMemoryUsageIncreased(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppMemoryUsageIncreased, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().AppMemoryUsageIncreased(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_AppMemoryUsageIncreased(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(AppMemoryUsageIncreased, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().AppMemoryUsageIncreased(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_AppMemoryUsageDecreased(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppMemoryUsageDecreased, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().AppMemoryUsageDecreased(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_AppMemoryUsageDecreased(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(AppMemoryUsageDecreased, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().AppMemoryUsageDecreased(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_AppMemoryUsageLimitChanging(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppMemoryUsageLimitChanging, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::System::AppMemoryUsageLimitChangingEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().AppMemoryUsageLimitChanging(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::System::AppMemoryUsageLimitChangingEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_AppMemoryUsageLimitChanging(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(AppMemoryUsageLimitChanging, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().AppMemoryUsageLimitChanging(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::System::IMemoryManagerStatics2> : produce_base<D, Windows::System::IMemoryManagerStatics2>
{
    int32_t WINRT_CALL GetAppMemoryReport(void** memoryReport) noexcept final
    {
        try
        {
            *memoryReport = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAppMemoryReport, WINRT_WRAP(Windows::System::AppMemoryReport));
            *memoryReport = detach_from<Windows::System::AppMemoryReport>(this->shim().GetAppMemoryReport());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetProcessMemoryReport(void** memoryReport) noexcept final
    {
        try
        {
            *memoryReport = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetProcessMemoryReport, WINRT_WRAP(Windows::System::ProcessMemoryReport));
            *memoryReport = detach_from<Windows::System::ProcessMemoryReport>(this->shim().GetProcessMemoryReport());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::IMemoryManagerStatics3> : produce_base<D, Windows::System::IMemoryManagerStatics3>
{
    int32_t WINRT_CALL TrySetAppMemoryUsageLimit(uint64_t value, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrySetAppMemoryUsageLimit, WINRT_WRAP(bool), uint64_t);
            *result = detach_from<bool>(this->shim().TrySetAppMemoryUsageLimit(value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::IMemoryManagerStatics4> : produce_base<D, Windows::System::IMemoryManagerStatics4>
{
    int32_t WINRT_CALL get_ExpectedAppMemoryUsageLimit(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExpectedAppMemoryUsageLimit, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().ExpectedAppMemoryUsageLimit());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::IProcessLauncherOptions> : produce_base<D, Windows::System::IProcessLauncherOptions>
{
    int32_t WINRT_CALL get_StandardInput(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StandardInput, WINRT_WRAP(Windows::Storage::Streams::IInputStream));
            *value = detach_from<Windows::Storage::Streams::IInputStream>(this->shim().StandardInput());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_StandardInput(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StandardInput, WINRT_WRAP(void), Windows::Storage::Streams::IInputStream const&);
            this->shim().StandardInput(*reinterpret_cast<Windows::Storage::Streams::IInputStream const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StandardOutput(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StandardOutput, WINRT_WRAP(Windows::Storage::Streams::IOutputStream));
            *value = detach_from<Windows::Storage::Streams::IOutputStream>(this->shim().StandardOutput());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_StandardOutput(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StandardOutput, WINRT_WRAP(void), Windows::Storage::Streams::IOutputStream const&);
            this->shim().StandardOutput(*reinterpret_cast<Windows::Storage::Streams::IOutputStream const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StandardError(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StandardError, WINRT_WRAP(Windows::Storage::Streams::IOutputStream));
            *value = detach_from<Windows::Storage::Streams::IOutputStream>(this->shim().StandardError());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_StandardError(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StandardError, WINRT_WRAP(void), Windows::Storage::Streams::IOutputStream const&);
            this->shim().StandardError(*reinterpret_cast<Windows::Storage::Streams::IOutputStream const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WorkingDirectory(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WorkingDirectory, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().WorkingDirectory());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_WorkingDirectory(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WorkingDirectory, WINRT_WRAP(void), hstring const&);
            this->shim().WorkingDirectory(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::IProcessLauncherResult> : produce_base<D, Windows::System::IProcessLauncherResult>
{
    int32_t WINRT_CALL get_ExitCode(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExitCode, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().ExitCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::IProcessLauncherStatics> : produce_base<D, Windows::System::IProcessLauncherStatics>
{
    int32_t WINRT_CALL RunToCompletionAsync(void* fileName, void* args, void** asyncOperationResult) noexcept final
    {
        try
        {
            *asyncOperationResult = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RunToCompletionAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::System::ProcessLauncherResult>), hstring const, hstring const);
            *asyncOperationResult = detach_from<Windows::Foundation::IAsyncOperation<Windows::System::ProcessLauncherResult>>(this->shim().RunToCompletionAsync(*reinterpret_cast<hstring const*>(&fileName), *reinterpret_cast<hstring const*>(&args)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RunToCompletionAsyncWithOptions(void* fileName, void* args, void* options, void** asyncOperationResult) noexcept final
    {
        try
        {
            *asyncOperationResult = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RunToCompletionAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::System::ProcessLauncherResult>), hstring const, hstring const, Windows::System::ProcessLauncherOptions const);
            *asyncOperationResult = detach_from<Windows::Foundation::IAsyncOperation<Windows::System::ProcessLauncherResult>>(this->shim().RunToCompletionAsync(*reinterpret_cast<hstring const*>(&fileName), *reinterpret_cast<hstring const*>(&args), *reinterpret_cast<Windows::System::ProcessLauncherOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::IProcessMemoryReport> : produce_base<D, Windows::System::IProcessMemoryReport>
{
    int32_t WINRT_CALL get_PrivateWorkingSetUsage(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PrivateWorkingSetUsage, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().PrivateWorkingSetUsage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TotalWorkingSetUsage(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TotalWorkingSetUsage, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().TotalWorkingSetUsage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::IProtocolForResultsOperation> : produce_base<D, Windows::System::IProtocolForResultsOperation>
{
    int32_t WINRT_CALL ReportCompleted(void* data) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportCompleted, WINRT_WRAP(void), Windows::Foundation::Collections::ValueSet const&);
            this->shim().ReportCompleted(*reinterpret_cast<Windows::Foundation::Collections::ValueSet const*>(&data));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::IRemoteLauncherOptions> : produce_base<D, Windows::System::IRemoteLauncherOptions>
{
    int32_t WINRT_CALL get_FallbackUri(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FallbackUri, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().FallbackUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FallbackUri(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FallbackUri, WINRT_WRAP(void), Windows::Foundation::Uri const&);
            this->shim().FallbackUri(*reinterpret_cast<Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PreferredAppIds(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PreferredAppIds, WINRT_WRAP(Windows::Foundation::Collections::IVector<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVector<hstring>>(this->shim().PreferredAppIds());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::IRemoteLauncherStatics> : produce_base<D, Windows::System::IRemoteLauncherStatics>
{
    int32_t WINRT_CALL LaunchUriAsync(void* remoteSystemConnectionRequest, void* uri, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LaunchUriAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::System::RemoteLaunchUriStatus>), Windows::System::RemoteSystems::RemoteSystemConnectionRequest const, Windows::Foundation::Uri const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::System::RemoteLaunchUriStatus>>(this->shim().LaunchUriAsync(*reinterpret_cast<Windows::System::RemoteSystems::RemoteSystemConnectionRequest const*>(&remoteSystemConnectionRequest), *reinterpret_cast<Windows::Foundation::Uri const*>(&uri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL LaunchUriWithOptionsAsync(void* remoteSystemConnectionRequest, void* uri, void* options, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LaunchUriAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::System::RemoteLaunchUriStatus>), Windows::System::RemoteSystems::RemoteSystemConnectionRequest const, Windows::Foundation::Uri const, Windows::System::RemoteLauncherOptions const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::System::RemoteLaunchUriStatus>>(this->shim().LaunchUriAsync(*reinterpret_cast<Windows::System::RemoteSystems::RemoteSystemConnectionRequest const*>(&remoteSystemConnectionRequest), *reinterpret_cast<Windows::Foundation::Uri const*>(&uri), *reinterpret_cast<Windows::System::RemoteLauncherOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL LaunchUriWithDataAsync(void* remoteSystemConnectionRequest, void* uri, void* options, void* inputData, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LaunchUriAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::System::RemoteLaunchUriStatus>), Windows::System::RemoteSystems::RemoteSystemConnectionRequest const, Windows::Foundation::Uri const, Windows::System::RemoteLauncherOptions const, Windows::Foundation::Collections::ValueSet const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::System::RemoteLaunchUriStatus>>(this->shim().LaunchUriAsync(*reinterpret_cast<Windows::System::RemoteSystems::RemoteSystemConnectionRequest const*>(&remoteSystemConnectionRequest), *reinterpret_cast<Windows::Foundation::Uri const*>(&uri), *reinterpret_cast<Windows::System::RemoteLauncherOptions const*>(&options), *reinterpret_cast<Windows::Foundation::Collections::ValueSet const*>(&inputData)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::IShutdownManagerStatics> : produce_base<D, Windows::System::IShutdownManagerStatics>
{
    int32_t WINRT_CALL BeginShutdown(Windows::System::ShutdownKind shutdownKind, Windows::Foundation::TimeSpan timeout) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BeginShutdown, WINRT_WRAP(void), Windows::System::ShutdownKind const&, Windows::Foundation::TimeSpan const&);
            this->shim().BeginShutdown(*reinterpret_cast<Windows::System::ShutdownKind const*>(&shutdownKind), *reinterpret_cast<Windows::Foundation::TimeSpan const*>(&timeout));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CancelShutdown() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CancelShutdown, WINRT_WRAP(void));
            this->shim().CancelShutdown();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::IShutdownManagerStatics2> : produce_base<D, Windows::System::IShutdownManagerStatics2>
{
    int32_t WINRT_CALL IsPowerStateSupported(Windows::System::PowerState powerState, bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsPowerStateSupported, WINRT_WRAP(bool), Windows::System::PowerState const&);
            *value = detach_from<bool>(this->shim().IsPowerStateSupported(*reinterpret_cast<Windows::System::PowerState const*>(&powerState)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL EnterPowerState(Windows::System::PowerState powerState) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnterPowerState, WINRT_WRAP(void), Windows::System::PowerState const&);
            this->shim().EnterPowerState(*reinterpret_cast<Windows::System::PowerState const*>(&powerState));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL EnterPowerStateWithTimeSpan(Windows::System::PowerState powerState, Windows::Foundation::TimeSpan wakeUpAfter) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnterPowerState, WINRT_WRAP(void), Windows::System::PowerState const&, Windows::Foundation::TimeSpan const&);
            this->shim().EnterPowerState(*reinterpret_cast<Windows::System::PowerState const*>(&powerState), *reinterpret_cast<Windows::Foundation::TimeSpan const*>(&wakeUpAfter));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::ITimeZoneSettingsStatics> : produce_base<D, Windows::System::ITimeZoneSettingsStatics>
{
    int32_t WINRT_CALL get_CurrentTimeZoneDisplayName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CurrentTimeZoneDisplayName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().CurrentTimeZoneDisplayName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportedTimeZoneDisplayNames(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedTimeZoneDisplayNames, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().SupportedTimeZoneDisplayNames());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanChangeTimeZone(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanChangeTimeZone, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanChangeTimeZone());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ChangeTimeZoneByDisplayName(void* timeZoneDisplayName) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChangeTimeZoneByDisplayName, WINRT_WRAP(void), hstring const&);
            this->shim().ChangeTimeZoneByDisplayName(*reinterpret_cast<hstring const*>(&timeZoneDisplayName));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::ITimeZoneSettingsStatics2> : produce_base<D, Windows::System::ITimeZoneSettingsStatics2>
{
    int32_t WINRT_CALL AutoUpdateTimeZoneAsync(Windows::Foundation::TimeSpan timeout, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AutoUpdateTimeZoneAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::System::AutoUpdateTimeZoneStatus>), Windows::Foundation::TimeSpan const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::System::AutoUpdateTimeZoneStatus>>(this->shim().AutoUpdateTimeZoneAsync(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&timeout)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::IUser> : produce_base<D, Windows::System::IUser>
{
    int32_t WINRT_CALL get_NonRoamableId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NonRoamableId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().NonRoamableId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AuthenticationStatus(Windows::System::UserAuthenticationStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AuthenticationStatus, WINRT_WRAP(Windows::System::UserAuthenticationStatus));
            *value = detach_from<Windows::System::UserAuthenticationStatus>(this->shim().AuthenticationStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Type(Windows::System::UserType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Type, WINRT_WRAP(Windows::System::UserType));
            *value = detach_from<Windows::System::UserType>(this->shim().Type());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetPropertyAsync(void* value, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetPropertyAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::IInspectable>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::IInspectable>>(this->shim().GetPropertyAsync(*reinterpret_cast<hstring const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetPropertiesAsync(void* values, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetPropertiesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IPropertySet>), Windows::Foundation::Collections::IVectorView<hstring> const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IPropertySet>>(this->shim().GetPropertiesAsync(*reinterpret_cast<Windows::Foundation::Collections::IVectorView<hstring> const*>(&values)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetPictureAsync(Windows::System::UserPictureSize desiredSize, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetPictureAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStreamReference>), Windows::System::UserPictureSize const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStreamReference>>(this->shim().GetPictureAsync(*reinterpret_cast<Windows::System::UserPictureSize const*>(&desiredSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::IUserAuthenticationStatusChangeDeferral> : produce_base<D, Windows::System::IUserAuthenticationStatusChangeDeferral>
{
    int32_t WINRT_CALL Complete() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Complete, WINRT_WRAP(void));
            this->shim().Complete();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::IUserAuthenticationStatusChangingEventArgs> : produce_base<D, Windows::System::IUserAuthenticationStatusChangingEventArgs>
{
    int32_t WINRT_CALL GetDeferral(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeferral, WINRT_WRAP(Windows::System::UserAuthenticationStatusChangeDeferral));
            *result = detach_from<Windows::System::UserAuthenticationStatusChangeDeferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_User(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(User, WINRT_WRAP(Windows::System::User));
            *value = detach_from<Windows::System::User>(this->shim().User());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NewStatus(Windows::System::UserAuthenticationStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NewStatus, WINRT_WRAP(Windows::System::UserAuthenticationStatus));
            *value = detach_from<Windows::System::UserAuthenticationStatus>(this->shim().NewStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CurrentStatus(Windows::System::UserAuthenticationStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CurrentStatus, WINRT_WRAP(Windows::System::UserAuthenticationStatus));
            *value = detach_from<Windows::System::UserAuthenticationStatus>(this->shim().CurrentStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::IUserChangedEventArgs> : produce_base<D, Windows::System::IUserChangedEventArgs>
{
    int32_t WINRT_CALL get_User(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(User, WINRT_WRAP(Windows::System::User));
            *value = detach_from<Windows::System::User>(this->shim().User());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::IUserDeviceAssociationChangedEventArgs> : produce_base<D, Windows::System::IUserDeviceAssociationChangedEventArgs>
{
    int32_t WINRT_CALL get_DeviceId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NewUser(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NewUser, WINRT_WRAP(Windows::System::User));
            *value = detach_from<Windows::System::User>(this->shim().NewUser());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OldUser(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OldUser, WINRT_WRAP(Windows::System::User));
            *value = detach_from<Windows::System::User>(this->shim().OldUser());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::IUserDeviceAssociationStatics> : produce_base<D, Windows::System::IUserDeviceAssociationStatics>
{
    int32_t WINRT_CALL FindUserFromDeviceId(void* deviceId, void** user) noexcept final
    {
        try
        {
            *user = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindUserFromDeviceId, WINRT_WRAP(Windows::System::User), hstring const&);
            *user = detach_from<Windows::System::User>(this->shim().FindUserFromDeviceId(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_UserDeviceAssociationChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UserDeviceAssociationChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::System::UserDeviceAssociationChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().UserDeviceAssociationChanged(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::System::UserDeviceAssociationChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_UserDeviceAssociationChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(UserDeviceAssociationChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().UserDeviceAssociationChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::System::IUserPicker> : produce_base<D, Windows::System::IUserPicker>
{
    int32_t WINRT_CALL get_AllowGuestAccounts(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllowGuestAccounts, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AllowGuestAccounts());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AllowGuestAccounts(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllowGuestAccounts, WINRT_WRAP(void), bool);
            this->shim().AllowGuestAccounts(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SuggestedSelectedUser(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SuggestedSelectedUser, WINRT_WRAP(Windows::System::User));
            *value = detach_from<Windows::System::User>(this->shim().SuggestedSelectedUser());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SuggestedSelectedUser(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SuggestedSelectedUser, WINRT_WRAP(void), Windows::System::User const&);
            this->shim().SuggestedSelectedUser(*reinterpret_cast<Windows::System::User const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PickSingleUserAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PickSingleUserAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::System::User>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::System::User>>(this->shim().PickSingleUserAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::IUserPickerStatics> : produce_base<D, Windows::System::IUserPickerStatics>
{
    int32_t WINRT_CALL IsSupported(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSupported, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().IsSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::IUserStatics> : produce_base<D, Windows::System::IUserStatics>
{
    int32_t WINRT_CALL CreateWatcher(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWatcher, WINRT_WRAP(Windows::System::UserWatcher));
            *result = detach_from<Windows::System::UserWatcher>(this->shim().CreateWatcher());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindAllAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindAllAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::System::User>>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::System::User>>>(this->shim().FindAllAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindAllAsyncByType(Windows::System::UserType type, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindAllAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::System::User>>), Windows::System::UserType const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::System::User>>>(this->shim().FindAllAsync(*reinterpret_cast<Windows::System::UserType const*>(&type)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindAllAsyncByTypeAndStatus(Windows::System::UserType type, Windows::System::UserAuthenticationStatus status, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindAllAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::System::User>>), Windows::System::UserType const, Windows::System::UserAuthenticationStatus const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::System::User>>>(this->shim().FindAllAsync(*reinterpret_cast<Windows::System::UserType const*>(&type), *reinterpret_cast<Windows::System::UserAuthenticationStatus const*>(&status)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetFromId(void* nonRoamableId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetFromId, WINRT_WRAP(Windows::System::User), hstring const&);
            *result = detach_from<Windows::System::User>(this->shim().GetFromId(*reinterpret_cast<hstring const*>(&nonRoamableId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::IUserWatcher> : produce_base<D, Windows::System::IUserWatcher>
{
    int32_t WINRT_CALL get_Status(Windows::System::UserWatcherStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::System::UserWatcherStatus));
            *value = detach_from<Windows::System::UserWatcherStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Start() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Start, WINRT_WRAP(void));
            this->shim().Start();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Stop() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Stop, WINRT_WRAP(void));
            this->shim().Stop();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_Added(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Added, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::System::UserWatcher, Windows::System::UserChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Added(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::System::UserWatcher, Windows::System::UserChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Added(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Added, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Added(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_Removed(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Removed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::System::UserWatcher, Windows::System::UserChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Removed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::System::UserWatcher, Windows::System::UserChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Removed(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Removed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Removed(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_Updated(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Updated, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::System::UserWatcher, Windows::System::UserChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Updated(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::System::UserWatcher, Windows::System::UserChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Updated(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Updated, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Updated(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_AuthenticationStatusChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AuthenticationStatusChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::System::UserWatcher, Windows::System::UserChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().AuthenticationStatusChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::System::UserWatcher, Windows::System::UserChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_AuthenticationStatusChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(AuthenticationStatusChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().AuthenticationStatusChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_AuthenticationStatusChanging(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AuthenticationStatusChanging, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::System::UserWatcher, Windows::System::UserAuthenticationStatusChangingEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().AuthenticationStatusChanging(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::System::UserWatcher, Windows::System::UserAuthenticationStatusChangingEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_AuthenticationStatusChanging(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(AuthenticationStatusChanging, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().AuthenticationStatusChanging(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_EnumerationCompleted(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnumerationCompleted, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::System::UserWatcher, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().EnumerationCompleted(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::System::UserWatcher, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_EnumerationCompleted(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(EnumerationCompleted, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().EnumerationCompleted(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_Stopped(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Stopped, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::System::UserWatcher, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().Stopped(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::System::UserWatcher, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Stopped(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Stopped, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Stopped(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

}

WINRT_EXPORT namespace winrt::Windows::System {

inline Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<Windows::System::AppDiagnosticInfo>> AppDiagnosticInfo::RequestInfoAsync()
{
    return impl::call_factory<AppDiagnosticInfo, Windows::System::IAppDiagnosticInfoStatics>([&](auto&& f) { return f.RequestInfoAsync(); });
}

inline Windows::System::AppDiagnosticInfoWatcher AppDiagnosticInfo::CreateWatcher()
{
    return impl::call_factory<AppDiagnosticInfo, Windows::System::IAppDiagnosticInfoStatics2>([&](auto&& f) { return f.CreateWatcher(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::System::DiagnosticAccessStatus> AppDiagnosticInfo::RequestAccessAsync()
{
    return impl::call_factory<AppDiagnosticInfo, Windows::System::IAppDiagnosticInfoStatics2>([&](auto&& f) { return f.RequestAccessAsync(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<Windows::System::AppDiagnosticInfo>> AppDiagnosticInfo::RequestInfoForPackageAsync(param::hstring const& packageFamilyName)
{
    return impl::call_factory<AppDiagnosticInfo, Windows::System::IAppDiagnosticInfoStatics2>([&](auto&& f) { return f.RequestInfoForPackageAsync(packageFamilyName); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<Windows::System::AppDiagnosticInfo>> AppDiagnosticInfo::RequestInfoForAppAsync()
{
    return impl::call_factory<AppDiagnosticInfo, Windows::System::IAppDiagnosticInfoStatics2>([&](auto&& f) { return f.RequestInfoForAppAsync(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<Windows::System::AppDiagnosticInfo>> AppDiagnosticInfo::RequestInfoForAppAsync(param::hstring const& appUserModelId)
{
    return impl::call_factory<AppDiagnosticInfo, Windows::System::IAppDiagnosticInfoStatics2>([&](auto&& f) { return f.RequestInfoForAppAsync(appUserModelId); });
}

inline AppUriHandlerHost::AppUriHandlerHost() :
    AppUriHandlerHost(impl::call_factory<AppUriHandlerHost>([](auto&& f) { return f.template ActivateInstance<AppUriHandlerHost>(); }))
{}

inline AppUriHandlerHost::AppUriHandlerHost(param::hstring const& name) :
    AppUriHandlerHost(impl::call_factory<AppUriHandlerHost, Windows::System::IAppUriHandlerHostFactory>([&](auto&& f) { return f.CreateInstance(name); }))
{}

inline Windows::System::AppUriHandlerRegistrationManager AppUriHandlerRegistrationManager::GetDefault()
{
    return impl::call_factory<AppUriHandlerRegistrationManager, Windows::System::IAppUriHandlerRegistrationManagerStatics>([&](auto&& f) { return f.GetDefault(); });
}

inline Windows::System::AppUriHandlerRegistrationManager AppUriHandlerRegistrationManager::GetForUser(Windows::System::User const& user)
{
    return impl::call_factory<AppUriHandlerRegistrationManager, Windows::System::IAppUriHandlerRegistrationManagerStatics>([&](auto&& f) { return f.GetForUser(user); });
}

inline void DateTimeSettings::SetSystemDateTime(Windows::Foundation::DateTime const& utcDateTime)
{
    impl::call_factory<DateTimeSettings, Windows::System::IDateTimeSettingsStatics>([&](auto&& f) { return f.SetSystemDateTime(utcDateTime); });
}

inline Windows::System::DispatcherQueue DispatcherQueue::GetForCurrentThread()
{
    return impl::call_factory<DispatcherQueue, Windows::System::IDispatcherQueueStatics>([&](auto&& f) { return f.GetForCurrentThread(); });
}

inline Windows::System::DispatcherQueueController DispatcherQueueController::CreateOnDedicatedThread()
{
    return impl::call_factory<DispatcherQueueController, Windows::System::IDispatcherQueueControllerStatics>([&](auto&& f) { return f.CreateOnDedicatedThread(); });
}

inline FolderLauncherOptions::FolderLauncherOptions() :
    FolderLauncherOptions(impl::call_factory<FolderLauncherOptions>([](auto&& f) { return f.template ActivateInstance<FolderLauncherOptions>(); }))
{}

inline hstring KnownUserProperties::DisplayName()
{
    return impl::call_factory<KnownUserProperties, Windows::System::IKnownUserPropertiesStatics>([&](auto&& f) { return f.DisplayName(); });
}

inline hstring KnownUserProperties::FirstName()
{
    return impl::call_factory<KnownUserProperties, Windows::System::IKnownUserPropertiesStatics>([&](auto&& f) { return f.FirstName(); });
}

inline hstring KnownUserProperties::LastName()
{
    return impl::call_factory<KnownUserProperties, Windows::System::IKnownUserPropertiesStatics>([&](auto&& f) { return f.LastName(); });
}

inline hstring KnownUserProperties::ProviderName()
{
    return impl::call_factory<KnownUserProperties, Windows::System::IKnownUserPropertiesStatics>([&](auto&& f) { return f.ProviderName(); });
}

inline hstring KnownUserProperties::AccountName()
{
    return impl::call_factory<KnownUserProperties, Windows::System::IKnownUserPropertiesStatics>([&](auto&& f) { return f.AccountName(); });
}

inline hstring KnownUserProperties::GuestHost()
{
    return impl::call_factory<KnownUserProperties, Windows::System::IKnownUserPropertiesStatics>([&](auto&& f) { return f.GuestHost(); });
}

inline hstring KnownUserProperties::PrincipalName()
{
    return impl::call_factory<KnownUserProperties, Windows::System::IKnownUserPropertiesStatics>([&](auto&& f) { return f.PrincipalName(); });
}

inline hstring KnownUserProperties::DomainName()
{
    return impl::call_factory<KnownUserProperties, Windows::System::IKnownUserPropertiesStatics>([&](auto&& f) { return f.DomainName(); });
}

inline hstring KnownUserProperties::SessionInitiationProtocolUri()
{
    return impl::call_factory<KnownUserProperties, Windows::System::IKnownUserPropertiesStatics>([&](auto&& f) { return f.SessionInitiationProtocolUri(); });
}

inline Windows::Foundation::IAsyncOperation<bool> Launcher::LaunchFileAsync(Windows::Storage::IStorageFile const& file)
{
    return impl::call_factory<Launcher, Windows::System::ILauncherStatics>([&](auto&& f) { return f.LaunchFileAsync(file); });
}

inline Windows::Foundation::IAsyncOperation<bool> Launcher::LaunchFileAsync(Windows::Storage::IStorageFile const& file, Windows::System::LauncherOptions const& options)
{
    return impl::call_factory<Launcher, Windows::System::ILauncherStatics>([&](auto&& f) { return f.LaunchFileAsync(file, options); });
}

inline Windows::Foundation::IAsyncOperation<bool> Launcher::LaunchUriAsync(Windows::Foundation::Uri const& uri)
{
    return impl::call_factory<Launcher, Windows::System::ILauncherStatics>([&](auto&& f) { return f.LaunchUriAsync(uri); });
}

inline Windows::Foundation::IAsyncOperation<bool> Launcher::LaunchUriAsync(Windows::Foundation::Uri const& uri, Windows::System::LauncherOptions const& options)
{
    return impl::call_factory<Launcher, Windows::System::ILauncherStatics>([&](auto&& f) { return f.LaunchUriAsync(uri, options); });
}

inline Windows::Foundation::IAsyncOperation<Windows::System::LaunchUriResult> Launcher::LaunchUriForResultsAsync(Windows::Foundation::Uri const& uri, Windows::System::LauncherOptions const& options)
{
    return impl::call_factory<Launcher, Windows::System::ILauncherStatics2>([&](auto&& f) { return f.LaunchUriForResultsAsync(uri, options); });
}

inline Windows::Foundation::IAsyncOperation<Windows::System::LaunchUriResult> Launcher::LaunchUriForResultsAsync(Windows::Foundation::Uri const& uri, Windows::System::LauncherOptions const& options, Windows::Foundation::Collections::ValueSet const& inputData)
{
    return impl::call_factory<Launcher, Windows::System::ILauncherStatics2>([&](auto&& f) { return f.LaunchUriForResultsAsync(uri, options, inputData); });
}

inline Windows::Foundation::IAsyncOperation<bool> Launcher::LaunchUriAsync(Windows::Foundation::Uri const& uri, Windows::System::LauncherOptions const& options, Windows::Foundation::Collections::ValueSet const& inputData)
{
    return impl::call_factory<Launcher, Windows::System::ILauncherStatics2>([&](auto&& f) { return f.LaunchUriAsync(uri, options, inputData); });
}

inline Windows::Foundation::IAsyncOperation<Windows::System::LaunchQuerySupportStatus> Launcher::QueryUriSupportAsync(Windows::Foundation::Uri const& uri, Windows::System::LaunchQuerySupportType const& launchQuerySupportType)
{
    return impl::call_factory<Launcher, Windows::System::ILauncherStatics2>([&](auto&& f) { return f.QueryUriSupportAsync(uri, launchQuerySupportType); });
}

inline Windows::Foundation::IAsyncOperation<Windows::System::LaunchQuerySupportStatus> Launcher::QueryUriSupportAsync(Windows::Foundation::Uri const& uri, Windows::System::LaunchQuerySupportType const& launchQuerySupportType, param::hstring const& packageFamilyName)
{
    return impl::call_factory<Launcher, Windows::System::ILauncherStatics2>([&](auto&& f) { return f.QueryUriSupportAsync(uri, launchQuerySupportType, packageFamilyName); });
}

inline Windows::Foundation::IAsyncOperation<Windows::System::LaunchQuerySupportStatus> Launcher::QueryFileSupportAsync(Windows::Storage::StorageFile const& file)
{
    return impl::call_factory<Launcher, Windows::System::ILauncherStatics2>([&](auto&& f) { return f.QueryFileSupportAsync(file); });
}

inline Windows::Foundation::IAsyncOperation<Windows::System::LaunchQuerySupportStatus> Launcher::QueryFileSupportAsync(Windows::Storage::StorageFile const& file, param::hstring const& packageFamilyName)
{
    return impl::call_factory<Launcher, Windows::System::ILauncherStatics2>([&](auto&& f) { return f.QueryFileSupportAsync(file, packageFamilyName); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::AppInfo>> Launcher::FindUriSchemeHandlersAsync(param::hstring const& scheme)
{
    return impl::call_factory<Launcher, Windows::System::ILauncherStatics2>([&](auto&& f) { return f.FindUriSchemeHandlersAsync(scheme); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::AppInfo>> Launcher::FindUriSchemeHandlersAsync(param::hstring const& scheme, Windows::System::LaunchQuerySupportType const& launchQuerySupportType)
{
    return impl::call_factory<Launcher, Windows::System::ILauncherStatics2>([&](auto&& f) { return f.FindUriSchemeHandlersAsync(scheme, launchQuerySupportType); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::AppInfo>> Launcher::FindFileHandlersAsync(param::hstring const& extension)
{
    return impl::call_factory<Launcher, Windows::System::ILauncherStatics2>([&](auto&& f) { return f.FindFileHandlersAsync(extension); });
}

inline Windows::Foundation::IAsyncOperation<bool> Launcher::LaunchFolderAsync(Windows::Storage::IStorageFolder const& folder)
{
    return impl::call_factory<Launcher, Windows::System::ILauncherStatics3>([&](auto&& f) { return f.LaunchFolderAsync(folder); });
}

inline Windows::Foundation::IAsyncOperation<bool> Launcher::LaunchFolderAsync(Windows::Storage::IStorageFolder const& folder, Windows::System::FolderLauncherOptions const& options)
{
    return impl::call_factory<Launcher, Windows::System::ILauncherStatics3>([&](auto&& f) { return f.LaunchFolderAsync(folder, options); });
}

inline Windows::Foundation::IAsyncOperation<Windows::System::LaunchQuerySupportStatus> Launcher::QueryAppUriSupportAsync(Windows::Foundation::Uri const& uri)
{
    return impl::call_factory<Launcher, Windows::System::ILauncherStatics4>([&](auto&& f) { return f.QueryAppUriSupportAsync(uri); });
}

inline Windows::Foundation::IAsyncOperation<Windows::System::LaunchQuerySupportStatus> Launcher::QueryAppUriSupportAsync(Windows::Foundation::Uri const& uri, param::hstring const& packageFamilyName)
{
    return impl::call_factory<Launcher, Windows::System::ILauncherStatics4>([&](auto&& f) { return f.QueryAppUriSupportAsync(uri, packageFamilyName); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::AppInfo>> Launcher::FindAppUriHandlersAsync(Windows::Foundation::Uri const& uri)
{
    return impl::call_factory<Launcher, Windows::System::ILauncherStatics4>([&](auto&& f) { return f.FindAppUriHandlersAsync(uri); });
}

inline Windows::Foundation::IAsyncOperation<Windows::System::LaunchUriStatus> Launcher::LaunchUriForUserAsync(Windows::System::User const& user, Windows::Foundation::Uri const& uri)
{
    return impl::call_factory<Launcher, Windows::System::ILauncherStatics4>([&](auto&& f) { return f.LaunchUriForUserAsync(user, uri); });
}

inline Windows::Foundation::IAsyncOperation<Windows::System::LaunchUriStatus> Launcher::LaunchUriForUserAsync(Windows::System::User const& user, Windows::Foundation::Uri const& uri, Windows::System::LauncherOptions const& options)
{
    return impl::call_factory<Launcher, Windows::System::ILauncherStatics4>([&](auto&& f) { return f.LaunchUriForUserAsync(user, uri, options); });
}

inline Windows::Foundation::IAsyncOperation<Windows::System::LaunchUriStatus> Launcher::LaunchUriForUserAsync(Windows::System::User const& user, Windows::Foundation::Uri const& uri, Windows::System::LauncherOptions const& options, Windows::Foundation::Collections::ValueSet const& inputData)
{
    return impl::call_factory<Launcher, Windows::System::ILauncherStatics4>([&](auto&& f) { return f.LaunchUriForUserAsync(user, uri, options, inputData); });
}

inline Windows::Foundation::IAsyncOperation<Windows::System::LaunchUriResult> Launcher::LaunchUriForResultsForUserAsync(Windows::System::User const& user, Windows::Foundation::Uri const& uri, Windows::System::LauncherOptions const& options)
{
    return impl::call_factory<Launcher, Windows::System::ILauncherStatics4>([&](auto&& f) { return f.LaunchUriForResultsForUserAsync(user, uri, options); });
}

inline Windows::Foundation::IAsyncOperation<Windows::System::LaunchUriResult> Launcher::LaunchUriForResultsForUserAsync(Windows::System::User const& user, Windows::Foundation::Uri const& uri, Windows::System::LauncherOptions const& options, Windows::Foundation::Collections::ValueSet const& inputData)
{
    return impl::call_factory<Launcher, Windows::System::ILauncherStatics4>([&](auto&& f) { return f.LaunchUriForResultsForUserAsync(user, uri, options, inputData); });
}

inline Windows::Foundation::IAsyncOperation<bool> Launcher::LaunchFolderPathAsync(param::hstring const& path)
{
    return impl::call_factory<Launcher, Windows::System::ILauncherStatics5>([&](auto&& f) { return f.LaunchFolderPathAsync(path); });
}

inline Windows::Foundation::IAsyncOperation<bool> Launcher::LaunchFolderPathAsync(param::hstring const& path, Windows::System::FolderLauncherOptions const& options)
{
    return impl::call_factory<Launcher, Windows::System::ILauncherStatics5>([&](auto&& f) { return f.LaunchFolderPathAsync(path, options); });
}

inline Windows::Foundation::IAsyncOperation<bool> Launcher::LaunchFolderPathForUserAsync(Windows::System::User const& user, param::hstring const& path)
{
    return impl::call_factory<Launcher, Windows::System::ILauncherStatics5>([&](auto&& f) { return f.LaunchFolderPathForUserAsync(user, path); });
}

inline Windows::Foundation::IAsyncOperation<bool> Launcher::LaunchFolderPathForUserAsync(Windows::System::User const& user, param::hstring const& path, Windows::System::FolderLauncherOptions const& options)
{
    return impl::call_factory<Launcher, Windows::System::ILauncherStatics5>([&](auto&& f) { return f.LaunchFolderPathForUserAsync(user, path, options); });
}

inline LauncherOptions::LauncherOptions() :
    LauncherOptions(impl::call_factory<LauncherOptions>([](auto&& f) { return f.template ActivateInstance<LauncherOptions>(); }))
{}

inline uint64_t MemoryManager::AppMemoryUsage()
{
    return impl::call_factory<MemoryManager, Windows::System::IMemoryManagerStatics>([&](auto&& f) { return f.AppMemoryUsage(); });
}

inline uint64_t MemoryManager::AppMemoryUsageLimit()
{
    return impl::call_factory<MemoryManager, Windows::System::IMemoryManagerStatics>([&](auto&& f) { return f.AppMemoryUsageLimit(); });
}

inline Windows::System::AppMemoryUsageLevel MemoryManager::AppMemoryUsageLevel()
{
    return impl::call_factory<MemoryManager, Windows::System::IMemoryManagerStatics>([&](auto&& f) { return f.AppMemoryUsageLevel(); });
}

inline winrt::event_token MemoryManager::AppMemoryUsageIncreased(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    return impl::call_factory<MemoryManager, Windows::System::IMemoryManagerStatics>([&](auto&& f) { return f.AppMemoryUsageIncreased(handler); });
}

inline MemoryManager::AppMemoryUsageIncreased_revoker MemoryManager::AppMemoryUsageIncreased(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    auto f = get_activation_factory<MemoryManager, Windows::System::IMemoryManagerStatics>();
    return { f, f.AppMemoryUsageIncreased(handler) };
}

inline void MemoryManager::AppMemoryUsageIncreased(winrt::event_token const& token)
{
    impl::call_factory<MemoryManager, Windows::System::IMemoryManagerStatics>([&](auto&& f) { return f.AppMemoryUsageIncreased(token); });
}

inline winrt::event_token MemoryManager::AppMemoryUsageDecreased(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    return impl::call_factory<MemoryManager, Windows::System::IMemoryManagerStatics>([&](auto&& f) { return f.AppMemoryUsageDecreased(handler); });
}

inline MemoryManager::AppMemoryUsageDecreased_revoker MemoryManager::AppMemoryUsageDecreased(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    auto f = get_activation_factory<MemoryManager, Windows::System::IMemoryManagerStatics>();
    return { f, f.AppMemoryUsageDecreased(handler) };
}

inline void MemoryManager::AppMemoryUsageDecreased(winrt::event_token const& token)
{
    impl::call_factory<MemoryManager, Windows::System::IMemoryManagerStatics>([&](auto&& f) { return f.AppMemoryUsageDecreased(token); });
}

inline winrt::event_token MemoryManager::AppMemoryUsageLimitChanging(Windows::Foundation::EventHandler<Windows::System::AppMemoryUsageLimitChangingEventArgs> const& handler)
{
    return impl::call_factory<MemoryManager, Windows::System::IMemoryManagerStatics>([&](auto&& f) { return f.AppMemoryUsageLimitChanging(handler); });
}

inline MemoryManager::AppMemoryUsageLimitChanging_revoker MemoryManager::AppMemoryUsageLimitChanging(auto_revoke_t, Windows::Foundation::EventHandler<Windows::System::AppMemoryUsageLimitChangingEventArgs> const& handler)
{
    auto f = get_activation_factory<MemoryManager, Windows::System::IMemoryManagerStatics>();
    return { f, f.AppMemoryUsageLimitChanging(handler) };
}

inline void MemoryManager::AppMemoryUsageLimitChanging(winrt::event_token const& token)
{
    impl::call_factory<MemoryManager, Windows::System::IMemoryManagerStatics>([&](auto&& f) { return f.AppMemoryUsageLimitChanging(token); });
}

inline Windows::System::AppMemoryReport MemoryManager::GetAppMemoryReport()
{
    return impl::call_factory<MemoryManager, Windows::System::IMemoryManagerStatics2>([&](auto&& f) { return f.GetAppMemoryReport(); });
}

inline Windows::System::ProcessMemoryReport MemoryManager::GetProcessMemoryReport()
{
    return impl::call_factory<MemoryManager, Windows::System::IMemoryManagerStatics2>([&](auto&& f) { return f.GetProcessMemoryReport(); });
}

inline bool MemoryManager::TrySetAppMemoryUsageLimit(uint64_t value)
{
    return impl::call_factory<MemoryManager, Windows::System::IMemoryManagerStatics3>([&](auto&& f) { return f.TrySetAppMemoryUsageLimit(value); });
}

inline uint64_t MemoryManager::ExpectedAppMemoryUsageLimit()
{
    return impl::call_factory<MemoryManager, Windows::System::IMemoryManagerStatics4>([&](auto&& f) { return f.ExpectedAppMemoryUsageLimit(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::System::ProcessLauncherResult> ProcessLauncher::RunToCompletionAsync(param::hstring const& fileName, param::hstring const& args)
{
    return impl::call_factory<ProcessLauncher, Windows::System::IProcessLauncherStatics>([&](auto&& f) { return f.RunToCompletionAsync(fileName, args); });
}

inline Windows::Foundation::IAsyncOperation<Windows::System::ProcessLauncherResult> ProcessLauncher::RunToCompletionAsync(param::hstring const& fileName, param::hstring const& args, Windows::System::ProcessLauncherOptions const& options)
{
    return impl::call_factory<ProcessLauncher, Windows::System::IProcessLauncherStatics>([&](auto&& f) { return f.RunToCompletionAsync(fileName, args, options); });
}

inline ProcessLauncherOptions::ProcessLauncherOptions() :
    ProcessLauncherOptions(impl::call_factory<ProcessLauncherOptions>([](auto&& f) { return f.template ActivateInstance<ProcessLauncherOptions>(); }))
{}

inline Windows::Foundation::IAsyncOperation<Windows::System::RemoteLaunchUriStatus> RemoteLauncher::LaunchUriAsync(Windows::System::RemoteSystems::RemoteSystemConnectionRequest const& remoteSystemConnectionRequest, Windows::Foundation::Uri const& uri)
{
    return impl::call_factory<RemoteLauncher, Windows::System::IRemoteLauncherStatics>([&](auto&& f) { return f.LaunchUriAsync(remoteSystemConnectionRequest, uri); });
}

inline Windows::Foundation::IAsyncOperation<Windows::System::RemoteLaunchUriStatus> RemoteLauncher::LaunchUriAsync(Windows::System::RemoteSystems::RemoteSystemConnectionRequest const& remoteSystemConnectionRequest, Windows::Foundation::Uri const& uri, Windows::System::RemoteLauncherOptions const& options)
{
    return impl::call_factory<RemoteLauncher, Windows::System::IRemoteLauncherStatics>([&](auto&& f) { return f.LaunchUriAsync(remoteSystemConnectionRequest, uri, options); });
}

inline Windows::Foundation::IAsyncOperation<Windows::System::RemoteLaunchUriStatus> RemoteLauncher::LaunchUriAsync(Windows::System::RemoteSystems::RemoteSystemConnectionRequest const& remoteSystemConnectionRequest, Windows::Foundation::Uri const& uri, Windows::System::RemoteLauncherOptions const& options, Windows::Foundation::Collections::ValueSet const& inputData)
{
    return impl::call_factory<RemoteLauncher, Windows::System::IRemoteLauncherStatics>([&](auto&& f) { return f.LaunchUriAsync(remoteSystemConnectionRequest, uri, options, inputData); });
}

inline RemoteLauncherOptions::RemoteLauncherOptions() :
    RemoteLauncherOptions(impl::call_factory<RemoteLauncherOptions>([](auto&& f) { return f.template ActivateInstance<RemoteLauncherOptions>(); }))
{}

inline void ShutdownManager::BeginShutdown(Windows::System::ShutdownKind const& shutdownKind, Windows::Foundation::TimeSpan const& timeout)
{
    impl::call_factory<ShutdownManager, Windows::System::IShutdownManagerStatics>([&](auto&& f) { return f.BeginShutdown(shutdownKind, timeout); });
}

inline void ShutdownManager::CancelShutdown()
{
    impl::call_factory<ShutdownManager, Windows::System::IShutdownManagerStatics>([&](auto&& f) { return f.CancelShutdown(); });
}

inline bool ShutdownManager::IsPowerStateSupported(Windows::System::PowerState const& powerState)
{
    return impl::call_factory<ShutdownManager, Windows::System::IShutdownManagerStatics2>([&](auto&& f) { return f.IsPowerStateSupported(powerState); });
}

inline void ShutdownManager::EnterPowerState(Windows::System::PowerState const& powerState)
{
    impl::call_factory<ShutdownManager, Windows::System::IShutdownManagerStatics2>([&](auto&& f) { return f.EnterPowerState(powerState); });
}

inline void ShutdownManager::EnterPowerState(Windows::System::PowerState const& powerState, Windows::Foundation::TimeSpan const& wakeUpAfter)
{
    impl::call_factory<ShutdownManager, Windows::System::IShutdownManagerStatics2>([&](auto&& f) { return f.EnterPowerState(powerState, wakeUpAfter); });
}

inline hstring TimeZoneSettings::CurrentTimeZoneDisplayName()
{
    return impl::call_factory<TimeZoneSettings, Windows::System::ITimeZoneSettingsStatics>([&](auto&& f) { return f.CurrentTimeZoneDisplayName(); });
}

inline Windows::Foundation::Collections::IVectorView<hstring> TimeZoneSettings::SupportedTimeZoneDisplayNames()
{
    return impl::call_factory<TimeZoneSettings, Windows::System::ITimeZoneSettingsStatics>([&](auto&& f) { return f.SupportedTimeZoneDisplayNames(); });
}

inline bool TimeZoneSettings::CanChangeTimeZone()
{
    return impl::call_factory<TimeZoneSettings, Windows::System::ITimeZoneSettingsStatics>([&](auto&& f) { return f.CanChangeTimeZone(); });
}

inline void TimeZoneSettings::ChangeTimeZoneByDisplayName(param::hstring const& timeZoneDisplayName)
{
    impl::call_factory<TimeZoneSettings, Windows::System::ITimeZoneSettingsStatics>([&](auto&& f) { return f.ChangeTimeZoneByDisplayName(timeZoneDisplayName); });
}

inline Windows::Foundation::IAsyncOperation<Windows::System::AutoUpdateTimeZoneStatus> TimeZoneSettings::AutoUpdateTimeZoneAsync(Windows::Foundation::TimeSpan const& timeout)
{
    return impl::call_factory<TimeZoneSettings, Windows::System::ITimeZoneSettingsStatics2>([&](auto&& f) { return f.AutoUpdateTimeZoneAsync(timeout); });
}

inline Windows::System::UserWatcher User::CreateWatcher()
{
    return impl::call_factory<User, Windows::System::IUserStatics>([&](auto&& f) { return f.CreateWatcher(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::System::User>> User::FindAllAsync()
{
    return impl::call_factory<User, Windows::System::IUserStatics>([&](auto&& f) { return f.FindAllAsync(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::System::User>> User::FindAllAsync(Windows::System::UserType const& type)
{
    return impl::call_factory<User, Windows::System::IUserStatics>([&](auto&& f) { return f.FindAllAsync(type); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::System::User>> User::FindAllAsync(Windows::System::UserType const& type, Windows::System::UserAuthenticationStatus const& status)
{
    return impl::call_factory<User, Windows::System::IUserStatics>([&](auto&& f) { return f.FindAllAsync(type, status); });
}

inline Windows::System::User User::GetFromId(param::hstring const& nonRoamableId)
{
    return impl::call_factory<User, Windows::System::IUserStatics>([&](auto&& f) { return f.GetFromId(nonRoamableId); });
}

inline Windows::System::User UserDeviceAssociation::FindUserFromDeviceId(param::hstring const& deviceId)
{
    return impl::call_factory<UserDeviceAssociation, Windows::System::IUserDeviceAssociationStatics>([&](auto&& f) { return f.FindUserFromDeviceId(deviceId); });
}

inline winrt::event_token UserDeviceAssociation::UserDeviceAssociationChanged(Windows::Foundation::EventHandler<Windows::System::UserDeviceAssociationChangedEventArgs> const& handler)
{
    return impl::call_factory<UserDeviceAssociation, Windows::System::IUserDeviceAssociationStatics>([&](auto&& f) { return f.UserDeviceAssociationChanged(handler); });
}

inline UserDeviceAssociation::UserDeviceAssociationChanged_revoker UserDeviceAssociation::UserDeviceAssociationChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::System::UserDeviceAssociationChangedEventArgs> const& handler)
{
    auto f = get_activation_factory<UserDeviceAssociation, Windows::System::IUserDeviceAssociationStatics>();
    return { f, f.UserDeviceAssociationChanged(handler) };
}

inline void UserDeviceAssociation::UserDeviceAssociationChanged(winrt::event_token const& token)
{
    impl::call_factory<UserDeviceAssociation, Windows::System::IUserDeviceAssociationStatics>([&](auto&& f) { return f.UserDeviceAssociationChanged(token); });
}

inline UserPicker::UserPicker() :
    UserPicker(impl::call_factory<UserPicker>([](auto&& f) { return f.template ActivateInstance<UserPicker>(); }))
{}

inline bool UserPicker::IsSupported()
{
    return impl::call_factory<UserPicker, Windows::System::IUserPickerStatics>([&](auto&& f) { return f.IsSupported(); });
}

template <typename L> DispatcherQueueHandler::DispatcherQueueHandler(L handler) :
    DispatcherQueueHandler(impl::make_delegate<DispatcherQueueHandler>(std::forward<L>(handler)))
{}

template <typename F> DispatcherQueueHandler::DispatcherQueueHandler(F* handler) :
    DispatcherQueueHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> DispatcherQueueHandler::DispatcherQueueHandler(O* object, M method) :
    DispatcherQueueHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> DispatcherQueueHandler::DispatcherQueueHandler(com_ptr<O>&& object, M method) :
    DispatcherQueueHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> DispatcherQueueHandler::DispatcherQueueHandler(weak_ref<O>&& object, M method) :
    DispatcherQueueHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void DispatcherQueueHandler::operator()() const
{
    check_hresult((*(impl::abi_t<DispatcherQueueHandler>**)this)->Invoke());
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::System::IAppActivationResult> : winrt::impl::hash_base<winrt::Windows::System::IAppActivationResult> {};
template<> struct hash<winrt::Windows::System::IAppDiagnosticInfo> : winrt::impl::hash_base<winrt::Windows::System::IAppDiagnosticInfo> {};
template<> struct hash<winrt::Windows::System::IAppDiagnosticInfo2> : winrt::impl::hash_base<winrt::Windows::System::IAppDiagnosticInfo2> {};
template<> struct hash<winrt::Windows::System::IAppDiagnosticInfo3> : winrt::impl::hash_base<winrt::Windows::System::IAppDiagnosticInfo3> {};
template<> struct hash<winrt::Windows::System::IAppDiagnosticInfoStatics> : winrt::impl::hash_base<winrt::Windows::System::IAppDiagnosticInfoStatics> {};
template<> struct hash<winrt::Windows::System::IAppDiagnosticInfoStatics2> : winrt::impl::hash_base<winrt::Windows::System::IAppDiagnosticInfoStatics2> {};
template<> struct hash<winrt::Windows::System::IAppDiagnosticInfoWatcher> : winrt::impl::hash_base<winrt::Windows::System::IAppDiagnosticInfoWatcher> {};
template<> struct hash<winrt::Windows::System::IAppDiagnosticInfoWatcherEventArgs> : winrt::impl::hash_base<winrt::Windows::System::IAppDiagnosticInfoWatcherEventArgs> {};
template<> struct hash<winrt::Windows::System::IAppExecutionStateChangeResult> : winrt::impl::hash_base<winrt::Windows::System::IAppExecutionStateChangeResult> {};
template<> struct hash<winrt::Windows::System::IAppMemoryReport> : winrt::impl::hash_base<winrt::Windows::System::IAppMemoryReport> {};
template<> struct hash<winrt::Windows::System::IAppMemoryReport2> : winrt::impl::hash_base<winrt::Windows::System::IAppMemoryReport2> {};
template<> struct hash<winrt::Windows::System::IAppMemoryUsageLimitChangingEventArgs> : winrt::impl::hash_base<winrt::Windows::System::IAppMemoryUsageLimitChangingEventArgs> {};
template<> struct hash<winrt::Windows::System::IAppResourceGroupBackgroundTaskReport> : winrt::impl::hash_base<winrt::Windows::System::IAppResourceGroupBackgroundTaskReport> {};
template<> struct hash<winrt::Windows::System::IAppResourceGroupInfo> : winrt::impl::hash_base<winrt::Windows::System::IAppResourceGroupInfo> {};
template<> struct hash<winrt::Windows::System::IAppResourceGroupInfo2> : winrt::impl::hash_base<winrt::Windows::System::IAppResourceGroupInfo2> {};
template<> struct hash<winrt::Windows::System::IAppResourceGroupInfoWatcher> : winrt::impl::hash_base<winrt::Windows::System::IAppResourceGroupInfoWatcher> {};
template<> struct hash<winrt::Windows::System::IAppResourceGroupInfoWatcherEventArgs> : winrt::impl::hash_base<winrt::Windows::System::IAppResourceGroupInfoWatcherEventArgs> {};
template<> struct hash<winrt::Windows::System::IAppResourceGroupInfoWatcherExecutionStateChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::System::IAppResourceGroupInfoWatcherExecutionStateChangedEventArgs> {};
template<> struct hash<winrt::Windows::System::IAppResourceGroupMemoryReport> : winrt::impl::hash_base<winrt::Windows::System::IAppResourceGroupMemoryReport> {};
template<> struct hash<winrt::Windows::System::IAppResourceGroupStateReport> : winrt::impl::hash_base<winrt::Windows::System::IAppResourceGroupStateReport> {};
template<> struct hash<winrt::Windows::System::IAppUriHandlerHost> : winrt::impl::hash_base<winrt::Windows::System::IAppUriHandlerHost> {};
template<> struct hash<winrt::Windows::System::IAppUriHandlerHostFactory> : winrt::impl::hash_base<winrt::Windows::System::IAppUriHandlerHostFactory> {};
template<> struct hash<winrt::Windows::System::IAppUriHandlerRegistration> : winrt::impl::hash_base<winrt::Windows::System::IAppUriHandlerRegistration> {};
template<> struct hash<winrt::Windows::System::IAppUriHandlerRegistrationManager> : winrt::impl::hash_base<winrt::Windows::System::IAppUriHandlerRegistrationManager> {};
template<> struct hash<winrt::Windows::System::IAppUriHandlerRegistrationManagerStatics> : winrt::impl::hash_base<winrt::Windows::System::IAppUriHandlerRegistrationManagerStatics> {};
template<> struct hash<winrt::Windows::System::IDateTimeSettingsStatics> : winrt::impl::hash_base<winrt::Windows::System::IDateTimeSettingsStatics> {};
template<> struct hash<winrt::Windows::System::IDispatcherQueue> : winrt::impl::hash_base<winrt::Windows::System::IDispatcherQueue> {};
template<> struct hash<winrt::Windows::System::IDispatcherQueue2> : winrt::impl::hash_base<winrt::Windows::System::IDispatcherQueue2> {};
template<> struct hash<winrt::Windows::System::IDispatcherQueueController> : winrt::impl::hash_base<winrt::Windows::System::IDispatcherQueueController> {};
template<> struct hash<winrt::Windows::System::IDispatcherQueueControllerStatics> : winrt::impl::hash_base<winrt::Windows::System::IDispatcherQueueControllerStatics> {};
template<> struct hash<winrt::Windows::System::IDispatcherQueueShutdownStartingEventArgs> : winrt::impl::hash_base<winrt::Windows::System::IDispatcherQueueShutdownStartingEventArgs> {};
template<> struct hash<winrt::Windows::System::IDispatcherQueueStatics> : winrt::impl::hash_base<winrt::Windows::System::IDispatcherQueueStatics> {};
template<> struct hash<winrt::Windows::System::IDispatcherQueueTimer> : winrt::impl::hash_base<winrt::Windows::System::IDispatcherQueueTimer> {};
template<> struct hash<winrt::Windows::System::IFolderLauncherOptions> : winrt::impl::hash_base<winrt::Windows::System::IFolderLauncherOptions> {};
template<> struct hash<winrt::Windows::System::IKnownUserPropertiesStatics> : winrt::impl::hash_base<winrt::Windows::System::IKnownUserPropertiesStatics> {};
template<> struct hash<winrt::Windows::System::ILaunchUriResult> : winrt::impl::hash_base<winrt::Windows::System::ILaunchUriResult> {};
template<> struct hash<winrt::Windows::System::ILauncherOptions> : winrt::impl::hash_base<winrt::Windows::System::ILauncherOptions> {};
template<> struct hash<winrt::Windows::System::ILauncherOptions2> : winrt::impl::hash_base<winrt::Windows::System::ILauncherOptions2> {};
template<> struct hash<winrt::Windows::System::ILauncherOptions3> : winrt::impl::hash_base<winrt::Windows::System::ILauncherOptions3> {};
template<> struct hash<winrt::Windows::System::ILauncherOptions4> : winrt::impl::hash_base<winrt::Windows::System::ILauncherOptions4> {};
template<> struct hash<winrt::Windows::System::ILauncherStatics> : winrt::impl::hash_base<winrt::Windows::System::ILauncherStatics> {};
template<> struct hash<winrt::Windows::System::ILauncherStatics2> : winrt::impl::hash_base<winrt::Windows::System::ILauncherStatics2> {};
template<> struct hash<winrt::Windows::System::ILauncherStatics3> : winrt::impl::hash_base<winrt::Windows::System::ILauncherStatics3> {};
template<> struct hash<winrt::Windows::System::ILauncherStatics4> : winrt::impl::hash_base<winrt::Windows::System::ILauncherStatics4> {};
template<> struct hash<winrt::Windows::System::ILauncherStatics5> : winrt::impl::hash_base<winrt::Windows::System::ILauncherStatics5> {};
template<> struct hash<winrt::Windows::System::ILauncherUIOptions> : winrt::impl::hash_base<winrt::Windows::System::ILauncherUIOptions> {};
template<> struct hash<winrt::Windows::System::ILauncherViewOptions> : winrt::impl::hash_base<winrt::Windows::System::ILauncherViewOptions> {};
template<> struct hash<winrt::Windows::System::IMemoryManagerStatics> : winrt::impl::hash_base<winrt::Windows::System::IMemoryManagerStatics> {};
template<> struct hash<winrt::Windows::System::IMemoryManagerStatics2> : winrt::impl::hash_base<winrt::Windows::System::IMemoryManagerStatics2> {};
template<> struct hash<winrt::Windows::System::IMemoryManagerStatics3> : winrt::impl::hash_base<winrt::Windows::System::IMemoryManagerStatics3> {};
template<> struct hash<winrt::Windows::System::IMemoryManagerStatics4> : winrt::impl::hash_base<winrt::Windows::System::IMemoryManagerStatics4> {};
template<> struct hash<winrt::Windows::System::IProcessLauncherOptions> : winrt::impl::hash_base<winrt::Windows::System::IProcessLauncherOptions> {};
template<> struct hash<winrt::Windows::System::IProcessLauncherResult> : winrt::impl::hash_base<winrt::Windows::System::IProcessLauncherResult> {};
template<> struct hash<winrt::Windows::System::IProcessLauncherStatics> : winrt::impl::hash_base<winrt::Windows::System::IProcessLauncherStatics> {};
template<> struct hash<winrt::Windows::System::IProcessMemoryReport> : winrt::impl::hash_base<winrt::Windows::System::IProcessMemoryReport> {};
template<> struct hash<winrt::Windows::System::IProtocolForResultsOperation> : winrt::impl::hash_base<winrt::Windows::System::IProtocolForResultsOperation> {};
template<> struct hash<winrt::Windows::System::IRemoteLauncherOptions> : winrt::impl::hash_base<winrt::Windows::System::IRemoteLauncherOptions> {};
template<> struct hash<winrt::Windows::System::IRemoteLauncherStatics> : winrt::impl::hash_base<winrt::Windows::System::IRemoteLauncherStatics> {};
template<> struct hash<winrt::Windows::System::IShutdownManagerStatics> : winrt::impl::hash_base<winrt::Windows::System::IShutdownManagerStatics> {};
template<> struct hash<winrt::Windows::System::IShutdownManagerStatics2> : winrt::impl::hash_base<winrt::Windows::System::IShutdownManagerStatics2> {};
template<> struct hash<winrt::Windows::System::ITimeZoneSettingsStatics> : winrt::impl::hash_base<winrt::Windows::System::ITimeZoneSettingsStatics> {};
template<> struct hash<winrt::Windows::System::ITimeZoneSettingsStatics2> : winrt::impl::hash_base<winrt::Windows::System::ITimeZoneSettingsStatics2> {};
template<> struct hash<winrt::Windows::System::IUser> : winrt::impl::hash_base<winrt::Windows::System::IUser> {};
template<> struct hash<winrt::Windows::System::IUserAuthenticationStatusChangeDeferral> : winrt::impl::hash_base<winrt::Windows::System::IUserAuthenticationStatusChangeDeferral> {};
template<> struct hash<winrt::Windows::System::IUserAuthenticationStatusChangingEventArgs> : winrt::impl::hash_base<winrt::Windows::System::IUserAuthenticationStatusChangingEventArgs> {};
template<> struct hash<winrt::Windows::System::IUserChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::System::IUserChangedEventArgs> {};
template<> struct hash<winrt::Windows::System::IUserDeviceAssociationChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::System::IUserDeviceAssociationChangedEventArgs> {};
template<> struct hash<winrt::Windows::System::IUserDeviceAssociationStatics> : winrt::impl::hash_base<winrt::Windows::System::IUserDeviceAssociationStatics> {};
template<> struct hash<winrt::Windows::System::IUserPicker> : winrt::impl::hash_base<winrt::Windows::System::IUserPicker> {};
template<> struct hash<winrt::Windows::System::IUserPickerStatics> : winrt::impl::hash_base<winrt::Windows::System::IUserPickerStatics> {};
template<> struct hash<winrt::Windows::System::IUserStatics> : winrt::impl::hash_base<winrt::Windows::System::IUserStatics> {};
template<> struct hash<winrt::Windows::System::IUserWatcher> : winrt::impl::hash_base<winrt::Windows::System::IUserWatcher> {};
template<> struct hash<winrt::Windows::System::AppActivationResult> : winrt::impl::hash_base<winrt::Windows::System::AppActivationResult> {};
template<> struct hash<winrt::Windows::System::AppDiagnosticInfo> : winrt::impl::hash_base<winrt::Windows::System::AppDiagnosticInfo> {};
template<> struct hash<winrt::Windows::System::AppDiagnosticInfoWatcher> : winrt::impl::hash_base<winrt::Windows::System::AppDiagnosticInfoWatcher> {};
template<> struct hash<winrt::Windows::System::AppDiagnosticInfoWatcherEventArgs> : winrt::impl::hash_base<winrt::Windows::System::AppDiagnosticInfoWatcherEventArgs> {};
template<> struct hash<winrt::Windows::System::AppExecutionStateChangeResult> : winrt::impl::hash_base<winrt::Windows::System::AppExecutionStateChangeResult> {};
template<> struct hash<winrt::Windows::System::AppMemoryReport> : winrt::impl::hash_base<winrt::Windows::System::AppMemoryReport> {};
template<> struct hash<winrt::Windows::System::AppMemoryUsageLimitChangingEventArgs> : winrt::impl::hash_base<winrt::Windows::System::AppMemoryUsageLimitChangingEventArgs> {};
template<> struct hash<winrt::Windows::System::AppResourceGroupBackgroundTaskReport> : winrt::impl::hash_base<winrt::Windows::System::AppResourceGroupBackgroundTaskReport> {};
template<> struct hash<winrt::Windows::System::AppResourceGroupInfo> : winrt::impl::hash_base<winrt::Windows::System::AppResourceGroupInfo> {};
template<> struct hash<winrt::Windows::System::AppResourceGroupInfoWatcher> : winrt::impl::hash_base<winrt::Windows::System::AppResourceGroupInfoWatcher> {};
template<> struct hash<winrt::Windows::System::AppResourceGroupInfoWatcherEventArgs> : winrt::impl::hash_base<winrt::Windows::System::AppResourceGroupInfoWatcherEventArgs> {};
template<> struct hash<winrt::Windows::System::AppResourceGroupInfoWatcherExecutionStateChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::System::AppResourceGroupInfoWatcherExecutionStateChangedEventArgs> {};
template<> struct hash<winrt::Windows::System::AppResourceGroupMemoryReport> : winrt::impl::hash_base<winrt::Windows::System::AppResourceGroupMemoryReport> {};
template<> struct hash<winrt::Windows::System::AppResourceGroupStateReport> : winrt::impl::hash_base<winrt::Windows::System::AppResourceGroupStateReport> {};
template<> struct hash<winrt::Windows::System::AppUriHandlerHost> : winrt::impl::hash_base<winrt::Windows::System::AppUriHandlerHost> {};
template<> struct hash<winrt::Windows::System::AppUriHandlerRegistration> : winrt::impl::hash_base<winrt::Windows::System::AppUriHandlerRegistration> {};
template<> struct hash<winrt::Windows::System::AppUriHandlerRegistrationManager> : winrt::impl::hash_base<winrt::Windows::System::AppUriHandlerRegistrationManager> {};
template<> struct hash<winrt::Windows::System::DateTimeSettings> : winrt::impl::hash_base<winrt::Windows::System::DateTimeSettings> {};
template<> struct hash<winrt::Windows::System::DispatcherQueue> : winrt::impl::hash_base<winrt::Windows::System::DispatcherQueue> {};
template<> struct hash<winrt::Windows::System::DispatcherQueueController> : winrt::impl::hash_base<winrt::Windows::System::DispatcherQueueController> {};
template<> struct hash<winrt::Windows::System::DispatcherQueueShutdownStartingEventArgs> : winrt::impl::hash_base<winrt::Windows::System::DispatcherQueueShutdownStartingEventArgs> {};
template<> struct hash<winrt::Windows::System::DispatcherQueueTimer> : winrt::impl::hash_base<winrt::Windows::System::DispatcherQueueTimer> {};
template<> struct hash<winrt::Windows::System::FolderLauncherOptions> : winrt::impl::hash_base<winrt::Windows::System::FolderLauncherOptions> {};
template<> struct hash<winrt::Windows::System::KnownUserProperties> : winrt::impl::hash_base<winrt::Windows::System::KnownUserProperties> {};
template<> struct hash<winrt::Windows::System::LaunchUriResult> : winrt::impl::hash_base<winrt::Windows::System::LaunchUriResult> {};
template<> struct hash<winrt::Windows::System::Launcher> : winrt::impl::hash_base<winrt::Windows::System::Launcher> {};
template<> struct hash<winrt::Windows::System::LauncherOptions> : winrt::impl::hash_base<winrt::Windows::System::LauncherOptions> {};
template<> struct hash<winrt::Windows::System::LauncherUIOptions> : winrt::impl::hash_base<winrt::Windows::System::LauncherUIOptions> {};
template<> struct hash<winrt::Windows::System::MemoryManager> : winrt::impl::hash_base<winrt::Windows::System::MemoryManager> {};
template<> struct hash<winrt::Windows::System::ProcessLauncher> : winrt::impl::hash_base<winrt::Windows::System::ProcessLauncher> {};
template<> struct hash<winrt::Windows::System::ProcessLauncherOptions> : winrt::impl::hash_base<winrt::Windows::System::ProcessLauncherOptions> {};
template<> struct hash<winrt::Windows::System::ProcessLauncherResult> : winrt::impl::hash_base<winrt::Windows::System::ProcessLauncherResult> {};
template<> struct hash<winrt::Windows::System::ProcessMemoryReport> : winrt::impl::hash_base<winrt::Windows::System::ProcessMemoryReport> {};
template<> struct hash<winrt::Windows::System::ProtocolForResultsOperation> : winrt::impl::hash_base<winrt::Windows::System::ProtocolForResultsOperation> {};
template<> struct hash<winrt::Windows::System::RemoteLauncher> : winrt::impl::hash_base<winrt::Windows::System::RemoteLauncher> {};
template<> struct hash<winrt::Windows::System::RemoteLauncherOptions> : winrt::impl::hash_base<winrt::Windows::System::RemoteLauncherOptions> {};
template<> struct hash<winrt::Windows::System::ShutdownManager> : winrt::impl::hash_base<winrt::Windows::System::ShutdownManager> {};
template<> struct hash<winrt::Windows::System::TimeZoneSettings> : winrt::impl::hash_base<winrt::Windows::System::TimeZoneSettings> {};
template<> struct hash<winrt::Windows::System::User> : winrt::impl::hash_base<winrt::Windows::System::User> {};
template<> struct hash<winrt::Windows::System::UserAuthenticationStatusChangeDeferral> : winrt::impl::hash_base<winrt::Windows::System::UserAuthenticationStatusChangeDeferral> {};
template<> struct hash<winrt::Windows::System::UserAuthenticationStatusChangingEventArgs> : winrt::impl::hash_base<winrt::Windows::System::UserAuthenticationStatusChangingEventArgs> {};
template<> struct hash<winrt::Windows::System::UserChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::System::UserChangedEventArgs> {};
template<> struct hash<winrt::Windows::System::UserDeviceAssociation> : winrt::impl::hash_base<winrt::Windows::System::UserDeviceAssociation> {};
template<> struct hash<winrt::Windows::System::UserDeviceAssociationChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::System::UserDeviceAssociationChangedEventArgs> {};
template<> struct hash<winrt::Windows::System::UserPicker> : winrt::impl::hash_base<winrt::Windows::System::UserPicker> {};
template<> struct hash<winrt::Windows::System::UserWatcher> : winrt::impl::hash_base<winrt::Windows::System::UserWatcher> {};

}
