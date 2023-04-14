// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Management.Deployment.2.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.ApplicationModel.Store.Preview.InstallControl.2.h"
#include "winrt/Windows.ApplicationModel.Store.Preview.h"

namespace winrt::impl {

template <typename D> hstring consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallItem<D>::ProductId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem)->get_ProductId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallItem<D>::PackageFamilyName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem)->get_PackageFamilyName(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallType consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallItem<D>::InstallType() const
{
    Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallType value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem)->get_InstallType(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallItem<D>::IsUserInitiated() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem)->get_IsUserInitiated(&value));
    return value;
}

template <typename D> Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallStatus consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallItem<D>::GetCurrentStatus() const
{
    Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallStatus result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem)->GetCurrentStatus(put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallItem<D>::Cancel() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem)->Cancel());
}

template <typename D> void consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallItem<D>::Pause() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem)->Pause());
}

template <typename D> void consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallItem<D>::Restart() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem)->Restart());
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallItem<D>::Completed(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem)->add_Completed(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallItem<D>::Completed_revoker consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallItem<D>::Completed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, Completed_revoker>(this, Completed(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallItem<D>::Completed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem)->remove_Completed(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallItem<D>::StatusChanged(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem)->add_StatusChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallItem<D>::StatusChanged_revoker consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallItem<D>::StatusChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, StatusChanged_revoker>(this, StatusChanged(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallItem<D>::StatusChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem)->remove_StatusChanged(get_abi(token)));
}

template <typename D> void consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallItem2<D>::Cancel(param::hstring const& correlationVector) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem2)->CancelWithTelemetry(get_abi(correlationVector)));
}

template <typename D> void consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallItem2<D>::Pause(param::hstring const& correlationVector) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem2)->PauseWithTelemetry(get_abi(correlationVector)));
}

template <typename D> void consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallItem2<D>::Restart(param::hstring const& correlationVector) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem2)->RestartWithTelemetry(get_abi(correlationVector)));
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem> consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallItem3<D>::Children() const
{
    Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem3)->get_Children(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallItem3<D>::ItemOperationsMightAffectOtherItems() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem3)->get_ItemOperationsMightAffectOtherItems(&value));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallItem4<D>::LaunchAfterInstall() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem4)->get_LaunchAfterInstall(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallItem4<D>::LaunchAfterInstall(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem4)->put_LaunchAfterInstall(value));
}

template <typename D> bool consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallItem5<D>::PinToDesktopAfterInstall() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem5)->get_PinToDesktopAfterInstall(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallItem5<D>::PinToDesktopAfterInstall(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem5)->put_PinToDesktopAfterInstall(value));
}

template <typename D> bool consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallItem5<D>::PinToStartAfterInstall() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem5)->get_PinToStartAfterInstall(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallItem5<D>::PinToStartAfterInstall(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem5)->put_PinToStartAfterInstall(value));
}

template <typename D> bool consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallItem5<D>::PinToTaskbarAfterInstall() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem5)->get_PinToTaskbarAfterInstall(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallItem5<D>::PinToTaskbarAfterInstall(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem5)->put_PinToTaskbarAfterInstall(value));
}

template <typename D> Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallationToastNotificationMode consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallItem5<D>::CompletedInstallToastNotificationMode() const
{
    Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallationToastNotificationMode value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem5)->get_CompletedInstallToastNotificationMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallItem5<D>::CompletedInstallToastNotificationMode(Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallationToastNotificationMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem5)->put_CompletedInstallToastNotificationMode(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallationToastNotificationMode consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallItem5<D>::InstallInProgressToastNotificationMode() const
{
    Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallationToastNotificationMode value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem5)->get_InstallInProgressToastNotificationMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallItem5<D>::InstallInProgressToastNotificationMode(Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallationToastNotificationMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem5)->put_InstallInProgressToastNotificationMode(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem> consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager<D>::AppInstallItems() const
{
    Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager)->get_AppInstallItems(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager<D>::Cancel(param::hstring const& productId) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager)->Cancel(get_abi(productId)));
}

template <typename D> void consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager<D>::Pause(param::hstring const& productId) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager)->Pause(get_abi(productId)));
}

template <typename D> void consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager<D>::Restart(param::hstring const& productId) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager)->Restart(get_abi(productId)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager<D>::ItemCompleted(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallManager, Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallManagerItemEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager)->add_ItemCompleted(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager<D>::ItemCompleted_revoker consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager<D>::ItemCompleted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallManager, Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallManagerItemEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ItemCompleted_revoker>(this, ItemCompleted(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager<D>::ItemCompleted(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager)->remove_ItemCompleted(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager<D>::ItemStatusChanged(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallManager, Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallManagerItemEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager)->add_ItemStatusChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager<D>::ItemStatusChanged_revoker consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager<D>::ItemStatusChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallManager, Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallManagerItemEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ItemStatusChanged_revoker>(this, ItemStatusChanged(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager<D>::ItemStatusChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager)->remove_ItemStatusChanged(get_abi(token)));
}

template <typename D> Windows::ApplicationModel::Store::Preview::InstallControl::AutoUpdateSetting consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager<D>::AutoUpdateSetting() const
{
    Windows::ApplicationModel::Store::Preview::InstallControl::AutoUpdateSetting value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager)->get_AutoUpdateSetting(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager<D>::AutoUpdateSetting(Windows::ApplicationModel::Store::Preview::InstallControl::AutoUpdateSetting const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager)->put_AutoUpdateSetting(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager<D>::AcquisitionIdentity() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager)->get_AcquisitionIdentity(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager<D>::AcquisitionIdentity(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager)->put_AcquisitionIdentity(get_abi(value)));
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager<D>::GetIsApplicableAsync(param::hstring const& productId, param::hstring const& skuId) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager)->GetIsApplicableAsync(get_abi(productId), get_abi(skuId), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem> consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager<D>::StartAppInstallAsync(param::hstring const& productId, param::hstring const& skuId, bool repair, bool forceUseOfNonRemovableStorage) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager)->StartAppInstallAsync(get_abi(productId), get_abi(skuId), repair, forceUseOfNonRemovableStorage, put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem> consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager<D>::UpdateAppByPackageFamilyNameAsync(param::hstring const& packageFamilyName) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager)->UpdateAppByPackageFamilyNameAsync(get_abi(packageFamilyName), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem> consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager<D>::SearchForUpdatesAsync(param::hstring const& productId, param::hstring const& skuId) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager)->SearchForUpdatesAsync(get_abi(productId), get_abi(skuId), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>> consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager<D>::SearchForAllUpdatesAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager)->SearchForAllUpdatesAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager<D>::IsStoreBlockedByPolicyAsync(param::hstring const& storeClientName, param::hstring const& storeClientPublisher) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager)->IsStoreBlockedByPolicyAsync(get_abi(storeClientName), get_abi(storeClientPublisher), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager<D>::GetIsAppAllowedToInstallAsync(param::hstring const& productId) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager)->GetIsAppAllowedToInstallAsync(get_abi(productId), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem> consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager2<D>::StartAppInstallAsync(param::hstring const& productId, param::hstring const& skuId, bool repair, bool forceUseOfNonRemovableStorage, param::hstring const& catalogId, param::hstring const& bundleId, param::hstring const& correlationVector) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager2)->StartAppInstallWithTelemetryAsync(get_abi(productId), get_abi(skuId), repair, forceUseOfNonRemovableStorage, get_abi(catalogId), get_abi(bundleId), get_abi(correlationVector), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem> consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager2<D>::UpdateAppByPackageFamilyNameAsync(param::hstring const& packageFamilyName, param::hstring const& correlationVector) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager2)->UpdateAppByPackageFamilyNameWithTelemetryAsync(get_abi(packageFamilyName), get_abi(correlationVector), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem> consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager2<D>::SearchForUpdatesAsync(param::hstring const& productId, param::hstring const& skuId, param::hstring const& catalogId, param::hstring const& correlationVector) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager2)->SearchForUpdatesWithTelemetryAsync(get_abi(productId), get_abi(skuId), get_abi(catalogId), get_abi(correlationVector), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>> consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager2<D>::SearchForAllUpdatesAsync(param::hstring const& correlationVector) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager2)->SearchForAllUpdatesWithTelemetryAsync(get_abi(correlationVector), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager2<D>::GetIsAppAllowedToInstallAsync(param::hstring const& productId, param::hstring const& skuId, param::hstring const& catalogId, param::hstring const& correlationVector) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager2)->GetIsAppAllowedToInstallWithTelemetryAsync(get_abi(productId), get_abi(skuId), get_abi(catalogId), get_abi(correlationVector), put_abi(operation)));
    return operation;
}

template <typename D> void consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager2<D>::Cancel(param::hstring const& productId, param::hstring const& correlationVector) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager2)->CancelWithTelemetry(get_abi(productId), get_abi(correlationVector)));
}

template <typename D> void consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager2<D>::Pause(param::hstring const& productId, param::hstring const& correlationVector) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager2)->PauseWithTelemetry(get_abi(productId), get_abi(correlationVector)));
}

template <typename D> void consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager2<D>::Restart(param::hstring const& productId, param::hstring const& correlationVector) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager2)->RestartWithTelemetry(get_abi(productId), get_abi(correlationVector)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>> consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager3<D>::StartProductInstallAsync(param::hstring const& productId, param::hstring const& catalogId, param::hstring const& flightId, param::hstring const& clientId, bool repair, bool forceUseOfNonRemovableStorage, param::hstring const& correlationVector, Windows::Management::Deployment::PackageVolume const& targetVolume) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager3)->StartProductInstallAsync(get_abi(productId), get_abi(catalogId), get_abi(flightId), get_abi(clientId), repair, forceUseOfNonRemovableStorage, get_abi(correlationVector), get_abi(targetVolume), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>> consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager3<D>::StartProductInstallForUserAsync(Windows::System::User const& user, param::hstring const& productId, param::hstring const& catalogId, param::hstring const& flightId, param::hstring const& clientId, bool repair, bool forceUseOfNonRemovableStorage, param::hstring const& correlationVector, Windows::Management::Deployment::PackageVolume const& targetVolume) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager3)->StartProductInstallForUserAsync(get_abi(user), get_abi(productId), get_abi(catalogId), get_abi(flightId), get_abi(clientId), repair, forceUseOfNonRemovableStorage, get_abi(correlationVector), get_abi(targetVolume), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem> consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager3<D>::UpdateAppByPackageFamilyNameForUserAsync(Windows::System::User const& user, param::hstring const& packageFamilyName, param::hstring const& correlationVector) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager3)->UpdateAppByPackageFamilyNameForUserAsync(get_abi(user), get_abi(packageFamilyName), get_abi(correlationVector), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem> consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager3<D>::SearchForUpdatesForUserAsync(Windows::System::User const& user, param::hstring const& productId, param::hstring const& skuId, param::hstring const& catalogId, param::hstring const& correlationVector) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager3)->SearchForUpdatesForUserAsync(get_abi(user), get_abi(productId), get_abi(skuId), get_abi(catalogId), get_abi(correlationVector), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>> consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager3<D>::SearchForAllUpdatesForUserAsync(Windows::System::User const& user, param::hstring const& correlationVector) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager3)->SearchForAllUpdatesForUserAsync(get_abi(user), get_abi(correlationVector), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager3<D>::GetIsAppAllowedToInstallForUserAsync(Windows::System::User const& user, param::hstring const& productId, param::hstring const& skuId, param::hstring const& catalogId, param::hstring const& correlationVector) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager3)->GetIsAppAllowedToInstallForUserAsync(get_abi(user), get_abi(productId), get_abi(skuId), get_abi(catalogId), get_abi(correlationVector), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager3<D>::GetIsApplicableForUserAsync(Windows::System::User const& user, param::hstring const& productId, param::hstring const& skuId) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager3)->GetIsApplicableForUserAsync(get_abi(user), get_abi(productId), get_abi(skuId), put_abi(operation)));
    return operation;
}

template <typename D> void consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager3<D>::MoveToFrontOfDownloadQueue(param::hstring const& productId, param::hstring const& correlationVector) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager3)->MoveToFrontOfDownloadQueue(get_abi(productId), get_abi(correlationVector)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::Preview::InstallControl::GetEntitlementResult> consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager4<D>::GetFreeUserEntitlementAsync(param::hstring const& storeId, param::hstring const& campaignId, param::hstring const& correlationVector) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::Preview::InstallControl::GetEntitlementResult> ppAsyncOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager4)->GetFreeUserEntitlementAsync(get_abi(storeId), get_abi(campaignId), get_abi(correlationVector), put_abi(ppAsyncOperation)));
    return ppAsyncOperation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::Preview::InstallControl::GetEntitlementResult> consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager4<D>::GetFreeUserEntitlementForUserAsync(Windows::System::User const& user, param::hstring const& storeId, param::hstring const& campaignId, param::hstring const& correlationVector) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::Preview::InstallControl::GetEntitlementResult> ppAsyncOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager4)->GetFreeUserEntitlementForUserAsync(get_abi(user), get_abi(storeId), get_abi(campaignId), get_abi(correlationVector), put_abi(ppAsyncOperation)));
    return ppAsyncOperation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::Preview::InstallControl::GetEntitlementResult> consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager4<D>::GetFreeDeviceEntitlementAsync(param::hstring const& storeId, param::hstring const& campaignId, param::hstring const& correlationVector) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::Preview::InstallControl::GetEntitlementResult> ppAsyncOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager4)->GetFreeDeviceEntitlementAsync(get_abi(storeId), get_abi(campaignId), get_abi(correlationVector), put_abi(ppAsyncOperation)));
    return ppAsyncOperation;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem> consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager5<D>::AppInstallItemsWithGroupSupport() const
{
    Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager5)->get_AppInstallItemsWithGroupSupport(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>> consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager6<D>::SearchForAllUpdatesAsync(param::hstring const& correlationVector, param::hstring const& clientId, Windows::ApplicationModel::Store::Preview::InstallControl::AppUpdateOptions const& updateOptions) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager6)->SearchForAllUpdatesWithUpdateOptionsAsync(get_abi(correlationVector), get_abi(clientId), get_abi(updateOptions), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>> consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager6<D>::SearchForAllUpdatesForUserAsync(Windows::System::User const& user, param::hstring const& correlationVector, param::hstring const& clientId, Windows::ApplicationModel::Store::Preview::InstallControl::AppUpdateOptions const& updateOptions) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager6)->SearchForAllUpdatesWithUpdateOptionsForUserAsync(get_abi(user), get_abi(correlationVector), get_abi(clientId), get_abi(updateOptions), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem> consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager6<D>::SearchForUpdatesAsync(param::hstring const& productId, param::hstring const& skuId, param::hstring const& correlationVector, param::hstring const& clientId, Windows::ApplicationModel::Store::Preview::InstallControl::AppUpdateOptions const& updateOptions) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager6)->SearchForUpdatesWithUpdateOptionsAsync(get_abi(productId), get_abi(skuId), get_abi(correlationVector), get_abi(clientId), get_abi(updateOptions), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem> consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager6<D>::SearchForUpdatesForUserAsync(Windows::System::User const& user, param::hstring const& productId, param::hstring const& skuId, param::hstring const& correlationVector, param::hstring const& clientId, Windows::ApplicationModel::Store::Preview::InstallControl::AppUpdateOptions const& updateOptions) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager6)->SearchForUpdatesWithUpdateOptionsForUserAsync(get_abi(user), get_abi(productId), get_abi(skuId), get_abi(correlationVector), get_abi(clientId), get_abi(updateOptions), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>> consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager6<D>::StartProductInstallAsync(param::hstring const& productId, param::hstring const& flightId, param::hstring const& clientId, param::hstring const& correlationVector, Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallOptions const& installOptions) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager6)->StartProductInstallWithOptionsAsync(get_abi(productId), get_abi(flightId), get_abi(clientId), get_abi(correlationVector), get_abi(installOptions), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>> consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager6<D>::StartProductInstallForUserAsync(Windows::System::User const& user, param::hstring const& productId, param::hstring const& flightId, param::hstring const& clientId, param::hstring const& correlationVector, Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallOptions const& installOptions) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager6)->StartProductInstallWithOptionsForUserAsync(get_abi(user), get_abi(productId), get_abi(flightId), get_abi(clientId), get_abi(correlationVector), get_abi(installOptions), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager6<D>::GetIsPackageIdentityAllowedToInstallAsync(param::hstring const& correlationVector, param::hstring const& packageIdentityName, param::hstring const& publisherCertificateName) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager6)->GetIsPackageIdentityAllowedToInstallAsync(get_abi(correlationVector), get_abi(packageIdentityName), get_abi(publisherCertificateName), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager6<D>::GetIsPackageIdentityAllowedToInstallForUserAsync(Windows::System::User const& user, param::hstring const& correlationVector, param::hstring const& packageIdentityName, param::hstring const& publisherCertificateName) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager6)->GetIsPackageIdentityAllowedToInstallForUserAsync(get_abi(user), get_abi(correlationVector), get_abi(packageIdentityName), get_abi(publisherCertificateName), put_abi(operation)));
    return operation;
}

template <typename D> bool consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManager7<D>::CanInstallForAllUsers() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager7)->get_CanInstallForAllUsers(&value));
    return value;
}

template <typename D> Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallManagerItemEventArgs<D>::Item() const
{
    Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManagerItemEventArgs)->get_Item(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallOptions<D>::CatalogId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions)->get_CatalogId(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallOptions<D>::CatalogId(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions)->put_CatalogId(get_abi(value)));
}

template <typename D> bool consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallOptions<D>::ForceUseOfNonRemovableStorage() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions)->get_ForceUseOfNonRemovableStorage(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallOptions<D>::ForceUseOfNonRemovableStorage(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions)->put_ForceUseOfNonRemovableStorage(value));
}

template <typename D> bool consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallOptions<D>::AllowForcedAppRestart() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions)->get_AllowForcedAppRestart(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallOptions<D>::AllowForcedAppRestart(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions)->put_AllowForcedAppRestart(value));
}

template <typename D> bool consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallOptions<D>::Repair() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions)->get_Repair(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallOptions<D>::Repair(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions)->put_Repair(value));
}

template <typename D> Windows::Management::Deployment::PackageVolume consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallOptions<D>::TargetVolume() const
{
    Windows::Management::Deployment::PackageVolume value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions)->get_TargetVolume(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallOptions<D>::TargetVolume(Windows::Management::Deployment::PackageVolume const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions)->put_TargetVolume(get_abi(value)));
}

template <typename D> bool consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallOptions<D>::LaunchAfterInstall() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions)->get_LaunchAfterInstall(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallOptions<D>::LaunchAfterInstall(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions)->put_LaunchAfterInstall(value));
}

template <typename D> bool consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallOptions2<D>::PinToDesktopAfterInstall() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions2)->get_PinToDesktopAfterInstall(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallOptions2<D>::PinToDesktopAfterInstall(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions2)->put_PinToDesktopAfterInstall(value));
}

template <typename D> bool consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallOptions2<D>::PinToStartAfterInstall() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions2)->get_PinToStartAfterInstall(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallOptions2<D>::PinToStartAfterInstall(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions2)->put_PinToStartAfterInstall(value));
}

template <typename D> bool consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallOptions2<D>::PinToTaskbarAfterInstall() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions2)->get_PinToTaskbarAfterInstall(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallOptions2<D>::PinToTaskbarAfterInstall(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions2)->put_PinToTaskbarAfterInstall(value));
}

template <typename D> Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallationToastNotificationMode consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallOptions2<D>::CompletedInstallToastNotificationMode() const
{
    Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallationToastNotificationMode value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions2)->get_CompletedInstallToastNotificationMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallOptions2<D>::CompletedInstallToastNotificationMode(Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallationToastNotificationMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions2)->put_CompletedInstallToastNotificationMode(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallationToastNotificationMode consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallOptions2<D>::InstallInProgressToastNotificationMode() const
{
    Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallationToastNotificationMode value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions2)->get_InstallInProgressToastNotificationMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallOptions2<D>::InstallInProgressToastNotificationMode(Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallationToastNotificationMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions2)->put_InstallInProgressToastNotificationMode(get_abi(value)));
}

template <typename D> bool consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallOptions2<D>::InstallForAllUsers() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions2)->get_InstallForAllUsers(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallOptions2<D>::InstallForAllUsers(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions2)->put_InstallForAllUsers(value));
}

template <typename D> bool consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallOptions2<D>::StageButDoNotInstall() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions2)->get_StageButDoNotInstall(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallOptions2<D>::StageButDoNotInstall(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions2)->put_StageButDoNotInstall(value));
}

template <typename D> hstring consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallOptions2<D>::CampaignId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions2)->get_CampaignId(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallOptions2<D>::CampaignId(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions2)->put_CampaignId(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallOptions2<D>::ExtendedCampaignId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions2)->get_ExtendedCampaignId(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallOptions2<D>::ExtendedCampaignId(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions2)->put_ExtendedCampaignId(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallState consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallStatus<D>::InstallState() const
{
    Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallState value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallStatus)->get_InstallState(put_abi(value)));
    return value;
}

template <typename D> uint64_t consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallStatus<D>::DownloadSizeInBytes() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallStatus)->get_DownloadSizeInBytes(&value));
    return value;
}

template <typename D> uint64_t consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallStatus<D>::BytesDownloaded() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallStatus)->get_BytesDownloaded(&value));
    return value;
}

template <typename D> double consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallStatus<D>::PercentComplete() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallStatus)->get_PercentComplete(&value));
    return value;
}

template <typename D> winrt::hresult consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallStatus<D>::ErrorCode() const
{
    winrt::hresult value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallStatus)->get_ErrorCode(put_abi(value)));
    return value;
}

template <typename D> Windows::System::User consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallStatus2<D>::User() const
{
    Windows::System::User value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallStatus2)->get_User(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallStatus2<D>::ReadyForLaunch() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallStatus2)->get_ReadyForLaunch(&value));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppInstallStatus3<D>::IsStaged() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallStatus3)->get_IsStaged(&value));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppUpdateOptions<D>::CatalogId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppUpdateOptions)->get_CatalogId(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppUpdateOptions<D>::CatalogId(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppUpdateOptions)->put_CatalogId(get_abi(value)));
}

template <typename D> bool consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppUpdateOptions<D>::AllowForcedAppRestart() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppUpdateOptions)->get_AllowForcedAppRestart(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppUpdateOptions<D>::AllowForcedAppRestart(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppUpdateOptions)->put_AllowForcedAppRestart(value));
}

template <typename D> bool consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppUpdateOptions2<D>::AutomaticallyDownloadAndInstallUpdateIfFound() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppUpdateOptions2)->get_AutomaticallyDownloadAndInstallUpdateIfFound(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Store_Preview_InstallControl_IAppUpdateOptions2<D>::AutomaticallyDownloadAndInstallUpdateIfFound(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IAppUpdateOptions2)->put_AutomaticallyDownloadAndInstallUpdateIfFound(value));
}

template <typename D> Windows::ApplicationModel::Store::Preview::InstallControl::GetEntitlementStatus consume_Windows_ApplicationModel_Store_Preview_InstallControl_IGetEntitlementResult<D>::Status() const
{
    Windows::ApplicationModel::Store::Preview::InstallControl::GetEntitlementStatus value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Store::Preview::InstallControl::IGetEntitlementResult)->get_Status(put_abi(value)));
    return value;
}

template <typename D>
struct produce<D, Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem> : produce_base<D, Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem>
{
    int32_t WINRT_CALL get_ProductId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProductId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ProductId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PackageFamilyName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PackageFamilyName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().PackageFamilyName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InstallType(Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InstallType, WINRT_WRAP(Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallType));
            *value = detach_from<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallType>(this->shim().InstallType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsUserInitiated(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsUserInitiated, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsUserInitiated());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetCurrentStatus(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCurrentStatus, WINRT_WRAP(Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallStatus));
            *result = detach_from<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallStatus>(this->shim().GetCurrentStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Cancel() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Cancel, WINRT_WRAP(void));
            this->shim().Cancel();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Pause() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Pause, WINRT_WRAP(void));
            this->shim().Pause();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Restart() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Restart, WINRT_WRAP(void));
            this->shim().Restart();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_Completed(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Completed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().Completed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Completed(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Completed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Completed(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_StatusChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StatusChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().StatusChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_StatusChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(StatusChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().StatusChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem2> : produce_base<D, Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem2>
{
    int32_t WINRT_CALL CancelWithTelemetry(void* correlationVector) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Cancel, WINRT_WRAP(void), hstring const&);
            this->shim().Cancel(*reinterpret_cast<hstring const*>(&correlationVector));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PauseWithTelemetry(void* correlationVector) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Pause, WINRT_WRAP(void), hstring const&);
            this->shim().Pause(*reinterpret_cast<hstring const*>(&correlationVector));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RestartWithTelemetry(void* correlationVector) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Restart, WINRT_WRAP(void), hstring const&);
            this->shim().Restart(*reinterpret_cast<hstring const*>(&correlationVector));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem3> : produce_base<D, Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem3>
{
    int32_t WINRT_CALL get_Children(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Children, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>>(this->shim().Children());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ItemOperationsMightAffectOtherItems(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ItemOperationsMightAffectOtherItems, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().ItemOperationsMightAffectOtherItems());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem4> : produce_base<D, Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem4>
{
    int32_t WINRT_CALL get_LaunchAfterInstall(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LaunchAfterInstall, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().LaunchAfterInstall());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_LaunchAfterInstall(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LaunchAfterInstall, WINRT_WRAP(void), bool);
            this->shim().LaunchAfterInstall(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem5> : produce_base<D, Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem5>
{
    int32_t WINRT_CALL get_PinToDesktopAfterInstall(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PinToDesktopAfterInstall, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().PinToDesktopAfterInstall());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PinToDesktopAfterInstall(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PinToDesktopAfterInstall, WINRT_WRAP(void), bool);
            this->shim().PinToDesktopAfterInstall(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PinToStartAfterInstall(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PinToStartAfterInstall, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().PinToStartAfterInstall());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PinToStartAfterInstall(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PinToStartAfterInstall, WINRT_WRAP(void), bool);
            this->shim().PinToStartAfterInstall(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PinToTaskbarAfterInstall(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PinToTaskbarAfterInstall, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().PinToTaskbarAfterInstall());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PinToTaskbarAfterInstall(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PinToTaskbarAfterInstall, WINRT_WRAP(void), bool);
            this->shim().PinToTaskbarAfterInstall(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CompletedInstallToastNotificationMode(Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallationToastNotificationMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CompletedInstallToastNotificationMode, WINRT_WRAP(Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallationToastNotificationMode));
            *value = detach_from<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallationToastNotificationMode>(this->shim().CompletedInstallToastNotificationMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CompletedInstallToastNotificationMode(Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallationToastNotificationMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CompletedInstallToastNotificationMode, WINRT_WRAP(void), Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallationToastNotificationMode const&);
            this->shim().CompletedInstallToastNotificationMode(*reinterpret_cast<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallationToastNotificationMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InstallInProgressToastNotificationMode(Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallationToastNotificationMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InstallInProgressToastNotificationMode, WINRT_WRAP(Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallationToastNotificationMode));
            *value = detach_from<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallationToastNotificationMode>(this->shim().InstallInProgressToastNotificationMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_InstallInProgressToastNotificationMode(Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallationToastNotificationMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InstallInProgressToastNotificationMode, WINRT_WRAP(void), Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallationToastNotificationMode const&);
            this->shim().InstallInProgressToastNotificationMode(*reinterpret_cast<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallationToastNotificationMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager> : produce_base<D, Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager>
{
    int32_t WINRT_CALL get_AppInstallItems(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppInstallItems, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>>(this->shim().AppInstallItems());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Cancel(void* productId) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Cancel, WINRT_WRAP(void), hstring const&);
            this->shim().Cancel(*reinterpret_cast<hstring const*>(&productId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Pause(void* productId) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Pause, WINRT_WRAP(void), hstring const&);
            this->shim().Pause(*reinterpret_cast<hstring const*>(&productId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Restart(void* productId) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Restart, WINRT_WRAP(void), hstring const&);
            this->shim().Restart(*reinterpret_cast<hstring const*>(&productId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_ItemCompleted(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ItemCompleted, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallManager, Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallManagerItemEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ItemCompleted(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallManager, Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallManagerItemEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ItemCompleted(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ItemCompleted, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ItemCompleted(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_ItemStatusChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ItemStatusChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallManager, Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallManagerItemEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ItemStatusChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallManager, Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallManagerItemEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ItemStatusChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ItemStatusChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ItemStatusChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL get_AutoUpdateSetting(Windows::ApplicationModel::Store::Preview::InstallControl::AutoUpdateSetting* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AutoUpdateSetting, WINRT_WRAP(Windows::ApplicationModel::Store::Preview::InstallControl::AutoUpdateSetting));
            *value = detach_from<Windows::ApplicationModel::Store::Preview::InstallControl::AutoUpdateSetting>(this->shim().AutoUpdateSetting());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AutoUpdateSetting(Windows::ApplicationModel::Store::Preview::InstallControl::AutoUpdateSetting value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AutoUpdateSetting, WINRT_WRAP(void), Windows::ApplicationModel::Store::Preview::InstallControl::AutoUpdateSetting const&);
            this->shim().AutoUpdateSetting(*reinterpret_cast<Windows::ApplicationModel::Store::Preview::InstallControl::AutoUpdateSetting const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AcquisitionIdentity(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AcquisitionIdentity, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AcquisitionIdentity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AcquisitionIdentity(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AcquisitionIdentity, WINRT_WRAP(void), hstring const&);
            this->shim().AcquisitionIdentity(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetIsApplicableAsync(void* productId, void* skuId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetIsApplicableAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), hstring const, hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().GetIsApplicableAsync(*reinterpret_cast<hstring const*>(&productId), *reinterpret_cast<hstring const*>(&skuId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StartAppInstallAsync(void* productId, void* skuId, bool repair, bool forceUseOfNonRemovableStorage, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartAppInstallAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>), hstring const, hstring const, bool, bool);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>>(this->shim().StartAppInstallAsync(*reinterpret_cast<hstring const*>(&productId), *reinterpret_cast<hstring const*>(&skuId), repair, forceUseOfNonRemovableStorage));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UpdateAppByPackageFamilyNameAsync(void* packageFamilyName, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpdateAppByPackageFamilyNameAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>>(this->shim().UpdateAppByPackageFamilyNameAsync(*reinterpret_cast<hstring const*>(&packageFamilyName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SearchForUpdatesAsync(void* productId, void* skuId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SearchForUpdatesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>), hstring const, hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>>(this->shim().SearchForUpdatesAsync(*reinterpret_cast<hstring const*>(&productId), *reinterpret_cast<hstring const*>(&skuId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SearchForAllUpdatesAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SearchForAllUpdatesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>>>(this->shim().SearchForAllUpdatesAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsStoreBlockedByPolicyAsync(void* storeClientName, void* storeClientPublisher, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsStoreBlockedByPolicyAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), hstring const, hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().IsStoreBlockedByPolicyAsync(*reinterpret_cast<hstring const*>(&storeClientName), *reinterpret_cast<hstring const*>(&storeClientPublisher)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetIsAppAllowedToInstallAsync(void* productId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetIsAppAllowedToInstallAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().GetIsAppAllowedToInstallAsync(*reinterpret_cast<hstring const*>(&productId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager2> : produce_base<D, Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager2>
{
    int32_t WINRT_CALL StartAppInstallWithTelemetryAsync(void* productId, void* skuId, bool repair, bool forceUseOfNonRemovableStorage, void* catalogId, void* bundleId, void* correlationVector, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartAppInstallAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>), hstring const, hstring const, bool, bool, hstring const, hstring const, hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>>(this->shim().StartAppInstallAsync(*reinterpret_cast<hstring const*>(&productId), *reinterpret_cast<hstring const*>(&skuId), repair, forceUseOfNonRemovableStorage, *reinterpret_cast<hstring const*>(&catalogId), *reinterpret_cast<hstring const*>(&bundleId), *reinterpret_cast<hstring const*>(&correlationVector)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UpdateAppByPackageFamilyNameWithTelemetryAsync(void* packageFamilyName, void* correlationVector, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpdateAppByPackageFamilyNameAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>), hstring const, hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>>(this->shim().UpdateAppByPackageFamilyNameAsync(*reinterpret_cast<hstring const*>(&packageFamilyName), *reinterpret_cast<hstring const*>(&correlationVector)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SearchForUpdatesWithTelemetryAsync(void* productId, void* skuId, void* catalogId, void* correlationVector, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SearchForUpdatesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>), hstring const, hstring const, hstring const, hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>>(this->shim().SearchForUpdatesAsync(*reinterpret_cast<hstring const*>(&productId), *reinterpret_cast<hstring const*>(&skuId), *reinterpret_cast<hstring const*>(&catalogId), *reinterpret_cast<hstring const*>(&correlationVector)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SearchForAllUpdatesWithTelemetryAsync(void* correlationVector, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SearchForAllUpdatesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>>>(this->shim().SearchForAllUpdatesAsync(*reinterpret_cast<hstring const*>(&correlationVector)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetIsAppAllowedToInstallWithTelemetryAsync(void* productId, void* skuId, void* catalogId, void* correlationVector, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetIsAppAllowedToInstallAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), hstring const, hstring const, hstring const, hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().GetIsAppAllowedToInstallAsync(*reinterpret_cast<hstring const*>(&productId), *reinterpret_cast<hstring const*>(&skuId), *reinterpret_cast<hstring const*>(&catalogId), *reinterpret_cast<hstring const*>(&correlationVector)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CancelWithTelemetry(void* productId, void* correlationVector) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Cancel, WINRT_WRAP(void), hstring const&, hstring const&);
            this->shim().Cancel(*reinterpret_cast<hstring const*>(&productId), *reinterpret_cast<hstring const*>(&correlationVector));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PauseWithTelemetry(void* productId, void* correlationVector) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Pause, WINRT_WRAP(void), hstring const&, hstring const&);
            this->shim().Pause(*reinterpret_cast<hstring const*>(&productId), *reinterpret_cast<hstring const*>(&correlationVector));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RestartWithTelemetry(void* productId, void* correlationVector) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Restart, WINRT_WRAP(void), hstring const&, hstring const&);
            this->shim().Restart(*reinterpret_cast<hstring const*>(&productId), *reinterpret_cast<hstring const*>(&correlationVector));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager3> : produce_base<D, Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager3>
{
    int32_t WINRT_CALL StartProductInstallAsync(void* productId, void* catalogId, void* flightId, void* clientId, bool repair, bool forceUseOfNonRemovableStorage, void* correlationVector, void* targetVolume, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartProductInstallAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>>), hstring const, hstring const, hstring const, hstring const, bool, bool, hstring const, Windows::Management::Deployment::PackageVolume const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>>>(this->shim().StartProductInstallAsync(*reinterpret_cast<hstring const*>(&productId), *reinterpret_cast<hstring const*>(&catalogId), *reinterpret_cast<hstring const*>(&flightId), *reinterpret_cast<hstring const*>(&clientId), repair, forceUseOfNonRemovableStorage, *reinterpret_cast<hstring const*>(&correlationVector), *reinterpret_cast<Windows::Management::Deployment::PackageVolume const*>(&targetVolume)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StartProductInstallForUserAsync(void* user, void* productId, void* catalogId, void* flightId, void* clientId, bool repair, bool forceUseOfNonRemovableStorage, void* correlationVector, void* targetVolume, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartProductInstallForUserAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>>), Windows::System::User const, hstring const, hstring const, hstring const, hstring const, bool, bool, hstring const, Windows::Management::Deployment::PackageVolume const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>>>(this->shim().StartProductInstallForUserAsync(*reinterpret_cast<Windows::System::User const*>(&user), *reinterpret_cast<hstring const*>(&productId), *reinterpret_cast<hstring const*>(&catalogId), *reinterpret_cast<hstring const*>(&flightId), *reinterpret_cast<hstring const*>(&clientId), repair, forceUseOfNonRemovableStorage, *reinterpret_cast<hstring const*>(&correlationVector), *reinterpret_cast<Windows::Management::Deployment::PackageVolume const*>(&targetVolume)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UpdateAppByPackageFamilyNameForUserAsync(void* user, void* packageFamilyName, void* correlationVector, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpdateAppByPackageFamilyNameForUserAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>), Windows::System::User const, hstring const, hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>>(this->shim().UpdateAppByPackageFamilyNameForUserAsync(*reinterpret_cast<Windows::System::User const*>(&user), *reinterpret_cast<hstring const*>(&packageFamilyName), *reinterpret_cast<hstring const*>(&correlationVector)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SearchForUpdatesForUserAsync(void* user, void* productId, void* skuId, void* catalogId, void* correlationVector, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SearchForUpdatesForUserAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>), Windows::System::User const, hstring const, hstring const, hstring const, hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>>(this->shim().SearchForUpdatesForUserAsync(*reinterpret_cast<Windows::System::User const*>(&user), *reinterpret_cast<hstring const*>(&productId), *reinterpret_cast<hstring const*>(&skuId), *reinterpret_cast<hstring const*>(&catalogId), *reinterpret_cast<hstring const*>(&correlationVector)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SearchForAllUpdatesForUserAsync(void* user, void* correlationVector, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SearchForAllUpdatesForUserAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>>), Windows::System::User const, hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>>>(this->shim().SearchForAllUpdatesForUserAsync(*reinterpret_cast<Windows::System::User const*>(&user), *reinterpret_cast<hstring const*>(&correlationVector)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetIsAppAllowedToInstallForUserAsync(void* user, void* productId, void* skuId, void* catalogId, void* correlationVector, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetIsAppAllowedToInstallForUserAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::System::User const, hstring const, hstring const, hstring const, hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().GetIsAppAllowedToInstallForUserAsync(*reinterpret_cast<Windows::System::User const*>(&user), *reinterpret_cast<hstring const*>(&productId), *reinterpret_cast<hstring const*>(&skuId), *reinterpret_cast<hstring const*>(&catalogId), *reinterpret_cast<hstring const*>(&correlationVector)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetIsApplicableForUserAsync(void* user, void* productId, void* skuId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetIsApplicableForUserAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::System::User const, hstring const, hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().GetIsApplicableForUserAsync(*reinterpret_cast<Windows::System::User const*>(&user), *reinterpret_cast<hstring const*>(&productId), *reinterpret_cast<hstring const*>(&skuId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL MoveToFrontOfDownloadQueue(void* productId, void* correlationVector) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MoveToFrontOfDownloadQueue, WINRT_WRAP(void), hstring const&, hstring const&);
            this->shim().MoveToFrontOfDownloadQueue(*reinterpret_cast<hstring const*>(&productId), *reinterpret_cast<hstring const*>(&correlationVector));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager4> : produce_base<D, Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager4>
{
    int32_t WINRT_CALL GetFreeUserEntitlementAsync(void* storeId, void* campaignId, void* correlationVector, void** ppAsyncOperation) noexcept final
    {
        try
        {
            *ppAsyncOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetFreeUserEntitlementAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::Preview::InstallControl::GetEntitlementResult>), hstring const, hstring const, hstring const);
            *ppAsyncOperation = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::Preview::InstallControl::GetEntitlementResult>>(this->shim().GetFreeUserEntitlementAsync(*reinterpret_cast<hstring const*>(&storeId), *reinterpret_cast<hstring const*>(&campaignId), *reinterpret_cast<hstring const*>(&correlationVector)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetFreeUserEntitlementForUserAsync(void* user, void* storeId, void* campaignId, void* correlationVector, void** ppAsyncOperation) noexcept final
    {
        try
        {
            *ppAsyncOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetFreeUserEntitlementForUserAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::Preview::InstallControl::GetEntitlementResult>), Windows::System::User const, hstring const, hstring const, hstring const);
            *ppAsyncOperation = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::Preview::InstallControl::GetEntitlementResult>>(this->shim().GetFreeUserEntitlementForUserAsync(*reinterpret_cast<Windows::System::User const*>(&user), *reinterpret_cast<hstring const*>(&storeId), *reinterpret_cast<hstring const*>(&campaignId), *reinterpret_cast<hstring const*>(&correlationVector)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetFreeDeviceEntitlementAsync(void* storeId, void* campaignId, void* correlationVector, void** ppAsyncOperation) noexcept final
    {
        try
        {
            *ppAsyncOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetFreeDeviceEntitlementAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::Preview::InstallControl::GetEntitlementResult>), hstring const, hstring const, hstring const);
            *ppAsyncOperation = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::Preview::InstallControl::GetEntitlementResult>>(this->shim().GetFreeDeviceEntitlementAsync(*reinterpret_cast<hstring const*>(&storeId), *reinterpret_cast<hstring const*>(&campaignId), *reinterpret_cast<hstring const*>(&correlationVector)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager5> : produce_base<D, Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager5>
{
    int32_t WINRT_CALL get_AppInstallItemsWithGroupSupport(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppInstallItemsWithGroupSupport, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>>(this->shim().AppInstallItemsWithGroupSupport());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager6> : produce_base<D, Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager6>
{
    int32_t WINRT_CALL SearchForAllUpdatesWithUpdateOptionsAsync(void* correlationVector, void* clientId, void* updateOptions, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SearchForAllUpdatesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>>), hstring const, hstring const, Windows::ApplicationModel::Store::Preview::InstallControl::AppUpdateOptions const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>>>(this->shim().SearchForAllUpdatesAsync(*reinterpret_cast<hstring const*>(&correlationVector), *reinterpret_cast<hstring const*>(&clientId), *reinterpret_cast<Windows::ApplicationModel::Store::Preview::InstallControl::AppUpdateOptions const*>(&updateOptions)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SearchForAllUpdatesWithUpdateOptionsForUserAsync(void* user, void* correlationVector, void* clientId, void* updateOptions, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SearchForAllUpdatesForUserAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>>), Windows::System::User const, hstring const, hstring const, Windows::ApplicationModel::Store::Preview::InstallControl::AppUpdateOptions const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>>>(this->shim().SearchForAllUpdatesForUserAsync(*reinterpret_cast<Windows::System::User const*>(&user), *reinterpret_cast<hstring const*>(&correlationVector), *reinterpret_cast<hstring const*>(&clientId), *reinterpret_cast<Windows::ApplicationModel::Store::Preview::InstallControl::AppUpdateOptions const*>(&updateOptions)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SearchForUpdatesWithUpdateOptionsAsync(void* productId, void* skuId, void* correlationVector, void* clientId, void* updateOptions, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SearchForUpdatesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>), hstring const, hstring const, hstring const, hstring const, Windows::ApplicationModel::Store::Preview::InstallControl::AppUpdateOptions const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>>(this->shim().SearchForUpdatesAsync(*reinterpret_cast<hstring const*>(&productId), *reinterpret_cast<hstring const*>(&skuId), *reinterpret_cast<hstring const*>(&correlationVector), *reinterpret_cast<hstring const*>(&clientId), *reinterpret_cast<Windows::ApplicationModel::Store::Preview::InstallControl::AppUpdateOptions const*>(&updateOptions)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SearchForUpdatesWithUpdateOptionsForUserAsync(void* user, void* productId, void* skuId, void* correlationVector, void* clientId, void* updateOptions, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SearchForUpdatesForUserAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>), Windows::System::User const, hstring const, hstring const, hstring const, hstring const, Windows::ApplicationModel::Store::Preview::InstallControl::AppUpdateOptions const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>>(this->shim().SearchForUpdatesForUserAsync(*reinterpret_cast<Windows::System::User const*>(&user), *reinterpret_cast<hstring const*>(&productId), *reinterpret_cast<hstring const*>(&skuId), *reinterpret_cast<hstring const*>(&correlationVector), *reinterpret_cast<hstring const*>(&clientId), *reinterpret_cast<Windows::ApplicationModel::Store::Preview::InstallControl::AppUpdateOptions const*>(&updateOptions)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StartProductInstallWithOptionsAsync(void* productId, void* flightId, void* clientId, void* correlationVector, void* installOptions, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartProductInstallAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>>), hstring const, hstring const, hstring const, hstring const, Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallOptions const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>>>(this->shim().StartProductInstallAsync(*reinterpret_cast<hstring const*>(&productId), *reinterpret_cast<hstring const*>(&flightId), *reinterpret_cast<hstring const*>(&clientId), *reinterpret_cast<hstring const*>(&correlationVector), *reinterpret_cast<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallOptions const*>(&installOptions)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StartProductInstallWithOptionsForUserAsync(void* user, void* productId, void* flightId, void* clientId, void* correlationVector, void* installOptions, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartProductInstallForUserAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>>), Windows::System::User const, hstring const, hstring const, hstring const, hstring const, Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallOptions const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>>>(this->shim().StartProductInstallForUserAsync(*reinterpret_cast<Windows::System::User const*>(&user), *reinterpret_cast<hstring const*>(&productId), *reinterpret_cast<hstring const*>(&flightId), *reinterpret_cast<hstring const*>(&clientId), *reinterpret_cast<hstring const*>(&correlationVector), *reinterpret_cast<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallOptions const*>(&installOptions)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetIsPackageIdentityAllowedToInstallAsync(void* correlationVector, void* packageIdentityName, void* publisherCertificateName, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetIsPackageIdentityAllowedToInstallAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), hstring const, hstring const, hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().GetIsPackageIdentityAllowedToInstallAsync(*reinterpret_cast<hstring const*>(&correlationVector), *reinterpret_cast<hstring const*>(&packageIdentityName), *reinterpret_cast<hstring const*>(&publisherCertificateName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetIsPackageIdentityAllowedToInstallForUserAsync(void* user, void* correlationVector, void* packageIdentityName, void* publisherCertificateName, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetIsPackageIdentityAllowedToInstallForUserAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::System::User const, hstring const, hstring const, hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().GetIsPackageIdentityAllowedToInstallForUserAsync(*reinterpret_cast<Windows::System::User const*>(&user), *reinterpret_cast<hstring const*>(&correlationVector), *reinterpret_cast<hstring const*>(&packageIdentityName), *reinterpret_cast<hstring const*>(&publisherCertificateName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager7> : produce_base<D, Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager7>
{
    int32_t WINRT_CALL get_CanInstallForAllUsers(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanInstallForAllUsers, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanInstallForAllUsers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManagerItemEventArgs> : produce_base<D, Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManagerItemEventArgs>
{
    int32_t WINRT_CALL get_Item(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Item, WINRT_WRAP(Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem));
            *value = detach_from<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem>(this->shim().Item());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions> : produce_base<D, Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions>
{
    int32_t WINRT_CALL get_CatalogId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CatalogId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().CatalogId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CatalogId(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CatalogId, WINRT_WRAP(void), hstring const&);
            this->shim().CatalogId(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ForceUseOfNonRemovableStorage(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ForceUseOfNonRemovableStorage, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().ForceUseOfNonRemovableStorage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ForceUseOfNonRemovableStorage(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ForceUseOfNonRemovableStorage, WINRT_WRAP(void), bool);
            this->shim().ForceUseOfNonRemovableStorage(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AllowForcedAppRestart(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllowForcedAppRestart, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AllowForcedAppRestart());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AllowForcedAppRestart(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllowForcedAppRestart, WINRT_WRAP(void), bool);
            this->shim().AllowForcedAppRestart(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Repair(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Repair, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Repair());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Repair(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Repair, WINRT_WRAP(void), bool);
            this->shim().Repair(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TargetVolume(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetVolume, WINRT_WRAP(Windows::Management::Deployment::PackageVolume));
            *value = detach_from<Windows::Management::Deployment::PackageVolume>(this->shim().TargetVolume());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TargetVolume(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetVolume, WINRT_WRAP(void), Windows::Management::Deployment::PackageVolume const&);
            this->shim().TargetVolume(*reinterpret_cast<Windows::Management::Deployment::PackageVolume const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LaunchAfterInstall(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LaunchAfterInstall, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().LaunchAfterInstall());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_LaunchAfterInstall(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LaunchAfterInstall, WINRT_WRAP(void), bool);
            this->shim().LaunchAfterInstall(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions2> : produce_base<D, Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions2>
{
    int32_t WINRT_CALL get_PinToDesktopAfterInstall(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PinToDesktopAfterInstall, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().PinToDesktopAfterInstall());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PinToDesktopAfterInstall(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PinToDesktopAfterInstall, WINRT_WRAP(void), bool);
            this->shim().PinToDesktopAfterInstall(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PinToStartAfterInstall(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PinToStartAfterInstall, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().PinToStartAfterInstall());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PinToStartAfterInstall(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PinToStartAfterInstall, WINRT_WRAP(void), bool);
            this->shim().PinToStartAfterInstall(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PinToTaskbarAfterInstall(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PinToTaskbarAfterInstall, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().PinToTaskbarAfterInstall());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PinToTaskbarAfterInstall(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PinToTaskbarAfterInstall, WINRT_WRAP(void), bool);
            this->shim().PinToTaskbarAfterInstall(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CompletedInstallToastNotificationMode(Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallationToastNotificationMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CompletedInstallToastNotificationMode, WINRT_WRAP(Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallationToastNotificationMode));
            *value = detach_from<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallationToastNotificationMode>(this->shim().CompletedInstallToastNotificationMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CompletedInstallToastNotificationMode(Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallationToastNotificationMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CompletedInstallToastNotificationMode, WINRT_WRAP(void), Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallationToastNotificationMode const&);
            this->shim().CompletedInstallToastNotificationMode(*reinterpret_cast<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallationToastNotificationMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InstallInProgressToastNotificationMode(Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallationToastNotificationMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InstallInProgressToastNotificationMode, WINRT_WRAP(Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallationToastNotificationMode));
            *value = detach_from<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallationToastNotificationMode>(this->shim().InstallInProgressToastNotificationMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_InstallInProgressToastNotificationMode(Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallationToastNotificationMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InstallInProgressToastNotificationMode, WINRT_WRAP(void), Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallationToastNotificationMode const&);
            this->shim().InstallInProgressToastNotificationMode(*reinterpret_cast<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallationToastNotificationMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InstallForAllUsers(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InstallForAllUsers, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().InstallForAllUsers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_InstallForAllUsers(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InstallForAllUsers, WINRT_WRAP(void), bool);
            this->shim().InstallForAllUsers(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StageButDoNotInstall(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StageButDoNotInstall, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().StageButDoNotInstall());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_StageButDoNotInstall(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StageButDoNotInstall, WINRT_WRAP(void), bool);
            this->shim().StageButDoNotInstall(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CampaignId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CampaignId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().CampaignId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CampaignId(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CampaignId, WINRT_WRAP(void), hstring const&);
            this->shim().CampaignId(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExtendedCampaignId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExtendedCampaignId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ExtendedCampaignId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ExtendedCampaignId(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExtendedCampaignId, WINRT_WRAP(void), hstring const&);
            this->shim().ExtendedCampaignId(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallStatus> : produce_base<D, Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallStatus>
{
    int32_t WINRT_CALL get_InstallState(Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InstallState, WINRT_WRAP(Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallState));
            *value = detach_from<Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallState>(this->shim().InstallState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DownloadSizeInBytes(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DownloadSizeInBytes, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().DownloadSizeInBytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BytesDownloaded(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BytesDownloaded, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().BytesDownloaded());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PercentComplete(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PercentComplete, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().PercentComplete());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ErrorCode(winrt::hresult* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ErrorCode, WINRT_WRAP(winrt::hresult));
            *value = detach_from<winrt::hresult>(this->shim().ErrorCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallStatus2> : produce_base<D, Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallStatus2>
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

    int32_t WINRT_CALL get_ReadyForLaunch(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadyForLaunch, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().ReadyForLaunch());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallStatus3> : produce_base<D, Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallStatus3>
{
    int32_t WINRT_CALL get_IsStaged(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsStaged, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsStaged());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Store::Preview::InstallControl::IAppUpdateOptions> : produce_base<D, Windows::ApplicationModel::Store::Preview::InstallControl::IAppUpdateOptions>
{
    int32_t WINRT_CALL get_CatalogId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CatalogId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().CatalogId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CatalogId(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CatalogId, WINRT_WRAP(void), hstring const&);
            this->shim().CatalogId(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AllowForcedAppRestart(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllowForcedAppRestart, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AllowForcedAppRestart());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AllowForcedAppRestart(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllowForcedAppRestart, WINRT_WRAP(void), bool);
            this->shim().AllowForcedAppRestart(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Store::Preview::InstallControl::IAppUpdateOptions2> : produce_base<D, Windows::ApplicationModel::Store::Preview::InstallControl::IAppUpdateOptions2>
{
    int32_t WINRT_CALL get_AutomaticallyDownloadAndInstallUpdateIfFound(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AutomaticallyDownloadAndInstallUpdateIfFound, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AutomaticallyDownloadAndInstallUpdateIfFound());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AutomaticallyDownloadAndInstallUpdateIfFound(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AutomaticallyDownloadAndInstallUpdateIfFound, WINRT_WRAP(void), bool);
            this->shim().AutomaticallyDownloadAndInstallUpdateIfFound(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Store::Preview::InstallControl::IGetEntitlementResult> : produce_base<D, Windows::ApplicationModel::Store::Preview::InstallControl::IGetEntitlementResult>
{
    int32_t WINRT_CALL get_Status(Windows::ApplicationModel::Store::Preview::InstallControl::GetEntitlementStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::ApplicationModel::Store::Preview::InstallControl::GetEntitlementStatus));
            *value = detach_from<Windows::ApplicationModel::Store::Preview::InstallControl::GetEntitlementStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Store::Preview::InstallControl {

inline AppInstallManager::AppInstallManager() :
    AppInstallManager(impl::call_factory<AppInstallManager>([](auto&& f) { return f.template ActivateInstance<AppInstallManager>(); }))
{}

inline AppInstallOptions::AppInstallOptions() :
    AppInstallOptions(impl::call_factory<AppInstallOptions>([](auto&& f) { return f.template ActivateInstance<AppInstallOptions>(); }))
{}

inline AppUpdateOptions::AppUpdateOptions() :
    AppUpdateOptions(impl::call_factory<AppUpdateOptions>([](auto&& f) { return f.template ActivateInstance<AppUpdateOptions>(); }))
{}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem2> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem3> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem3> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem4> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem4> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem5> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallItem5> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager2> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager3> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager3> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager4> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager4> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager5> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager5> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager6> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager6> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager7> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManager7> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManagerItemEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallManagerItemEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallOptions2> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallStatus> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallStatus> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallStatus2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallStatus2> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallStatus3> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppInstallStatus3> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppUpdateOptions> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppUpdateOptions> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppUpdateOptions2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IAppUpdateOptions2> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IGetEntitlementResult> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::IGetEntitlementResult> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallItem> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallManager> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallManager> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallManagerItemEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallManagerItemEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallOptions> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallOptions> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallStatus> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppInstallStatus> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppUpdateOptions> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::AppUpdateOptions> {};
template<> struct hash<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::GetEntitlementResult> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Store::Preview::InstallControl::GetEntitlementResult> {};

}
