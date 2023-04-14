// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.ApplicationModel.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.Web.Http.2.h"
#include "winrt/impl/Windows.Services.Store.2.h"

namespace winrt::impl {

template <typename D> Windows::Services::Store::StorePackageLicense consume_Windows_Services_Store_IStoreAcquireLicenseResult<D>::StorePackageLicense() const
{
    Windows::Services::Store::StorePackageLicense value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreAcquireLicenseResult)->get_StorePackageLicense(put_abi(value)));
    return value;
}

template <typename D> winrt::hresult consume_Windows_Services_Store_IStoreAcquireLicenseResult<D>::ExtendedError() const
{
    winrt::hresult value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreAcquireLicenseResult)->get_ExtendedError(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Store_IStoreAppLicense<D>::SkuStoreId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreAppLicense)->get_SkuStoreId(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Services_Store_IStoreAppLicense<D>::IsActive() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreAppLicense)->get_IsActive(&value));
    return value;
}

template <typename D> bool consume_Windows_Services_Store_IStoreAppLicense<D>::IsTrial() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreAppLicense)->get_IsTrial(&value));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_Services_Store_IStoreAppLicense<D>::ExpirationDate() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreAppLicense)->get_ExpirationDate(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Store_IStoreAppLicense<D>::ExtendedJsonData() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreAppLicense)->get_ExtendedJsonData(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IMapView<hstring, Windows::Services::Store::StoreLicense> consume_Windows_Services_Store_IStoreAppLicense<D>::AddOnLicenses() const
{
    Windows::Foundation::Collections::IMapView<hstring, Windows::Services::Store::StoreLicense> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreAppLicense)->get_AddOnLicenses(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Services_Store_IStoreAppLicense<D>::TrialTimeRemaining() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreAppLicense)->get_TrialTimeRemaining(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Services_Store_IStoreAppLicense<D>::IsTrialOwnedByThisUser() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreAppLicense)->get_IsTrialOwnedByThisUser(&value));
    return value;
}

template <typename D> hstring consume_Windows_Services_Store_IStoreAppLicense<D>::TrialUniqueId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreAppLicense)->get_TrialUniqueId(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Services_Store_IStoreAppLicense2<D>::IsDiscLicense() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreAppLicense2)->get_IsDiscLicense(&value));
    return value;
}

template <typename D> hstring consume_Windows_Services_Store_IStoreAvailability<D>::StoreId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreAvailability)->get_StoreId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_Services_Store_IStoreAvailability<D>::EndDate() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreAvailability)->get_EndDate(put_abi(value)));
    return value;
}

template <typename D> Windows::Services::Store::StorePrice consume_Windows_Services_Store_IStoreAvailability<D>::Price() const
{
    Windows::Services::Store::StorePrice value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreAvailability)->get_Price(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Store_IStoreAvailability<D>::ExtendedJsonData() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreAvailability)->get_ExtendedJsonData(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Services::Store::StorePurchaseResult> consume_Windows_Services_Store_IStoreAvailability<D>::RequestPurchaseAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Services::Store::StorePurchaseResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreAvailability)->RequestPurchaseAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Services::Store::StorePurchaseResult> consume_Windows_Services_Store_IStoreAvailability<D>::RequestPurchaseAsync(Windows::Services::Store::StorePurchaseProperties const& storePurchaseProperties) const
{
    Windows::Foundation::IAsyncOperation<Windows::Services::Store::StorePurchaseResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreAvailability)->RequestPurchaseWithPurchasePropertiesAsync(get_abi(storePurchaseProperties), put_abi(operation)));
    return operation;
}

template <typename D> winrt::hresult consume_Windows_Services_Store_IStoreCanAcquireLicenseResult<D>::ExtendedError() const
{
    winrt::hresult value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreCanAcquireLicenseResult)->get_ExtendedError(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Store_IStoreCanAcquireLicenseResult<D>::LicensableSku() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreCanAcquireLicenseResult)->get_LicensableSku(put_abi(value)));
    return value;
}

template <typename D> Windows::Services::Store::StoreCanLicenseStatus consume_Windows_Services_Store_IStoreCanAcquireLicenseResult<D>::Status() const
{
    Windows::Services::Store::StoreCanLicenseStatus value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreCanAcquireLicenseResult)->get_Status(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Services_Store_IStoreCollectionData<D>::IsTrial() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreCollectionData)->get_IsTrial(&value));
    return value;
}

template <typename D> hstring consume_Windows_Services_Store_IStoreCollectionData<D>::CampaignId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreCollectionData)->get_CampaignId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Store_IStoreCollectionData<D>::DeveloperOfferId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreCollectionData)->get_DeveloperOfferId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_Services_Store_IStoreCollectionData<D>::AcquiredDate() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreCollectionData)->get_AcquiredDate(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_Services_Store_IStoreCollectionData<D>::StartDate() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreCollectionData)->get_StartDate(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_Services_Store_IStoreCollectionData<D>::EndDate() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreCollectionData)->get_EndDate(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Services_Store_IStoreCollectionData<D>::TrialTimeRemaining() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreCollectionData)->get_TrialTimeRemaining(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Store_IStoreCollectionData<D>::ExtendedJsonData() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreCollectionData)->get_ExtendedJsonData(put_abi(value)));
    return value;
}

template <typename D> Windows::Services::Store::StoreConsumableStatus consume_Windows_Services_Store_IStoreConsumableResult<D>::Status() const
{
    Windows::Services::Store::StoreConsumableStatus value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreConsumableResult)->get_Status(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Services_Store_IStoreConsumableResult<D>::TrackingId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreConsumableResult)->get_TrackingId(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Services_Store_IStoreConsumableResult<D>::BalanceRemaining() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreConsumableResult)->get_BalanceRemaining(&value));
    return value;
}

template <typename D> winrt::hresult consume_Windows_Services_Store_IStoreConsumableResult<D>::ExtendedError() const
{
    winrt::hresult value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreConsumableResult)->get_ExtendedError(put_abi(value)));
    return value;
}

template <typename D> Windows::System::User consume_Windows_Services_Store_IStoreContext<D>::User() const
{
    Windows::System::User value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreContext)->get_User(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Services_Store_IStoreContext<D>::OfflineLicensesChanged(Windows::Foundation::TypedEventHandler<Windows::Services::Store::StoreContext, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreContext)->add_OfflineLicensesChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Services_Store_IStoreContext<D>::OfflineLicensesChanged_revoker consume_Windows_Services_Store_IStoreContext<D>::OfflineLicensesChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Services::Store::StoreContext, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, OfflineLicensesChanged_revoker>(this, OfflineLicensesChanged(handler));
}

template <typename D> void consume_Windows_Services_Store_IStoreContext<D>::OfflineLicensesChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Services::Store::IStoreContext)->remove_OfflineLicensesChanged(get_abi(token)));
}

template <typename D> Windows::Foundation::IAsyncOperation<hstring> consume_Windows_Services_Store_IStoreContext<D>::GetCustomerPurchaseIdAsync(param::hstring const& serviceTicket, param::hstring const& publisherUserId) const
{
    Windows::Foundation::IAsyncOperation<hstring> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreContext)->GetCustomerPurchaseIdAsync(get_abi(serviceTicket), get_abi(publisherUserId), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<hstring> consume_Windows_Services_Store_IStoreContext<D>::GetCustomerCollectionsIdAsync(param::hstring const& serviceTicket, param::hstring const& publisherUserId) const
{
    Windows::Foundation::IAsyncOperation<hstring> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreContext)->GetCustomerCollectionsIdAsync(get_abi(serviceTicket), get_abi(publisherUserId), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreAppLicense> consume_Windows_Services_Store_IStoreContext<D>::GetAppLicenseAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreAppLicense> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreContext)->GetAppLicenseAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreProductResult> consume_Windows_Services_Store_IStoreContext<D>::GetStoreProductForCurrentAppAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreProductResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreContext)->GetStoreProductForCurrentAppAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreProductQueryResult> consume_Windows_Services_Store_IStoreContext<D>::GetStoreProductsAsync(param::async_iterable<hstring> const& productKinds, param::async_iterable<hstring> const& storeIds) const
{
    Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreProductQueryResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreContext)->GetStoreProductsAsync(get_abi(productKinds), get_abi(storeIds), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreProductQueryResult> consume_Windows_Services_Store_IStoreContext<D>::GetAssociatedStoreProductsAsync(param::async_iterable<hstring> const& productKinds) const
{
    Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreProductQueryResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreContext)->GetAssociatedStoreProductsAsync(get_abi(productKinds), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreProductPagedQueryResult> consume_Windows_Services_Store_IStoreContext<D>::GetAssociatedStoreProductsWithPagingAsync(param::async_iterable<hstring> const& productKinds, uint32_t maxItemsToRetrievePerPage) const
{
    Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreProductPagedQueryResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreContext)->GetAssociatedStoreProductsWithPagingAsync(get_abi(productKinds), maxItemsToRetrievePerPage, put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreProductQueryResult> consume_Windows_Services_Store_IStoreContext<D>::GetUserCollectionAsync(param::async_iterable<hstring> const& productKinds) const
{
    Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreProductQueryResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreContext)->GetUserCollectionAsync(get_abi(productKinds), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreProductPagedQueryResult> consume_Windows_Services_Store_IStoreContext<D>::GetUserCollectionWithPagingAsync(param::async_iterable<hstring> const& productKinds, uint32_t maxItemsToRetrievePerPage) const
{
    Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreProductPagedQueryResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreContext)->GetUserCollectionWithPagingAsync(get_abi(productKinds), maxItemsToRetrievePerPage, put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreConsumableResult> consume_Windows_Services_Store_IStoreContext<D>::ReportConsumableFulfillmentAsync(param::hstring const& productStoreId, uint32_t quantity, winrt::guid const& trackingId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreConsumableResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreContext)->ReportConsumableFulfillmentAsync(get_abi(productStoreId), quantity, get_abi(trackingId), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreConsumableResult> consume_Windows_Services_Store_IStoreContext<D>::GetConsumableBalanceRemainingAsync(param::hstring const& productStoreId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreConsumableResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreContext)->GetConsumableBalanceRemainingAsync(get_abi(productStoreId), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreAcquireLicenseResult> consume_Windows_Services_Store_IStoreContext<D>::AcquireStoreLicenseForOptionalPackageAsync(Windows::ApplicationModel::Package const& optionalPackage) const
{
    Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreAcquireLicenseResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreContext)->AcquireStoreLicenseForOptionalPackageAsync(get_abi(optionalPackage), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Services::Store::StorePurchaseResult> consume_Windows_Services_Store_IStoreContext<D>::RequestPurchaseAsync(param::hstring const& storeId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Services::Store::StorePurchaseResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreContext)->RequestPurchaseAsync(get_abi(storeId), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Services::Store::StorePurchaseResult> consume_Windows_Services_Store_IStoreContext<D>::RequestPurchaseAsync(param::hstring const& storeId, Windows::Services::Store::StorePurchaseProperties const& storePurchaseProperties) const
{
    Windows::Foundation::IAsyncOperation<Windows::Services::Store::StorePurchaseResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreContext)->RequestPurchaseWithPurchasePropertiesAsync(get_abi(storeId), get_abi(storePurchaseProperties), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Services::Store::StorePackageUpdate>> consume_Windows_Services_Store_IStoreContext<D>::GetAppAndOptionalStorePackageUpdatesAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Services::Store::StorePackageUpdate>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreContext)->GetAppAndOptionalStorePackageUpdatesAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Services::Store::StorePackageUpdateResult, Windows::Services::Store::StorePackageUpdateStatus> consume_Windows_Services_Store_IStoreContext<D>::RequestDownloadStorePackageUpdatesAsync(param::async_iterable<Windows::Services::Store::StorePackageUpdate> const& storePackageUpdates) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Services::Store::StorePackageUpdateResult, Windows::Services::Store::StorePackageUpdateStatus> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreContext)->RequestDownloadStorePackageUpdatesAsync(get_abi(storePackageUpdates), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Services::Store::StorePackageUpdateResult, Windows::Services::Store::StorePackageUpdateStatus> consume_Windows_Services_Store_IStoreContext<D>::RequestDownloadAndInstallStorePackageUpdatesAsync(param::async_iterable<Windows::Services::Store::StorePackageUpdate> const& storePackageUpdates) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Services::Store::StorePackageUpdateResult, Windows::Services::Store::StorePackageUpdateStatus> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreContext)->RequestDownloadAndInstallStorePackageUpdatesAsync(get_abi(storePackageUpdates), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Services::Store::StorePackageUpdateResult, Windows::Services::Store::StorePackageUpdateStatus> consume_Windows_Services_Store_IStoreContext<D>::RequestDownloadAndInstallStorePackagesAsync(param::async_iterable<hstring> const& storeIds) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Services::Store::StorePackageUpdateResult, Windows::Services::Store::StorePackageUpdateStatus> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreContext)->RequestDownloadAndInstallStorePackagesAsync(get_abi(storeIds), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreProductResult> consume_Windows_Services_Store_IStoreContext2<D>::FindStoreProductForPackageAsync(param::async_iterable<hstring> const& productKinds, Windows::ApplicationModel::Package const& package) const
{
    Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreProductResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreContext2)->FindStoreProductForPackageAsync(get_abi(productKinds), get_abi(package), put_abi(operation)));
    return operation;
}

template <typename D> bool consume_Windows_Services_Store_IStoreContext3<D>::CanSilentlyDownloadStorePackageUpdates() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreContext3)->get_CanSilentlyDownloadStorePackageUpdates(&value));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Services::Store::StorePackageUpdateResult, Windows::Services::Store::StorePackageUpdateStatus> consume_Windows_Services_Store_IStoreContext3<D>::TrySilentDownloadStorePackageUpdatesAsync(param::async_iterable<Windows::Services::Store::StorePackageUpdate> const& storePackageUpdates) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Services::Store::StorePackageUpdateResult, Windows::Services::Store::StorePackageUpdateStatus> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreContext3)->TrySilentDownloadStorePackageUpdatesAsync(get_abi(storePackageUpdates), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Services::Store::StorePackageUpdateResult, Windows::Services::Store::StorePackageUpdateStatus> consume_Windows_Services_Store_IStoreContext3<D>::TrySilentDownloadAndInstallStorePackageUpdatesAsync(param::async_iterable<Windows::Services::Store::StorePackageUpdate> const& storePackageUpdates) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Services::Store::StorePackageUpdateResult, Windows::Services::Store::StorePackageUpdateStatus> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreContext3)->TrySilentDownloadAndInstallStorePackageUpdatesAsync(get_abi(storePackageUpdates), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreCanAcquireLicenseResult> consume_Windows_Services_Store_IStoreContext3<D>::CanAcquireStoreLicenseForOptionalPackageAsync(Windows::ApplicationModel::Package const& optionalPackage) const
{
    Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreCanAcquireLicenseResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreContext3)->CanAcquireStoreLicenseForOptionalPackageAsync(get_abi(optionalPackage), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreCanAcquireLicenseResult> consume_Windows_Services_Store_IStoreContext3<D>::CanAcquireStoreLicenseAsync(param::hstring const& productStoreId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreCanAcquireLicenseResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreContext3)->CanAcquireStoreLicenseAsync(get_abi(productStoreId), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreProductQueryResult> consume_Windows_Services_Store_IStoreContext3<D>::GetStoreProductsAsync(param::async_iterable<hstring> const& productKinds, param::async_iterable<hstring> const& storeIds, Windows::Services::Store::StoreProductOptions const& storeProductOptions) const
{
    Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreProductQueryResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreContext3)->GetStoreProductsWithOptionsAsync(get_abi(productKinds), get_abi(storeIds), get_abi(storeProductOptions), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Services::Store::StoreQueueItem>> consume_Windows_Services_Store_IStoreContext3<D>::GetAssociatedStoreQueueItemsAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Services::Store::StoreQueueItem>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreContext3)->GetAssociatedStoreQueueItemsAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Services::Store::StoreQueueItem>> consume_Windows_Services_Store_IStoreContext3<D>::GetStoreQueueItemsAsync(param::async_iterable<hstring> const& storeIds) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Services::Store::StoreQueueItem>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreContext3)->GetStoreQueueItemsAsync(get_abi(storeIds), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Services::Store::StorePackageUpdateResult, Windows::Services::Store::StorePackageUpdateStatus> consume_Windows_Services_Store_IStoreContext3<D>::RequestDownloadAndInstallStorePackagesAsync(param::async_iterable<hstring> const& storeIds, Windows::Services::Store::StorePackageInstallOptions const& storePackageInstallOptions) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Services::Store::StorePackageUpdateResult, Windows::Services::Store::StorePackageUpdateStatus> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreContext3)->RequestDownloadAndInstallStorePackagesWithInstallOptionsAsync(get_abi(storeIds), get_abi(storePackageInstallOptions), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Services::Store::StorePackageUpdateResult, Windows::Services::Store::StorePackageUpdateStatus> consume_Windows_Services_Store_IStoreContext3<D>::DownloadAndInstallStorePackagesAsync(param::async_iterable<hstring> const& storeIds) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Services::Store::StorePackageUpdateResult, Windows::Services::Store::StorePackageUpdateStatus> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreContext3)->DownloadAndInstallStorePackagesAsync(get_abi(storeIds), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreUninstallStorePackageResult> consume_Windows_Services_Store_IStoreContext3<D>::RequestUninstallStorePackageAsync(Windows::ApplicationModel::Package const& package) const
{
    Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreUninstallStorePackageResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreContext3)->RequestUninstallStorePackageAsync(get_abi(package), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreUninstallStorePackageResult> consume_Windows_Services_Store_IStoreContext3<D>::RequestUninstallStorePackageByStoreIdAsync(param::hstring const& storeId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreUninstallStorePackageResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreContext3)->RequestUninstallStorePackageByStoreIdAsync(get_abi(storeId), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreUninstallStorePackageResult> consume_Windows_Services_Store_IStoreContext3<D>::UninstallStorePackageAsync(Windows::ApplicationModel::Package const& package) const
{
    Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreUninstallStorePackageResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreContext3)->UninstallStorePackageAsync(get_abi(package), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreUninstallStorePackageResult> consume_Windows_Services_Store_IStoreContext3<D>::UninstallStorePackageByStoreIdAsync(param::hstring const& storeId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreUninstallStorePackageResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreContext3)->UninstallStorePackageByStoreIdAsync(get_abi(storeId), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreRateAndReviewResult> consume_Windows_Services_Store_IStoreContext4<D>::RequestRateAndReviewAppAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreRateAndReviewResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreContext4)->RequestRateAndReviewAppAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Services::Store::StoreQueueItem>> consume_Windows_Services_Store_IStoreContext4<D>::SetInstallOrderForAssociatedStoreQueueItemsAsync(param::async_iterable<Windows::Services::Store::StoreQueueItem> const& items) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Services::Store::StoreQueueItem>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreContext4)->SetInstallOrderForAssociatedStoreQueueItemsAsync(get_abi(items), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Services::Store::StoreContext consume_Windows_Services_Store_IStoreContextStatics<D>::GetDefault() const
{
    Windows::Services::Store::StoreContext value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreContextStatics)->GetDefault(put_abi(value)));
    return value;
}

template <typename D> Windows::Services::Store::StoreContext consume_Windows_Services_Store_IStoreContextStatics<D>::GetForUser(Windows::System::User const& user) const
{
    Windows::Services::Store::StoreContext value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreContextStatics)->GetForUser(get_abi(user), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Uri consume_Windows_Services_Store_IStoreImage<D>::Uri() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreImage)->get_Uri(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Store_IStoreImage<D>::ImagePurposeTag() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreImage)->get_ImagePurposeTag(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Services_Store_IStoreImage<D>::Width() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreImage)->get_Width(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Services_Store_IStoreImage<D>::Height() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreImage)->get_Height(&value));
    return value;
}

template <typename D> hstring consume_Windows_Services_Store_IStoreImage<D>::Caption() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreImage)->get_Caption(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Store_IStoreLicense<D>::SkuStoreId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreLicense)->get_SkuStoreId(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Services_Store_IStoreLicense<D>::IsActive() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreLicense)->get_IsActive(&value));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_Services_Store_IStoreLicense<D>::ExpirationDate() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreLicense)->get_ExpirationDate(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Store_IStoreLicense<D>::ExtendedJsonData() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreLicense)->get_ExtendedJsonData(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Store_IStoreLicense<D>::InAppOfferToken() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreLicense)->get_InAppOfferToken(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Services_Store_IStorePackageInstallOptions<D>::AllowForcedAppRestart() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStorePackageInstallOptions)->get_AllowForcedAppRestart(&value));
    return value;
}

template <typename D> void consume_Windows_Services_Store_IStorePackageInstallOptions<D>::AllowForcedAppRestart(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStorePackageInstallOptions)->put_AllowForcedAppRestart(value));
}

template <typename D> winrt::event_token consume_Windows_Services_Store_IStorePackageLicense<D>::LicenseLost(Windows::Foundation::TypedEventHandler<Windows::Services::Store::StorePackageLicense, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStorePackageLicense)->add_LicenseLost(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Services_Store_IStorePackageLicense<D>::LicenseLost_revoker consume_Windows_Services_Store_IStorePackageLicense<D>::LicenseLost(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Services::Store::StorePackageLicense, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, LicenseLost_revoker>(this, LicenseLost(handler));
}

template <typename D> void consume_Windows_Services_Store_IStorePackageLicense<D>::LicenseLost(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Services::Store::IStorePackageLicense)->remove_LicenseLost(get_abi(token)));
}

template <typename D> Windows::ApplicationModel::Package consume_Windows_Services_Store_IStorePackageLicense<D>::Package() const
{
    Windows::ApplicationModel::Package value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStorePackageLicense)->get_Package(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Services_Store_IStorePackageLicense<D>::IsValid() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStorePackageLicense)->get_IsValid(&value));
    return value;
}

template <typename D> void consume_Windows_Services_Store_IStorePackageLicense<D>::ReleaseLicense() const
{
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStorePackageLicense)->ReleaseLicense());
}

template <typename D> Windows::ApplicationModel::Package consume_Windows_Services_Store_IStorePackageUpdate<D>::Package() const
{
    Windows::ApplicationModel::Package value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStorePackageUpdate)->get_Package(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Services_Store_IStorePackageUpdate<D>::Mandatory() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStorePackageUpdate)->get_Mandatory(&value));
    return value;
}

template <typename D> Windows::Services::Store::StorePackageUpdateState consume_Windows_Services_Store_IStorePackageUpdateResult<D>::OverallState() const
{
    Windows::Services::Store::StorePackageUpdateState value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStorePackageUpdateResult)->get_OverallState(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Services::Store::StorePackageUpdateStatus> consume_Windows_Services_Store_IStorePackageUpdateResult<D>::StorePackageUpdateStatuses() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Services::Store::StorePackageUpdateStatus> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStorePackageUpdateResult)->get_StorePackageUpdateStatuses(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Services::Store::StoreQueueItem> consume_Windows_Services_Store_IStorePackageUpdateResult2<D>::StoreQueueItems() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Services::Store::StoreQueueItem> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStorePackageUpdateResult2)->get_StoreQueueItems(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Store_IStorePrice<D>::FormattedBasePrice() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStorePrice)->get_FormattedBasePrice(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Store_IStorePrice<D>::FormattedPrice() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStorePrice)->get_FormattedPrice(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Services_Store_IStorePrice<D>::IsOnSale() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStorePrice)->get_IsOnSale(&value));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_Services_Store_IStorePrice<D>::SaleEndDate() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStorePrice)->get_SaleEndDate(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Store_IStorePrice<D>::CurrencyCode() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStorePrice)->get_CurrencyCode(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Store_IStorePrice<D>::FormattedRecurrencePrice() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStorePrice)->get_FormattedRecurrencePrice(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Store_IStoreProduct<D>::StoreId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreProduct)->get_StoreId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Store_IStoreProduct<D>::Language() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreProduct)->get_Language(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Store_IStoreProduct<D>::Title() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreProduct)->get_Title(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Store_IStoreProduct<D>::Description() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreProduct)->get_Description(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Store_IStoreProduct<D>::ProductKind() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreProduct)->get_ProductKind(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Services_Store_IStoreProduct<D>::HasDigitalDownload() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreProduct)->get_HasDigitalDownload(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<hstring> consume_Windows_Services_Store_IStoreProduct<D>::Keywords() const
{
    Windows::Foundation::Collections::IVectorView<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreProduct)->get_Keywords(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Services::Store::StoreImage> consume_Windows_Services_Store_IStoreProduct<D>::Images() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Services::Store::StoreImage> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreProduct)->get_Images(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Services::Store::StoreVideo> consume_Windows_Services_Store_IStoreProduct<D>::Videos() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Services::Store::StoreVideo> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreProduct)->get_Videos(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Services::Store::StoreSku> consume_Windows_Services_Store_IStoreProduct<D>::Skus() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Services::Store::StoreSku> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreProduct)->get_Skus(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Services_Store_IStoreProduct<D>::IsInUserCollection() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreProduct)->get_IsInUserCollection(&value));
    return value;
}

template <typename D> Windows::Services::Store::StorePrice consume_Windows_Services_Store_IStoreProduct<D>::Price() const
{
    Windows::Services::Store::StorePrice value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreProduct)->get_Price(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Store_IStoreProduct<D>::ExtendedJsonData() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreProduct)->get_ExtendedJsonData(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Uri consume_Windows_Services_Store_IStoreProduct<D>::LinkUri() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreProduct)->get_LinkUri(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Services_Store_IStoreProduct<D>::GetIsAnySkuInstalledAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreProduct)->GetIsAnySkuInstalledAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Services::Store::StorePurchaseResult> consume_Windows_Services_Store_IStoreProduct<D>::RequestPurchaseAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Services::Store::StorePurchaseResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreProduct)->RequestPurchaseAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Services::Store::StorePurchaseResult> consume_Windows_Services_Store_IStoreProduct<D>::RequestPurchaseAsync(Windows::Services::Store::StorePurchaseProperties const& storePurchaseProperties) const
{
    Windows::Foundation::IAsyncOperation<Windows::Services::Store::StorePurchaseResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreProduct)->RequestPurchaseWithPurchasePropertiesAsync(get_abi(storePurchaseProperties), put_abi(operation)));
    return operation;
}

template <typename D> hstring consume_Windows_Services_Store_IStoreProduct<D>::InAppOfferToken() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreProduct)->get_InAppOfferToken(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<hstring> consume_Windows_Services_Store_IStoreProductOptions<D>::ActionFilters() const
{
    Windows::Foundation::Collections::IVector<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreProductOptions)->get_ActionFilters(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IMapView<hstring, Windows::Services::Store::StoreProduct> consume_Windows_Services_Store_IStoreProductPagedQueryResult<D>::Products() const
{
    Windows::Foundation::Collections::IMapView<hstring, Windows::Services::Store::StoreProduct> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreProductPagedQueryResult)->get_Products(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Services_Store_IStoreProductPagedQueryResult<D>::HasMoreResults() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreProductPagedQueryResult)->get_HasMoreResults(&value));
    return value;
}

template <typename D> winrt::hresult consume_Windows_Services_Store_IStoreProductPagedQueryResult<D>::ExtendedError() const
{
    winrt::hresult value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreProductPagedQueryResult)->get_ExtendedError(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreProductPagedQueryResult> consume_Windows_Services_Store_IStoreProductPagedQueryResult<D>::GetNextAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreProductPagedQueryResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreProductPagedQueryResult)->GetNextAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::Collections::IMapView<hstring, Windows::Services::Store::StoreProduct> consume_Windows_Services_Store_IStoreProductQueryResult<D>::Products() const
{
    Windows::Foundation::Collections::IMapView<hstring, Windows::Services::Store::StoreProduct> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreProductQueryResult)->get_Products(put_abi(value)));
    return value;
}

template <typename D> winrt::hresult consume_Windows_Services_Store_IStoreProductQueryResult<D>::ExtendedError() const
{
    winrt::hresult value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreProductQueryResult)->get_ExtendedError(put_abi(value)));
    return value;
}

template <typename D> Windows::Services::Store::StoreProduct consume_Windows_Services_Store_IStoreProductResult<D>::Product() const
{
    Windows::Services::Store::StoreProduct value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreProductResult)->get_Product(put_abi(value)));
    return value;
}

template <typename D> winrt::hresult consume_Windows_Services_Store_IStoreProductResult<D>::ExtendedError() const
{
    winrt::hresult value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreProductResult)->get_ExtendedError(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Store_IStorePurchaseProperties<D>::Name() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStorePurchaseProperties)->get_Name(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Services_Store_IStorePurchaseProperties<D>::Name(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStorePurchaseProperties)->put_Name(get_abi(value)));
}

template <typename D> hstring consume_Windows_Services_Store_IStorePurchaseProperties<D>::ExtendedJsonData() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStorePurchaseProperties)->get_ExtendedJsonData(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Services_Store_IStorePurchaseProperties<D>::ExtendedJsonData(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStorePurchaseProperties)->put_ExtendedJsonData(get_abi(value)));
}

template <typename D> Windows::Services::Store::StorePurchaseProperties consume_Windows_Services_Store_IStorePurchasePropertiesFactory<D>::Create(param::hstring const& name) const
{
    Windows::Services::Store::StorePurchaseProperties storePurchaseProperties{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStorePurchasePropertiesFactory)->Create(get_abi(name), put_abi(storePurchaseProperties)));
    return storePurchaseProperties;
}

template <typename D> Windows::Services::Store::StorePurchaseStatus consume_Windows_Services_Store_IStorePurchaseResult<D>::Status() const
{
    Windows::Services::Store::StorePurchaseStatus value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStorePurchaseResult)->get_Status(put_abi(value)));
    return value;
}

template <typename D> winrt::hresult consume_Windows_Services_Store_IStorePurchaseResult<D>::ExtendedError() const
{
    winrt::hresult value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStorePurchaseResult)->get_ExtendedError(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Store_IStoreQueueItem<D>::ProductId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreQueueItem)->get_ProductId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Store_IStoreQueueItem<D>::PackageFamilyName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreQueueItem)->get_PackageFamilyName(put_abi(value)));
    return value;
}

template <typename D> Windows::Services::Store::StoreQueueItemKind consume_Windows_Services_Store_IStoreQueueItem<D>::InstallKind() const
{
    Windows::Services::Store::StoreQueueItemKind value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreQueueItem)->get_InstallKind(put_abi(value)));
    return value;
}

template <typename D> Windows::Services::Store::StoreQueueItemStatus consume_Windows_Services_Store_IStoreQueueItem<D>::GetCurrentStatus() const
{
    Windows::Services::Store::StoreQueueItemStatus result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreQueueItem)->GetCurrentStatus(put_abi(result)));
    return result;
}

template <typename D> winrt::event_token consume_Windows_Services_Store_IStoreQueueItem<D>::Completed(Windows::Foundation::TypedEventHandler<Windows::Services::Store::StoreQueueItem, Windows::Services::Store::StoreQueueItemCompletedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreQueueItem)->add_Completed(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Services_Store_IStoreQueueItem<D>::Completed_revoker consume_Windows_Services_Store_IStoreQueueItem<D>::Completed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Services::Store::StoreQueueItem, Windows::Services::Store::StoreQueueItemCompletedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Completed_revoker>(this, Completed(handler));
}

template <typename D> void consume_Windows_Services_Store_IStoreQueueItem<D>::Completed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Services::Store::IStoreQueueItem)->remove_Completed(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Services_Store_IStoreQueueItem<D>::StatusChanged(Windows::Foundation::TypedEventHandler<Windows::Services::Store::StoreQueueItem, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreQueueItem)->add_StatusChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Services_Store_IStoreQueueItem<D>::StatusChanged_revoker consume_Windows_Services_Store_IStoreQueueItem<D>::StatusChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Services::Store::StoreQueueItem, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, StatusChanged_revoker>(this, StatusChanged(handler));
}

template <typename D> void consume_Windows_Services_Store_IStoreQueueItem<D>::StatusChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Services::Store::IStoreQueueItem)->remove_StatusChanged(get_abi(token)));
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Services_Store_IStoreQueueItem2<D>::CancelInstallAsync() const
{
    Windows::Foundation::IAsyncAction action{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreQueueItem2)->CancelInstallAsync(put_abi(action)));
    return action;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Services_Store_IStoreQueueItem2<D>::PauseInstallAsync() const
{
    Windows::Foundation::IAsyncAction action{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreQueueItem2)->PauseInstallAsync(put_abi(action)));
    return action;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Services_Store_IStoreQueueItem2<D>::ResumeInstallAsync() const
{
    Windows::Foundation::IAsyncAction action{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreQueueItem2)->ResumeInstallAsync(put_abi(action)));
    return action;
}

template <typename D> Windows::Services::Store::StoreQueueItemStatus consume_Windows_Services_Store_IStoreQueueItemCompletedEventArgs<D>::Status() const
{
    Windows::Services::Store::StoreQueueItemStatus value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreQueueItemCompletedEventArgs)->get_Status(put_abi(value)));
    return value;
}

template <typename D> Windows::Services::Store::StoreQueueItemState consume_Windows_Services_Store_IStoreQueueItemStatus<D>::PackageInstallState() const
{
    Windows::Services::Store::StoreQueueItemState value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreQueueItemStatus)->get_PackageInstallState(put_abi(value)));
    return value;
}

template <typename D> Windows::Services::Store::StoreQueueItemExtendedState consume_Windows_Services_Store_IStoreQueueItemStatus<D>::PackageInstallExtendedState() const
{
    Windows::Services::Store::StoreQueueItemExtendedState value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreQueueItemStatus)->get_PackageInstallExtendedState(put_abi(value)));
    return value;
}

template <typename D> Windows::Services::Store::StorePackageUpdateStatus consume_Windows_Services_Store_IStoreQueueItemStatus<D>::UpdateStatus() const
{
    Windows::Services::Store::StorePackageUpdateStatus value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreQueueItemStatus)->get_UpdateStatus(put_abi(value)));
    return value;
}

template <typename D> winrt::hresult consume_Windows_Services_Store_IStoreQueueItemStatus<D>::ExtendedError() const
{
    winrt::hresult value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreQueueItemStatus)->get_ExtendedError(put_abi(value)));
    return value;
}

template <typename D> winrt::hresult consume_Windows_Services_Store_IStoreRateAndReviewResult<D>::ExtendedError() const
{
    winrt::hresult value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreRateAndReviewResult)->get_ExtendedError(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Store_IStoreRateAndReviewResult<D>::ExtendedJsonData() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreRateAndReviewResult)->get_ExtendedJsonData(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Services_Store_IStoreRateAndReviewResult<D>::WasUpdated() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreRateAndReviewResult)->get_WasUpdated(&value));
    return value;
}

template <typename D> Windows::Services::Store::StoreRateAndReviewStatus consume_Windows_Services_Store_IStoreRateAndReviewResult<D>::Status() const
{
    Windows::Services::Store::StoreRateAndReviewStatus value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreRateAndReviewResult)->get_Status(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreSendRequestResult> consume_Windows_Services_Store_IStoreRequestHelperStatics<D>::SendRequestAsync(Windows::Services::Store::StoreContext const& context, uint32_t requestKind, param::hstring const& parametersAsJson) const
{
    Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreSendRequestResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreRequestHelperStatics)->SendRequestAsync(get_abi(context), requestKind, get_abi(parametersAsJson), put_abi(operation)));
    return operation;
}

template <typename D> hstring consume_Windows_Services_Store_IStoreSendRequestResult<D>::Response() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreSendRequestResult)->get_Response(put_abi(value)));
    return value;
}

template <typename D> winrt::hresult consume_Windows_Services_Store_IStoreSendRequestResult<D>::ExtendedError() const
{
    winrt::hresult value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreSendRequestResult)->get_ExtendedError(put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::HttpStatusCode consume_Windows_Services_Store_IStoreSendRequestResult2<D>::HttpStatusCode() const
{
    Windows::Web::Http::HttpStatusCode value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreSendRequestResult2)->get_HttpStatusCode(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Store_IStoreSku<D>::StoreId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreSku)->get_StoreId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Store_IStoreSku<D>::Language() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreSku)->get_Language(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Store_IStoreSku<D>::Title() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreSku)->get_Title(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Store_IStoreSku<D>::Description() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreSku)->get_Description(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Services_Store_IStoreSku<D>::IsTrial() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreSku)->get_IsTrial(&value));
    return value;
}

template <typename D> hstring consume_Windows_Services_Store_IStoreSku<D>::CustomDeveloperData() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreSku)->get_CustomDeveloperData(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Services::Store::StoreImage> consume_Windows_Services_Store_IStoreSku<D>::Images() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Services::Store::StoreImage> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreSku)->get_Images(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Services::Store::StoreVideo> consume_Windows_Services_Store_IStoreSku<D>::Videos() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Services::Store::StoreVideo> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreSku)->get_Videos(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Services::Store::StoreAvailability> consume_Windows_Services_Store_IStoreSku<D>::Availabilities() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Services::Store::StoreAvailability> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreSku)->get_Availabilities(put_abi(value)));
    return value;
}

template <typename D> Windows::Services::Store::StorePrice consume_Windows_Services_Store_IStoreSku<D>::Price() const
{
    Windows::Services::Store::StorePrice value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreSku)->get_Price(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Store_IStoreSku<D>::ExtendedJsonData() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreSku)->get_ExtendedJsonData(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Services_Store_IStoreSku<D>::IsInUserCollection() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreSku)->get_IsInUserCollection(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<hstring> consume_Windows_Services_Store_IStoreSku<D>::BundledSkus() const
{
    Windows::Foundation::Collections::IVectorView<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreSku)->get_BundledSkus(put_abi(value)));
    return value;
}

template <typename D> Windows::Services::Store::StoreCollectionData consume_Windows_Services_Store_IStoreSku<D>::CollectionData() const
{
    Windows::Services::Store::StoreCollectionData value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreSku)->get_CollectionData(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Services_Store_IStoreSku<D>::GetIsInstalledAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreSku)->GetIsInstalledAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Services::Store::StorePurchaseResult> consume_Windows_Services_Store_IStoreSku<D>::RequestPurchaseAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Services::Store::StorePurchaseResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreSku)->RequestPurchaseAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Services::Store::StorePurchaseResult> consume_Windows_Services_Store_IStoreSku<D>::RequestPurchaseAsync(Windows::Services::Store::StorePurchaseProperties const& storePurchaseProperties) const
{
    Windows::Foundation::IAsyncOperation<Windows::Services::Store::StorePurchaseResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreSku)->RequestPurchaseWithPurchasePropertiesAsync(get_abi(storePurchaseProperties), put_abi(operation)));
    return operation;
}

template <typename D> bool consume_Windows_Services_Store_IStoreSku<D>::IsSubscription() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreSku)->get_IsSubscription(&value));
    return value;
}

template <typename D> Windows::Services::Store::StoreSubscriptionInfo consume_Windows_Services_Store_IStoreSku<D>::SubscriptionInfo() const
{
    Windows::Services::Store::StoreSubscriptionInfo value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreSku)->get_SubscriptionInfo(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Services_Store_IStoreSubscriptionInfo<D>::BillingPeriod() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreSubscriptionInfo)->get_BillingPeriod(&value));
    return value;
}

template <typename D> Windows::Services::Store::StoreDurationUnit consume_Windows_Services_Store_IStoreSubscriptionInfo<D>::BillingPeriodUnit() const
{
    Windows::Services::Store::StoreDurationUnit value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreSubscriptionInfo)->get_BillingPeriodUnit(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Services_Store_IStoreSubscriptionInfo<D>::HasTrialPeriod() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreSubscriptionInfo)->get_HasTrialPeriod(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Services_Store_IStoreSubscriptionInfo<D>::TrialPeriod() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreSubscriptionInfo)->get_TrialPeriod(&value));
    return value;
}

template <typename D> Windows::Services::Store::StoreDurationUnit consume_Windows_Services_Store_IStoreSubscriptionInfo<D>::TrialPeriodUnit() const
{
    Windows::Services::Store::StoreDurationUnit value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreSubscriptionInfo)->get_TrialPeriodUnit(put_abi(value)));
    return value;
}

template <typename D> winrt::hresult consume_Windows_Services_Store_IStoreUninstallStorePackageResult<D>::ExtendedError() const
{
    winrt::hresult value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreUninstallStorePackageResult)->get_ExtendedError(put_abi(value)));
    return value;
}

template <typename D> Windows::Services::Store::StoreUninstallStorePackageStatus consume_Windows_Services_Store_IStoreUninstallStorePackageResult<D>::Status() const
{
    Windows::Services::Store::StoreUninstallStorePackageStatus value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreUninstallStorePackageResult)->get_Status(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Uri consume_Windows_Services_Store_IStoreVideo<D>::Uri() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreVideo)->get_Uri(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Store_IStoreVideo<D>::VideoPurposeTag() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreVideo)->get_VideoPurposeTag(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Services_Store_IStoreVideo<D>::Width() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreVideo)->get_Width(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Services_Store_IStoreVideo<D>::Height() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreVideo)->get_Height(&value));
    return value;
}

template <typename D> hstring consume_Windows_Services_Store_IStoreVideo<D>::Caption() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreVideo)->get_Caption(put_abi(value)));
    return value;
}

template <typename D> Windows::Services::Store::StoreImage consume_Windows_Services_Store_IStoreVideo<D>::PreviewImage() const
{
    Windows::Services::Store::StoreImage value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Store::IStoreVideo)->get_PreviewImage(put_abi(value)));
    return value;
}

template <typename D>
struct produce<D, Windows::Services::Store::IStoreAcquireLicenseResult> : produce_base<D, Windows::Services::Store::IStoreAcquireLicenseResult>
{
    int32_t WINRT_CALL get_StorePackageLicense(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StorePackageLicense, WINRT_WRAP(Windows::Services::Store::StorePackageLicense));
            *value = detach_from<Windows::Services::Store::StorePackageLicense>(this->shim().StorePackageLicense());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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
struct produce<D, Windows::Services::Store::IStoreAppLicense> : produce_base<D, Windows::Services::Store::IStoreAppLicense>
{
    int32_t WINRT_CALL get_SkuStoreId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SkuStoreId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SkuStoreId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsActive(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsActive, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsActive());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsTrial(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsTrial, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsTrial());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExpirationDate(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExpirationDate, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().ExpirationDate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExtendedJsonData(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExtendedJsonData, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ExtendedJsonData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AddOnLicenses(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddOnLicenses, WINRT_WRAP(Windows::Foundation::Collections::IMapView<hstring, Windows::Services::Store::StoreLicense>));
            *value = detach_from<Windows::Foundation::Collections::IMapView<hstring, Windows::Services::Store::StoreLicense>>(this->shim().AddOnLicenses());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TrialTimeRemaining(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrialTimeRemaining, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().TrialTimeRemaining());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsTrialOwnedByThisUser(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsTrialOwnedByThisUser, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsTrialOwnedByThisUser());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TrialUniqueId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrialUniqueId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().TrialUniqueId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Store::IStoreAppLicense2> : produce_base<D, Windows::Services::Store::IStoreAppLicense2>
{
    int32_t WINRT_CALL get_IsDiscLicense(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDiscLicense, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsDiscLicense());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Store::IStoreAvailability> : produce_base<D, Windows::Services::Store::IStoreAvailability>
{
    int32_t WINRT_CALL get_StoreId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StoreId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().StoreId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EndDate(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EndDate, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().EndDate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Price(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Price, WINRT_WRAP(Windows::Services::Store::StorePrice));
            *value = detach_from<Windows::Services::Store::StorePrice>(this->shim().Price());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExtendedJsonData(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExtendedJsonData, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ExtendedJsonData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestPurchaseAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestPurchaseAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Services::Store::StorePurchaseResult>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Services::Store::StorePurchaseResult>>(this->shim().RequestPurchaseAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestPurchaseWithPurchasePropertiesAsync(void* storePurchaseProperties, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestPurchaseAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Services::Store::StorePurchaseResult>), Windows::Services::Store::StorePurchaseProperties const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Services::Store::StorePurchaseResult>>(this->shim().RequestPurchaseAsync(*reinterpret_cast<Windows::Services::Store::StorePurchaseProperties const*>(&storePurchaseProperties)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Store::IStoreCanAcquireLicenseResult> : produce_base<D, Windows::Services::Store::IStoreCanAcquireLicenseResult>
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

    int32_t WINRT_CALL get_LicensableSku(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LicensableSku, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().LicensableSku());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Status(Windows::Services::Store::StoreCanLicenseStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Services::Store::StoreCanLicenseStatus));
            *value = detach_from<Windows::Services::Store::StoreCanLicenseStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Store::IStoreCollectionData> : produce_base<D, Windows::Services::Store::IStoreCollectionData>
{
    int32_t WINRT_CALL get_IsTrial(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsTrial, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsTrial());
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

    int32_t WINRT_CALL get_DeveloperOfferId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeveloperOfferId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DeveloperOfferId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AcquiredDate(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AcquiredDate, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().AcquiredDate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StartDate(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartDate, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().StartDate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EndDate(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EndDate, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().EndDate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TrialTimeRemaining(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrialTimeRemaining, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().TrialTimeRemaining());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExtendedJsonData(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExtendedJsonData, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ExtendedJsonData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Store::IStoreConsumableResult> : produce_base<D, Windows::Services::Store::IStoreConsumableResult>
{
    int32_t WINRT_CALL get_Status(Windows::Services::Store::StoreConsumableStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Services::Store::StoreConsumableStatus));
            *value = detach_from<Windows::Services::Store::StoreConsumableStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TrackingId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrackingId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().TrackingId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BalanceRemaining(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BalanceRemaining, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().BalanceRemaining());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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
struct produce<D, Windows::Services::Store::IStoreContext> : produce_base<D, Windows::Services::Store::IStoreContext>
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

    int32_t WINRT_CALL add_OfflineLicensesChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OfflineLicensesChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Services::Store::StoreContext, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().OfflineLicensesChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Services::Store::StoreContext, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_OfflineLicensesChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(OfflineLicensesChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().OfflineLicensesChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL GetCustomerPurchaseIdAsync(void* serviceTicket, void* publisherUserId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCustomerPurchaseIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<hstring>), hstring const, hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<hstring>>(this->shim().GetCustomerPurchaseIdAsync(*reinterpret_cast<hstring const*>(&serviceTicket), *reinterpret_cast<hstring const*>(&publisherUserId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetCustomerCollectionsIdAsync(void* serviceTicket, void* publisherUserId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCustomerCollectionsIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<hstring>), hstring const, hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<hstring>>(this->shim().GetCustomerCollectionsIdAsync(*reinterpret_cast<hstring const*>(&serviceTicket), *reinterpret_cast<hstring const*>(&publisherUserId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetAppLicenseAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAppLicenseAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreAppLicense>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreAppLicense>>(this->shim().GetAppLicenseAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetStoreProductForCurrentAppAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetStoreProductForCurrentAppAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreProductResult>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreProductResult>>(this->shim().GetStoreProductForCurrentAppAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetStoreProductsAsync(void* productKinds, void* storeIds, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetStoreProductsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreProductQueryResult>), Windows::Foundation::Collections::IIterable<hstring> const, Windows::Foundation::Collections::IIterable<hstring> const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreProductQueryResult>>(this->shim().GetStoreProductsAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&productKinds), *reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&storeIds)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetAssociatedStoreProductsAsync(void* productKinds, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAssociatedStoreProductsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreProductQueryResult>), Windows::Foundation::Collections::IIterable<hstring> const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreProductQueryResult>>(this->shim().GetAssociatedStoreProductsAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&productKinds)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetAssociatedStoreProductsWithPagingAsync(void* productKinds, uint32_t maxItemsToRetrievePerPage, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAssociatedStoreProductsWithPagingAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreProductPagedQueryResult>), Windows::Foundation::Collections::IIterable<hstring> const, uint32_t);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreProductPagedQueryResult>>(this->shim().GetAssociatedStoreProductsWithPagingAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&productKinds), maxItemsToRetrievePerPage));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetUserCollectionAsync(void* productKinds, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetUserCollectionAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreProductQueryResult>), Windows::Foundation::Collections::IIterable<hstring> const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreProductQueryResult>>(this->shim().GetUserCollectionAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&productKinds)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetUserCollectionWithPagingAsync(void* productKinds, uint32_t maxItemsToRetrievePerPage, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetUserCollectionWithPagingAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreProductPagedQueryResult>), Windows::Foundation::Collections::IIterable<hstring> const, uint32_t);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreProductPagedQueryResult>>(this->shim().GetUserCollectionWithPagingAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&productKinds), maxItemsToRetrievePerPage));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReportConsumableFulfillmentAsync(void* productStoreId, uint32_t quantity, winrt::guid trackingId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportConsumableFulfillmentAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreConsumableResult>), hstring const, uint32_t, winrt::guid const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreConsumableResult>>(this->shim().ReportConsumableFulfillmentAsync(*reinterpret_cast<hstring const*>(&productStoreId), quantity, *reinterpret_cast<winrt::guid const*>(&trackingId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetConsumableBalanceRemainingAsync(void* productStoreId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetConsumableBalanceRemainingAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreConsumableResult>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreConsumableResult>>(this->shim().GetConsumableBalanceRemainingAsync(*reinterpret_cast<hstring const*>(&productStoreId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AcquireStoreLicenseForOptionalPackageAsync(void* optionalPackage, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AcquireStoreLicenseForOptionalPackageAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreAcquireLicenseResult>), Windows::ApplicationModel::Package const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreAcquireLicenseResult>>(this->shim().AcquireStoreLicenseForOptionalPackageAsync(*reinterpret_cast<Windows::ApplicationModel::Package const*>(&optionalPackage)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestPurchaseAsync(void* storeId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestPurchaseAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Services::Store::StorePurchaseResult>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Services::Store::StorePurchaseResult>>(this->shim().RequestPurchaseAsync(*reinterpret_cast<hstring const*>(&storeId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestPurchaseWithPurchasePropertiesAsync(void* storeId, void* storePurchaseProperties, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestPurchaseAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Services::Store::StorePurchaseResult>), hstring const, Windows::Services::Store::StorePurchaseProperties const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Services::Store::StorePurchaseResult>>(this->shim().RequestPurchaseAsync(*reinterpret_cast<hstring const*>(&storeId), *reinterpret_cast<Windows::Services::Store::StorePurchaseProperties const*>(&storePurchaseProperties)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetAppAndOptionalStorePackageUpdatesAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAppAndOptionalStorePackageUpdatesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Services::Store::StorePackageUpdate>>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Services::Store::StorePackageUpdate>>>(this->shim().GetAppAndOptionalStorePackageUpdatesAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestDownloadStorePackageUpdatesAsync(void* storePackageUpdates, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestDownloadStorePackageUpdatesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Services::Store::StorePackageUpdateResult, Windows::Services::Store::StorePackageUpdateStatus>), Windows::Foundation::Collections::IIterable<Windows::Services::Store::StorePackageUpdate> const);
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Services::Store::StorePackageUpdateResult, Windows::Services::Store::StorePackageUpdateStatus>>(this->shim().RequestDownloadStorePackageUpdatesAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Services::Store::StorePackageUpdate> const*>(&storePackageUpdates)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestDownloadAndInstallStorePackageUpdatesAsync(void* storePackageUpdates, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestDownloadAndInstallStorePackageUpdatesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Services::Store::StorePackageUpdateResult, Windows::Services::Store::StorePackageUpdateStatus>), Windows::Foundation::Collections::IIterable<Windows::Services::Store::StorePackageUpdate> const);
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Services::Store::StorePackageUpdateResult, Windows::Services::Store::StorePackageUpdateStatus>>(this->shim().RequestDownloadAndInstallStorePackageUpdatesAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Services::Store::StorePackageUpdate> const*>(&storePackageUpdates)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestDownloadAndInstallStorePackagesAsync(void* storeIds, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestDownloadAndInstallStorePackagesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Services::Store::StorePackageUpdateResult, Windows::Services::Store::StorePackageUpdateStatus>), Windows::Foundation::Collections::IIterable<hstring> const);
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Services::Store::StorePackageUpdateResult, Windows::Services::Store::StorePackageUpdateStatus>>(this->shim().RequestDownloadAndInstallStorePackagesAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&storeIds)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Store::IStoreContext2> : produce_base<D, Windows::Services::Store::IStoreContext2>
{
    int32_t WINRT_CALL FindStoreProductForPackageAsync(void* productKinds, void* package, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindStoreProductForPackageAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreProductResult>), Windows::Foundation::Collections::IIterable<hstring> const, Windows::ApplicationModel::Package const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreProductResult>>(this->shim().FindStoreProductForPackageAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&productKinds), *reinterpret_cast<Windows::ApplicationModel::Package const*>(&package)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Store::IStoreContext3> : produce_base<D, Windows::Services::Store::IStoreContext3>
{
    int32_t WINRT_CALL get_CanSilentlyDownloadStorePackageUpdates(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanSilentlyDownloadStorePackageUpdates, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanSilentlyDownloadStorePackageUpdates());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TrySilentDownloadStorePackageUpdatesAsync(void* storePackageUpdates, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrySilentDownloadStorePackageUpdatesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Services::Store::StorePackageUpdateResult, Windows::Services::Store::StorePackageUpdateStatus>), Windows::Foundation::Collections::IIterable<Windows::Services::Store::StorePackageUpdate> const);
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Services::Store::StorePackageUpdateResult, Windows::Services::Store::StorePackageUpdateStatus>>(this->shim().TrySilentDownloadStorePackageUpdatesAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Services::Store::StorePackageUpdate> const*>(&storePackageUpdates)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TrySilentDownloadAndInstallStorePackageUpdatesAsync(void* storePackageUpdates, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrySilentDownloadAndInstallStorePackageUpdatesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Services::Store::StorePackageUpdateResult, Windows::Services::Store::StorePackageUpdateStatus>), Windows::Foundation::Collections::IIterable<Windows::Services::Store::StorePackageUpdate> const);
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Services::Store::StorePackageUpdateResult, Windows::Services::Store::StorePackageUpdateStatus>>(this->shim().TrySilentDownloadAndInstallStorePackageUpdatesAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Services::Store::StorePackageUpdate> const*>(&storePackageUpdates)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CanAcquireStoreLicenseForOptionalPackageAsync(void* optionalPackage, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanAcquireStoreLicenseForOptionalPackageAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreCanAcquireLicenseResult>), Windows::ApplicationModel::Package const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreCanAcquireLicenseResult>>(this->shim().CanAcquireStoreLicenseForOptionalPackageAsync(*reinterpret_cast<Windows::ApplicationModel::Package const*>(&optionalPackage)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CanAcquireStoreLicenseAsync(void* productStoreId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanAcquireStoreLicenseAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreCanAcquireLicenseResult>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreCanAcquireLicenseResult>>(this->shim().CanAcquireStoreLicenseAsync(*reinterpret_cast<hstring const*>(&productStoreId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetStoreProductsWithOptionsAsync(void* productKinds, void* storeIds, void* storeProductOptions, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetStoreProductsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreProductQueryResult>), Windows::Foundation::Collections::IIterable<hstring> const, Windows::Foundation::Collections::IIterable<hstring> const, Windows::Services::Store::StoreProductOptions const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreProductQueryResult>>(this->shim().GetStoreProductsAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&productKinds), *reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&storeIds), *reinterpret_cast<Windows::Services::Store::StoreProductOptions const*>(&storeProductOptions)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetAssociatedStoreQueueItemsAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAssociatedStoreQueueItemsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Services::Store::StoreQueueItem>>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Services::Store::StoreQueueItem>>>(this->shim().GetAssociatedStoreQueueItemsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetStoreQueueItemsAsync(void* storeIds, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetStoreQueueItemsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Services::Store::StoreQueueItem>>), Windows::Foundation::Collections::IIterable<hstring> const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Services::Store::StoreQueueItem>>>(this->shim().GetStoreQueueItemsAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&storeIds)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestDownloadAndInstallStorePackagesWithInstallOptionsAsync(void* storeIds, void* storePackageInstallOptions, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestDownloadAndInstallStorePackagesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Services::Store::StorePackageUpdateResult, Windows::Services::Store::StorePackageUpdateStatus>), Windows::Foundation::Collections::IIterable<hstring> const, Windows::Services::Store::StorePackageInstallOptions const);
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Services::Store::StorePackageUpdateResult, Windows::Services::Store::StorePackageUpdateStatus>>(this->shim().RequestDownloadAndInstallStorePackagesAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&storeIds), *reinterpret_cast<Windows::Services::Store::StorePackageInstallOptions const*>(&storePackageInstallOptions)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DownloadAndInstallStorePackagesAsync(void* storeIds, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DownloadAndInstallStorePackagesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Services::Store::StorePackageUpdateResult, Windows::Services::Store::StorePackageUpdateStatus>), Windows::Foundation::Collections::IIterable<hstring> const);
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Services::Store::StorePackageUpdateResult, Windows::Services::Store::StorePackageUpdateStatus>>(this->shim().DownloadAndInstallStorePackagesAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&storeIds)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestUninstallStorePackageAsync(void* package, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestUninstallStorePackageAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreUninstallStorePackageResult>), Windows::ApplicationModel::Package const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreUninstallStorePackageResult>>(this->shim().RequestUninstallStorePackageAsync(*reinterpret_cast<Windows::ApplicationModel::Package const*>(&package)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestUninstallStorePackageByStoreIdAsync(void* storeId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestUninstallStorePackageByStoreIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreUninstallStorePackageResult>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreUninstallStorePackageResult>>(this->shim().RequestUninstallStorePackageByStoreIdAsync(*reinterpret_cast<hstring const*>(&storeId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UninstallStorePackageAsync(void* package, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UninstallStorePackageAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreUninstallStorePackageResult>), Windows::ApplicationModel::Package const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreUninstallStorePackageResult>>(this->shim().UninstallStorePackageAsync(*reinterpret_cast<Windows::ApplicationModel::Package const*>(&package)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UninstallStorePackageByStoreIdAsync(void* storeId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UninstallStorePackageByStoreIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreUninstallStorePackageResult>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreUninstallStorePackageResult>>(this->shim().UninstallStorePackageByStoreIdAsync(*reinterpret_cast<hstring const*>(&storeId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Store::IStoreContext4> : produce_base<D, Windows::Services::Store::IStoreContext4>
{
    int32_t WINRT_CALL RequestRateAndReviewAppAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestRateAndReviewAppAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreRateAndReviewResult>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreRateAndReviewResult>>(this->shim().RequestRateAndReviewAppAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetInstallOrderForAssociatedStoreQueueItemsAsync(void* items, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetInstallOrderForAssociatedStoreQueueItemsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Services::Store::StoreQueueItem>>), Windows::Foundation::Collections::IIterable<Windows::Services::Store::StoreQueueItem> const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Services::Store::StoreQueueItem>>>(this->shim().SetInstallOrderForAssociatedStoreQueueItemsAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Services::Store::StoreQueueItem> const*>(&items)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Store::IStoreContextStatics> : produce_base<D, Windows::Services::Store::IStoreContextStatics>
{
    int32_t WINRT_CALL GetDefault(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefault, WINRT_WRAP(Windows::Services::Store::StoreContext));
            *value = detach_from<Windows::Services::Store::StoreContext>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetForUser(void* user, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForUser, WINRT_WRAP(Windows::Services::Store::StoreContext), Windows::System::User const&);
            *value = detach_from<Windows::Services::Store::StoreContext>(this->shim().GetForUser(*reinterpret_cast<Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Store::IStoreImage> : produce_base<D, Windows::Services::Store::IStoreImage>
{
    int32_t WINRT_CALL get_Uri(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Uri, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().Uri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ImagePurposeTag(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ImagePurposeTag, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ImagePurposeTag());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Width(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Width, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Width());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Height(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Height, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Height());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Caption(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Caption, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Caption());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Store::IStoreLicense> : produce_base<D, Windows::Services::Store::IStoreLicense>
{
    int32_t WINRT_CALL get_SkuStoreId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SkuStoreId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SkuStoreId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsActive(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsActive, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsActive());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExpirationDate(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExpirationDate, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().ExpirationDate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExtendedJsonData(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExtendedJsonData, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ExtendedJsonData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InAppOfferToken(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InAppOfferToken, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().InAppOfferToken());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Store::IStorePackageInstallOptions> : produce_base<D, Windows::Services::Store::IStorePackageInstallOptions>
{
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
struct produce<D, Windows::Services::Store::IStorePackageLicense> : produce_base<D, Windows::Services::Store::IStorePackageLicense>
{
    int32_t WINRT_CALL add_LicenseLost(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LicenseLost, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Services::Store::StorePackageLicense, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().LicenseLost(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Services::Store::StorePackageLicense, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_LicenseLost(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(LicenseLost, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().LicenseLost(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL get_Package(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Package, WINRT_WRAP(Windows::ApplicationModel::Package));
            *value = detach_from<Windows::ApplicationModel::Package>(this->shim().Package());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsValid(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsValid, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsValid());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReleaseLicense() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReleaseLicense, WINRT_WRAP(void));
            this->shim().ReleaseLicense();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Store::IStorePackageUpdate> : produce_base<D, Windows::Services::Store::IStorePackageUpdate>
{
    int32_t WINRT_CALL get_Package(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Package, WINRT_WRAP(Windows::ApplicationModel::Package));
            *value = detach_from<Windows::ApplicationModel::Package>(this->shim().Package());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Mandatory(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Mandatory, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Mandatory());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Store::IStorePackageUpdateResult> : produce_base<D, Windows::Services::Store::IStorePackageUpdateResult>
{
    int32_t WINRT_CALL get_OverallState(Windows::Services::Store::StorePackageUpdateState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OverallState, WINRT_WRAP(Windows::Services::Store::StorePackageUpdateState));
            *value = detach_from<Windows::Services::Store::StorePackageUpdateState>(this->shim().OverallState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StorePackageUpdateStatuses(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StorePackageUpdateStatuses, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Services::Store::StorePackageUpdateStatus>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Services::Store::StorePackageUpdateStatus>>(this->shim().StorePackageUpdateStatuses());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Store::IStorePackageUpdateResult2> : produce_base<D, Windows::Services::Store::IStorePackageUpdateResult2>
{
    int32_t WINRT_CALL get_StoreQueueItems(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StoreQueueItems, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Services::Store::StoreQueueItem>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Services::Store::StoreQueueItem>>(this->shim().StoreQueueItems());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Store::IStorePrice> : produce_base<D, Windows::Services::Store::IStorePrice>
{
    int32_t WINRT_CALL get_FormattedBasePrice(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FormattedBasePrice, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().FormattedBasePrice());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FormattedPrice(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FormattedPrice, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().FormattedPrice());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsOnSale(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsOnSale, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsOnSale());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SaleEndDate(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SaleEndDate, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().SaleEndDate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CurrencyCode(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CurrencyCode, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().CurrencyCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FormattedRecurrencePrice(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FormattedRecurrencePrice, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().FormattedRecurrencePrice());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Store::IStoreProduct> : produce_base<D, Windows::Services::Store::IStoreProduct>
{
    int32_t WINRT_CALL get_StoreId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StoreId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().StoreId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Language(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Language, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Language());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Title(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Title, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Title());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Description(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Description, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Description());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProductKind(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProductKind, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ProductKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HasDigitalDownload(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HasDigitalDownload, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().HasDigitalDownload());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Keywords(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Keywords, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().Keywords());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Images(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Images, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Services::Store::StoreImage>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Services::Store::StoreImage>>(this->shim().Images());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Videos(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Videos, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Services::Store::StoreVideo>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Services::Store::StoreVideo>>(this->shim().Videos());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Skus(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Skus, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Services::Store::StoreSku>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Services::Store::StoreSku>>(this->shim().Skus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsInUserCollection(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsInUserCollection, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsInUserCollection());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Price(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Price, WINRT_WRAP(Windows::Services::Store::StorePrice));
            *value = detach_from<Windows::Services::Store::StorePrice>(this->shim().Price());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExtendedJsonData(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExtendedJsonData, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ExtendedJsonData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LinkUri(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LinkUri, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().LinkUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetIsAnySkuInstalledAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetIsAnySkuInstalledAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().GetIsAnySkuInstalledAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestPurchaseAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestPurchaseAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Services::Store::StorePurchaseResult>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Services::Store::StorePurchaseResult>>(this->shim().RequestPurchaseAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestPurchaseWithPurchasePropertiesAsync(void* storePurchaseProperties, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestPurchaseAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Services::Store::StorePurchaseResult>), Windows::Services::Store::StorePurchaseProperties const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Services::Store::StorePurchaseResult>>(this->shim().RequestPurchaseAsync(*reinterpret_cast<Windows::Services::Store::StorePurchaseProperties const*>(&storePurchaseProperties)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InAppOfferToken(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InAppOfferToken, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().InAppOfferToken());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Store::IStoreProductOptions> : produce_base<D, Windows::Services::Store::IStoreProductOptions>
{
    int32_t WINRT_CALL get_ActionFilters(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ActionFilters, WINRT_WRAP(Windows::Foundation::Collections::IVector<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVector<hstring>>(this->shim().ActionFilters());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Store::IStoreProductPagedQueryResult> : produce_base<D, Windows::Services::Store::IStoreProductPagedQueryResult>
{
    int32_t WINRT_CALL get_Products(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Products, WINRT_WRAP(Windows::Foundation::Collections::IMapView<hstring, Windows::Services::Store::StoreProduct>));
            *value = detach_from<Windows::Foundation::Collections::IMapView<hstring, Windows::Services::Store::StoreProduct>>(this->shim().Products());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HasMoreResults(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HasMoreResults, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().HasMoreResults());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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

    int32_t WINRT_CALL GetNextAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetNextAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreProductPagedQueryResult>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreProductPagedQueryResult>>(this->shim().GetNextAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Store::IStoreProductQueryResult> : produce_base<D, Windows::Services::Store::IStoreProductQueryResult>
{
    int32_t WINRT_CALL get_Products(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Products, WINRT_WRAP(Windows::Foundation::Collections::IMapView<hstring, Windows::Services::Store::StoreProduct>));
            *value = detach_from<Windows::Foundation::Collections::IMapView<hstring, Windows::Services::Store::StoreProduct>>(this->shim().Products());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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
struct produce<D, Windows::Services::Store::IStoreProductResult> : produce_base<D, Windows::Services::Store::IStoreProductResult>
{
    int32_t WINRT_CALL get_Product(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Product, WINRT_WRAP(Windows::Services::Store::StoreProduct));
            *value = detach_from<Windows::Services::Store::StoreProduct>(this->shim().Product());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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
struct produce<D, Windows::Services::Store::IStorePurchaseProperties> : produce_base<D, Windows::Services::Store::IStorePurchaseProperties>
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

    int32_t WINRT_CALL get_ExtendedJsonData(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExtendedJsonData, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ExtendedJsonData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ExtendedJsonData(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExtendedJsonData, WINRT_WRAP(void), hstring const&);
            this->shim().ExtendedJsonData(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Store::IStorePurchasePropertiesFactory> : produce_base<D, Windows::Services::Store::IStorePurchasePropertiesFactory>
{
    int32_t WINRT_CALL Create(void* name, void** storePurchaseProperties) noexcept final
    {
        try
        {
            *storePurchaseProperties = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Services::Store::StorePurchaseProperties), hstring const&);
            *storePurchaseProperties = detach_from<Windows::Services::Store::StorePurchaseProperties>(this->shim().Create(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Store::IStorePurchaseResult> : produce_base<D, Windows::Services::Store::IStorePurchaseResult>
{
    int32_t WINRT_CALL get_Status(Windows::Services::Store::StorePurchaseStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Services::Store::StorePurchaseStatus));
            *value = detach_from<Windows::Services::Store::StorePurchaseStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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
struct produce<D, Windows::Services::Store::IStoreQueueItem> : produce_base<D, Windows::Services::Store::IStoreQueueItem>
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

    int32_t WINRT_CALL get_InstallKind(Windows::Services::Store::StoreQueueItemKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InstallKind, WINRT_WRAP(Windows::Services::Store::StoreQueueItemKind));
            *value = detach_from<Windows::Services::Store::StoreQueueItemKind>(this->shim().InstallKind());
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
            WINRT_ASSERT_DECLARATION(GetCurrentStatus, WINRT_WRAP(Windows::Services::Store::StoreQueueItemStatus));
            *result = detach_from<Windows::Services::Store::StoreQueueItemStatus>(this->shim().GetCurrentStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_Completed(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Completed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Services::Store::StoreQueueItem, Windows::Services::Store::StoreQueueItemCompletedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Completed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Services::Store::StoreQueueItem, Windows::Services::Store::StoreQueueItemCompletedEventArgs> const*>(&handler)));
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
            WINRT_ASSERT_DECLARATION(StatusChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Services::Store::StoreQueueItem, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().StatusChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Services::Store::StoreQueueItem, Windows::Foundation::IInspectable> const*>(&handler)));
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
struct produce<D, Windows::Services::Store::IStoreQueueItem2> : produce_base<D, Windows::Services::Store::IStoreQueueItem2>
{
    int32_t WINRT_CALL CancelInstallAsync(void** action) noexcept final
    {
        try
        {
            *action = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CancelInstallAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *action = detach_from<Windows::Foundation::IAsyncAction>(this->shim().CancelInstallAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PauseInstallAsync(void** action) noexcept final
    {
        try
        {
            *action = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PauseInstallAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *action = detach_from<Windows::Foundation::IAsyncAction>(this->shim().PauseInstallAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ResumeInstallAsync(void** action) noexcept final
    {
        try
        {
            *action = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResumeInstallAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *action = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ResumeInstallAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Store::IStoreQueueItemCompletedEventArgs> : produce_base<D, Windows::Services::Store::IStoreQueueItemCompletedEventArgs>
{
    int32_t WINRT_CALL get_Status(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Services::Store::StoreQueueItemStatus));
            *value = detach_from<Windows::Services::Store::StoreQueueItemStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Store::IStoreQueueItemStatus> : produce_base<D, Windows::Services::Store::IStoreQueueItemStatus>
{
    int32_t WINRT_CALL get_PackageInstallState(Windows::Services::Store::StoreQueueItemState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PackageInstallState, WINRT_WRAP(Windows::Services::Store::StoreQueueItemState));
            *value = detach_from<Windows::Services::Store::StoreQueueItemState>(this->shim().PackageInstallState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PackageInstallExtendedState(Windows::Services::Store::StoreQueueItemExtendedState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PackageInstallExtendedState, WINRT_WRAP(Windows::Services::Store::StoreQueueItemExtendedState));
            *value = detach_from<Windows::Services::Store::StoreQueueItemExtendedState>(this->shim().PackageInstallExtendedState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UpdateStatus(struct struct_Windows_Services_Store_StorePackageUpdateStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpdateStatus, WINRT_WRAP(Windows::Services::Store::StorePackageUpdateStatus));
            *value = detach_from<Windows::Services::Store::StorePackageUpdateStatus>(this->shim().UpdateStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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
struct produce<D, Windows::Services::Store::IStoreRateAndReviewResult> : produce_base<D, Windows::Services::Store::IStoreRateAndReviewResult>
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

    int32_t WINRT_CALL get_ExtendedJsonData(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExtendedJsonData, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ExtendedJsonData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WasUpdated(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WasUpdated, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().WasUpdated());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Status(Windows::Services::Store::StoreRateAndReviewStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Services::Store::StoreRateAndReviewStatus));
            *value = detach_from<Windows::Services::Store::StoreRateAndReviewStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Store::IStoreRequestHelperStatics> : produce_base<D, Windows::Services::Store::IStoreRequestHelperStatics>
{
    int32_t WINRT_CALL SendRequestAsync(void* context, uint32_t requestKind, void* parametersAsJson, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SendRequestAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreSendRequestResult>), Windows::Services::Store::StoreContext const, uint32_t, hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreSendRequestResult>>(this->shim().SendRequestAsync(*reinterpret_cast<Windows::Services::Store::StoreContext const*>(&context), requestKind, *reinterpret_cast<hstring const*>(&parametersAsJson)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Store::IStoreSendRequestResult> : produce_base<D, Windows::Services::Store::IStoreSendRequestResult>
{
    int32_t WINRT_CALL get_Response(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Response, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Response());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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
struct produce<D, Windows::Services::Store::IStoreSendRequestResult2> : produce_base<D, Windows::Services::Store::IStoreSendRequestResult2>
{
    int32_t WINRT_CALL get_HttpStatusCode(Windows::Web::Http::HttpStatusCode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HttpStatusCode, WINRT_WRAP(Windows::Web::Http::HttpStatusCode));
            *value = detach_from<Windows::Web::Http::HttpStatusCode>(this->shim().HttpStatusCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Store::IStoreSku> : produce_base<D, Windows::Services::Store::IStoreSku>
{
    int32_t WINRT_CALL get_StoreId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StoreId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().StoreId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Language(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Language, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Language());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Title(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Title, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Title());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Description(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Description, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Description());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsTrial(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsTrial, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsTrial());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CustomDeveloperData(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CustomDeveloperData, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().CustomDeveloperData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Images(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Images, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Services::Store::StoreImage>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Services::Store::StoreImage>>(this->shim().Images());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Videos(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Videos, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Services::Store::StoreVideo>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Services::Store::StoreVideo>>(this->shim().Videos());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Availabilities(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Availabilities, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Services::Store::StoreAvailability>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Services::Store::StoreAvailability>>(this->shim().Availabilities());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Price(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Price, WINRT_WRAP(Windows::Services::Store::StorePrice));
            *value = detach_from<Windows::Services::Store::StorePrice>(this->shim().Price());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExtendedJsonData(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExtendedJsonData, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ExtendedJsonData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsInUserCollection(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsInUserCollection, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsInUserCollection());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BundledSkus(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BundledSkus, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().BundledSkus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CollectionData(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CollectionData, WINRT_WRAP(Windows::Services::Store::StoreCollectionData));
            *value = detach_from<Windows::Services::Store::StoreCollectionData>(this->shim().CollectionData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetIsInstalledAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetIsInstalledAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().GetIsInstalledAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestPurchaseAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestPurchaseAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Services::Store::StorePurchaseResult>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Services::Store::StorePurchaseResult>>(this->shim().RequestPurchaseAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestPurchaseWithPurchasePropertiesAsync(void* storePurchaseProperties, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestPurchaseAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Services::Store::StorePurchaseResult>), Windows::Services::Store::StorePurchaseProperties const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Services::Store::StorePurchaseResult>>(this->shim().RequestPurchaseAsync(*reinterpret_cast<Windows::Services::Store::StorePurchaseProperties const*>(&storePurchaseProperties)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsSubscription(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSubscription, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsSubscription());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SubscriptionInfo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SubscriptionInfo, WINRT_WRAP(Windows::Services::Store::StoreSubscriptionInfo));
            *value = detach_from<Windows::Services::Store::StoreSubscriptionInfo>(this->shim().SubscriptionInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Store::IStoreSubscriptionInfo> : produce_base<D, Windows::Services::Store::IStoreSubscriptionInfo>
{
    int32_t WINRT_CALL get_BillingPeriod(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BillingPeriod, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().BillingPeriod());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BillingPeriodUnit(Windows::Services::Store::StoreDurationUnit* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BillingPeriodUnit, WINRT_WRAP(Windows::Services::Store::StoreDurationUnit));
            *value = detach_from<Windows::Services::Store::StoreDurationUnit>(this->shim().BillingPeriodUnit());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HasTrialPeriod(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HasTrialPeriod, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().HasTrialPeriod());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TrialPeriod(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrialPeriod, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().TrialPeriod());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TrialPeriodUnit(Windows::Services::Store::StoreDurationUnit* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrialPeriodUnit, WINRT_WRAP(Windows::Services::Store::StoreDurationUnit));
            *value = detach_from<Windows::Services::Store::StoreDurationUnit>(this->shim().TrialPeriodUnit());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Store::IStoreUninstallStorePackageResult> : produce_base<D, Windows::Services::Store::IStoreUninstallStorePackageResult>
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

    int32_t WINRT_CALL get_Status(Windows::Services::Store::StoreUninstallStorePackageStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Services::Store::StoreUninstallStorePackageStatus));
            *value = detach_from<Windows::Services::Store::StoreUninstallStorePackageStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Store::IStoreVideo> : produce_base<D, Windows::Services::Store::IStoreVideo>
{
    int32_t WINRT_CALL get_Uri(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Uri, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().Uri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VideoPurposeTag(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoPurposeTag, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().VideoPurposeTag());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Width(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Width, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Width());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Height(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Height, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Height());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Caption(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Caption, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Caption());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PreviewImage(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PreviewImage, WINRT_WRAP(Windows::Services::Store::StoreImage));
            *value = detach_from<Windows::Services::Store::StoreImage>(this->shim().PreviewImage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Services::Store {

inline Windows::Services::Store::StoreContext StoreContext::GetDefault()
{
    return impl::call_factory<StoreContext, Windows::Services::Store::IStoreContextStatics>([&](auto&& f) { return f.GetDefault(); });
}

inline Windows::Services::Store::StoreContext StoreContext::GetForUser(Windows::System::User const& user)
{
    return impl::call_factory<StoreContext, Windows::Services::Store::IStoreContextStatics>([&](auto&& f) { return f.GetForUser(user); });
}

inline StorePackageInstallOptions::StorePackageInstallOptions() :
    StorePackageInstallOptions(impl::call_factory<StorePackageInstallOptions>([](auto&& f) { return f.template ActivateInstance<StorePackageInstallOptions>(); }))
{}

inline StoreProductOptions::StoreProductOptions() :
    StoreProductOptions(impl::call_factory<StoreProductOptions>([](auto&& f) { return f.template ActivateInstance<StoreProductOptions>(); }))
{}

inline StorePurchaseProperties::StorePurchaseProperties() :
    StorePurchaseProperties(impl::call_factory<StorePurchaseProperties>([](auto&& f) { return f.template ActivateInstance<StorePurchaseProperties>(); }))
{}

inline StorePurchaseProperties::StorePurchaseProperties(param::hstring const& name) :
    StorePurchaseProperties(impl::call_factory<StorePurchaseProperties, Windows::Services::Store::IStorePurchasePropertiesFactory>([&](auto&& f) { return f.Create(name); }))
{}

inline Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreSendRequestResult> StoreRequestHelper::SendRequestAsync(Windows::Services::Store::StoreContext const& context, uint32_t requestKind, param::hstring const& parametersAsJson)
{
    return impl::call_factory<StoreRequestHelper, Windows::Services::Store::IStoreRequestHelperStatics>([&](auto&& f) { return f.SendRequestAsync(context, requestKind, parametersAsJson); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Services::Store::IStoreAcquireLicenseResult> : winrt::impl::hash_base<winrt::Windows::Services::Store::IStoreAcquireLicenseResult> {};
template<> struct hash<winrt::Windows::Services::Store::IStoreAppLicense> : winrt::impl::hash_base<winrt::Windows::Services::Store::IStoreAppLicense> {};
template<> struct hash<winrt::Windows::Services::Store::IStoreAppLicense2> : winrt::impl::hash_base<winrt::Windows::Services::Store::IStoreAppLicense2> {};
template<> struct hash<winrt::Windows::Services::Store::IStoreAvailability> : winrt::impl::hash_base<winrt::Windows::Services::Store::IStoreAvailability> {};
template<> struct hash<winrt::Windows::Services::Store::IStoreCanAcquireLicenseResult> : winrt::impl::hash_base<winrt::Windows::Services::Store::IStoreCanAcquireLicenseResult> {};
template<> struct hash<winrt::Windows::Services::Store::IStoreCollectionData> : winrt::impl::hash_base<winrt::Windows::Services::Store::IStoreCollectionData> {};
template<> struct hash<winrt::Windows::Services::Store::IStoreConsumableResult> : winrt::impl::hash_base<winrt::Windows::Services::Store::IStoreConsumableResult> {};
template<> struct hash<winrt::Windows::Services::Store::IStoreContext> : winrt::impl::hash_base<winrt::Windows::Services::Store::IStoreContext> {};
template<> struct hash<winrt::Windows::Services::Store::IStoreContext2> : winrt::impl::hash_base<winrt::Windows::Services::Store::IStoreContext2> {};
template<> struct hash<winrt::Windows::Services::Store::IStoreContext3> : winrt::impl::hash_base<winrt::Windows::Services::Store::IStoreContext3> {};
template<> struct hash<winrt::Windows::Services::Store::IStoreContext4> : winrt::impl::hash_base<winrt::Windows::Services::Store::IStoreContext4> {};
template<> struct hash<winrt::Windows::Services::Store::IStoreContextStatics> : winrt::impl::hash_base<winrt::Windows::Services::Store::IStoreContextStatics> {};
template<> struct hash<winrt::Windows::Services::Store::IStoreImage> : winrt::impl::hash_base<winrt::Windows::Services::Store::IStoreImage> {};
template<> struct hash<winrt::Windows::Services::Store::IStoreLicense> : winrt::impl::hash_base<winrt::Windows::Services::Store::IStoreLicense> {};
template<> struct hash<winrt::Windows::Services::Store::IStorePackageInstallOptions> : winrt::impl::hash_base<winrt::Windows::Services::Store::IStorePackageInstallOptions> {};
template<> struct hash<winrt::Windows::Services::Store::IStorePackageLicense> : winrt::impl::hash_base<winrt::Windows::Services::Store::IStorePackageLicense> {};
template<> struct hash<winrt::Windows::Services::Store::IStorePackageUpdate> : winrt::impl::hash_base<winrt::Windows::Services::Store::IStorePackageUpdate> {};
template<> struct hash<winrt::Windows::Services::Store::IStorePackageUpdateResult> : winrt::impl::hash_base<winrt::Windows::Services::Store::IStorePackageUpdateResult> {};
template<> struct hash<winrt::Windows::Services::Store::IStorePackageUpdateResult2> : winrt::impl::hash_base<winrt::Windows::Services::Store::IStorePackageUpdateResult2> {};
template<> struct hash<winrt::Windows::Services::Store::IStorePrice> : winrt::impl::hash_base<winrt::Windows::Services::Store::IStorePrice> {};
template<> struct hash<winrt::Windows::Services::Store::IStoreProduct> : winrt::impl::hash_base<winrt::Windows::Services::Store::IStoreProduct> {};
template<> struct hash<winrt::Windows::Services::Store::IStoreProductOptions> : winrt::impl::hash_base<winrt::Windows::Services::Store::IStoreProductOptions> {};
template<> struct hash<winrt::Windows::Services::Store::IStoreProductPagedQueryResult> : winrt::impl::hash_base<winrt::Windows::Services::Store::IStoreProductPagedQueryResult> {};
template<> struct hash<winrt::Windows::Services::Store::IStoreProductQueryResult> : winrt::impl::hash_base<winrt::Windows::Services::Store::IStoreProductQueryResult> {};
template<> struct hash<winrt::Windows::Services::Store::IStoreProductResult> : winrt::impl::hash_base<winrt::Windows::Services::Store::IStoreProductResult> {};
template<> struct hash<winrt::Windows::Services::Store::IStorePurchaseProperties> : winrt::impl::hash_base<winrt::Windows::Services::Store::IStorePurchaseProperties> {};
template<> struct hash<winrt::Windows::Services::Store::IStorePurchasePropertiesFactory> : winrt::impl::hash_base<winrt::Windows::Services::Store::IStorePurchasePropertiesFactory> {};
template<> struct hash<winrt::Windows::Services::Store::IStorePurchaseResult> : winrt::impl::hash_base<winrt::Windows::Services::Store::IStorePurchaseResult> {};
template<> struct hash<winrt::Windows::Services::Store::IStoreQueueItem> : winrt::impl::hash_base<winrt::Windows::Services::Store::IStoreQueueItem> {};
template<> struct hash<winrt::Windows::Services::Store::IStoreQueueItem2> : winrt::impl::hash_base<winrt::Windows::Services::Store::IStoreQueueItem2> {};
template<> struct hash<winrt::Windows::Services::Store::IStoreQueueItemCompletedEventArgs> : winrt::impl::hash_base<winrt::Windows::Services::Store::IStoreQueueItemCompletedEventArgs> {};
template<> struct hash<winrt::Windows::Services::Store::IStoreQueueItemStatus> : winrt::impl::hash_base<winrt::Windows::Services::Store::IStoreQueueItemStatus> {};
template<> struct hash<winrt::Windows::Services::Store::IStoreRateAndReviewResult> : winrt::impl::hash_base<winrt::Windows::Services::Store::IStoreRateAndReviewResult> {};
template<> struct hash<winrt::Windows::Services::Store::IStoreRequestHelperStatics> : winrt::impl::hash_base<winrt::Windows::Services::Store::IStoreRequestHelperStatics> {};
template<> struct hash<winrt::Windows::Services::Store::IStoreSendRequestResult> : winrt::impl::hash_base<winrt::Windows::Services::Store::IStoreSendRequestResult> {};
template<> struct hash<winrt::Windows::Services::Store::IStoreSendRequestResult2> : winrt::impl::hash_base<winrt::Windows::Services::Store::IStoreSendRequestResult2> {};
template<> struct hash<winrt::Windows::Services::Store::IStoreSku> : winrt::impl::hash_base<winrt::Windows::Services::Store::IStoreSku> {};
template<> struct hash<winrt::Windows::Services::Store::IStoreSubscriptionInfo> : winrt::impl::hash_base<winrt::Windows::Services::Store::IStoreSubscriptionInfo> {};
template<> struct hash<winrt::Windows::Services::Store::IStoreUninstallStorePackageResult> : winrt::impl::hash_base<winrt::Windows::Services::Store::IStoreUninstallStorePackageResult> {};
template<> struct hash<winrt::Windows::Services::Store::IStoreVideo> : winrt::impl::hash_base<winrt::Windows::Services::Store::IStoreVideo> {};
template<> struct hash<winrt::Windows::Services::Store::StoreAcquireLicenseResult> : winrt::impl::hash_base<winrt::Windows::Services::Store::StoreAcquireLicenseResult> {};
template<> struct hash<winrt::Windows::Services::Store::StoreAppLicense> : winrt::impl::hash_base<winrt::Windows::Services::Store::StoreAppLicense> {};
template<> struct hash<winrt::Windows::Services::Store::StoreAvailability> : winrt::impl::hash_base<winrt::Windows::Services::Store::StoreAvailability> {};
template<> struct hash<winrt::Windows::Services::Store::StoreCanAcquireLicenseResult> : winrt::impl::hash_base<winrt::Windows::Services::Store::StoreCanAcquireLicenseResult> {};
template<> struct hash<winrt::Windows::Services::Store::StoreCollectionData> : winrt::impl::hash_base<winrt::Windows::Services::Store::StoreCollectionData> {};
template<> struct hash<winrt::Windows::Services::Store::StoreConsumableResult> : winrt::impl::hash_base<winrt::Windows::Services::Store::StoreConsumableResult> {};
template<> struct hash<winrt::Windows::Services::Store::StoreContext> : winrt::impl::hash_base<winrt::Windows::Services::Store::StoreContext> {};
template<> struct hash<winrt::Windows::Services::Store::StoreImage> : winrt::impl::hash_base<winrt::Windows::Services::Store::StoreImage> {};
template<> struct hash<winrt::Windows::Services::Store::StoreLicense> : winrt::impl::hash_base<winrt::Windows::Services::Store::StoreLicense> {};
template<> struct hash<winrt::Windows::Services::Store::StorePackageInstallOptions> : winrt::impl::hash_base<winrt::Windows::Services::Store::StorePackageInstallOptions> {};
template<> struct hash<winrt::Windows::Services::Store::StorePackageLicense> : winrt::impl::hash_base<winrt::Windows::Services::Store::StorePackageLicense> {};
template<> struct hash<winrt::Windows::Services::Store::StorePackageUpdate> : winrt::impl::hash_base<winrt::Windows::Services::Store::StorePackageUpdate> {};
template<> struct hash<winrt::Windows::Services::Store::StorePackageUpdateResult> : winrt::impl::hash_base<winrt::Windows::Services::Store::StorePackageUpdateResult> {};
template<> struct hash<winrt::Windows::Services::Store::StorePrice> : winrt::impl::hash_base<winrt::Windows::Services::Store::StorePrice> {};
template<> struct hash<winrt::Windows::Services::Store::StoreProduct> : winrt::impl::hash_base<winrt::Windows::Services::Store::StoreProduct> {};
template<> struct hash<winrt::Windows::Services::Store::StoreProductOptions> : winrt::impl::hash_base<winrt::Windows::Services::Store::StoreProductOptions> {};
template<> struct hash<winrt::Windows::Services::Store::StoreProductPagedQueryResult> : winrt::impl::hash_base<winrt::Windows::Services::Store::StoreProductPagedQueryResult> {};
template<> struct hash<winrt::Windows::Services::Store::StoreProductQueryResult> : winrt::impl::hash_base<winrt::Windows::Services::Store::StoreProductQueryResult> {};
template<> struct hash<winrt::Windows::Services::Store::StoreProductResult> : winrt::impl::hash_base<winrt::Windows::Services::Store::StoreProductResult> {};
template<> struct hash<winrt::Windows::Services::Store::StorePurchaseProperties> : winrt::impl::hash_base<winrt::Windows::Services::Store::StorePurchaseProperties> {};
template<> struct hash<winrt::Windows::Services::Store::StorePurchaseResult> : winrt::impl::hash_base<winrt::Windows::Services::Store::StorePurchaseResult> {};
template<> struct hash<winrt::Windows::Services::Store::StoreQueueItem> : winrt::impl::hash_base<winrt::Windows::Services::Store::StoreQueueItem> {};
template<> struct hash<winrt::Windows::Services::Store::StoreQueueItemCompletedEventArgs> : winrt::impl::hash_base<winrt::Windows::Services::Store::StoreQueueItemCompletedEventArgs> {};
template<> struct hash<winrt::Windows::Services::Store::StoreQueueItemStatus> : winrt::impl::hash_base<winrt::Windows::Services::Store::StoreQueueItemStatus> {};
template<> struct hash<winrt::Windows::Services::Store::StoreRateAndReviewResult> : winrt::impl::hash_base<winrt::Windows::Services::Store::StoreRateAndReviewResult> {};
template<> struct hash<winrt::Windows::Services::Store::StoreRequestHelper> : winrt::impl::hash_base<winrt::Windows::Services::Store::StoreRequestHelper> {};
template<> struct hash<winrt::Windows::Services::Store::StoreSendRequestResult> : winrt::impl::hash_base<winrt::Windows::Services::Store::StoreSendRequestResult> {};
template<> struct hash<winrt::Windows::Services::Store::StoreSku> : winrt::impl::hash_base<winrt::Windows::Services::Store::StoreSku> {};
template<> struct hash<winrt::Windows::Services::Store::StoreSubscriptionInfo> : winrt::impl::hash_base<winrt::Windows::Services::Store::StoreSubscriptionInfo> {};
template<> struct hash<winrt::Windows::Services::Store::StoreUninstallStorePackageResult> : winrt::impl::hash_base<winrt::Windows::Services::Store::StoreUninstallStorePackageResult> {};
template<> struct hash<winrt::Windows::Services::Store::StoreVideo> : winrt::impl::hash_base<winrt::Windows::Services::Store::StoreVideo> {};

}
