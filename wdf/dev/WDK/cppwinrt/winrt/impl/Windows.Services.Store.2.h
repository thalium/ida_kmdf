// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.ApplicationModel.1.h"
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.System.1.h"
#include "winrt/impl/Windows.Web.Http.1.h"
#include "winrt/impl/Windows.Services.Store.1.h"

WINRT_EXPORT namespace winrt::Windows::Services::Store {

struct StorePackageUpdateStatus
{
    hstring PackageFamilyName;
    uint64_t PackageDownloadSizeInBytes;
    uint64_t PackageBytesDownloaded;
    double PackageDownloadProgress;
    double TotalDownloadProgress;
    Windows::Services::Store::StorePackageUpdateState PackageUpdateState;
};

inline bool operator==(StorePackageUpdateStatus const& left, StorePackageUpdateStatus const& right) noexcept
{
    return left.PackageFamilyName == right.PackageFamilyName && left.PackageDownloadSizeInBytes == right.PackageDownloadSizeInBytes && left.PackageBytesDownloaded == right.PackageBytesDownloaded && left.PackageDownloadProgress == right.PackageDownloadProgress && left.TotalDownloadProgress == right.TotalDownloadProgress && left.PackageUpdateState == right.PackageUpdateState;
}

inline bool operator!=(StorePackageUpdateStatus const& left, StorePackageUpdateStatus const& right) noexcept
{
    return !(left == right);
}

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::Services::Store {

struct WINRT_EBO StoreAcquireLicenseResult :
    Windows::Services::Store::IStoreAcquireLicenseResult
{
    StoreAcquireLicenseResult(std::nullptr_t) noexcept {}
};

struct WINRT_EBO StoreAppLicense :
    Windows::Services::Store::IStoreAppLicense,
    impl::require<StoreAppLicense, Windows::Services::Store::IStoreAppLicense2>
{
    StoreAppLicense(std::nullptr_t) noexcept {}
};

struct WINRT_EBO StoreAvailability :
    Windows::Services::Store::IStoreAvailability
{
    StoreAvailability(std::nullptr_t) noexcept {}
};

struct WINRT_EBO StoreCanAcquireLicenseResult :
    Windows::Services::Store::IStoreCanAcquireLicenseResult
{
    StoreCanAcquireLicenseResult(std::nullptr_t) noexcept {}
};

struct WINRT_EBO StoreCollectionData :
    Windows::Services::Store::IStoreCollectionData
{
    StoreCollectionData(std::nullptr_t) noexcept {}
};

struct WINRT_EBO StoreConsumableResult :
    Windows::Services::Store::IStoreConsumableResult
{
    StoreConsumableResult(std::nullptr_t) noexcept {}
};

struct WINRT_EBO StoreContext :
    Windows::Services::Store::IStoreContext,
    impl::require<StoreContext, Windows::Services::Store::IStoreContext2, Windows::Services::Store::IStoreContext3, Windows::Services::Store::IStoreContext4>
{
    StoreContext(std::nullptr_t) noexcept {}
    using impl::consume_t<StoreContext, Windows::Services::Store::IStoreContext3>::GetStoreProductsAsync;
    using Windows::Services::Store::IStoreContext::GetStoreProductsAsync;
    using impl::consume_t<StoreContext, Windows::Services::Store::IStoreContext3>::RequestDownloadAndInstallStorePackagesAsync;
    using Windows::Services::Store::IStoreContext::RequestDownloadAndInstallStorePackagesAsync;
    static Windows::Services::Store::StoreContext GetDefault();
    static Windows::Services::Store::StoreContext GetForUser(Windows::System::User const& user);
};

struct WINRT_EBO StoreImage :
    Windows::Services::Store::IStoreImage
{
    StoreImage(std::nullptr_t) noexcept {}
};

struct WINRT_EBO StoreLicense :
    Windows::Services::Store::IStoreLicense
{
    StoreLicense(std::nullptr_t) noexcept {}
};

struct WINRT_EBO StorePackageInstallOptions :
    Windows::Services::Store::IStorePackageInstallOptions
{
    StorePackageInstallOptions(std::nullptr_t) noexcept {}
    StorePackageInstallOptions();
};

struct WINRT_EBO StorePackageLicense :
    Windows::Services::Store::IStorePackageLicense
{
    StorePackageLicense(std::nullptr_t) noexcept {}
};

struct WINRT_EBO StorePackageUpdate :
    Windows::Services::Store::IStorePackageUpdate
{
    StorePackageUpdate(std::nullptr_t) noexcept {}
};

struct WINRT_EBO StorePackageUpdateResult :
    Windows::Services::Store::IStorePackageUpdateResult,
    impl::require<StorePackageUpdateResult, Windows::Services::Store::IStorePackageUpdateResult2>
{
    StorePackageUpdateResult(std::nullptr_t) noexcept {}
};

struct WINRT_EBO StorePrice :
    Windows::Services::Store::IStorePrice
{
    StorePrice(std::nullptr_t) noexcept {}
};

struct WINRT_EBO StoreProduct :
    Windows::Services::Store::IStoreProduct
{
    StoreProduct(std::nullptr_t) noexcept {}
};

struct WINRT_EBO StoreProductOptions :
    Windows::Services::Store::IStoreProductOptions
{
    StoreProductOptions(std::nullptr_t) noexcept {}
    StoreProductOptions();
};

struct WINRT_EBO StoreProductPagedQueryResult :
    Windows::Services::Store::IStoreProductPagedQueryResult
{
    StoreProductPagedQueryResult(std::nullptr_t) noexcept {}
};

struct WINRT_EBO StoreProductQueryResult :
    Windows::Services::Store::IStoreProductQueryResult
{
    StoreProductQueryResult(std::nullptr_t) noexcept {}
};

struct WINRT_EBO StoreProductResult :
    Windows::Services::Store::IStoreProductResult
{
    StoreProductResult(std::nullptr_t) noexcept {}
};

struct WINRT_EBO StorePurchaseProperties :
    Windows::Services::Store::IStorePurchaseProperties
{
    StorePurchaseProperties(std::nullptr_t) noexcept {}
    StorePurchaseProperties();
    StorePurchaseProperties(param::hstring const& name);
};

struct WINRT_EBO StorePurchaseResult :
    Windows::Services::Store::IStorePurchaseResult
{
    StorePurchaseResult(std::nullptr_t) noexcept {}
};

struct WINRT_EBO StoreQueueItem :
    Windows::Services::Store::IStoreQueueItem,
    impl::require<StoreQueueItem, Windows::Services::Store::IStoreQueueItem2>
{
    StoreQueueItem(std::nullptr_t) noexcept {}
};

struct WINRT_EBO StoreQueueItemCompletedEventArgs :
    Windows::Services::Store::IStoreQueueItemCompletedEventArgs
{
    StoreQueueItemCompletedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO StoreQueueItemStatus :
    Windows::Services::Store::IStoreQueueItemStatus
{
    StoreQueueItemStatus(std::nullptr_t) noexcept {}
};

struct WINRT_EBO StoreRateAndReviewResult :
    Windows::Services::Store::IStoreRateAndReviewResult
{
    StoreRateAndReviewResult(std::nullptr_t) noexcept {}
};

struct StoreRequestHelper
{
    StoreRequestHelper() = delete;
    static Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreSendRequestResult> SendRequestAsync(Windows::Services::Store::StoreContext const& context, uint32_t requestKind, param::hstring const& parametersAsJson);
};

struct WINRT_EBO StoreSendRequestResult :
    Windows::Services::Store::IStoreSendRequestResult,
    impl::require<StoreSendRequestResult, Windows::Services::Store::IStoreSendRequestResult2>
{
    StoreSendRequestResult(std::nullptr_t) noexcept {}
};

struct WINRT_EBO StoreSku :
    Windows::Services::Store::IStoreSku
{
    StoreSku(std::nullptr_t) noexcept {}
};

struct WINRT_EBO StoreSubscriptionInfo :
    Windows::Services::Store::IStoreSubscriptionInfo
{
    StoreSubscriptionInfo(std::nullptr_t) noexcept {}
};

struct WINRT_EBO StoreUninstallStorePackageResult :
    Windows::Services::Store::IStoreUninstallStorePackageResult
{
    StoreUninstallStorePackageResult(std::nullptr_t) noexcept {}
};

struct WINRT_EBO StoreVideo :
    Windows::Services::Store::IStoreVideo
{
    StoreVideo(std::nullptr_t) noexcept {}
};

}
