// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.ApplicationModel.0.h"
#include "winrt/impl/Windows.Foundation.0.h"
#include "winrt/impl/Windows.System.0.h"
#include "winrt/impl/Windows.Web.Http.0.h"
#include "winrt/impl/Windows.Services.Store.0.h"

WINRT_EXPORT namespace winrt::Windows::Services::Store {

struct WINRT_EBO IStoreAcquireLicenseResult :
    Windows::Foundation::IInspectable,
    impl::consume_t<IStoreAcquireLicenseResult>
{
    IStoreAcquireLicenseResult(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IStoreAppLicense :
    Windows::Foundation::IInspectable,
    impl::consume_t<IStoreAppLicense>
{
    IStoreAppLicense(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IStoreAppLicense2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IStoreAppLicense2>
{
    IStoreAppLicense2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IStoreAvailability :
    Windows::Foundation::IInspectable,
    impl::consume_t<IStoreAvailability>
{
    IStoreAvailability(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IStoreCanAcquireLicenseResult :
    Windows::Foundation::IInspectable,
    impl::consume_t<IStoreCanAcquireLicenseResult>
{
    IStoreCanAcquireLicenseResult(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IStoreCollectionData :
    Windows::Foundation::IInspectable,
    impl::consume_t<IStoreCollectionData>
{
    IStoreCollectionData(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IStoreConsumableResult :
    Windows::Foundation::IInspectable,
    impl::consume_t<IStoreConsumableResult>
{
    IStoreConsumableResult(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IStoreContext :
    Windows::Foundation::IInspectable,
    impl::consume_t<IStoreContext>
{
    IStoreContext(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IStoreContext2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IStoreContext2>
{
    IStoreContext2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IStoreContext3 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IStoreContext3>
{
    IStoreContext3(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IStoreContext4 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IStoreContext4>
{
    IStoreContext4(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IStoreContextStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IStoreContextStatics>
{
    IStoreContextStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IStoreImage :
    Windows::Foundation::IInspectable,
    impl::consume_t<IStoreImage>
{
    IStoreImage(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IStoreLicense :
    Windows::Foundation::IInspectable,
    impl::consume_t<IStoreLicense>
{
    IStoreLicense(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IStorePackageInstallOptions :
    Windows::Foundation::IInspectable,
    impl::consume_t<IStorePackageInstallOptions>
{
    IStorePackageInstallOptions(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IStorePackageLicense :
    Windows::Foundation::IInspectable,
    impl::consume_t<IStorePackageLicense>,
    impl::require<IStorePackageLicense, Windows::Foundation::IClosable>
{
    IStorePackageLicense(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IStorePackageUpdate :
    Windows::Foundation::IInspectable,
    impl::consume_t<IStorePackageUpdate>
{
    IStorePackageUpdate(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IStorePackageUpdateResult :
    Windows::Foundation::IInspectable,
    impl::consume_t<IStorePackageUpdateResult>
{
    IStorePackageUpdateResult(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IStorePackageUpdateResult2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IStorePackageUpdateResult2>
{
    IStorePackageUpdateResult2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IStorePrice :
    Windows::Foundation::IInspectable,
    impl::consume_t<IStorePrice>
{
    IStorePrice(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IStoreProduct :
    Windows::Foundation::IInspectable,
    impl::consume_t<IStoreProduct>
{
    IStoreProduct(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IStoreProductOptions :
    Windows::Foundation::IInspectable,
    impl::consume_t<IStoreProductOptions>
{
    IStoreProductOptions(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IStoreProductPagedQueryResult :
    Windows::Foundation::IInspectable,
    impl::consume_t<IStoreProductPagedQueryResult>
{
    IStoreProductPagedQueryResult(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IStoreProductQueryResult :
    Windows::Foundation::IInspectable,
    impl::consume_t<IStoreProductQueryResult>
{
    IStoreProductQueryResult(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IStoreProductResult :
    Windows::Foundation::IInspectable,
    impl::consume_t<IStoreProductResult>
{
    IStoreProductResult(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IStorePurchaseProperties :
    Windows::Foundation::IInspectable,
    impl::consume_t<IStorePurchaseProperties>
{
    IStorePurchaseProperties(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IStorePurchasePropertiesFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<IStorePurchasePropertiesFactory>
{
    IStorePurchasePropertiesFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IStorePurchaseResult :
    Windows::Foundation::IInspectable,
    impl::consume_t<IStorePurchaseResult>
{
    IStorePurchaseResult(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IStoreQueueItem :
    Windows::Foundation::IInspectable,
    impl::consume_t<IStoreQueueItem>
{
    IStoreQueueItem(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IStoreQueueItem2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IStoreQueueItem2>
{
    IStoreQueueItem2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IStoreQueueItemCompletedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IStoreQueueItemCompletedEventArgs>
{
    IStoreQueueItemCompletedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IStoreQueueItemStatus :
    Windows::Foundation::IInspectable,
    impl::consume_t<IStoreQueueItemStatus>
{
    IStoreQueueItemStatus(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IStoreRateAndReviewResult :
    Windows::Foundation::IInspectable,
    impl::consume_t<IStoreRateAndReviewResult>
{
    IStoreRateAndReviewResult(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IStoreRequestHelperStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IStoreRequestHelperStatics>
{
    IStoreRequestHelperStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IStoreSendRequestResult :
    Windows::Foundation::IInspectable,
    impl::consume_t<IStoreSendRequestResult>
{
    IStoreSendRequestResult(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IStoreSendRequestResult2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IStoreSendRequestResult2>
{
    IStoreSendRequestResult2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IStoreSku :
    Windows::Foundation::IInspectable,
    impl::consume_t<IStoreSku>
{
    IStoreSku(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IStoreSubscriptionInfo :
    Windows::Foundation::IInspectable,
    impl::consume_t<IStoreSubscriptionInfo>
{
    IStoreSubscriptionInfo(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IStoreUninstallStorePackageResult :
    Windows::Foundation::IInspectable,
    impl::consume_t<IStoreUninstallStorePackageResult>
{
    IStoreUninstallStorePackageResult(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IStoreVideo :
    Windows::Foundation::IInspectable,
    impl::consume_t<IStoreVideo>
{
    IStoreVideo(std::nullptr_t = nullptr) noexcept {}
};

}
