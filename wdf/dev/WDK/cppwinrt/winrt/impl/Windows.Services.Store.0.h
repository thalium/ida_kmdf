// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::ApplicationModel {

struct Package;

}

WINRT_EXPORT namespace winrt::Windows::Foundation {

struct Uri;

}

WINRT_EXPORT namespace winrt::Windows::System {

struct User;

}

WINRT_EXPORT namespace winrt::Windows::Web::Http {

enum class HttpStatusCode;

}

WINRT_EXPORT namespace winrt::Windows::Services::Store {

enum class StoreCanLicenseStatus : int32_t
{
    NotLicensableToUser = 0,
    Licensable = 1,
    LicenseActionNotApplicableToProduct = 2,
    NetworkError = 3,
    ServerError = 4,
};

enum class StoreConsumableStatus : int32_t
{
    Succeeded = 0,
    InsufficentQuantity = 1,
    NetworkError = 2,
    ServerError = 3,
};

enum class StoreDurationUnit : int32_t
{
    Minute = 0,
    Hour = 1,
    Day = 2,
    Week = 3,
    Month = 4,
    Year = 5,
};

enum class StorePackageUpdateState : int32_t
{
    Pending = 0,
    Downloading = 1,
    Deploying = 2,
    Completed = 3,
    Canceled = 4,
    OtherError = 5,
    ErrorLowBattery = 6,
    ErrorWiFiRecommended = 7,
    ErrorWiFiRequired = 8,
};

enum class StorePurchaseStatus : int32_t
{
    Succeeded = 0,
    AlreadyPurchased = 1,
    NotPurchased = 2,
    NetworkError = 3,
    ServerError = 4,
};

enum class StoreQueueItemExtendedState : int32_t
{
    ActivePending = 0,
    ActiveStarting = 1,
    ActiveAcquiringLicense = 2,
    ActiveDownloading = 3,
    ActiveRestoringData = 4,
    ActiveInstalling = 5,
    Completed = 6,
    Canceled = 7,
    Paused = 8,
    Error = 9,
    PausedPackagesInUse = 10,
    PausedLowBattery = 11,
    PausedWiFiRecommended = 12,
    PausedWiFiRequired = 13,
    PausedReadyToInstall = 14,
};

enum class StoreQueueItemKind : int32_t
{
    Install = 0,
    Update = 1,
    Repair = 2,
};

enum class StoreQueueItemState : int32_t
{
    Active = 0,
    Completed = 1,
    Canceled = 2,
    Error = 3,
    Paused = 4,
};

enum class StoreRateAndReviewStatus : int32_t
{
    Succeeded = 0,
    CanceledByUser = 1,
    NetworkError = 2,
    Error = 3,
};

enum class StoreUninstallStorePackageStatus : int32_t
{
    Succeeded = 0,
    CanceledByUser = 1,
    NetworkError = 2,
    UninstallNotApplicable = 3,
    Error = 4,
};

struct IStoreAcquireLicenseResult;
struct IStoreAppLicense;
struct IStoreAppLicense2;
struct IStoreAvailability;
struct IStoreCanAcquireLicenseResult;
struct IStoreCollectionData;
struct IStoreConsumableResult;
struct IStoreContext;
struct IStoreContext2;
struct IStoreContext3;
struct IStoreContext4;
struct IStoreContextStatics;
struct IStoreImage;
struct IStoreLicense;
struct IStorePackageInstallOptions;
struct IStorePackageLicense;
struct IStorePackageUpdate;
struct IStorePackageUpdateResult;
struct IStorePackageUpdateResult2;
struct IStorePrice;
struct IStoreProduct;
struct IStoreProductOptions;
struct IStoreProductPagedQueryResult;
struct IStoreProductQueryResult;
struct IStoreProductResult;
struct IStorePurchaseProperties;
struct IStorePurchasePropertiesFactory;
struct IStorePurchaseResult;
struct IStoreQueueItem;
struct IStoreQueueItem2;
struct IStoreQueueItemCompletedEventArgs;
struct IStoreQueueItemStatus;
struct IStoreRateAndReviewResult;
struct IStoreRequestHelperStatics;
struct IStoreSendRequestResult;
struct IStoreSendRequestResult2;
struct IStoreSku;
struct IStoreSubscriptionInfo;
struct IStoreUninstallStorePackageResult;
struct IStoreVideo;
struct StoreAcquireLicenseResult;
struct StoreAppLicense;
struct StoreAvailability;
struct StoreCanAcquireLicenseResult;
struct StoreCollectionData;
struct StoreConsumableResult;
struct StoreContext;
struct StoreImage;
struct StoreLicense;
struct StorePackageInstallOptions;
struct StorePackageLicense;
struct StorePackageUpdate;
struct StorePackageUpdateResult;
struct StorePrice;
struct StoreProduct;
struct StoreProductOptions;
struct StoreProductPagedQueryResult;
struct StoreProductQueryResult;
struct StoreProductResult;
struct StorePurchaseProperties;
struct StorePurchaseResult;
struct StoreQueueItem;
struct StoreQueueItemCompletedEventArgs;
struct StoreQueueItemStatus;
struct StoreRateAndReviewResult;
struct StoreRequestHelper;
struct StoreSendRequestResult;
struct StoreSku;
struct StoreSubscriptionInfo;
struct StoreUninstallStorePackageResult;
struct StoreVideo;
struct StorePackageUpdateStatus;

}

namespace winrt::impl {

template <> struct category<Windows::Services::Store::IStoreAcquireLicenseResult>{ using type = interface_category; };
template <> struct category<Windows::Services::Store::IStoreAppLicense>{ using type = interface_category; };
template <> struct category<Windows::Services::Store::IStoreAppLicense2>{ using type = interface_category; };
template <> struct category<Windows::Services::Store::IStoreAvailability>{ using type = interface_category; };
template <> struct category<Windows::Services::Store::IStoreCanAcquireLicenseResult>{ using type = interface_category; };
template <> struct category<Windows::Services::Store::IStoreCollectionData>{ using type = interface_category; };
template <> struct category<Windows::Services::Store::IStoreConsumableResult>{ using type = interface_category; };
template <> struct category<Windows::Services::Store::IStoreContext>{ using type = interface_category; };
template <> struct category<Windows::Services::Store::IStoreContext2>{ using type = interface_category; };
template <> struct category<Windows::Services::Store::IStoreContext3>{ using type = interface_category; };
template <> struct category<Windows::Services::Store::IStoreContext4>{ using type = interface_category; };
template <> struct category<Windows::Services::Store::IStoreContextStatics>{ using type = interface_category; };
template <> struct category<Windows::Services::Store::IStoreImage>{ using type = interface_category; };
template <> struct category<Windows::Services::Store::IStoreLicense>{ using type = interface_category; };
template <> struct category<Windows::Services::Store::IStorePackageInstallOptions>{ using type = interface_category; };
template <> struct category<Windows::Services::Store::IStorePackageLicense>{ using type = interface_category; };
template <> struct category<Windows::Services::Store::IStorePackageUpdate>{ using type = interface_category; };
template <> struct category<Windows::Services::Store::IStorePackageUpdateResult>{ using type = interface_category; };
template <> struct category<Windows::Services::Store::IStorePackageUpdateResult2>{ using type = interface_category; };
template <> struct category<Windows::Services::Store::IStorePrice>{ using type = interface_category; };
template <> struct category<Windows::Services::Store::IStoreProduct>{ using type = interface_category; };
template <> struct category<Windows::Services::Store::IStoreProductOptions>{ using type = interface_category; };
template <> struct category<Windows::Services::Store::IStoreProductPagedQueryResult>{ using type = interface_category; };
template <> struct category<Windows::Services::Store::IStoreProductQueryResult>{ using type = interface_category; };
template <> struct category<Windows::Services::Store::IStoreProductResult>{ using type = interface_category; };
template <> struct category<Windows::Services::Store::IStorePurchaseProperties>{ using type = interface_category; };
template <> struct category<Windows::Services::Store::IStorePurchasePropertiesFactory>{ using type = interface_category; };
template <> struct category<Windows::Services::Store::IStorePurchaseResult>{ using type = interface_category; };
template <> struct category<Windows::Services::Store::IStoreQueueItem>{ using type = interface_category; };
template <> struct category<Windows::Services::Store::IStoreQueueItem2>{ using type = interface_category; };
template <> struct category<Windows::Services::Store::IStoreQueueItemCompletedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Services::Store::IStoreQueueItemStatus>{ using type = interface_category; };
template <> struct category<Windows::Services::Store::IStoreRateAndReviewResult>{ using type = interface_category; };
template <> struct category<Windows::Services::Store::IStoreRequestHelperStatics>{ using type = interface_category; };
template <> struct category<Windows::Services::Store::IStoreSendRequestResult>{ using type = interface_category; };
template <> struct category<Windows::Services::Store::IStoreSendRequestResult2>{ using type = interface_category; };
template <> struct category<Windows::Services::Store::IStoreSku>{ using type = interface_category; };
template <> struct category<Windows::Services::Store::IStoreSubscriptionInfo>{ using type = interface_category; };
template <> struct category<Windows::Services::Store::IStoreUninstallStorePackageResult>{ using type = interface_category; };
template <> struct category<Windows::Services::Store::IStoreVideo>{ using type = interface_category; };
template <> struct category<Windows::Services::Store::StoreAcquireLicenseResult>{ using type = class_category; };
template <> struct category<Windows::Services::Store::StoreAppLicense>{ using type = class_category; };
template <> struct category<Windows::Services::Store::StoreAvailability>{ using type = class_category; };
template <> struct category<Windows::Services::Store::StoreCanAcquireLicenseResult>{ using type = class_category; };
template <> struct category<Windows::Services::Store::StoreCollectionData>{ using type = class_category; };
template <> struct category<Windows::Services::Store::StoreConsumableResult>{ using type = class_category; };
template <> struct category<Windows::Services::Store::StoreContext>{ using type = class_category; };
template <> struct category<Windows::Services::Store::StoreImage>{ using type = class_category; };
template <> struct category<Windows::Services::Store::StoreLicense>{ using type = class_category; };
template <> struct category<Windows::Services::Store::StorePackageInstallOptions>{ using type = class_category; };
template <> struct category<Windows::Services::Store::StorePackageLicense>{ using type = class_category; };
template <> struct category<Windows::Services::Store::StorePackageUpdate>{ using type = class_category; };
template <> struct category<Windows::Services::Store::StorePackageUpdateResult>{ using type = class_category; };
template <> struct category<Windows::Services::Store::StorePrice>{ using type = class_category; };
template <> struct category<Windows::Services::Store::StoreProduct>{ using type = class_category; };
template <> struct category<Windows::Services::Store::StoreProductOptions>{ using type = class_category; };
template <> struct category<Windows::Services::Store::StoreProductPagedQueryResult>{ using type = class_category; };
template <> struct category<Windows::Services::Store::StoreProductQueryResult>{ using type = class_category; };
template <> struct category<Windows::Services::Store::StoreProductResult>{ using type = class_category; };
template <> struct category<Windows::Services::Store::StorePurchaseProperties>{ using type = class_category; };
template <> struct category<Windows::Services::Store::StorePurchaseResult>{ using type = class_category; };
template <> struct category<Windows::Services::Store::StoreQueueItem>{ using type = class_category; };
template <> struct category<Windows::Services::Store::StoreQueueItemCompletedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Services::Store::StoreQueueItemStatus>{ using type = class_category; };
template <> struct category<Windows::Services::Store::StoreRateAndReviewResult>{ using type = class_category; };
template <> struct category<Windows::Services::Store::StoreRequestHelper>{ using type = class_category; };
template <> struct category<Windows::Services::Store::StoreSendRequestResult>{ using type = class_category; };
template <> struct category<Windows::Services::Store::StoreSku>{ using type = class_category; };
template <> struct category<Windows::Services::Store::StoreSubscriptionInfo>{ using type = class_category; };
template <> struct category<Windows::Services::Store::StoreUninstallStorePackageResult>{ using type = class_category; };
template <> struct category<Windows::Services::Store::StoreVideo>{ using type = class_category; };
template <> struct category<Windows::Services::Store::StoreCanLicenseStatus>{ using type = enum_category; };
template <> struct category<Windows::Services::Store::StoreConsumableStatus>{ using type = enum_category; };
template <> struct category<Windows::Services::Store::StoreDurationUnit>{ using type = enum_category; };
template <> struct category<Windows::Services::Store::StorePackageUpdateState>{ using type = enum_category; };
template <> struct category<Windows::Services::Store::StorePurchaseStatus>{ using type = enum_category; };
template <> struct category<Windows::Services::Store::StoreQueueItemExtendedState>{ using type = enum_category; };
template <> struct category<Windows::Services::Store::StoreQueueItemKind>{ using type = enum_category; };
template <> struct category<Windows::Services::Store::StoreQueueItemState>{ using type = enum_category; };
template <> struct category<Windows::Services::Store::StoreRateAndReviewStatus>{ using type = enum_category; };
template <> struct category<Windows::Services::Store::StoreUninstallStorePackageStatus>{ using type = enum_category; };
template <> struct category<Windows::Services::Store::StorePackageUpdateStatus>{ using type = struct_category<hstring,uint64_t,uint64_t,double,double,Windows::Services::Store::StorePackageUpdateState>; };
template <> struct name<Windows::Services::Store::IStoreAcquireLicenseResult>{ static constexpr auto & value{ L"Windows.Services.Store.IStoreAcquireLicenseResult" }; };
template <> struct name<Windows::Services::Store::IStoreAppLicense>{ static constexpr auto & value{ L"Windows.Services.Store.IStoreAppLicense" }; };
template <> struct name<Windows::Services::Store::IStoreAppLicense2>{ static constexpr auto & value{ L"Windows.Services.Store.IStoreAppLicense2" }; };
template <> struct name<Windows::Services::Store::IStoreAvailability>{ static constexpr auto & value{ L"Windows.Services.Store.IStoreAvailability" }; };
template <> struct name<Windows::Services::Store::IStoreCanAcquireLicenseResult>{ static constexpr auto & value{ L"Windows.Services.Store.IStoreCanAcquireLicenseResult" }; };
template <> struct name<Windows::Services::Store::IStoreCollectionData>{ static constexpr auto & value{ L"Windows.Services.Store.IStoreCollectionData" }; };
template <> struct name<Windows::Services::Store::IStoreConsumableResult>{ static constexpr auto & value{ L"Windows.Services.Store.IStoreConsumableResult" }; };
template <> struct name<Windows::Services::Store::IStoreContext>{ static constexpr auto & value{ L"Windows.Services.Store.IStoreContext" }; };
template <> struct name<Windows::Services::Store::IStoreContext2>{ static constexpr auto & value{ L"Windows.Services.Store.IStoreContext2" }; };
template <> struct name<Windows::Services::Store::IStoreContext3>{ static constexpr auto & value{ L"Windows.Services.Store.IStoreContext3" }; };
template <> struct name<Windows::Services::Store::IStoreContext4>{ static constexpr auto & value{ L"Windows.Services.Store.IStoreContext4" }; };
template <> struct name<Windows::Services::Store::IStoreContextStatics>{ static constexpr auto & value{ L"Windows.Services.Store.IStoreContextStatics" }; };
template <> struct name<Windows::Services::Store::IStoreImage>{ static constexpr auto & value{ L"Windows.Services.Store.IStoreImage" }; };
template <> struct name<Windows::Services::Store::IStoreLicense>{ static constexpr auto & value{ L"Windows.Services.Store.IStoreLicense" }; };
template <> struct name<Windows::Services::Store::IStorePackageInstallOptions>{ static constexpr auto & value{ L"Windows.Services.Store.IStorePackageInstallOptions" }; };
template <> struct name<Windows::Services::Store::IStorePackageLicense>{ static constexpr auto & value{ L"Windows.Services.Store.IStorePackageLicense" }; };
template <> struct name<Windows::Services::Store::IStorePackageUpdate>{ static constexpr auto & value{ L"Windows.Services.Store.IStorePackageUpdate" }; };
template <> struct name<Windows::Services::Store::IStorePackageUpdateResult>{ static constexpr auto & value{ L"Windows.Services.Store.IStorePackageUpdateResult" }; };
template <> struct name<Windows::Services::Store::IStorePackageUpdateResult2>{ static constexpr auto & value{ L"Windows.Services.Store.IStorePackageUpdateResult2" }; };
template <> struct name<Windows::Services::Store::IStorePrice>{ static constexpr auto & value{ L"Windows.Services.Store.IStorePrice" }; };
template <> struct name<Windows::Services::Store::IStoreProduct>{ static constexpr auto & value{ L"Windows.Services.Store.IStoreProduct" }; };
template <> struct name<Windows::Services::Store::IStoreProductOptions>{ static constexpr auto & value{ L"Windows.Services.Store.IStoreProductOptions" }; };
template <> struct name<Windows::Services::Store::IStoreProductPagedQueryResult>{ static constexpr auto & value{ L"Windows.Services.Store.IStoreProductPagedQueryResult" }; };
template <> struct name<Windows::Services::Store::IStoreProductQueryResult>{ static constexpr auto & value{ L"Windows.Services.Store.IStoreProductQueryResult" }; };
template <> struct name<Windows::Services::Store::IStoreProductResult>{ static constexpr auto & value{ L"Windows.Services.Store.IStoreProductResult" }; };
template <> struct name<Windows::Services::Store::IStorePurchaseProperties>{ static constexpr auto & value{ L"Windows.Services.Store.IStorePurchaseProperties" }; };
template <> struct name<Windows::Services::Store::IStorePurchasePropertiesFactory>{ static constexpr auto & value{ L"Windows.Services.Store.IStorePurchasePropertiesFactory" }; };
template <> struct name<Windows::Services::Store::IStorePurchaseResult>{ static constexpr auto & value{ L"Windows.Services.Store.IStorePurchaseResult" }; };
template <> struct name<Windows::Services::Store::IStoreQueueItem>{ static constexpr auto & value{ L"Windows.Services.Store.IStoreQueueItem" }; };
template <> struct name<Windows::Services::Store::IStoreQueueItem2>{ static constexpr auto & value{ L"Windows.Services.Store.IStoreQueueItem2" }; };
template <> struct name<Windows::Services::Store::IStoreQueueItemCompletedEventArgs>{ static constexpr auto & value{ L"Windows.Services.Store.IStoreQueueItemCompletedEventArgs" }; };
template <> struct name<Windows::Services::Store::IStoreQueueItemStatus>{ static constexpr auto & value{ L"Windows.Services.Store.IStoreQueueItemStatus" }; };
template <> struct name<Windows::Services::Store::IStoreRateAndReviewResult>{ static constexpr auto & value{ L"Windows.Services.Store.IStoreRateAndReviewResult" }; };
template <> struct name<Windows::Services::Store::IStoreRequestHelperStatics>{ static constexpr auto & value{ L"Windows.Services.Store.IStoreRequestHelperStatics" }; };
template <> struct name<Windows::Services::Store::IStoreSendRequestResult>{ static constexpr auto & value{ L"Windows.Services.Store.IStoreSendRequestResult" }; };
template <> struct name<Windows::Services::Store::IStoreSendRequestResult2>{ static constexpr auto & value{ L"Windows.Services.Store.IStoreSendRequestResult2" }; };
template <> struct name<Windows::Services::Store::IStoreSku>{ static constexpr auto & value{ L"Windows.Services.Store.IStoreSku" }; };
template <> struct name<Windows::Services::Store::IStoreSubscriptionInfo>{ static constexpr auto & value{ L"Windows.Services.Store.IStoreSubscriptionInfo" }; };
template <> struct name<Windows::Services::Store::IStoreUninstallStorePackageResult>{ static constexpr auto & value{ L"Windows.Services.Store.IStoreUninstallStorePackageResult" }; };
template <> struct name<Windows::Services::Store::IStoreVideo>{ static constexpr auto & value{ L"Windows.Services.Store.IStoreVideo" }; };
template <> struct name<Windows::Services::Store::StoreAcquireLicenseResult>{ static constexpr auto & value{ L"Windows.Services.Store.StoreAcquireLicenseResult" }; };
template <> struct name<Windows::Services::Store::StoreAppLicense>{ static constexpr auto & value{ L"Windows.Services.Store.StoreAppLicense" }; };
template <> struct name<Windows::Services::Store::StoreAvailability>{ static constexpr auto & value{ L"Windows.Services.Store.StoreAvailability" }; };
template <> struct name<Windows::Services::Store::StoreCanAcquireLicenseResult>{ static constexpr auto & value{ L"Windows.Services.Store.StoreCanAcquireLicenseResult" }; };
template <> struct name<Windows::Services::Store::StoreCollectionData>{ static constexpr auto & value{ L"Windows.Services.Store.StoreCollectionData" }; };
template <> struct name<Windows::Services::Store::StoreConsumableResult>{ static constexpr auto & value{ L"Windows.Services.Store.StoreConsumableResult" }; };
template <> struct name<Windows::Services::Store::StoreContext>{ static constexpr auto & value{ L"Windows.Services.Store.StoreContext" }; };
template <> struct name<Windows::Services::Store::StoreImage>{ static constexpr auto & value{ L"Windows.Services.Store.StoreImage" }; };
template <> struct name<Windows::Services::Store::StoreLicense>{ static constexpr auto & value{ L"Windows.Services.Store.StoreLicense" }; };
template <> struct name<Windows::Services::Store::StorePackageInstallOptions>{ static constexpr auto & value{ L"Windows.Services.Store.StorePackageInstallOptions" }; };
template <> struct name<Windows::Services::Store::StorePackageLicense>{ static constexpr auto & value{ L"Windows.Services.Store.StorePackageLicense" }; };
template <> struct name<Windows::Services::Store::StorePackageUpdate>{ static constexpr auto & value{ L"Windows.Services.Store.StorePackageUpdate" }; };
template <> struct name<Windows::Services::Store::StorePackageUpdateResult>{ static constexpr auto & value{ L"Windows.Services.Store.StorePackageUpdateResult" }; };
template <> struct name<Windows::Services::Store::StorePrice>{ static constexpr auto & value{ L"Windows.Services.Store.StorePrice" }; };
template <> struct name<Windows::Services::Store::StoreProduct>{ static constexpr auto & value{ L"Windows.Services.Store.StoreProduct" }; };
template <> struct name<Windows::Services::Store::StoreProductOptions>{ static constexpr auto & value{ L"Windows.Services.Store.StoreProductOptions" }; };
template <> struct name<Windows::Services::Store::StoreProductPagedQueryResult>{ static constexpr auto & value{ L"Windows.Services.Store.StoreProductPagedQueryResult" }; };
template <> struct name<Windows::Services::Store::StoreProductQueryResult>{ static constexpr auto & value{ L"Windows.Services.Store.StoreProductQueryResult" }; };
template <> struct name<Windows::Services::Store::StoreProductResult>{ static constexpr auto & value{ L"Windows.Services.Store.StoreProductResult" }; };
template <> struct name<Windows::Services::Store::StorePurchaseProperties>{ static constexpr auto & value{ L"Windows.Services.Store.StorePurchaseProperties" }; };
template <> struct name<Windows::Services::Store::StorePurchaseResult>{ static constexpr auto & value{ L"Windows.Services.Store.StorePurchaseResult" }; };
template <> struct name<Windows::Services::Store::StoreQueueItem>{ static constexpr auto & value{ L"Windows.Services.Store.StoreQueueItem" }; };
template <> struct name<Windows::Services::Store::StoreQueueItemCompletedEventArgs>{ static constexpr auto & value{ L"Windows.Services.Store.StoreQueueItemCompletedEventArgs" }; };
template <> struct name<Windows::Services::Store::StoreQueueItemStatus>{ static constexpr auto & value{ L"Windows.Services.Store.StoreQueueItemStatus" }; };
template <> struct name<Windows::Services::Store::StoreRateAndReviewResult>{ static constexpr auto & value{ L"Windows.Services.Store.StoreRateAndReviewResult" }; };
template <> struct name<Windows::Services::Store::StoreRequestHelper>{ static constexpr auto & value{ L"Windows.Services.Store.StoreRequestHelper" }; };
template <> struct name<Windows::Services::Store::StoreSendRequestResult>{ static constexpr auto & value{ L"Windows.Services.Store.StoreSendRequestResult" }; };
template <> struct name<Windows::Services::Store::StoreSku>{ static constexpr auto & value{ L"Windows.Services.Store.StoreSku" }; };
template <> struct name<Windows::Services::Store::StoreSubscriptionInfo>{ static constexpr auto & value{ L"Windows.Services.Store.StoreSubscriptionInfo" }; };
template <> struct name<Windows::Services::Store::StoreUninstallStorePackageResult>{ static constexpr auto & value{ L"Windows.Services.Store.StoreUninstallStorePackageResult" }; };
template <> struct name<Windows::Services::Store::StoreVideo>{ static constexpr auto & value{ L"Windows.Services.Store.StoreVideo" }; };
template <> struct name<Windows::Services::Store::StoreCanLicenseStatus>{ static constexpr auto & value{ L"Windows.Services.Store.StoreCanLicenseStatus" }; };
template <> struct name<Windows::Services::Store::StoreConsumableStatus>{ static constexpr auto & value{ L"Windows.Services.Store.StoreConsumableStatus" }; };
template <> struct name<Windows::Services::Store::StoreDurationUnit>{ static constexpr auto & value{ L"Windows.Services.Store.StoreDurationUnit" }; };
template <> struct name<Windows::Services::Store::StorePackageUpdateState>{ static constexpr auto & value{ L"Windows.Services.Store.StorePackageUpdateState" }; };
template <> struct name<Windows::Services::Store::StorePurchaseStatus>{ static constexpr auto & value{ L"Windows.Services.Store.StorePurchaseStatus" }; };
template <> struct name<Windows::Services::Store::StoreQueueItemExtendedState>{ static constexpr auto & value{ L"Windows.Services.Store.StoreQueueItemExtendedState" }; };
template <> struct name<Windows::Services::Store::StoreQueueItemKind>{ static constexpr auto & value{ L"Windows.Services.Store.StoreQueueItemKind" }; };
template <> struct name<Windows::Services::Store::StoreQueueItemState>{ static constexpr auto & value{ L"Windows.Services.Store.StoreQueueItemState" }; };
template <> struct name<Windows::Services::Store::StoreRateAndReviewStatus>{ static constexpr auto & value{ L"Windows.Services.Store.StoreRateAndReviewStatus" }; };
template <> struct name<Windows::Services::Store::StoreUninstallStorePackageStatus>{ static constexpr auto & value{ L"Windows.Services.Store.StoreUninstallStorePackageStatus" }; };
template <> struct name<Windows::Services::Store::StorePackageUpdateStatus>{ static constexpr auto & value{ L"Windows.Services.Store.StorePackageUpdateStatus" }; };
template <> struct guid_storage<Windows::Services::Store::IStoreAcquireLicenseResult>{ static constexpr guid value{ 0xFBD7946D,0xF040,0x4CB3,{ 0x9A,0x39,0x29,0xBC,0xEC,0xDB,0xE2,0x2D } }; };
template <> struct guid_storage<Windows::Services::Store::IStoreAppLicense>{ static constexpr guid value{ 0xF389F9DE,0x73C0,0x45CE,{ 0x9B,0xAB,0xB2,0xFE,0x3E,0x5E,0xAF,0xD3 } }; };
template <> struct guid_storage<Windows::Services::Store::IStoreAppLicense2>{ static constexpr guid value{ 0xB4666E91,0x4443,0x40B3,{ 0x99,0x3F,0x28,0x90,0x44,0x35,0xBD,0xC6 } }; };
template <> struct guid_storage<Windows::Services::Store::IStoreAvailability>{ static constexpr guid value{ 0xFA060325,0x0FFD,0x4493,{ 0xAD,0x43,0xF1,0xF9,0x91,0x8F,0x69,0xFA } }; };
template <> struct guid_storage<Windows::Services::Store::IStoreCanAcquireLicenseResult>{ static constexpr guid value{ 0x3A693DB3,0x0088,0x482F,{ 0x86,0xD5,0xBD,0x46,0x52,0x26,0x63,0xAD } }; };
template <> struct guid_storage<Windows::Services::Store::IStoreCollectionData>{ static constexpr guid value{ 0x8AA4C3B3,0x5BB3,0x441A,{ 0x2A,0xB4,0x4D,0xAB,0x73,0xD5,0xCE,0x67 } }; };
template <> struct guid_storage<Windows::Services::Store::IStoreConsumableResult>{ static constexpr guid value{ 0xEA5DAB72,0x6A00,0x4052,{ 0xBE,0x5B,0xBF,0xDA,0xB4,0x43,0x33,0x52 } }; };
template <> struct guid_storage<Windows::Services::Store::IStoreContext>{ static constexpr guid value{ 0xAC98B6BE,0xF4FD,0x4912,{ 0xBA,0xBD,0x50,0x35,0xE5,0xE8,0xBC,0xAB } }; };
template <> struct guid_storage<Windows::Services::Store::IStoreContext2>{ static constexpr guid value{ 0x18BC54DA,0x7BD9,0x452C,{ 0x91,0x16,0x3B,0xBD,0x06,0xFF,0xC6,0x3A } }; };
template <> struct guid_storage<Windows::Services::Store::IStoreContext3>{ static constexpr guid value{ 0xE26226CA,0x1A01,0x4730,{ 0x85,0xA6,0xEC,0xC8,0x96,0xE4,0xAE,0x38 } }; };
template <> struct guid_storage<Windows::Services::Store::IStoreContext4>{ static constexpr guid value{ 0xAF9C6F69,0xBEA1,0x4BF4,{ 0x8E,0x74,0xAE,0x03,0xE2,0x06,0xC6,0xB0 } }; };
template <> struct guid_storage<Windows::Services::Store::IStoreContextStatics>{ static constexpr guid value{ 0x9C06EE5F,0x15C0,0x4E72,{ 0x93,0x30,0xD6,0x19,0x1C,0xEB,0xD1,0x9C } }; };
template <> struct guid_storage<Windows::Services::Store::IStoreImage>{ static constexpr guid value{ 0x081FD248,0xADB4,0x4B64,{ 0xA9,0x93,0x78,0x47,0x89,0x92,0x6E,0xD5 } }; };
template <> struct guid_storage<Windows::Services::Store::IStoreLicense>{ static constexpr guid value{ 0x26DC9579,0x4C4F,0x4F30,{ 0xBC,0x89,0x64,0x9F,0x60,0xE3,0x60,0x55 } }; };
template <> struct guid_storage<Windows::Services::Store::IStorePackageInstallOptions>{ static constexpr guid value{ 0x1D3D630C,0x0CCD,0x44DD,{ 0x8C,0x59,0x80,0x81,0x0A,0x72,0x99,0x73 } }; };
template <> struct guid_storage<Windows::Services::Store::IStorePackageLicense>{ static constexpr guid value{ 0x0C465714,0x14E1,0x4973,{ 0xBD,0x14,0xF7,0x77,0x24,0x27,0x1E,0x99 } }; };
template <> struct guid_storage<Windows::Services::Store::IStorePackageUpdate>{ static constexpr guid value{ 0x140FA150,0x3CBF,0x4A35,{ 0xB9,0x1F,0x48,0x27,0x1C,0x31,0xB0,0x72 } }; };
template <> struct guid_storage<Windows::Services::Store::IStorePackageUpdateResult>{ static constexpr guid value{ 0xE79142ED,0x61F9,0x4893,{ 0xB4,0xFE,0xCF,0x19,0x16,0x03,0xAF,0x7B } }; };
template <> struct guid_storage<Windows::Services::Store::IStorePackageUpdateResult2>{ static constexpr guid value{ 0x071D012E,0xBC62,0x4F2E,{ 0x87,0xEA,0x99,0xD8,0x01,0xAE,0xAF,0x98 } }; };
template <> struct guid_storage<Windows::Services::Store::IStorePrice>{ static constexpr guid value{ 0x55BA94C4,0x15F1,0x407C,{ 0x8F,0x06,0x00,0x63,0x80,0xF4,0xDF,0x0B } }; };
template <> struct guid_storage<Windows::Services::Store::IStoreProduct>{ static constexpr guid value{ 0x320E2C52,0xD760,0x450A,{ 0xA4,0x2B,0x67,0xD1,0xE9,0x01,0xAC,0x90 } }; };
template <> struct guid_storage<Windows::Services::Store::IStoreProductOptions>{ static constexpr guid value{ 0x5B34A0F9,0xA113,0x4811,{ 0x83,0x26,0x16,0x19,0x9C,0x92,0x7F,0x31 } }; };
template <> struct guid_storage<Windows::Services::Store::IStoreProductPagedQueryResult>{ static constexpr guid value{ 0xC92718C5,0x4DD5,0x4869,{ 0xA4,0x62,0xEC,0xC6,0x87,0x2E,0x43,0xC5 } }; };
template <> struct guid_storage<Windows::Services::Store::IStoreProductQueryResult>{ static constexpr guid value{ 0xD805E6C5,0xD456,0x4FF6,{ 0x80,0x49,0x90,0x76,0xD5,0x16,0x5F,0x73 } }; };
template <> struct guid_storage<Windows::Services::Store::IStoreProductResult>{ static constexpr guid value{ 0xB7674F73,0x3C87,0x4EE1,{ 0x82,0x01,0xF4,0x28,0x35,0x9B,0xD3,0xAF } }; };
template <> struct guid_storage<Windows::Services::Store::IStorePurchaseProperties>{ static constexpr guid value{ 0x836278F3,0xFF87,0x4364,{ 0xA5,0xB4,0xFD,0x21,0x53,0xEB,0xE4,0x3B } }; };
template <> struct guid_storage<Windows::Services::Store::IStorePurchasePropertiesFactory>{ static constexpr guid value{ 0xA768F59E,0xFEFD,0x489F,{ 0x9A,0x17,0x22,0xA5,0x93,0xE6,0x8B,0x9D } }; };
template <> struct guid_storage<Windows::Services::Store::IStorePurchaseResult>{ static constexpr guid value{ 0xADD28552,0xF96A,0x463D,{ 0xA7,0xBB,0xC2,0x0B,0x4F,0xCA,0x69,0x52 } }; };
template <> struct guid_storage<Windows::Services::Store::IStoreQueueItem>{ static constexpr guid value{ 0x56D5C32B,0xF830,0x4293,{ 0x91,0x88,0xCA,0xD2,0xDC,0xDE,0x73,0x57 } }; };
template <> struct guid_storage<Windows::Services::Store::IStoreQueueItem2>{ static constexpr guid value{ 0x69491CA8,0x1AD4,0x447C,{ 0xAD,0x8C,0xA9,0x50,0x35,0xF6,0x4D,0x82 } }; };
template <> struct guid_storage<Windows::Services::Store::IStoreQueueItemCompletedEventArgs>{ static constexpr guid value{ 0x1247DF6C,0xB44A,0x439B,{ 0xBB,0x07,0x1D,0x30,0x03,0xD0,0x05,0xC2 } }; };
template <> struct guid_storage<Windows::Services::Store::IStoreQueueItemStatus>{ static constexpr guid value{ 0x9BD6796F,0x9CC3,0x4EC3,{ 0xB2,0xEF,0x7B,0xE4,0x33,0xB3,0x01,0x74 } }; };
template <> struct guid_storage<Windows::Services::Store::IStoreRateAndReviewResult>{ static constexpr guid value{ 0x9D209D56,0xA6B5,0x4121,{ 0x9B,0x61,0xEE,0x6D,0x0F,0xBD,0xBD,0xBB } }; };
template <> struct guid_storage<Windows::Services::Store::IStoreRequestHelperStatics>{ static constexpr guid value{ 0x6CE5E5F9,0xA0C9,0x4B2C,{ 0x96,0xA6,0xA1,0x71,0xC6,0x30,0x03,0x8D } }; };
template <> struct guid_storage<Windows::Services::Store::IStoreSendRequestResult>{ static constexpr guid value{ 0xC73ABE60,0x8272,0x4502,{ 0x8A,0x69,0x6E,0x75,0x15,0x3A,0x42,0x99 } }; };
template <> struct guid_storage<Windows::Services::Store::IStoreSendRequestResult2>{ static constexpr guid value{ 0x2901296F,0xC0B0,0x49D0,{ 0x8E,0x8D,0xAA,0x94,0x0A,0xF9,0xC1,0x0B } }; };
template <> struct guid_storage<Windows::Services::Store::IStoreSku>{ static constexpr guid value{ 0x397E6F55,0x4440,0x4F03,{ 0x86,0x3C,0x91,0xF3,0xFE,0xC8,0x3D,0x79 } }; };
template <> struct guid_storage<Windows::Services::Store::IStoreSubscriptionInfo>{ static constexpr guid value{ 0x4189776A,0x0559,0x43AC,{ 0xA9,0xC6,0x3A,0xB0,0x01,0x1F,0xB8,0xEB } }; };
template <> struct guid_storage<Windows::Services::Store::IStoreUninstallStorePackageResult>{ static constexpr guid value{ 0x9FCA39FD,0x126F,0x4CDA,{ 0xB8,0x01,0x13,0x46,0xB8,0xD0,0xA2,0x60 } }; };
template <> struct guid_storage<Windows::Services::Store::IStoreVideo>{ static constexpr guid value{ 0xF26CB184,0x6F5E,0x4DC2,{ 0x88,0x6C,0x3C,0x63,0x08,0x3C,0x2F,0x94 } }; };
template <> struct default_interface<Windows::Services::Store::StoreAcquireLicenseResult>{ using type = Windows::Services::Store::IStoreAcquireLicenseResult; };
template <> struct default_interface<Windows::Services::Store::StoreAppLicense>{ using type = Windows::Services::Store::IStoreAppLicense; };
template <> struct default_interface<Windows::Services::Store::StoreAvailability>{ using type = Windows::Services::Store::IStoreAvailability; };
template <> struct default_interface<Windows::Services::Store::StoreCanAcquireLicenseResult>{ using type = Windows::Services::Store::IStoreCanAcquireLicenseResult; };
template <> struct default_interface<Windows::Services::Store::StoreCollectionData>{ using type = Windows::Services::Store::IStoreCollectionData; };
template <> struct default_interface<Windows::Services::Store::StoreConsumableResult>{ using type = Windows::Services::Store::IStoreConsumableResult; };
template <> struct default_interface<Windows::Services::Store::StoreContext>{ using type = Windows::Services::Store::IStoreContext; };
template <> struct default_interface<Windows::Services::Store::StoreImage>{ using type = Windows::Services::Store::IStoreImage; };
template <> struct default_interface<Windows::Services::Store::StoreLicense>{ using type = Windows::Services::Store::IStoreLicense; };
template <> struct default_interface<Windows::Services::Store::StorePackageInstallOptions>{ using type = Windows::Services::Store::IStorePackageInstallOptions; };
template <> struct default_interface<Windows::Services::Store::StorePackageLicense>{ using type = Windows::Services::Store::IStorePackageLicense; };
template <> struct default_interface<Windows::Services::Store::StorePackageUpdate>{ using type = Windows::Services::Store::IStorePackageUpdate; };
template <> struct default_interface<Windows::Services::Store::StorePackageUpdateResult>{ using type = Windows::Services::Store::IStorePackageUpdateResult; };
template <> struct default_interface<Windows::Services::Store::StorePrice>{ using type = Windows::Services::Store::IStorePrice; };
template <> struct default_interface<Windows::Services::Store::StoreProduct>{ using type = Windows::Services::Store::IStoreProduct; };
template <> struct default_interface<Windows::Services::Store::StoreProductOptions>{ using type = Windows::Services::Store::IStoreProductOptions; };
template <> struct default_interface<Windows::Services::Store::StoreProductPagedQueryResult>{ using type = Windows::Services::Store::IStoreProductPagedQueryResult; };
template <> struct default_interface<Windows::Services::Store::StoreProductQueryResult>{ using type = Windows::Services::Store::IStoreProductQueryResult; };
template <> struct default_interface<Windows::Services::Store::StoreProductResult>{ using type = Windows::Services::Store::IStoreProductResult; };
template <> struct default_interface<Windows::Services::Store::StorePurchaseProperties>{ using type = Windows::Services::Store::IStorePurchaseProperties; };
template <> struct default_interface<Windows::Services::Store::StorePurchaseResult>{ using type = Windows::Services::Store::IStorePurchaseResult; };
template <> struct default_interface<Windows::Services::Store::StoreQueueItem>{ using type = Windows::Services::Store::IStoreQueueItem; };
template <> struct default_interface<Windows::Services::Store::StoreQueueItemCompletedEventArgs>{ using type = Windows::Services::Store::IStoreQueueItemCompletedEventArgs; };
template <> struct default_interface<Windows::Services::Store::StoreQueueItemStatus>{ using type = Windows::Services::Store::IStoreQueueItemStatus; };
template <> struct default_interface<Windows::Services::Store::StoreRateAndReviewResult>{ using type = Windows::Services::Store::IStoreRateAndReviewResult; };
template <> struct default_interface<Windows::Services::Store::StoreSendRequestResult>{ using type = Windows::Services::Store::IStoreSendRequestResult; };
template <> struct default_interface<Windows::Services::Store::StoreSku>{ using type = Windows::Services::Store::IStoreSku; };
template <> struct default_interface<Windows::Services::Store::StoreSubscriptionInfo>{ using type = Windows::Services::Store::IStoreSubscriptionInfo; };
template <> struct default_interface<Windows::Services::Store::StoreUninstallStorePackageResult>{ using type = Windows::Services::Store::IStoreUninstallStorePackageResult; };
template <> struct default_interface<Windows::Services::Store::StoreVideo>{ using type = Windows::Services::Store::IStoreVideo; };

template <> struct abi<Windows::Services::Store::IStoreAcquireLicenseResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_StorePackageLicense(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ExtendedError(winrt::hresult* value) noexcept = 0;
};};

template <> struct abi<Windows::Services::Store::IStoreAppLicense>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_SkuStoreId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsActive(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsTrial(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ExpirationDate(Windows::Foundation::DateTime* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ExtendedJsonData(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AddOnLicenses(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TrialTimeRemaining(Windows::Foundation::TimeSpan* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsTrialOwnedByThisUser(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TrialUniqueId(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Services::Store::IStoreAppLicense2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsDiscLicense(bool* value) noexcept = 0;
};};

template <> struct abi<Windows::Services::Store::IStoreAvailability>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_StoreId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_EndDate(Windows::Foundation::DateTime* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Price(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ExtendedJsonData(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL RequestPurchaseAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL RequestPurchaseWithPurchasePropertiesAsync(void* storePurchaseProperties, void** operation) noexcept = 0;
};};

template <> struct abi<Windows::Services::Store::IStoreCanAcquireLicenseResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ExtendedError(winrt::hresult* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LicensableSku(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Status(Windows::Services::Store::StoreCanLicenseStatus* value) noexcept = 0;
};};

template <> struct abi<Windows::Services::Store::IStoreCollectionData>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsTrial(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CampaignId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DeveloperOfferId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AcquiredDate(Windows::Foundation::DateTime* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_StartDate(Windows::Foundation::DateTime* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_EndDate(Windows::Foundation::DateTime* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TrialTimeRemaining(Windows::Foundation::TimeSpan* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ExtendedJsonData(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Services::Store::IStoreConsumableResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Status(Windows::Services::Store::StoreConsumableStatus* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TrackingId(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BalanceRemaining(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ExtendedError(winrt::hresult* value) noexcept = 0;
};};

template <> struct abi<Windows::Services::Store::IStoreContext>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_User(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL add_OfflineLicensesChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_OfflineLicensesChanged(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL GetCustomerPurchaseIdAsync(void* serviceTicket, void* publisherUserId, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetCustomerCollectionsIdAsync(void* serviceTicket, void* publisherUserId, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetAppLicenseAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetStoreProductForCurrentAppAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetStoreProductsAsync(void* productKinds, void* storeIds, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetAssociatedStoreProductsAsync(void* productKinds, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetAssociatedStoreProductsWithPagingAsync(void* productKinds, uint32_t maxItemsToRetrievePerPage, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetUserCollectionAsync(void* productKinds, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetUserCollectionWithPagingAsync(void* productKinds, uint32_t maxItemsToRetrievePerPage, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL ReportConsumableFulfillmentAsync(void* productStoreId, uint32_t quantity, winrt::guid trackingId, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetConsumableBalanceRemainingAsync(void* productStoreId, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL AcquireStoreLicenseForOptionalPackageAsync(void* optionalPackage, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL RequestPurchaseAsync(void* storeId, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL RequestPurchaseWithPurchasePropertiesAsync(void* storeId, void* storePurchaseProperties, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetAppAndOptionalStorePackageUpdatesAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL RequestDownloadStorePackageUpdatesAsync(void* storePackageUpdates, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL RequestDownloadAndInstallStorePackageUpdatesAsync(void* storePackageUpdates, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL RequestDownloadAndInstallStorePackagesAsync(void* storeIds, void** operation) noexcept = 0;
};};

template <> struct abi<Windows::Services::Store::IStoreContext2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL FindStoreProductForPackageAsync(void* productKinds, void* package, void** operation) noexcept = 0;
};};

template <> struct abi<Windows::Services::Store::IStoreContext3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_CanSilentlyDownloadStorePackageUpdates(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL TrySilentDownloadStorePackageUpdatesAsync(void* storePackageUpdates, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL TrySilentDownloadAndInstallStorePackageUpdatesAsync(void* storePackageUpdates, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL CanAcquireStoreLicenseForOptionalPackageAsync(void* optionalPackage, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL CanAcquireStoreLicenseAsync(void* productStoreId, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetStoreProductsWithOptionsAsync(void* productKinds, void* storeIds, void* storeProductOptions, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetAssociatedStoreQueueItemsAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetStoreQueueItemsAsync(void* storeIds, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL RequestDownloadAndInstallStorePackagesWithInstallOptionsAsync(void* storeIds, void* storePackageInstallOptions, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL DownloadAndInstallStorePackagesAsync(void* storeIds, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL RequestUninstallStorePackageAsync(void* package, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL RequestUninstallStorePackageByStoreIdAsync(void* storeId, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL UninstallStorePackageAsync(void* package, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL UninstallStorePackageByStoreIdAsync(void* storeId, void** operation) noexcept = 0;
};};

template <> struct abi<Windows::Services::Store::IStoreContext4>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL RequestRateAndReviewAppAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL SetInstallOrderForAssociatedStoreQueueItemsAsync(void* items, void** operation) noexcept = 0;
};};

template <> struct abi<Windows::Services::Store::IStoreContextStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetDefault(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetForUser(void* user, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Services::Store::IStoreImage>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Uri(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ImagePurposeTag(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Width(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Height(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Caption(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Services::Store::IStoreLicense>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_SkuStoreId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsActive(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ExpirationDate(Windows::Foundation::DateTime* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ExtendedJsonData(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_InAppOfferToken(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Services::Store::IStorePackageInstallOptions>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_AllowForcedAppRestart(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_AllowForcedAppRestart(bool value) noexcept = 0;
};};

template <> struct abi<Windows::Services::Store::IStorePackageLicense>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL add_LicenseLost(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_LicenseLost(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL get_Package(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsValid(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL ReleaseLicense() noexcept = 0;
};};

template <> struct abi<Windows::Services::Store::IStorePackageUpdate>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Package(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Mandatory(bool* value) noexcept = 0;
};};

template <> struct abi<Windows::Services::Store::IStorePackageUpdateResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_OverallState(Windows::Services::Store::StorePackageUpdateState* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_StorePackageUpdateStatuses(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Services::Store::IStorePackageUpdateResult2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_StoreQueueItems(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Services::Store::IStorePrice>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_FormattedBasePrice(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_FormattedPrice(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsOnSale(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SaleEndDate(Windows::Foundation::DateTime* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CurrencyCode(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_FormattedRecurrencePrice(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Services::Store::IStoreProduct>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_StoreId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Language(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Title(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Description(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ProductKind(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HasDigitalDownload(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Keywords(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Images(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Videos(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Skus(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsInUserCollection(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Price(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ExtendedJsonData(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LinkUri(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetIsAnySkuInstalledAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL RequestPurchaseAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL RequestPurchaseWithPurchasePropertiesAsync(void* storePurchaseProperties, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL get_InAppOfferToken(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Services::Store::IStoreProductOptions>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ActionFilters(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Services::Store::IStoreProductPagedQueryResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Products(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HasMoreResults(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ExtendedError(winrt::hresult* value) noexcept = 0;
    virtual int32_t WINRT_CALL GetNextAsync(void** operation) noexcept = 0;
};};

template <> struct abi<Windows::Services::Store::IStoreProductQueryResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Products(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ExtendedError(winrt::hresult* value) noexcept = 0;
};};

template <> struct abi<Windows::Services::Store::IStoreProductResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Product(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ExtendedError(winrt::hresult* value) noexcept = 0;
};};

template <> struct abi<Windows::Services::Store::IStorePurchaseProperties>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Name(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Name(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ExtendedJsonData(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ExtendedJsonData(void* value) noexcept = 0;
};};

template <> struct abi<Windows::Services::Store::IStorePurchasePropertiesFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Create(void* name, void** storePurchaseProperties) noexcept = 0;
};};

template <> struct abi<Windows::Services::Store::IStorePurchaseResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Status(Windows::Services::Store::StorePurchaseStatus* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ExtendedError(winrt::hresult* value) noexcept = 0;
};};

template <> struct abi<Windows::Services::Store::IStoreQueueItem>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ProductId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PackageFamilyName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_InstallKind(Windows::Services::Store::StoreQueueItemKind* value) noexcept = 0;
    virtual int32_t WINRT_CALL GetCurrentStatus(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL add_Completed(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_Completed(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_StatusChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_StatusChanged(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::Services::Store::IStoreQueueItem2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CancelInstallAsync(void** action) noexcept = 0;
    virtual int32_t WINRT_CALL PauseInstallAsync(void** action) noexcept = 0;
    virtual int32_t WINRT_CALL ResumeInstallAsync(void** action) noexcept = 0;
};};

template <> struct abi<Windows::Services::Store::IStoreQueueItemCompletedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Status(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Services::Store::IStoreQueueItemStatus>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_PackageInstallState(Windows::Services::Store::StoreQueueItemState* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PackageInstallExtendedState(Windows::Services::Store::StoreQueueItemExtendedState* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_UpdateStatus(struct struct_Windows_Services_Store_StorePackageUpdateStatus* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ExtendedError(winrt::hresult* value) noexcept = 0;
};};

template <> struct abi<Windows::Services::Store::IStoreRateAndReviewResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ExtendedError(winrt::hresult* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ExtendedJsonData(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_WasUpdated(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Status(Windows::Services::Store::StoreRateAndReviewStatus* value) noexcept = 0;
};};

template <> struct abi<Windows::Services::Store::IStoreRequestHelperStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL SendRequestAsync(void* context, uint32_t requestKind, void* parametersAsJson, void** operation) noexcept = 0;
};};

template <> struct abi<Windows::Services::Store::IStoreSendRequestResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Response(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ExtendedError(winrt::hresult* value) noexcept = 0;
};};

template <> struct abi<Windows::Services::Store::IStoreSendRequestResult2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_HttpStatusCode(Windows::Web::Http::HttpStatusCode* value) noexcept = 0;
};};

template <> struct abi<Windows::Services::Store::IStoreSku>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_StoreId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Language(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Title(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Description(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsTrial(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CustomDeveloperData(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Images(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Videos(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Availabilities(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Price(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ExtendedJsonData(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsInUserCollection(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BundledSkus(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CollectionData(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetIsInstalledAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL RequestPurchaseAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL RequestPurchaseWithPurchasePropertiesAsync(void* storePurchaseProperties, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsSubscription(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SubscriptionInfo(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Services::Store::IStoreSubscriptionInfo>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_BillingPeriod(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BillingPeriodUnit(Windows::Services::Store::StoreDurationUnit* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HasTrialPeriod(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TrialPeriod(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TrialPeriodUnit(Windows::Services::Store::StoreDurationUnit* value) noexcept = 0;
};};

template <> struct abi<Windows::Services::Store::IStoreUninstallStorePackageResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ExtendedError(winrt::hresult* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Status(Windows::Services::Store::StoreUninstallStorePackageStatus* value) noexcept = 0;
};};

template <> struct abi<Windows::Services::Store::IStoreVideo>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Uri(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_VideoPurposeTag(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Width(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Height(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Caption(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PreviewImage(void** value) noexcept = 0;
};};

template <typename D>
struct consume_Windows_Services_Store_IStoreAcquireLicenseResult
{
    Windows::Services::Store::StorePackageLicense StorePackageLicense() const;
    winrt::hresult ExtendedError() const;
};
template <> struct consume<Windows::Services::Store::IStoreAcquireLicenseResult> { template <typename D> using type = consume_Windows_Services_Store_IStoreAcquireLicenseResult<D>; };

template <typename D>
struct consume_Windows_Services_Store_IStoreAppLicense
{
    hstring SkuStoreId() const;
    bool IsActive() const;
    bool IsTrial() const;
    Windows::Foundation::DateTime ExpirationDate() const;
    hstring ExtendedJsonData() const;
    Windows::Foundation::Collections::IMapView<hstring, Windows::Services::Store::StoreLicense> AddOnLicenses() const;
    Windows::Foundation::TimeSpan TrialTimeRemaining() const;
    bool IsTrialOwnedByThisUser() const;
    hstring TrialUniqueId() const;
};
template <> struct consume<Windows::Services::Store::IStoreAppLicense> { template <typename D> using type = consume_Windows_Services_Store_IStoreAppLicense<D>; };

template <typename D>
struct consume_Windows_Services_Store_IStoreAppLicense2
{
    bool IsDiscLicense() const;
};
template <> struct consume<Windows::Services::Store::IStoreAppLicense2> { template <typename D> using type = consume_Windows_Services_Store_IStoreAppLicense2<D>; };

template <typename D>
struct consume_Windows_Services_Store_IStoreAvailability
{
    hstring StoreId() const;
    Windows::Foundation::DateTime EndDate() const;
    Windows::Services::Store::StorePrice Price() const;
    hstring ExtendedJsonData() const;
    Windows::Foundation::IAsyncOperation<Windows::Services::Store::StorePurchaseResult> RequestPurchaseAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::Services::Store::StorePurchaseResult> RequestPurchaseAsync(Windows::Services::Store::StorePurchaseProperties const& storePurchaseProperties) const;
};
template <> struct consume<Windows::Services::Store::IStoreAvailability> { template <typename D> using type = consume_Windows_Services_Store_IStoreAvailability<D>; };

template <typename D>
struct consume_Windows_Services_Store_IStoreCanAcquireLicenseResult
{
    winrt::hresult ExtendedError() const;
    hstring LicensableSku() const;
    Windows::Services::Store::StoreCanLicenseStatus Status() const;
};
template <> struct consume<Windows::Services::Store::IStoreCanAcquireLicenseResult> { template <typename D> using type = consume_Windows_Services_Store_IStoreCanAcquireLicenseResult<D>; };

template <typename D>
struct consume_Windows_Services_Store_IStoreCollectionData
{
    bool IsTrial() const;
    hstring CampaignId() const;
    hstring DeveloperOfferId() const;
    Windows::Foundation::DateTime AcquiredDate() const;
    Windows::Foundation::DateTime StartDate() const;
    Windows::Foundation::DateTime EndDate() const;
    Windows::Foundation::TimeSpan TrialTimeRemaining() const;
    hstring ExtendedJsonData() const;
};
template <> struct consume<Windows::Services::Store::IStoreCollectionData> { template <typename D> using type = consume_Windows_Services_Store_IStoreCollectionData<D>; };

template <typename D>
struct consume_Windows_Services_Store_IStoreConsumableResult
{
    Windows::Services::Store::StoreConsumableStatus Status() const;
    winrt::guid TrackingId() const;
    uint32_t BalanceRemaining() const;
    winrt::hresult ExtendedError() const;
};
template <> struct consume<Windows::Services::Store::IStoreConsumableResult> { template <typename D> using type = consume_Windows_Services_Store_IStoreConsumableResult<D>; };

template <typename D>
struct consume_Windows_Services_Store_IStoreContext
{
    Windows::System::User User() const;
    winrt::event_token OfflineLicensesChanged(Windows::Foundation::TypedEventHandler<Windows::Services::Store::StoreContext, Windows::Foundation::IInspectable> const& handler) const;
    using OfflineLicensesChanged_revoker = impl::event_revoker<Windows::Services::Store::IStoreContext, &impl::abi_t<Windows::Services::Store::IStoreContext>::remove_OfflineLicensesChanged>;
    OfflineLicensesChanged_revoker OfflineLicensesChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Services::Store::StoreContext, Windows::Foundation::IInspectable> const& handler) const;
    void OfflineLicensesChanged(winrt::event_token const& token) const noexcept;
    Windows::Foundation::IAsyncOperation<hstring> GetCustomerPurchaseIdAsync(param::hstring const& serviceTicket, param::hstring const& publisherUserId) const;
    Windows::Foundation::IAsyncOperation<hstring> GetCustomerCollectionsIdAsync(param::hstring const& serviceTicket, param::hstring const& publisherUserId) const;
    Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreAppLicense> GetAppLicenseAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreProductResult> GetStoreProductForCurrentAppAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreProductQueryResult> GetStoreProductsAsync(param::async_iterable<hstring> const& productKinds, param::async_iterable<hstring> const& storeIds) const;
    Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreProductQueryResult> GetAssociatedStoreProductsAsync(param::async_iterable<hstring> const& productKinds) const;
    Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreProductPagedQueryResult> GetAssociatedStoreProductsWithPagingAsync(param::async_iterable<hstring> const& productKinds, uint32_t maxItemsToRetrievePerPage) const;
    Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreProductQueryResult> GetUserCollectionAsync(param::async_iterable<hstring> const& productKinds) const;
    Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreProductPagedQueryResult> GetUserCollectionWithPagingAsync(param::async_iterable<hstring> const& productKinds, uint32_t maxItemsToRetrievePerPage) const;
    Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreConsumableResult> ReportConsumableFulfillmentAsync(param::hstring const& productStoreId, uint32_t quantity, winrt::guid const& trackingId) const;
    Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreConsumableResult> GetConsumableBalanceRemainingAsync(param::hstring const& productStoreId) const;
    Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreAcquireLicenseResult> AcquireStoreLicenseForOptionalPackageAsync(Windows::ApplicationModel::Package const& optionalPackage) const;
    Windows::Foundation::IAsyncOperation<Windows::Services::Store::StorePurchaseResult> RequestPurchaseAsync(param::hstring const& storeId) const;
    Windows::Foundation::IAsyncOperation<Windows::Services::Store::StorePurchaseResult> RequestPurchaseAsync(param::hstring const& storeId, Windows::Services::Store::StorePurchaseProperties const& storePurchaseProperties) const;
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Services::Store::StorePackageUpdate>> GetAppAndOptionalStorePackageUpdatesAsync() const;
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Services::Store::StorePackageUpdateResult, Windows::Services::Store::StorePackageUpdateStatus> RequestDownloadStorePackageUpdatesAsync(param::async_iterable<Windows::Services::Store::StorePackageUpdate> const& storePackageUpdates) const;
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Services::Store::StorePackageUpdateResult, Windows::Services::Store::StorePackageUpdateStatus> RequestDownloadAndInstallStorePackageUpdatesAsync(param::async_iterable<Windows::Services::Store::StorePackageUpdate> const& storePackageUpdates) const;
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Services::Store::StorePackageUpdateResult, Windows::Services::Store::StorePackageUpdateStatus> RequestDownloadAndInstallStorePackagesAsync(param::async_iterable<hstring> const& storeIds) const;
};
template <> struct consume<Windows::Services::Store::IStoreContext> { template <typename D> using type = consume_Windows_Services_Store_IStoreContext<D>; };

template <typename D>
struct consume_Windows_Services_Store_IStoreContext2
{
    Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreProductResult> FindStoreProductForPackageAsync(param::async_iterable<hstring> const& productKinds, Windows::ApplicationModel::Package const& package) const;
};
template <> struct consume<Windows::Services::Store::IStoreContext2> { template <typename D> using type = consume_Windows_Services_Store_IStoreContext2<D>; };

template <typename D>
struct consume_Windows_Services_Store_IStoreContext3
{
    bool CanSilentlyDownloadStorePackageUpdates() const;
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Services::Store::StorePackageUpdateResult, Windows::Services::Store::StorePackageUpdateStatus> TrySilentDownloadStorePackageUpdatesAsync(param::async_iterable<Windows::Services::Store::StorePackageUpdate> const& storePackageUpdates) const;
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Services::Store::StorePackageUpdateResult, Windows::Services::Store::StorePackageUpdateStatus> TrySilentDownloadAndInstallStorePackageUpdatesAsync(param::async_iterable<Windows::Services::Store::StorePackageUpdate> const& storePackageUpdates) const;
    Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreCanAcquireLicenseResult> CanAcquireStoreLicenseForOptionalPackageAsync(Windows::ApplicationModel::Package const& optionalPackage) const;
    Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreCanAcquireLicenseResult> CanAcquireStoreLicenseAsync(param::hstring const& productStoreId) const;
    Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreProductQueryResult> GetStoreProductsAsync(param::async_iterable<hstring> const& productKinds, param::async_iterable<hstring> const& storeIds, Windows::Services::Store::StoreProductOptions const& storeProductOptions) const;
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Services::Store::StoreQueueItem>> GetAssociatedStoreQueueItemsAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Services::Store::StoreQueueItem>> GetStoreQueueItemsAsync(param::async_iterable<hstring> const& storeIds) const;
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Services::Store::StorePackageUpdateResult, Windows::Services::Store::StorePackageUpdateStatus> RequestDownloadAndInstallStorePackagesAsync(param::async_iterable<hstring> const& storeIds, Windows::Services::Store::StorePackageInstallOptions const& storePackageInstallOptions) const;
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Services::Store::StorePackageUpdateResult, Windows::Services::Store::StorePackageUpdateStatus> DownloadAndInstallStorePackagesAsync(param::async_iterable<hstring> const& storeIds) const;
    Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreUninstallStorePackageResult> RequestUninstallStorePackageAsync(Windows::ApplicationModel::Package const& package) const;
    Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreUninstallStorePackageResult> RequestUninstallStorePackageByStoreIdAsync(param::hstring const& storeId) const;
    Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreUninstallStorePackageResult> UninstallStorePackageAsync(Windows::ApplicationModel::Package const& package) const;
    Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreUninstallStorePackageResult> UninstallStorePackageByStoreIdAsync(param::hstring const& storeId) const;
};
template <> struct consume<Windows::Services::Store::IStoreContext3> { template <typename D> using type = consume_Windows_Services_Store_IStoreContext3<D>; };

template <typename D>
struct consume_Windows_Services_Store_IStoreContext4
{
    Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreRateAndReviewResult> RequestRateAndReviewAppAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Services::Store::StoreQueueItem>> SetInstallOrderForAssociatedStoreQueueItemsAsync(param::async_iterable<Windows::Services::Store::StoreQueueItem> const& items) const;
};
template <> struct consume<Windows::Services::Store::IStoreContext4> { template <typename D> using type = consume_Windows_Services_Store_IStoreContext4<D>; };

template <typename D>
struct consume_Windows_Services_Store_IStoreContextStatics
{
    Windows::Services::Store::StoreContext GetDefault() const;
    Windows::Services::Store::StoreContext GetForUser(Windows::System::User const& user) const;
};
template <> struct consume<Windows::Services::Store::IStoreContextStatics> { template <typename D> using type = consume_Windows_Services_Store_IStoreContextStatics<D>; };

template <typename D>
struct consume_Windows_Services_Store_IStoreImage
{
    Windows::Foundation::Uri Uri() const;
    hstring ImagePurposeTag() const;
    uint32_t Width() const;
    uint32_t Height() const;
    hstring Caption() const;
};
template <> struct consume<Windows::Services::Store::IStoreImage> { template <typename D> using type = consume_Windows_Services_Store_IStoreImage<D>; };

template <typename D>
struct consume_Windows_Services_Store_IStoreLicense
{
    hstring SkuStoreId() const;
    bool IsActive() const;
    Windows::Foundation::DateTime ExpirationDate() const;
    hstring ExtendedJsonData() const;
    hstring InAppOfferToken() const;
};
template <> struct consume<Windows::Services::Store::IStoreLicense> { template <typename D> using type = consume_Windows_Services_Store_IStoreLicense<D>; };

template <typename D>
struct consume_Windows_Services_Store_IStorePackageInstallOptions
{
    bool AllowForcedAppRestart() const;
    void AllowForcedAppRestart(bool value) const;
};
template <> struct consume<Windows::Services::Store::IStorePackageInstallOptions> { template <typename D> using type = consume_Windows_Services_Store_IStorePackageInstallOptions<D>; };

template <typename D>
struct consume_Windows_Services_Store_IStorePackageLicense
{
    winrt::event_token LicenseLost(Windows::Foundation::TypedEventHandler<Windows::Services::Store::StorePackageLicense, Windows::Foundation::IInspectable> const& handler) const;
    using LicenseLost_revoker = impl::event_revoker<Windows::Services::Store::IStorePackageLicense, &impl::abi_t<Windows::Services::Store::IStorePackageLicense>::remove_LicenseLost>;
    LicenseLost_revoker LicenseLost(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Services::Store::StorePackageLicense, Windows::Foundation::IInspectable> const& handler) const;
    void LicenseLost(winrt::event_token const& token) const noexcept;
    Windows::ApplicationModel::Package Package() const;
    bool IsValid() const;
    void ReleaseLicense() const;
};
template <> struct consume<Windows::Services::Store::IStorePackageLicense> { template <typename D> using type = consume_Windows_Services_Store_IStorePackageLicense<D>; };

template <typename D>
struct consume_Windows_Services_Store_IStorePackageUpdate
{
    Windows::ApplicationModel::Package Package() const;
    bool Mandatory() const;
};
template <> struct consume<Windows::Services::Store::IStorePackageUpdate> { template <typename D> using type = consume_Windows_Services_Store_IStorePackageUpdate<D>; };

template <typename D>
struct consume_Windows_Services_Store_IStorePackageUpdateResult
{
    Windows::Services::Store::StorePackageUpdateState OverallState() const;
    Windows::Foundation::Collections::IVectorView<Windows::Services::Store::StorePackageUpdateStatus> StorePackageUpdateStatuses() const;
};
template <> struct consume<Windows::Services::Store::IStorePackageUpdateResult> { template <typename D> using type = consume_Windows_Services_Store_IStorePackageUpdateResult<D>; };

template <typename D>
struct consume_Windows_Services_Store_IStorePackageUpdateResult2
{
    Windows::Foundation::Collections::IVectorView<Windows::Services::Store::StoreQueueItem> StoreQueueItems() const;
};
template <> struct consume<Windows::Services::Store::IStorePackageUpdateResult2> { template <typename D> using type = consume_Windows_Services_Store_IStorePackageUpdateResult2<D>; };

template <typename D>
struct consume_Windows_Services_Store_IStorePrice
{
    hstring FormattedBasePrice() const;
    hstring FormattedPrice() const;
    bool IsOnSale() const;
    Windows::Foundation::DateTime SaleEndDate() const;
    hstring CurrencyCode() const;
    hstring FormattedRecurrencePrice() const;
};
template <> struct consume<Windows::Services::Store::IStorePrice> { template <typename D> using type = consume_Windows_Services_Store_IStorePrice<D>; };

template <typename D>
struct consume_Windows_Services_Store_IStoreProduct
{
    hstring StoreId() const;
    hstring Language() const;
    hstring Title() const;
    hstring Description() const;
    hstring ProductKind() const;
    bool HasDigitalDownload() const;
    Windows::Foundation::Collections::IVectorView<hstring> Keywords() const;
    Windows::Foundation::Collections::IVectorView<Windows::Services::Store::StoreImage> Images() const;
    Windows::Foundation::Collections::IVectorView<Windows::Services::Store::StoreVideo> Videos() const;
    Windows::Foundation::Collections::IVectorView<Windows::Services::Store::StoreSku> Skus() const;
    bool IsInUserCollection() const;
    Windows::Services::Store::StorePrice Price() const;
    hstring ExtendedJsonData() const;
    Windows::Foundation::Uri LinkUri() const;
    Windows::Foundation::IAsyncOperation<bool> GetIsAnySkuInstalledAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::Services::Store::StorePurchaseResult> RequestPurchaseAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::Services::Store::StorePurchaseResult> RequestPurchaseAsync(Windows::Services::Store::StorePurchaseProperties const& storePurchaseProperties) const;
    hstring InAppOfferToken() const;
};
template <> struct consume<Windows::Services::Store::IStoreProduct> { template <typename D> using type = consume_Windows_Services_Store_IStoreProduct<D>; };

template <typename D>
struct consume_Windows_Services_Store_IStoreProductOptions
{
    Windows::Foundation::Collections::IVector<hstring> ActionFilters() const;
};
template <> struct consume<Windows::Services::Store::IStoreProductOptions> { template <typename D> using type = consume_Windows_Services_Store_IStoreProductOptions<D>; };

template <typename D>
struct consume_Windows_Services_Store_IStoreProductPagedQueryResult
{
    Windows::Foundation::Collections::IMapView<hstring, Windows::Services::Store::StoreProduct> Products() const;
    bool HasMoreResults() const;
    winrt::hresult ExtendedError() const;
    Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreProductPagedQueryResult> GetNextAsync() const;
};
template <> struct consume<Windows::Services::Store::IStoreProductPagedQueryResult> { template <typename D> using type = consume_Windows_Services_Store_IStoreProductPagedQueryResult<D>; };

template <typename D>
struct consume_Windows_Services_Store_IStoreProductQueryResult
{
    Windows::Foundation::Collections::IMapView<hstring, Windows::Services::Store::StoreProduct> Products() const;
    winrt::hresult ExtendedError() const;
};
template <> struct consume<Windows::Services::Store::IStoreProductQueryResult> { template <typename D> using type = consume_Windows_Services_Store_IStoreProductQueryResult<D>; };

template <typename D>
struct consume_Windows_Services_Store_IStoreProductResult
{
    Windows::Services::Store::StoreProduct Product() const;
    winrt::hresult ExtendedError() const;
};
template <> struct consume<Windows::Services::Store::IStoreProductResult> { template <typename D> using type = consume_Windows_Services_Store_IStoreProductResult<D>; };

template <typename D>
struct consume_Windows_Services_Store_IStorePurchaseProperties
{
    hstring Name() const;
    void Name(param::hstring const& value) const;
    hstring ExtendedJsonData() const;
    void ExtendedJsonData(param::hstring const& value) const;
};
template <> struct consume<Windows::Services::Store::IStorePurchaseProperties> { template <typename D> using type = consume_Windows_Services_Store_IStorePurchaseProperties<D>; };

template <typename D>
struct consume_Windows_Services_Store_IStorePurchasePropertiesFactory
{
    Windows::Services::Store::StorePurchaseProperties Create(param::hstring const& name) const;
};
template <> struct consume<Windows::Services::Store::IStorePurchasePropertiesFactory> { template <typename D> using type = consume_Windows_Services_Store_IStorePurchasePropertiesFactory<D>; };

template <typename D>
struct consume_Windows_Services_Store_IStorePurchaseResult
{
    Windows::Services::Store::StorePurchaseStatus Status() const;
    winrt::hresult ExtendedError() const;
};
template <> struct consume<Windows::Services::Store::IStorePurchaseResult> { template <typename D> using type = consume_Windows_Services_Store_IStorePurchaseResult<D>; };

template <typename D>
struct consume_Windows_Services_Store_IStoreQueueItem
{
    hstring ProductId() const;
    hstring PackageFamilyName() const;
    Windows::Services::Store::StoreQueueItemKind InstallKind() const;
    Windows::Services::Store::StoreQueueItemStatus GetCurrentStatus() const;
    winrt::event_token Completed(Windows::Foundation::TypedEventHandler<Windows::Services::Store::StoreQueueItem, Windows::Services::Store::StoreQueueItemCompletedEventArgs> const& handler) const;
    using Completed_revoker = impl::event_revoker<Windows::Services::Store::IStoreQueueItem, &impl::abi_t<Windows::Services::Store::IStoreQueueItem>::remove_Completed>;
    Completed_revoker Completed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Services::Store::StoreQueueItem, Windows::Services::Store::StoreQueueItemCompletedEventArgs> const& handler) const;
    void Completed(winrt::event_token const& token) const noexcept;
    winrt::event_token StatusChanged(Windows::Foundation::TypedEventHandler<Windows::Services::Store::StoreQueueItem, Windows::Foundation::IInspectable> const& handler) const;
    using StatusChanged_revoker = impl::event_revoker<Windows::Services::Store::IStoreQueueItem, &impl::abi_t<Windows::Services::Store::IStoreQueueItem>::remove_StatusChanged>;
    StatusChanged_revoker StatusChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Services::Store::StoreQueueItem, Windows::Foundation::IInspectable> const& handler) const;
    void StatusChanged(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::Services::Store::IStoreQueueItem> { template <typename D> using type = consume_Windows_Services_Store_IStoreQueueItem<D>; };

template <typename D>
struct consume_Windows_Services_Store_IStoreQueueItem2
{
    Windows::Foundation::IAsyncAction CancelInstallAsync() const;
    Windows::Foundation::IAsyncAction PauseInstallAsync() const;
    Windows::Foundation::IAsyncAction ResumeInstallAsync() const;
};
template <> struct consume<Windows::Services::Store::IStoreQueueItem2> { template <typename D> using type = consume_Windows_Services_Store_IStoreQueueItem2<D>; };

template <typename D>
struct consume_Windows_Services_Store_IStoreQueueItemCompletedEventArgs
{
    Windows::Services::Store::StoreQueueItemStatus Status() const;
};
template <> struct consume<Windows::Services::Store::IStoreQueueItemCompletedEventArgs> { template <typename D> using type = consume_Windows_Services_Store_IStoreQueueItemCompletedEventArgs<D>; };

template <typename D>
struct consume_Windows_Services_Store_IStoreQueueItemStatus
{
    Windows::Services::Store::StoreQueueItemState PackageInstallState() const;
    Windows::Services::Store::StoreQueueItemExtendedState PackageInstallExtendedState() const;
    Windows::Services::Store::StorePackageUpdateStatus UpdateStatus() const;
    winrt::hresult ExtendedError() const;
};
template <> struct consume<Windows::Services::Store::IStoreQueueItemStatus> { template <typename D> using type = consume_Windows_Services_Store_IStoreQueueItemStatus<D>; };

template <typename D>
struct consume_Windows_Services_Store_IStoreRateAndReviewResult
{
    winrt::hresult ExtendedError() const;
    hstring ExtendedJsonData() const;
    bool WasUpdated() const;
    Windows::Services::Store::StoreRateAndReviewStatus Status() const;
};
template <> struct consume<Windows::Services::Store::IStoreRateAndReviewResult> { template <typename D> using type = consume_Windows_Services_Store_IStoreRateAndReviewResult<D>; };

template <typename D>
struct consume_Windows_Services_Store_IStoreRequestHelperStatics
{
    Windows::Foundation::IAsyncOperation<Windows::Services::Store::StoreSendRequestResult> SendRequestAsync(Windows::Services::Store::StoreContext const& context, uint32_t requestKind, param::hstring const& parametersAsJson) const;
};
template <> struct consume<Windows::Services::Store::IStoreRequestHelperStatics> { template <typename D> using type = consume_Windows_Services_Store_IStoreRequestHelperStatics<D>; };

template <typename D>
struct consume_Windows_Services_Store_IStoreSendRequestResult
{
    hstring Response() const;
    winrt::hresult ExtendedError() const;
};
template <> struct consume<Windows::Services::Store::IStoreSendRequestResult> { template <typename D> using type = consume_Windows_Services_Store_IStoreSendRequestResult<D>; };

template <typename D>
struct consume_Windows_Services_Store_IStoreSendRequestResult2
{
    Windows::Web::Http::HttpStatusCode HttpStatusCode() const;
};
template <> struct consume<Windows::Services::Store::IStoreSendRequestResult2> { template <typename D> using type = consume_Windows_Services_Store_IStoreSendRequestResult2<D>; };

template <typename D>
struct consume_Windows_Services_Store_IStoreSku
{
    hstring StoreId() const;
    hstring Language() const;
    hstring Title() const;
    hstring Description() const;
    bool IsTrial() const;
    hstring CustomDeveloperData() const;
    Windows::Foundation::Collections::IVectorView<Windows::Services::Store::StoreImage> Images() const;
    Windows::Foundation::Collections::IVectorView<Windows::Services::Store::StoreVideo> Videos() const;
    Windows::Foundation::Collections::IVectorView<Windows::Services::Store::StoreAvailability> Availabilities() const;
    Windows::Services::Store::StorePrice Price() const;
    hstring ExtendedJsonData() const;
    bool IsInUserCollection() const;
    Windows::Foundation::Collections::IVectorView<hstring> BundledSkus() const;
    Windows::Services::Store::StoreCollectionData CollectionData() const;
    Windows::Foundation::IAsyncOperation<bool> GetIsInstalledAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::Services::Store::StorePurchaseResult> RequestPurchaseAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::Services::Store::StorePurchaseResult> RequestPurchaseAsync(Windows::Services::Store::StorePurchaseProperties const& storePurchaseProperties) const;
    bool IsSubscription() const;
    Windows::Services::Store::StoreSubscriptionInfo SubscriptionInfo() const;
};
template <> struct consume<Windows::Services::Store::IStoreSku> { template <typename D> using type = consume_Windows_Services_Store_IStoreSku<D>; };

template <typename D>
struct consume_Windows_Services_Store_IStoreSubscriptionInfo
{
    uint32_t BillingPeriod() const;
    Windows::Services::Store::StoreDurationUnit BillingPeriodUnit() const;
    bool HasTrialPeriod() const;
    uint32_t TrialPeriod() const;
    Windows::Services::Store::StoreDurationUnit TrialPeriodUnit() const;
};
template <> struct consume<Windows::Services::Store::IStoreSubscriptionInfo> { template <typename D> using type = consume_Windows_Services_Store_IStoreSubscriptionInfo<D>; };

template <typename D>
struct consume_Windows_Services_Store_IStoreUninstallStorePackageResult
{
    winrt::hresult ExtendedError() const;
    Windows::Services::Store::StoreUninstallStorePackageStatus Status() const;
};
template <> struct consume<Windows::Services::Store::IStoreUninstallStorePackageResult> { template <typename D> using type = consume_Windows_Services_Store_IStoreUninstallStorePackageResult<D>; };

template <typename D>
struct consume_Windows_Services_Store_IStoreVideo
{
    Windows::Foundation::Uri Uri() const;
    hstring VideoPurposeTag() const;
    uint32_t Width() const;
    uint32_t Height() const;
    hstring Caption() const;
    Windows::Services::Store::StoreImage PreviewImage() const;
};
template <> struct consume<Windows::Services::Store::IStoreVideo> { template <typename D> using type = consume_Windows_Services_Store_IStoreVideo<D>; };

struct struct_Windows_Services_Store_StorePackageUpdateStatus
{
    void* PackageFamilyName;
    uint64_t PackageDownloadSizeInBytes;
    uint64_t PackageBytesDownloaded;
    double PackageDownloadProgress;
    double TotalDownloadProgress;
    Windows::Services::Store::StorePackageUpdateState PackageUpdateState;
};
template <> struct abi<Windows::Services::Store::StorePackageUpdateStatus>{ using type = struct_Windows_Services_Store_StorePackageUpdateStatus; };


}
