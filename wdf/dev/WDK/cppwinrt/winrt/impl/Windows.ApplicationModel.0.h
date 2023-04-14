// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Activation {

struct IActivatedEventArgs;

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Core {

struct AppListEntry;

}

WINRT_EXPORT namespace winrt::Windows::Foundation {

struct Deferral;
struct Uri;

}

WINRT_EXPORT namespace winrt::Windows::Storage {

struct StorageFolder;

}

WINRT_EXPORT namespace winrt::Windows::Storage::Streams {

struct RandomAccessStreamReference;

}

WINRT_EXPORT namespace winrt::Windows::System {

enum class ProcessorArchitecture;

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel {

enum class AddResourcePackageOptions : uint32_t
{
    None = 0x0,
    ForceTargetAppShutdown = 0x1,
    ApplyUpdateIfAvailable = 0x2,
};

enum class LimitedAccessFeatureStatus : int32_t
{
    Unavailable = 0,
    Available = 1,
    AvailableWithoutToken = 2,
    Unknown = 3,
};

enum class PackageContentGroupState : int32_t
{
    NotStaged = 0,
    Queued = 1,
    Staging = 2,
    Staged = 3,
};

enum class PackageSignatureKind : int32_t
{
    None = 0,
    Developer = 1,
    Enterprise = 2,
    Store = 3,
    System = 4,
};

enum class PackageUpdateAvailability : int32_t
{
    Unknown = 0,
    NoUpdates = 1,
    Available = 2,
    Required = 3,
    Error = 4,
};

enum class StartupTaskState : int32_t
{
    Disabled = 0,
    DisabledByUser = 1,
    Enabled = 2,
    DisabledByPolicy = 3,
    EnabledByPolicy = 4,
};

struct IAppDisplayInfo;
struct IAppInfo;
struct IAppInstallerInfo;
struct IAppInstance;
struct IAppInstanceStatics;
struct IDesignModeStatics;
struct IDesignModeStatics2;
struct IEnteredBackgroundEventArgs;
struct IFullTrustProcessLauncherStatics;
struct ILeavingBackgroundEventArgs;
struct ILimitedAccessFeatureRequestResult;
struct ILimitedAccessFeaturesStatics;
struct IPackage;
struct IPackage2;
struct IPackage3;
struct IPackage4;
struct IPackage5;
struct IPackage6;
struct IPackage7;
struct IPackageCatalog;
struct IPackageCatalog2;
struct IPackageCatalog3;
struct IPackageCatalog4;
struct IPackageCatalogAddOptionalPackageResult;
struct IPackageCatalogAddResourcePackageResult;
struct IPackageCatalogRemoveOptionalPackagesResult;
struct IPackageCatalogRemoveResourcePackagesResult;
struct IPackageCatalogStatics;
struct IPackageContentGroup;
struct IPackageContentGroupStagingEventArgs;
struct IPackageContentGroupStatics;
struct IPackageId;
struct IPackageIdWithMetadata;
struct IPackageInstallingEventArgs;
struct IPackageStagingEventArgs;
struct IPackageStatics;
struct IPackageStatus;
struct IPackageStatus2;
struct IPackageStatusChangedEventArgs;
struct IPackageUninstallingEventArgs;
struct IPackageUpdateAvailabilityResult;
struct IPackageUpdatingEventArgs;
struct IPackageWithMetadata;
struct IStartupTask;
struct IStartupTaskStatics;
struct ISuspendingDeferral;
struct ISuspendingEventArgs;
struct ISuspendingOperation;
struct AppDisplayInfo;
struct AppInfo;
struct AppInstallerInfo;
struct AppInstance;
struct DesignMode;
struct EnteredBackgroundEventArgs;
struct FullTrustProcessLauncher;
struct LeavingBackgroundEventArgs;
struct LimitedAccessFeatureRequestResult;
struct LimitedAccessFeatures;
struct Package;
struct PackageCatalog;
struct PackageCatalogAddOptionalPackageResult;
struct PackageCatalogAddResourcePackageResult;
struct PackageCatalogRemoveOptionalPackagesResult;
struct PackageCatalogRemoveResourcePackagesResult;
struct PackageContentGroup;
struct PackageContentGroupStagingEventArgs;
struct PackageId;
struct PackageInstallingEventArgs;
struct PackageStagingEventArgs;
struct PackageStatus;
struct PackageStatusChangedEventArgs;
struct PackageUninstallingEventArgs;
struct PackageUpdateAvailabilityResult;
struct PackageUpdatingEventArgs;
struct StartupTask;
struct SuspendingDeferral;
struct SuspendingEventArgs;
struct SuspendingOperation;
struct PackageInstallProgress;
struct PackageVersion;

}

namespace winrt::impl {

template<> struct is_enum_flag<Windows::ApplicationModel::AddResourcePackageOptions> : std::true_type {};
template <> struct category<Windows::ApplicationModel::IAppDisplayInfo>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::IAppInfo>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::IAppInstallerInfo>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::IAppInstance>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::IAppInstanceStatics>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::IDesignModeStatics>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::IDesignModeStatics2>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::IEnteredBackgroundEventArgs>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::IFullTrustProcessLauncherStatics>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::ILeavingBackgroundEventArgs>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::ILimitedAccessFeatureRequestResult>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::ILimitedAccessFeaturesStatics>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::IPackage>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::IPackage2>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::IPackage3>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::IPackage4>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::IPackage5>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::IPackage6>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::IPackage7>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::IPackageCatalog>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::IPackageCatalog2>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::IPackageCatalog3>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::IPackageCatalog4>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::IPackageCatalogAddOptionalPackageResult>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::IPackageCatalogAddResourcePackageResult>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::IPackageCatalogRemoveOptionalPackagesResult>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::IPackageCatalogRemoveResourcePackagesResult>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::IPackageCatalogStatics>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::IPackageContentGroup>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::IPackageContentGroupStagingEventArgs>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::IPackageContentGroupStatics>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::IPackageId>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::IPackageIdWithMetadata>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::IPackageInstallingEventArgs>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::IPackageStagingEventArgs>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::IPackageStatics>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::IPackageStatus>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::IPackageStatus2>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::IPackageStatusChangedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::IPackageUninstallingEventArgs>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::IPackageUpdateAvailabilityResult>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::IPackageUpdatingEventArgs>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::IPackageWithMetadata>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::IStartupTask>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::IStartupTaskStatics>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::ISuspendingDeferral>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::ISuspendingEventArgs>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::ISuspendingOperation>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::AppDisplayInfo>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::AppInfo>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::AppInstallerInfo>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::AppInstance>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::DesignMode>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::EnteredBackgroundEventArgs>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::FullTrustProcessLauncher>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::LeavingBackgroundEventArgs>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::LimitedAccessFeatureRequestResult>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::LimitedAccessFeatures>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::Package>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::PackageCatalog>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::PackageCatalogAddOptionalPackageResult>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::PackageCatalogAddResourcePackageResult>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::PackageCatalogRemoveOptionalPackagesResult>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::PackageCatalogRemoveResourcePackagesResult>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::PackageContentGroup>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::PackageContentGroupStagingEventArgs>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::PackageId>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::PackageInstallingEventArgs>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::PackageStagingEventArgs>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::PackageStatus>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::PackageStatusChangedEventArgs>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::PackageUninstallingEventArgs>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::PackageUpdateAvailabilityResult>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::PackageUpdatingEventArgs>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::StartupTask>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::SuspendingDeferral>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::SuspendingEventArgs>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::SuspendingOperation>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::AddResourcePackageOptions>{ using type = enum_category; };
template <> struct category<Windows::ApplicationModel::LimitedAccessFeatureStatus>{ using type = enum_category; };
template <> struct category<Windows::ApplicationModel::PackageContentGroupState>{ using type = enum_category; };
template <> struct category<Windows::ApplicationModel::PackageSignatureKind>{ using type = enum_category; };
template <> struct category<Windows::ApplicationModel::PackageUpdateAvailability>{ using type = enum_category; };
template <> struct category<Windows::ApplicationModel::StartupTaskState>{ using type = enum_category; };
template <> struct category<Windows::ApplicationModel::PackageInstallProgress>{ using type = struct_category<uint32_t>; };
template <> struct category<Windows::ApplicationModel::PackageVersion>{ using type = struct_category<uint16_t,uint16_t,uint16_t,uint16_t>; };
template <> struct name<Windows::ApplicationModel::IAppDisplayInfo>{ static constexpr auto & value{ L"Windows.ApplicationModel.IAppDisplayInfo" }; };
template <> struct name<Windows::ApplicationModel::IAppInfo>{ static constexpr auto & value{ L"Windows.ApplicationModel.IAppInfo" }; };
template <> struct name<Windows::ApplicationModel::IAppInstallerInfo>{ static constexpr auto & value{ L"Windows.ApplicationModel.IAppInstallerInfo" }; };
template <> struct name<Windows::ApplicationModel::IAppInstance>{ static constexpr auto & value{ L"Windows.ApplicationModel.IAppInstance" }; };
template <> struct name<Windows::ApplicationModel::IAppInstanceStatics>{ static constexpr auto & value{ L"Windows.ApplicationModel.IAppInstanceStatics" }; };
template <> struct name<Windows::ApplicationModel::IDesignModeStatics>{ static constexpr auto & value{ L"Windows.ApplicationModel.IDesignModeStatics" }; };
template <> struct name<Windows::ApplicationModel::IDesignModeStatics2>{ static constexpr auto & value{ L"Windows.ApplicationModel.IDesignModeStatics2" }; };
template <> struct name<Windows::ApplicationModel::IEnteredBackgroundEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.IEnteredBackgroundEventArgs" }; };
template <> struct name<Windows::ApplicationModel::IFullTrustProcessLauncherStatics>{ static constexpr auto & value{ L"Windows.ApplicationModel.IFullTrustProcessLauncherStatics" }; };
template <> struct name<Windows::ApplicationModel::ILeavingBackgroundEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.ILeavingBackgroundEventArgs" }; };
template <> struct name<Windows::ApplicationModel::ILimitedAccessFeatureRequestResult>{ static constexpr auto & value{ L"Windows.ApplicationModel.ILimitedAccessFeatureRequestResult" }; };
template <> struct name<Windows::ApplicationModel::ILimitedAccessFeaturesStatics>{ static constexpr auto & value{ L"Windows.ApplicationModel.ILimitedAccessFeaturesStatics" }; };
template <> struct name<Windows::ApplicationModel::IPackage>{ static constexpr auto & value{ L"Windows.ApplicationModel.IPackage" }; };
template <> struct name<Windows::ApplicationModel::IPackage2>{ static constexpr auto & value{ L"Windows.ApplicationModel.IPackage2" }; };
template <> struct name<Windows::ApplicationModel::IPackage3>{ static constexpr auto & value{ L"Windows.ApplicationModel.IPackage3" }; };
template <> struct name<Windows::ApplicationModel::IPackage4>{ static constexpr auto & value{ L"Windows.ApplicationModel.IPackage4" }; };
template <> struct name<Windows::ApplicationModel::IPackage5>{ static constexpr auto & value{ L"Windows.ApplicationModel.IPackage5" }; };
template <> struct name<Windows::ApplicationModel::IPackage6>{ static constexpr auto & value{ L"Windows.ApplicationModel.IPackage6" }; };
template <> struct name<Windows::ApplicationModel::IPackage7>{ static constexpr auto & value{ L"Windows.ApplicationModel.IPackage7" }; };
template <> struct name<Windows::ApplicationModel::IPackageCatalog>{ static constexpr auto & value{ L"Windows.ApplicationModel.IPackageCatalog" }; };
template <> struct name<Windows::ApplicationModel::IPackageCatalog2>{ static constexpr auto & value{ L"Windows.ApplicationModel.IPackageCatalog2" }; };
template <> struct name<Windows::ApplicationModel::IPackageCatalog3>{ static constexpr auto & value{ L"Windows.ApplicationModel.IPackageCatalog3" }; };
template <> struct name<Windows::ApplicationModel::IPackageCatalog4>{ static constexpr auto & value{ L"Windows.ApplicationModel.IPackageCatalog4" }; };
template <> struct name<Windows::ApplicationModel::IPackageCatalogAddOptionalPackageResult>{ static constexpr auto & value{ L"Windows.ApplicationModel.IPackageCatalogAddOptionalPackageResult" }; };
template <> struct name<Windows::ApplicationModel::IPackageCatalogAddResourcePackageResult>{ static constexpr auto & value{ L"Windows.ApplicationModel.IPackageCatalogAddResourcePackageResult" }; };
template <> struct name<Windows::ApplicationModel::IPackageCatalogRemoveOptionalPackagesResult>{ static constexpr auto & value{ L"Windows.ApplicationModel.IPackageCatalogRemoveOptionalPackagesResult" }; };
template <> struct name<Windows::ApplicationModel::IPackageCatalogRemoveResourcePackagesResult>{ static constexpr auto & value{ L"Windows.ApplicationModel.IPackageCatalogRemoveResourcePackagesResult" }; };
template <> struct name<Windows::ApplicationModel::IPackageCatalogStatics>{ static constexpr auto & value{ L"Windows.ApplicationModel.IPackageCatalogStatics" }; };
template <> struct name<Windows::ApplicationModel::IPackageContentGroup>{ static constexpr auto & value{ L"Windows.ApplicationModel.IPackageContentGroup" }; };
template <> struct name<Windows::ApplicationModel::IPackageContentGroupStagingEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.IPackageContentGroupStagingEventArgs" }; };
template <> struct name<Windows::ApplicationModel::IPackageContentGroupStatics>{ static constexpr auto & value{ L"Windows.ApplicationModel.IPackageContentGroupStatics" }; };
template <> struct name<Windows::ApplicationModel::IPackageId>{ static constexpr auto & value{ L"Windows.ApplicationModel.IPackageId" }; };
template <> struct name<Windows::ApplicationModel::IPackageIdWithMetadata>{ static constexpr auto & value{ L"Windows.ApplicationModel.IPackageIdWithMetadata" }; };
template <> struct name<Windows::ApplicationModel::IPackageInstallingEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.IPackageInstallingEventArgs" }; };
template <> struct name<Windows::ApplicationModel::IPackageStagingEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.IPackageStagingEventArgs" }; };
template <> struct name<Windows::ApplicationModel::IPackageStatics>{ static constexpr auto & value{ L"Windows.ApplicationModel.IPackageStatics" }; };
template <> struct name<Windows::ApplicationModel::IPackageStatus>{ static constexpr auto & value{ L"Windows.ApplicationModel.IPackageStatus" }; };
template <> struct name<Windows::ApplicationModel::IPackageStatus2>{ static constexpr auto & value{ L"Windows.ApplicationModel.IPackageStatus2" }; };
template <> struct name<Windows::ApplicationModel::IPackageStatusChangedEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.IPackageStatusChangedEventArgs" }; };
template <> struct name<Windows::ApplicationModel::IPackageUninstallingEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.IPackageUninstallingEventArgs" }; };
template <> struct name<Windows::ApplicationModel::IPackageUpdateAvailabilityResult>{ static constexpr auto & value{ L"Windows.ApplicationModel.IPackageUpdateAvailabilityResult" }; };
template <> struct name<Windows::ApplicationModel::IPackageUpdatingEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.IPackageUpdatingEventArgs" }; };
template <> struct name<Windows::ApplicationModel::IPackageWithMetadata>{ static constexpr auto & value{ L"Windows.ApplicationModel.IPackageWithMetadata" }; };
template <> struct name<Windows::ApplicationModel::IStartupTask>{ static constexpr auto & value{ L"Windows.ApplicationModel.IStartupTask" }; };
template <> struct name<Windows::ApplicationModel::IStartupTaskStatics>{ static constexpr auto & value{ L"Windows.ApplicationModel.IStartupTaskStatics" }; };
template <> struct name<Windows::ApplicationModel::ISuspendingDeferral>{ static constexpr auto & value{ L"Windows.ApplicationModel.ISuspendingDeferral" }; };
template <> struct name<Windows::ApplicationModel::ISuspendingEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.ISuspendingEventArgs" }; };
template <> struct name<Windows::ApplicationModel::ISuspendingOperation>{ static constexpr auto & value{ L"Windows.ApplicationModel.ISuspendingOperation" }; };
template <> struct name<Windows::ApplicationModel::AppDisplayInfo>{ static constexpr auto & value{ L"Windows.ApplicationModel.AppDisplayInfo" }; };
template <> struct name<Windows::ApplicationModel::AppInfo>{ static constexpr auto & value{ L"Windows.ApplicationModel.AppInfo" }; };
template <> struct name<Windows::ApplicationModel::AppInstallerInfo>{ static constexpr auto & value{ L"Windows.ApplicationModel.AppInstallerInfo" }; };
template <> struct name<Windows::ApplicationModel::AppInstance>{ static constexpr auto & value{ L"Windows.ApplicationModel.AppInstance" }; };
template <> struct name<Windows::ApplicationModel::DesignMode>{ static constexpr auto & value{ L"Windows.ApplicationModel.DesignMode" }; };
template <> struct name<Windows::ApplicationModel::EnteredBackgroundEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.EnteredBackgroundEventArgs" }; };
template <> struct name<Windows::ApplicationModel::FullTrustProcessLauncher>{ static constexpr auto & value{ L"Windows.ApplicationModel.FullTrustProcessLauncher" }; };
template <> struct name<Windows::ApplicationModel::LeavingBackgroundEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.LeavingBackgroundEventArgs" }; };
template <> struct name<Windows::ApplicationModel::LimitedAccessFeatureRequestResult>{ static constexpr auto & value{ L"Windows.ApplicationModel.LimitedAccessFeatureRequestResult" }; };
template <> struct name<Windows::ApplicationModel::LimitedAccessFeatures>{ static constexpr auto & value{ L"Windows.ApplicationModel.LimitedAccessFeatures" }; };
template <> struct name<Windows::ApplicationModel::Package>{ static constexpr auto & value{ L"Windows.ApplicationModel.Package" }; };
template <> struct name<Windows::ApplicationModel::PackageCatalog>{ static constexpr auto & value{ L"Windows.ApplicationModel.PackageCatalog" }; };
template <> struct name<Windows::ApplicationModel::PackageCatalogAddOptionalPackageResult>{ static constexpr auto & value{ L"Windows.ApplicationModel.PackageCatalogAddOptionalPackageResult" }; };
template <> struct name<Windows::ApplicationModel::PackageCatalogAddResourcePackageResult>{ static constexpr auto & value{ L"Windows.ApplicationModel.PackageCatalogAddResourcePackageResult" }; };
template <> struct name<Windows::ApplicationModel::PackageCatalogRemoveOptionalPackagesResult>{ static constexpr auto & value{ L"Windows.ApplicationModel.PackageCatalogRemoveOptionalPackagesResult" }; };
template <> struct name<Windows::ApplicationModel::PackageCatalogRemoveResourcePackagesResult>{ static constexpr auto & value{ L"Windows.ApplicationModel.PackageCatalogRemoveResourcePackagesResult" }; };
template <> struct name<Windows::ApplicationModel::PackageContentGroup>{ static constexpr auto & value{ L"Windows.ApplicationModel.PackageContentGroup" }; };
template <> struct name<Windows::ApplicationModel::PackageContentGroupStagingEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.PackageContentGroupStagingEventArgs" }; };
template <> struct name<Windows::ApplicationModel::PackageId>{ static constexpr auto & value{ L"Windows.ApplicationModel.PackageId" }; };
template <> struct name<Windows::ApplicationModel::PackageInstallingEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.PackageInstallingEventArgs" }; };
template <> struct name<Windows::ApplicationModel::PackageStagingEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.PackageStagingEventArgs" }; };
template <> struct name<Windows::ApplicationModel::PackageStatus>{ static constexpr auto & value{ L"Windows.ApplicationModel.PackageStatus" }; };
template <> struct name<Windows::ApplicationModel::PackageStatusChangedEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.PackageStatusChangedEventArgs" }; };
template <> struct name<Windows::ApplicationModel::PackageUninstallingEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.PackageUninstallingEventArgs" }; };
template <> struct name<Windows::ApplicationModel::PackageUpdateAvailabilityResult>{ static constexpr auto & value{ L"Windows.ApplicationModel.PackageUpdateAvailabilityResult" }; };
template <> struct name<Windows::ApplicationModel::PackageUpdatingEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.PackageUpdatingEventArgs" }; };
template <> struct name<Windows::ApplicationModel::StartupTask>{ static constexpr auto & value{ L"Windows.ApplicationModel.StartupTask" }; };
template <> struct name<Windows::ApplicationModel::SuspendingDeferral>{ static constexpr auto & value{ L"Windows.ApplicationModel.SuspendingDeferral" }; };
template <> struct name<Windows::ApplicationModel::SuspendingEventArgs>{ static constexpr auto & value{ L"Windows.ApplicationModel.SuspendingEventArgs" }; };
template <> struct name<Windows::ApplicationModel::SuspendingOperation>{ static constexpr auto & value{ L"Windows.ApplicationModel.SuspendingOperation" }; };
template <> struct name<Windows::ApplicationModel::AddResourcePackageOptions>{ static constexpr auto & value{ L"Windows.ApplicationModel.AddResourcePackageOptions" }; };
template <> struct name<Windows::ApplicationModel::LimitedAccessFeatureStatus>{ static constexpr auto & value{ L"Windows.ApplicationModel.LimitedAccessFeatureStatus" }; };
template <> struct name<Windows::ApplicationModel::PackageContentGroupState>{ static constexpr auto & value{ L"Windows.ApplicationModel.PackageContentGroupState" }; };
template <> struct name<Windows::ApplicationModel::PackageSignatureKind>{ static constexpr auto & value{ L"Windows.ApplicationModel.PackageSignatureKind" }; };
template <> struct name<Windows::ApplicationModel::PackageUpdateAvailability>{ static constexpr auto & value{ L"Windows.ApplicationModel.PackageUpdateAvailability" }; };
template <> struct name<Windows::ApplicationModel::StartupTaskState>{ static constexpr auto & value{ L"Windows.ApplicationModel.StartupTaskState" }; };
template <> struct name<Windows::ApplicationModel::PackageInstallProgress>{ static constexpr auto & value{ L"Windows.ApplicationModel.PackageInstallProgress" }; };
template <> struct name<Windows::ApplicationModel::PackageVersion>{ static constexpr auto & value{ L"Windows.ApplicationModel.PackageVersion" }; };
template <> struct guid_storage<Windows::ApplicationModel::IAppDisplayInfo>{ static constexpr guid value{ 0x1AEB1103,0xE4D4,0x41AA,{ 0xA4,0xF6,0xC4,0xA2,0x76,0xE7,0x9E,0xAC } }; };
template <> struct guid_storage<Windows::ApplicationModel::IAppInfo>{ static constexpr guid value{ 0xCF7F59B3,0x6A09,0x4DE8,{ 0xA6,0xC0,0x57,0x92,0xD5,0x68,0x80,0xD1 } }; };
template <> struct guid_storage<Windows::ApplicationModel::IAppInstallerInfo>{ static constexpr guid value{ 0x29AB2AC0,0xD4F6,0x42A3,{ 0xAD,0xCD,0xD6,0x58,0x3C,0x65,0x95,0x08 } }; };
template <> struct guid_storage<Windows::ApplicationModel::IAppInstance>{ static constexpr guid value{ 0x675F2B47,0xF25F,0x4532,{ 0x9F,0xD6,0x36,0x33,0xE0,0x63,0x4D,0x01 } }; };
template <> struct guid_storage<Windows::ApplicationModel::IAppInstanceStatics>{ static constexpr guid value{ 0x9D11E77F,0x9EA6,0x47AF,{ 0xA6,0xEC,0x46,0x78,0x4C,0x5B,0xA2,0x54 } }; };
template <> struct guid_storage<Windows::ApplicationModel::IDesignModeStatics>{ static constexpr guid value{ 0x2C3893CC,0xF81A,0x4E7A,{ 0xB8,0x57,0x76,0xA8,0x08,0x87,0xE1,0x85 } }; };
template <> struct guid_storage<Windows::ApplicationModel::IDesignModeStatics2>{ static constexpr guid value{ 0x80CF8137,0xB064,0x4858,{ 0xBE,0xC8,0x3E,0xBA,0x22,0x35,0x75,0x35 } }; };
template <> struct guid_storage<Windows::ApplicationModel::IEnteredBackgroundEventArgs>{ static constexpr guid value{ 0xF722DCC2,0x9827,0x403D,{ 0xAA,0xED,0xEC,0xCA,0x9A,0xC1,0x73,0x98 } }; };
template <> struct guid_storage<Windows::ApplicationModel::IFullTrustProcessLauncherStatics>{ static constexpr guid value{ 0xD784837F,0x1100,0x3C6B,{ 0xA4,0x55,0xF6,0x26,0x2C,0xC3,0x31,0xB6 } }; };
template <> struct guid_storage<Windows::ApplicationModel::ILeavingBackgroundEventArgs>{ static constexpr guid value{ 0x39C6EC9A,0xAE6E,0x46F9,{ 0xA0,0x7A,0xCF,0xC2,0x3F,0x88,0x73,0x3E } }; };
template <> struct guid_storage<Windows::ApplicationModel::ILimitedAccessFeatureRequestResult>{ static constexpr guid value{ 0xD45156A6,0x1E24,0x5DDD,{ 0xAB,0xB4,0x61,0x88,0xAB,0xA4,0xD5,0xBF } }; };
template <> struct guid_storage<Windows::ApplicationModel::ILimitedAccessFeaturesStatics>{ static constexpr guid value{ 0x8BE612D4,0x302B,0x5FBF,{ 0xA6,0x32,0x1A,0x99,0xE4,0x3E,0x89,0x25 } }; };
template <> struct guid_storage<Windows::ApplicationModel::IPackage>{ static constexpr guid value{ 0x163C792F,0xBD75,0x413C,{ 0xBF,0x23,0xB1,0xFE,0x7B,0x95,0xD8,0x25 } }; };
template <> struct guid_storage<Windows::ApplicationModel::IPackage2>{ static constexpr guid value{ 0xA6612FB6,0x7688,0x4ACE,{ 0x95,0xFB,0x35,0x95,0x38,0xE7,0xAA,0x01 } }; };
template <> struct guid_storage<Windows::ApplicationModel::IPackage3>{ static constexpr guid value{ 0x5F738B61,0xF86A,0x4917,{ 0x93,0xD1,0xF1,0xEE,0x9D,0x3B,0x35,0xD9 } }; };
template <> struct guid_storage<Windows::ApplicationModel::IPackage4>{ static constexpr guid value{ 0x65AED1AE,0xB95B,0x450C,{ 0x88,0x2B,0x62,0x55,0x18,0x7F,0x39,0x7E } }; };
template <> struct guid_storage<Windows::ApplicationModel::IPackage5>{ static constexpr guid value{ 0x0E842DD4,0xD9AC,0x45ED,{ 0x9A,0x1E,0x74,0xCE,0x05,0x6B,0x26,0x35 } }; };
template <> struct guid_storage<Windows::ApplicationModel::IPackage6>{ static constexpr guid value{ 0x8B1AD942,0x12D7,0x4754,{ 0xAE,0x4E,0x63,0x8C,0xBC,0x0E,0x3A,0x2E } }; };
template <> struct guid_storage<Windows::ApplicationModel::IPackage7>{ static constexpr guid value{ 0x86FF8D31,0xA2E4,0x45E0,{ 0x97,0x32,0x28,0x3A,0x6D,0x88,0xFD,0xE1 } }; };
template <> struct guid_storage<Windows::ApplicationModel::IPackageCatalog>{ static constexpr guid value{ 0x230A3751,0x9DE3,0x4445,{ 0xBE,0x74,0x91,0xFB,0x32,0x5A,0xBE,0xFE } }; };
template <> struct guid_storage<Windows::ApplicationModel::IPackageCatalog2>{ static constexpr guid value{ 0x96A60C36,0x8FF7,0x4344,{ 0xB6,0xBF,0xEE,0x64,0xC2,0x20,0x7E,0xD2 } }; };
template <> struct guid_storage<Windows::ApplicationModel::IPackageCatalog3>{ static constexpr guid value{ 0x96DD5C88,0x8837,0x43F9,{ 0x90,0x15,0x03,0x34,0x34,0xBA,0x14,0xF3 } }; };
template <> struct guid_storage<Windows::ApplicationModel::IPackageCatalog4>{ static constexpr guid value{ 0xC37C399B,0x44CC,0x4B7B,{ 0x8B,0xAF,0x79,0x6C,0x04,0xEA,0xD3,0xB9 } }; };
template <> struct guid_storage<Windows::ApplicationModel::IPackageCatalogAddOptionalPackageResult>{ static constexpr guid value{ 0x3BF10CD4,0xB4DF,0x47B3,{ 0xA9,0x63,0xE2,0xFA,0x83,0x2F,0x7D,0xD3 } }; };
template <> struct guid_storage<Windows::ApplicationModel::IPackageCatalogAddResourcePackageResult>{ static constexpr guid value{ 0x9636CE0D,0x3E17,0x493F,{ 0xAA,0x08,0xCC,0xEC,0x6F,0xDE,0xF6,0x99 } }; };
template <> struct guid_storage<Windows::ApplicationModel::IPackageCatalogRemoveOptionalPackagesResult>{ static constexpr guid value{ 0x29D2F97B,0xD974,0x4E64,{ 0x93,0x59,0x22,0xCA,0xDF,0xD7,0x98,0x28 } }; };
template <> struct guid_storage<Windows::ApplicationModel::IPackageCatalogRemoveResourcePackagesResult>{ static constexpr guid value{ 0xAE719709,0x1A52,0x4321,{ 0x87,0xB3,0xE5,0xA1,0xA1,0x79,0x81,0xA7 } }; };
template <> struct guid_storage<Windows::ApplicationModel::IPackageCatalogStatics>{ static constexpr guid value{ 0xA18C9696,0xE65B,0x4634,{ 0xBA,0x21,0x5E,0x63,0xEB,0x72,0x44,0xA7 } }; };
template <> struct guid_storage<Windows::ApplicationModel::IPackageContentGroup>{ static constexpr guid value{ 0x8F62695D,0x120A,0x4798,{ 0xB5,0xE1,0x58,0x00,0xDD,0xA8,0xF2,0xE1 } }; };
template <> struct guid_storage<Windows::ApplicationModel::IPackageContentGroupStagingEventArgs>{ static constexpr guid value{ 0x3D7BC27E,0x6F27,0x446C,{ 0x98,0x6E,0xD4,0x73,0x3D,0x4D,0x91,0x13 } }; };
template <> struct guid_storage<Windows::ApplicationModel::IPackageContentGroupStatics>{ static constexpr guid value{ 0x70EE7619,0x5F12,0x4B92,{ 0xB9,0xEA,0x6C,0xCA,0xDA,0x13,0xBC,0x75 } }; };
template <> struct guid_storage<Windows::ApplicationModel::IPackageId>{ static constexpr guid value{ 0x1ADB665E,0x37C7,0x4790,{ 0x99,0x80,0xDD,0x7A,0xE7,0x4E,0x8B,0xB2 } }; };
template <> struct guid_storage<Windows::ApplicationModel::IPackageIdWithMetadata>{ static constexpr guid value{ 0x40577A7C,0x0C9E,0x443D,{ 0x90,0x74,0x85,0x5F,0x5C,0xE0,0xA0,0x8D } }; };
template <> struct guid_storage<Windows::ApplicationModel::IPackageInstallingEventArgs>{ static constexpr guid value{ 0x97741EB7,0xAB7A,0x401A,{ 0x8B,0x61,0xEB,0x0E,0x7F,0xAF,0xF2,0x37 } }; };
template <> struct guid_storage<Windows::ApplicationModel::IPackageStagingEventArgs>{ static constexpr guid value{ 0x1041682D,0x54E2,0x4F51,{ 0xB8,0x28,0x9E,0xF7,0x04,0x6C,0x21,0x0F } }; };
template <> struct guid_storage<Windows::ApplicationModel::IPackageStatics>{ static constexpr guid value{ 0x4E534BDF,0x2960,0x4878,{ 0x97,0xA4,0x96,0x24,0xDE,0xB7,0x2F,0x2D } }; };
template <> struct guid_storage<Windows::ApplicationModel::IPackageStatus>{ static constexpr guid value{ 0x5FE74F71,0xA365,0x4C09,{ 0xA0,0x2D,0x04,0x6D,0x52,0x5E,0xA1,0xDA } }; };
template <> struct guid_storage<Windows::ApplicationModel::IPackageStatus2>{ static constexpr guid value{ 0xF428FA93,0x7C56,0x4862,{ 0xAC,0xFA,0xAB,0xAE,0xDC,0xC0,0x69,0x4D } }; };
template <> struct guid_storage<Windows::ApplicationModel::IPackageStatusChangedEventArgs>{ static constexpr guid value{ 0x437D714D,0xBD80,0x4A70,{ 0xBC,0x50,0xF6,0xE7,0x96,0x50,0x95,0x75 } }; };
template <> struct guid_storage<Windows::ApplicationModel::IPackageUninstallingEventArgs>{ static constexpr guid value{ 0x4443AA52,0xAB22,0x44CD,{ 0x82,0xBB,0x4E,0xC9,0xB8,0x27,0x36,0x7A } }; };
template <> struct guid_storage<Windows::ApplicationModel::IPackageUpdateAvailabilityResult>{ static constexpr guid value{ 0x114E5009,0x199A,0x48A1,{ 0xA0,0x79,0x31,0x3C,0x45,0x63,0x4A,0x71 } }; };
template <> struct guid_storage<Windows::ApplicationModel::IPackageUpdatingEventArgs>{ static constexpr guid value{ 0xCD7B4228,0xFD74,0x443E,{ 0xB1,0x14,0x23,0xE6,0x77,0xB0,0xE8,0x6F } }; };
template <> struct guid_storage<Windows::ApplicationModel::IPackageWithMetadata>{ static constexpr guid value{ 0x95949780,0x1DE9,0x40F2,{ 0xB4,0x52,0x0D,0xE9,0xF1,0x91,0x00,0x12 } }; };
template <> struct guid_storage<Windows::ApplicationModel::IStartupTask>{ static constexpr guid value{ 0xF75C23C8,0xB5F2,0x4F6C,{ 0x88,0xDD,0x36,0xCB,0x1D,0x59,0x9D,0x17 } }; };
template <> struct guid_storage<Windows::ApplicationModel::IStartupTaskStatics>{ static constexpr guid value{ 0xEE5B60BD,0xA148,0x41A7,{ 0xB2,0x6E,0xE8,0xB8,0x8A,0x1E,0x62,0xF8 } }; };
template <> struct guid_storage<Windows::ApplicationModel::ISuspendingDeferral>{ static constexpr guid value{ 0x59140509,0x8BC9,0x4EB4,{ 0xB6,0x36,0xDA,0xBD,0xC4,0xF4,0x6F,0x66 } }; };
template <> struct guid_storage<Windows::ApplicationModel::ISuspendingEventArgs>{ static constexpr guid value{ 0x96061C05,0x2DBA,0x4D08,{ 0xB0,0xBD,0x2B,0x30,0xA1,0x31,0xC6,0xAA } }; };
template <> struct guid_storage<Windows::ApplicationModel::ISuspendingOperation>{ static constexpr guid value{ 0x9DA4CA41,0x20E1,0x4E9B,{ 0x9F,0x65,0xA9,0xF4,0x35,0x34,0x0C,0x3A } }; };
template <> struct default_interface<Windows::ApplicationModel::AppDisplayInfo>{ using type = Windows::ApplicationModel::IAppDisplayInfo; };
template <> struct default_interface<Windows::ApplicationModel::AppInfo>{ using type = Windows::ApplicationModel::IAppInfo; };
template <> struct default_interface<Windows::ApplicationModel::AppInstallerInfo>{ using type = Windows::ApplicationModel::IAppInstallerInfo; };
template <> struct default_interface<Windows::ApplicationModel::AppInstance>{ using type = Windows::ApplicationModel::IAppInstance; };
template <> struct default_interface<Windows::ApplicationModel::EnteredBackgroundEventArgs>{ using type = Windows::ApplicationModel::IEnteredBackgroundEventArgs; };
template <> struct default_interface<Windows::ApplicationModel::LeavingBackgroundEventArgs>{ using type = Windows::ApplicationModel::ILeavingBackgroundEventArgs; };
template <> struct default_interface<Windows::ApplicationModel::LimitedAccessFeatureRequestResult>{ using type = Windows::ApplicationModel::ILimitedAccessFeatureRequestResult; };
template <> struct default_interface<Windows::ApplicationModel::Package>{ using type = Windows::ApplicationModel::IPackage; };
template <> struct default_interface<Windows::ApplicationModel::PackageCatalog>{ using type = Windows::ApplicationModel::IPackageCatalog; };
template <> struct default_interface<Windows::ApplicationModel::PackageCatalogAddOptionalPackageResult>{ using type = Windows::ApplicationModel::IPackageCatalogAddOptionalPackageResult; };
template <> struct default_interface<Windows::ApplicationModel::PackageCatalogAddResourcePackageResult>{ using type = Windows::ApplicationModel::IPackageCatalogAddResourcePackageResult; };
template <> struct default_interface<Windows::ApplicationModel::PackageCatalogRemoveOptionalPackagesResult>{ using type = Windows::ApplicationModel::IPackageCatalogRemoveOptionalPackagesResult; };
template <> struct default_interface<Windows::ApplicationModel::PackageCatalogRemoveResourcePackagesResult>{ using type = Windows::ApplicationModel::IPackageCatalogRemoveResourcePackagesResult; };
template <> struct default_interface<Windows::ApplicationModel::PackageContentGroup>{ using type = Windows::ApplicationModel::IPackageContentGroup; };
template <> struct default_interface<Windows::ApplicationModel::PackageContentGroupStagingEventArgs>{ using type = Windows::ApplicationModel::IPackageContentGroupStagingEventArgs; };
template <> struct default_interface<Windows::ApplicationModel::PackageId>{ using type = Windows::ApplicationModel::IPackageId; };
template <> struct default_interface<Windows::ApplicationModel::PackageInstallingEventArgs>{ using type = Windows::ApplicationModel::IPackageInstallingEventArgs; };
template <> struct default_interface<Windows::ApplicationModel::PackageStagingEventArgs>{ using type = Windows::ApplicationModel::IPackageStagingEventArgs; };
template <> struct default_interface<Windows::ApplicationModel::PackageStatus>{ using type = Windows::ApplicationModel::IPackageStatus; };
template <> struct default_interface<Windows::ApplicationModel::PackageStatusChangedEventArgs>{ using type = Windows::ApplicationModel::IPackageStatusChangedEventArgs; };
template <> struct default_interface<Windows::ApplicationModel::PackageUninstallingEventArgs>{ using type = Windows::ApplicationModel::IPackageUninstallingEventArgs; };
template <> struct default_interface<Windows::ApplicationModel::PackageUpdateAvailabilityResult>{ using type = Windows::ApplicationModel::IPackageUpdateAvailabilityResult; };
template <> struct default_interface<Windows::ApplicationModel::PackageUpdatingEventArgs>{ using type = Windows::ApplicationModel::IPackageUpdatingEventArgs; };
template <> struct default_interface<Windows::ApplicationModel::StartupTask>{ using type = Windows::ApplicationModel::IStartupTask; };
template <> struct default_interface<Windows::ApplicationModel::SuspendingDeferral>{ using type = Windows::ApplicationModel::ISuspendingDeferral; };
template <> struct default_interface<Windows::ApplicationModel::SuspendingEventArgs>{ using type = Windows::ApplicationModel::ISuspendingEventArgs; };
template <> struct default_interface<Windows::ApplicationModel::SuspendingOperation>{ using type = Windows::ApplicationModel::ISuspendingOperation; };

template <> struct abi<Windows::ApplicationModel::IAppDisplayInfo>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_DisplayName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Description(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetLogo(Windows::Foundation::Size size, void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::IAppInfo>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Id(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AppUserModelId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DisplayInfo(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PackageFamilyName(void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::IAppInstallerInfo>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Uri(void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::IAppInstance>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Key(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsCurrentInstance(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL RedirectActivationTo() noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::IAppInstanceStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_RecommendedInstance(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetActivatedEventArgs(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL FindOrRegisterInstanceForKey(void* key, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL Unregister() noexcept = 0;
    virtual int32_t WINRT_CALL GetInstances(void** result) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::IDesignModeStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_DesignModeEnabled(bool* value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::IDesignModeStatics2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_DesignMode2Enabled(bool* value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::IEnteredBackgroundEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetDeferral(void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::IFullTrustProcessLauncherStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL LaunchFullTrustProcessForCurrentAppAsync(void** asyncAction) noexcept = 0;
    virtual int32_t WINRT_CALL LaunchFullTrustProcessForCurrentAppWithParametersAsync(void* parameterGroupId, void** asyncAction) noexcept = 0;
    virtual int32_t WINRT_CALL LaunchFullTrustProcessForAppAsync(void* fullTrustPackageRelativeAppId, void** asyncAction) noexcept = 0;
    virtual int32_t WINRT_CALL LaunchFullTrustProcessForAppWithParametersAsync(void* fullTrustPackageRelativeAppId, void* parameterGroupId, void** asyncAction) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::ILeavingBackgroundEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetDeferral(void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::ILimitedAccessFeatureRequestResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_FeatureId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Status(Windows::ApplicationModel::LimitedAccessFeatureStatus* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_EstimatedRemovalDate(void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::ILimitedAccessFeaturesStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL TryUnlockFeature(void* featureId, void* token, void* attestation, void** result) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::IPackage>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Id(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_InstalledLocation(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsFramework(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Dependencies(void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::IPackage2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_DisplayName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PublisherDisplayName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Description(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Logo(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsResourcePackage(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsBundle(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsDevelopmentMode(bool* value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::IPackage3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Status(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_InstalledDate(Windows::Foundation::DateTime* value) noexcept = 0;
    virtual int32_t WINRT_CALL GetAppListEntriesAsync(void** operation) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::IPackage4>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_SignatureKind(Windows::ApplicationModel::PackageSignatureKind* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsOptional(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL VerifyContentIntegrityAsync(void** operation) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::IPackage5>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetContentGroupsAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetContentGroupAsync(void* name, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL StageContentGroupsAsync(void* names, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL StageContentGroupsWithPriorityAsync(void* names, bool moveToHeadOfQueue, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL SetInUseAsync(bool inUse, void** operation) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::IPackage6>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetAppInstallerInfo(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CheckUpdateAvailabilityAsync(void** operation) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::IPackage7>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_MutableLocation(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_EffectiveLocation(void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::IPackageCatalog>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL add_PackageStaging(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_PackageStaging(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_PackageInstalling(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_PackageInstalling(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_PackageUpdating(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_PackageUpdating(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_PackageUninstalling(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_PackageUninstalling(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_PackageStatusChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_PackageStatusChanged(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::IPackageCatalog2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL add_PackageContentGroupStaging(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_PackageContentGroupStaging(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL AddOptionalPackageAsync(void* optionalPackageFamilyName, void** operation) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::IPackageCatalog3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL RemoveOptionalPackagesAsync(void* optionalPackageFamilyNames, void** operation) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::IPackageCatalog4>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL AddResourcePackageAsync(void* resourcePackageFamilyName, void* resourceID, Windows::ApplicationModel::AddResourcePackageOptions options, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL RemoveResourcePackagesAsync(void* resourcePackages, void** operation) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::IPackageCatalogAddOptionalPackageResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Package(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ExtendedError(winrt::hresult* value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::IPackageCatalogAddResourcePackageResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Package(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsComplete(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ExtendedError(winrt::hresult* value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::IPackageCatalogRemoveOptionalPackagesResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_PackagesRemoved(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ExtendedError(winrt::hresult* value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::IPackageCatalogRemoveResourcePackagesResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_PackagesRemoved(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ExtendedError(winrt::hresult* value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::IPackageCatalogStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL OpenForCurrentPackage(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL OpenForCurrentUser(void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::IPackageContentGroup>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Package(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Name(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_State(Windows::ApplicationModel::PackageContentGroupState* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsRequired(bool* value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::IPackageContentGroupStagingEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ActivityId(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Package(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Progress(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsComplete(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ErrorCode(winrt::hresult* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ContentGroupName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsContentGroupRequired(bool* value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::IPackageContentGroupStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_RequiredGroupName(void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::IPackageId>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Name(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Version(struct struct_Windows_ApplicationModel_PackageVersion* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Architecture(Windows::System::ProcessorArchitecture* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ResourceId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Publisher(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PublisherId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_FullName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_FamilyName(void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::IPackageIdWithMetadata>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ProductId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Author(void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::IPackageInstallingEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ActivityId(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Package(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Progress(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsComplete(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ErrorCode(winrt::hresult* value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::IPackageStagingEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ActivityId(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Package(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Progress(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsComplete(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ErrorCode(winrt::hresult* value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::IPackageStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Current(void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::IPackageStatus>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL VerifyIsOK(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_NotAvailable(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PackageOffline(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DataOffline(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Disabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_NeedsRemediation(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LicenseIssue(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Modified(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Tampered(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DependencyIssue(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Servicing(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DeploymentInProgress(bool* value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::IPackageStatus2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsPartiallyStaged(bool* value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::IPackageStatusChangedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Package(void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::IPackageUninstallingEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ActivityId(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Package(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Progress(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsComplete(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ErrorCode(winrt::hresult* value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::IPackageUpdateAvailabilityResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Availability(Windows::ApplicationModel::PackageUpdateAvailability* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ExtendedError(winrt::hresult* value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::IPackageUpdatingEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ActivityId(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SourcePackage(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TargetPackage(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Progress(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsComplete(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ErrorCode(winrt::hresult* value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::IPackageWithMetadata>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_InstallDate(Windows::Foundation::DateTime* value) noexcept = 0;
    virtual int32_t WINRT_CALL GetThumbnailToken(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL Launch(void* parameters) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::IStartupTask>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL RequestEnableAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL Disable() noexcept = 0;
    virtual int32_t WINRT_CALL get_State(Windows::ApplicationModel::StartupTaskState* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TaskId(void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::IStartupTaskStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetForCurrentPackageAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetAsync(void* taskId, void** operation) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::ISuspendingDeferral>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Complete() noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::ISuspendingEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_SuspendingOperation(void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::ISuspendingOperation>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetDeferral(void** deferral) noexcept = 0;
    virtual int32_t WINRT_CALL get_Deadline(Windows::Foundation::DateTime* value) noexcept = 0;
};};

template <typename D>
struct consume_Windows_ApplicationModel_IAppDisplayInfo
{
    hstring DisplayName() const;
    hstring Description() const;
    Windows::Storage::Streams::RandomAccessStreamReference GetLogo(Windows::Foundation::Size const& size) const;
};
template <> struct consume<Windows::ApplicationModel::IAppDisplayInfo> { template <typename D> using type = consume_Windows_ApplicationModel_IAppDisplayInfo<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_IAppInfo
{
    hstring Id() const;
    hstring AppUserModelId() const;
    Windows::ApplicationModel::AppDisplayInfo DisplayInfo() const;
    hstring PackageFamilyName() const;
};
template <> struct consume<Windows::ApplicationModel::IAppInfo> { template <typename D> using type = consume_Windows_ApplicationModel_IAppInfo<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_IAppInstallerInfo
{
    Windows::Foundation::Uri Uri() const;
};
template <> struct consume<Windows::ApplicationModel::IAppInstallerInfo> { template <typename D> using type = consume_Windows_ApplicationModel_IAppInstallerInfo<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_IAppInstance
{
    hstring Key() const;
    bool IsCurrentInstance() const;
    void RedirectActivationTo() const;
};
template <> struct consume<Windows::ApplicationModel::IAppInstance> { template <typename D> using type = consume_Windows_ApplicationModel_IAppInstance<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_IAppInstanceStatics
{
    Windows::ApplicationModel::AppInstance RecommendedInstance() const;
    Windows::ApplicationModel::Activation::IActivatedEventArgs GetActivatedEventArgs() const;
    Windows::ApplicationModel::AppInstance FindOrRegisterInstanceForKey(param::hstring const& key) const;
    void Unregister() const;
    Windows::Foundation::Collections::IVector<Windows::ApplicationModel::AppInstance> GetInstances() const;
};
template <> struct consume<Windows::ApplicationModel::IAppInstanceStatics> { template <typename D> using type = consume_Windows_ApplicationModel_IAppInstanceStatics<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_IDesignModeStatics
{
    bool DesignModeEnabled() const;
};
template <> struct consume<Windows::ApplicationModel::IDesignModeStatics> { template <typename D> using type = consume_Windows_ApplicationModel_IDesignModeStatics<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_IDesignModeStatics2
{
    bool DesignMode2Enabled() const;
};
template <> struct consume<Windows::ApplicationModel::IDesignModeStatics2> { template <typename D> using type = consume_Windows_ApplicationModel_IDesignModeStatics2<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_IEnteredBackgroundEventArgs
{
    Windows::Foundation::Deferral GetDeferral() const;
};
template <> struct consume<Windows::ApplicationModel::IEnteredBackgroundEventArgs> { template <typename D> using type = consume_Windows_ApplicationModel_IEnteredBackgroundEventArgs<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_IFullTrustProcessLauncherStatics
{
    Windows::Foundation::IAsyncAction LaunchFullTrustProcessForCurrentAppAsync() const;
    Windows::Foundation::IAsyncAction LaunchFullTrustProcessForCurrentAppAsync(param::hstring const& parameterGroupId) const;
    Windows::Foundation::IAsyncAction LaunchFullTrustProcessForAppAsync(param::hstring const& fullTrustPackageRelativeAppId) const;
    Windows::Foundation::IAsyncAction LaunchFullTrustProcessForAppAsync(param::hstring const& fullTrustPackageRelativeAppId, param::hstring const& parameterGroupId) const;
};
template <> struct consume<Windows::ApplicationModel::IFullTrustProcessLauncherStatics> { template <typename D> using type = consume_Windows_ApplicationModel_IFullTrustProcessLauncherStatics<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_ILeavingBackgroundEventArgs
{
    Windows::Foundation::Deferral GetDeferral() const;
};
template <> struct consume<Windows::ApplicationModel::ILeavingBackgroundEventArgs> { template <typename D> using type = consume_Windows_ApplicationModel_ILeavingBackgroundEventArgs<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_ILimitedAccessFeatureRequestResult
{
    hstring FeatureId() const;
    Windows::ApplicationModel::LimitedAccessFeatureStatus Status() const;
    Windows::Foundation::IReference<Windows::Foundation::DateTime> EstimatedRemovalDate() const;
};
template <> struct consume<Windows::ApplicationModel::ILimitedAccessFeatureRequestResult> { template <typename D> using type = consume_Windows_ApplicationModel_ILimitedAccessFeatureRequestResult<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_ILimitedAccessFeaturesStatics
{
    Windows::ApplicationModel::LimitedAccessFeatureRequestResult TryUnlockFeature(param::hstring const& featureId, param::hstring const& token, param::hstring const& attestation) const;
};
template <> struct consume<Windows::ApplicationModel::ILimitedAccessFeaturesStatics> { template <typename D> using type = consume_Windows_ApplicationModel_ILimitedAccessFeaturesStatics<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_IPackage
{
    Windows::ApplicationModel::PackageId Id() const;
    Windows::Storage::StorageFolder InstalledLocation() const;
    bool IsFramework() const;
    Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Package> Dependencies() const;
};
template <> struct consume<Windows::ApplicationModel::IPackage> { template <typename D> using type = consume_Windows_ApplicationModel_IPackage<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_IPackage2
{
    hstring DisplayName() const;
    hstring PublisherDisplayName() const;
    hstring Description() const;
    Windows::Foundation::Uri Logo() const;
    bool IsResourcePackage() const;
    bool IsBundle() const;
    bool IsDevelopmentMode() const;
};
template <> struct consume<Windows::ApplicationModel::IPackage2> { template <typename D> using type = consume_Windows_ApplicationModel_IPackage2<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_IPackage3
{
    Windows::ApplicationModel::PackageStatus Status() const;
    Windows::Foundation::DateTime InstalledDate() const;
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Core::AppListEntry>> GetAppListEntriesAsync() const;
};
template <> struct consume<Windows::ApplicationModel::IPackage3> { template <typename D> using type = consume_Windows_ApplicationModel_IPackage3<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_IPackage4
{
    Windows::ApplicationModel::PackageSignatureKind SignatureKind() const;
    bool IsOptional() const;
    Windows::Foundation::IAsyncOperation<bool> VerifyContentIntegrityAsync() const;
};
template <> struct consume<Windows::ApplicationModel::IPackage4> { template <typename D> using type = consume_Windows_ApplicationModel_IPackage4<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_IPackage5
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<Windows::ApplicationModel::PackageContentGroup>> GetContentGroupsAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::PackageContentGroup> GetContentGroupAsync(param::hstring const& name) const;
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<Windows::ApplicationModel::PackageContentGroup>> StageContentGroupsAsync(param::async_iterable<hstring> const& names) const;
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<Windows::ApplicationModel::PackageContentGroup>> StageContentGroupsAsync(param::async_iterable<hstring> const& names, bool moveToHeadOfQueue) const;
    Windows::Foundation::IAsyncOperation<bool> SetInUseAsync(bool inUse) const;
};
template <> struct consume<Windows::ApplicationModel::IPackage5> { template <typename D> using type = consume_Windows_ApplicationModel_IPackage5<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_IPackage6
{
    Windows::ApplicationModel::AppInstallerInfo GetAppInstallerInfo() const;
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::PackageUpdateAvailabilityResult> CheckUpdateAvailabilityAsync() const;
};
template <> struct consume<Windows::ApplicationModel::IPackage6> { template <typename D> using type = consume_Windows_ApplicationModel_IPackage6<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_IPackage7
{
    Windows::Storage::StorageFolder MutableLocation() const;
    Windows::Storage::StorageFolder EffectiveLocation() const;
};
template <> struct consume<Windows::ApplicationModel::IPackage7> { template <typename D> using type = consume_Windows_ApplicationModel_IPackage7<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_IPackageCatalog
{
    winrt::event_token PackageStaging(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::PackageCatalog, Windows::ApplicationModel::PackageStagingEventArgs> const& handler) const;
    using PackageStaging_revoker = impl::event_revoker<Windows::ApplicationModel::IPackageCatalog, &impl::abi_t<Windows::ApplicationModel::IPackageCatalog>::remove_PackageStaging>;
    PackageStaging_revoker PackageStaging(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::PackageCatalog, Windows::ApplicationModel::PackageStagingEventArgs> const& handler) const;
    void PackageStaging(winrt::event_token const& token) const noexcept;
    winrt::event_token PackageInstalling(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::PackageCatalog, Windows::ApplicationModel::PackageInstallingEventArgs> const& handler) const;
    using PackageInstalling_revoker = impl::event_revoker<Windows::ApplicationModel::IPackageCatalog, &impl::abi_t<Windows::ApplicationModel::IPackageCatalog>::remove_PackageInstalling>;
    PackageInstalling_revoker PackageInstalling(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::PackageCatalog, Windows::ApplicationModel::PackageInstallingEventArgs> const& handler) const;
    void PackageInstalling(winrt::event_token const& token) const noexcept;
    winrt::event_token PackageUpdating(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::PackageCatalog, Windows::ApplicationModel::PackageUpdatingEventArgs> const& handler) const;
    using PackageUpdating_revoker = impl::event_revoker<Windows::ApplicationModel::IPackageCatalog, &impl::abi_t<Windows::ApplicationModel::IPackageCatalog>::remove_PackageUpdating>;
    PackageUpdating_revoker PackageUpdating(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::PackageCatalog, Windows::ApplicationModel::PackageUpdatingEventArgs> const& handler) const;
    void PackageUpdating(winrt::event_token const& token) const noexcept;
    winrt::event_token PackageUninstalling(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::PackageCatalog, Windows::ApplicationModel::PackageUninstallingEventArgs> const& handler) const;
    using PackageUninstalling_revoker = impl::event_revoker<Windows::ApplicationModel::IPackageCatalog, &impl::abi_t<Windows::ApplicationModel::IPackageCatalog>::remove_PackageUninstalling>;
    PackageUninstalling_revoker PackageUninstalling(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::PackageCatalog, Windows::ApplicationModel::PackageUninstallingEventArgs> const& handler) const;
    void PackageUninstalling(winrt::event_token const& token) const noexcept;
    winrt::event_token PackageStatusChanged(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::PackageCatalog, Windows::ApplicationModel::PackageStatusChangedEventArgs> const& handler) const;
    using PackageStatusChanged_revoker = impl::event_revoker<Windows::ApplicationModel::IPackageCatalog, &impl::abi_t<Windows::ApplicationModel::IPackageCatalog>::remove_PackageStatusChanged>;
    PackageStatusChanged_revoker PackageStatusChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::PackageCatalog, Windows::ApplicationModel::PackageStatusChangedEventArgs> const& handler) const;
    void PackageStatusChanged(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::ApplicationModel::IPackageCatalog> { template <typename D> using type = consume_Windows_ApplicationModel_IPackageCatalog<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_IPackageCatalog2
{
    winrt::event_token PackageContentGroupStaging(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::PackageCatalog, Windows::ApplicationModel::PackageContentGroupStagingEventArgs> const& handler) const;
    using PackageContentGroupStaging_revoker = impl::event_revoker<Windows::ApplicationModel::IPackageCatalog2, &impl::abi_t<Windows::ApplicationModel::IPackageCatalog2>::remove_PackageContentGroupStaging>;
    PackageContentGroupStaging_revoker PackageContentGroupStaging(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::PackageCatalog, Windows::ApplicationModel::PackageContentGroupStagingEventArgs> const& handler) const;
    void PackageContentGroupStaging(winrt::event_token const& token) const noexcept;
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::PackageCatalogAddOptionalPackageResult> AddOptionalPackageAsync(param::hstring const& optionalPackageFamilyName) const;
};
template <> struct consume<Windows::ApplicationModel::IPackageCatalog2> { template <typename D> using type = consume_Windows_ApplicationModel_IPackageCatalog2<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_IPackageCatalog3
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::PackageCatalogRemoveOptionalPackagesResult> RemoveOptionalPackagesAsync(param::async_iterable<hstring> const& optionalPackageFamilyNames) const;
};
template <> struct consume<Windows::ApplicationModel::IPackageCatalog3> { template <typename D> using type = consume_Windows_ApplicationModel_IPackageCatalog3<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_IPackageCatalog4
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::ApplicationModel::PackageCatalogAddResourcePackageResult, Windows::ApplicationModel::PackageInstallProgress> AddResourcePackageAsync(param::hstring const& resourcePackageFamilyName, param::hstring const& resourceID, Windows::ApplicationModel::AddResourcePackageOptions const& options) const;
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::PackageCatalogRemoveResourcePackagesResult> RemoveResourcePackagesAsync(param::async_iterable<Windows::ApplicationModel::Package> const& resourcePackages) const;
};
template <> struct consume<Windows::ApplicationModel::IPackageCatalog4> { template <typename D> using type = consume_Windows_ApplicationModel_IPackageCatalog4<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_IPackageCatalogAddOptionalPackageResult
{
    Windows::ApplicationModel::Package Package() const;
    winrt::hresult ExtendedError() const;
};
template <> struct consume<Windows::ApplicationModel::IPackageCatalogAddOptionalPackageResult> { template <typename D> using type = consume_Windows_ApplicationModel_IPackageCatalogAddOptionalPackageResult<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_IPackageCatalogAddResourcePackageResult
{
    Windows::ApplicationModel::Package Package() const;
    bool IsComplete() const;
    winrt::hresult ExtendedError() const;
};
template <> struct consume<Windows::ApplicationModel::IPackageCatalogAddResourcePackageResult> { template <typename D> using type = consume_Windows_ApplicationModel_IPackageCatalogAddResourcePackageResult<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_IPackageCatalogRemoveOptionalPackagesResult
{
    Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Package> PackagesRemoved() const;
    winrt::hresult ExtendedError() const;
};
template <> struct consume<Windows::ApplicationModel::IPackageCatalogRemoveOptionalPackagesResult> { template <typename D> using type = consume_Windows_ApplicationModel_IPackageCatalogRemoveOptionalPackagesResult<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_IPackageCatalogRemoveResourcePackagesResult
{
    Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Package> PackagesRemoved() const;
    winrt::hresult ExtendedError() const;
};
template <> struct consume<Windows::ApplicationModel::IPackageCatalogRemoveResourcePackagesResult> { template <typename D> using type = consume_Windows_ApplicationModel_IPackageCatalogRemoveResourcePackagesResult<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_IPackageCatalogStatics
{
    Windows::ApplicationModel::PackageCatalog OpenForCurrentPackage() const;
    Windows::ApplicationModel::PackageCatalog OpenForCurrentUser() const;
};
template <> struct consume<Windows::ApplicationModel::IPackageCatalogStatics> { template <typename D> using type = consume_Windows_ApplicationModel_IPackageCatalogStatics<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_IPackageContentGroup
{
    Windows::ApplicationModel::Package Package() const;
    hstring Name() const;
    Windows::ApplicationModel::PackageContentGroupState State() const;
    bool IsRequired() const;
};
template <> struct consume<Windows::ApplicationModel::IPackageContentGroup> { template <typename D> using type = consume_Windows_ApplicationModel_IPackageContentGroup<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_IPackageContentGroupStagingEventArgs
{
    winrt::guid ActivityId() const;
    Windows::ApplicationModel::Package Package() const;
    double Progress() const;
    bool IsComplete() const;
    winrt::hresult ErrorCode() const;
    hstring ContentGroupName() const;
    bool IsContentGroupRequired() const;
};
template <> struct consume<Windows::ApplicationModel::IPackageContentGroupStagingEventArgs> { template <typename D> using type = consume_Windows_ApplicationModel_IPackageContentGroupStagingEventArgs<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_IPackageContentGroupStatics
{
    hstring RequiredGroupName() const;
};
template <> struct consume<Windows::ApplicationModel::IPackageContentGroupStatics> { template <typename D> using type = consume_Windows_ApplicationModel_IPackageContentGroupStatics<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_IPackageId
{
    hstring Name() const;
    Windows::ApplicationModel::PackageVersion Version() const;
    Windows::System::ProcessorArchitecture Architecture() const;
    hstring ResourceId() const;
    hstring Publisher() const;
    hstring PublisherId() const;
    hstring FullName() const;
    hstring FamilyName() const;
};
template <> struct consume<Windows::ApplicationModel::IPackageId> { template <typename D> using type = consume_Windows_ApplicationModel_IPackageId<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_IPackageIdWithMetadata
{
    hstring ProductId() const;
    hstring Author() const;
};
template <> struct consume<Windows::ApplicationModel::IPackageIdWithMetadata> { template <typename D> using type = consume_Windows_ApplicationModel_IPackageIdWithMetadata<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_IPackageInstallingEventArgs
{
    winrt::guid ActivityId() const;
    Windows::ApplicationModel::Package Package() const;
    double Progress() const;
    bool IsComplete() const;
    winrt::hresult ErrorCode() const;
};
template <> struct consume<Windows::ApplicationModel::IPackageInstallingEventArgs> { template <typename D> using type = consume_Windows_ApplicationModel_IPackageInstallingEventArgs<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_IPackageStagingEventArgs
{
    winrt::guid ActivityId() const;
    Windows::ApplicationModel::Package Package() const;
    double Progress() const;
    bool IsComplete() const;
    winrt::hresult ErrorCode() const;
};
template <> struct consume<Windows::ApplicationModel::IPackageStagingEventArgs> { template <typename D> using type = consume_Windows_ApplicationModel_IPackageStagingEventArgs<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_IPackageStatics
{
    Windows::ApplicationModel::Package Current() const;
};
template <> struct consume<Windows::ApplicationModel::IPackageStatics> { template <typename D> using type = consume_Windows_ApplicationModel_IPackageStatics<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_IPackageStatus
{
    bool VerifyIsOK() const;
    bool NotAvailable() const;
    bool PackageOffline() const;
    bool DataOffline() const;
    bool Disabled() const;
    bool NeedsRemediation() const;
    bool LicenseIssue() const;
    bool Modified() const;
    bool Tampered() const;
    bool DependencyIssue() const;
    bool Servicing() const;
    bool DeploymentInProgress() const;
};
template <> struct consume<Windows::ApplicationModel::IPackageStatus> { template <typename D> using type = consume_Windows_ApplicationModel_IPackageStatus<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_IPackageStatus2
{
    bool IsPartiallyStaged() const;
};
template <> struct consume<Windows::ApplicationModel::IPackageStatus2> { template <typename D> using type = consume_Windows_ApplicationModel_IPackageStatus2<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_IPackageStatusChangedEventArgs
{
    Windows::ApplicationModel::Package Package() const;
};
template <> struct consume<Windows::ApplicationModel::IPackageStatusChangedEventArgs> { template <typename D> using type = consume_Windows_ApplicationModel_IPackageStatusChangedEventArgs<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_IPackageUninstallingEventArgs
{
    winrt::guid ActivityId() const;
    Windows::ApplicationModel::Package Package() const;
    double Progress() const;
    bool IsComplete() const;
    winrt::hresult ErrorCode() const;
};
template <> struct consume<Windows::ApplicationModel::IPackageUninstallingEventArgs> { template <typename D> using type = consume_Windows_ApplicationModel_IPackageUninstallingEventArgs<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_IPackageUpdateAvailabilityResult
{
    Windows::ApplicationModel::PackageUpdateAvailability Availability() const;
    winrt::hresult ExtendedError() const;
};
template <> struct consume<Windows::ApplicationModel::IPackageUpdateAvailabilityResult> { template <typename D> using type = consume_Windows_ApplicationModel_IPackageUpdateAvailabilityResult<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_IPackageUpdatingEventArgs
{
    winrt::guid ActivityId() const;
    Windows::ApplicationModel::Package SourcePackage() const;
    Windows::ApplicationModel::Package TargetPackage() const;
    double Progress() const;
    bool IsComplete() const;
    winrt::hresult ErrorCode() const;
};
template <> struct consume<Windows::ApplicationModel::IPackageUpdatingEventArgs> { template <typename D> using type = consume_Windows_ApplicationModel_IPackageUpdatingEventArgs<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_IPackageWithMetadata
{
    Windows::Foundation::DateTime InstallDate() const;
    hstring GetThumbnailToken() const;
    void Launch(param::hstring const& parameters) const;
};
template <> struct consume<Windows::ApplicationModel::IPackageWithMetadata> { template <typename D> using type = consume_Windows_ApplicationModel_IPackageWithMetadata<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_IStartupTask
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::StartupTaskState> RequestEnableAsync() const;
    void Disable() const;
    Windows::ApplicationModel::StartupTaskState State() const;
    hstring TaskId() const;
};
template <> struct consume<Windows::ApplicationModel::IStartupTask> { template <typename D> using type = consume_Windows_ApplicationModel_IStartupTask<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_IStartupTaskStatics
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::StartupTask>> GetForCurrentPackageAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::StartupTask> GetAsync(param::hstring const& taskId) const;
};
template <> struct consume<Windows::ApplicationModel::IStartupTaskStatics> { template <typename D> using type = consume_Windows_ApplicationModel_IStartupTaskStatics<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_ISuspendingDeferral
{
    void Complete() const;
};
template <> struct consume<Windows::ApplicationModel::ISuspendingDeferral> { template <typename D> using type = consume_Windows_ApplicationModel_ISuspendingDeferral<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_ISuspendingEventArgs
{
    Windows::ApplicationModel::SuspendingOperation SuspendingOperation() const;
};
template <> struct consume<Windows::ApplicationModel::ISuspendingEventArgs> { template <typename D> using type = consume_Windows_ApplicationModel_ISuspendingEventArgs<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_ISuspendingOperation
{
    Windows::ApplicationModel::SuspendingDeferral GetDeferral() const;
    Windows::Foundation::DateTime Deadline() const;
};
template <> struct consume<Windows::ApplicationModel::ISuspendingOperation> { template <typename D> using type = consume_Windows_ApplicationModel_ISuspendingOperation<D>; };

struct struct_Windows_ApplicationModel_PackageInstallProgress
{
    uint32_t PercentComplete;
};
template <> struct abi<Windows::ApplicationModel::PackageInstallProgress>{ using type = struct_Windows_ApplicationModel_PackageInstallProgress; };


struct struct_Windows_ApplicationModel_PackageVersion
{
    uint16_t Major;
    uint16_t Minor;
    uint16_t Build;
    uint16_t Revision;
};
template <> struct abi<Windows::ApplicationModel::PackageVersion>{ using type = struct_Windows_ApplicationModel_PackageVersion; };


}
