// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::ApplicationModel {

enum class PackageContentGroupState;
struct Package;

}

WINRT_EXPORT namespace winrt::Windows::Foundation {

struct Uri;

}

WINRT_EXPORT namespace winrt::Windows::Management::Deployment {

enum class AddPackageByAppInstallerOptions : uint32_t
{
    None = 0x0,
    InstallAllResources = 0x20,
    ForceTargetAppShutdown = 0x40,
    RequiredContentGroupOnly = 0x100,
    LimitToExistingPackages = 0x200,
};

enum class DeploymentOptions : uint32_t
{
    None = 0x0,
    ForceApplicationShutdown = 0x1,
    DevelopmentMode = 0x2,
    InstallAllResources = 0x20,
    ForceTargetApplicationShutdown = 0x40,
    RequiredContentGroupOnly = 0x100,
    ForceUpdateFromAnyVersion = 0x40000,
    RetainFilesOnFailure = 0x200000,
};

enum class DeploymentProgressState : int32_t
{
    Queued = 0,
    Processing = 1,
};

enum class PackageInstallState : int32_t
{
    NotInstalled = 0,
    Staged = 1,
    Installed = 2,
    Paused = 6,
};

enum class PackageState : int32_t
{
    Normal = 0,
    LicenseInvalid = 1,
    Modified = 2,
    Tampered = 3,
};

enum class PackageStatus : uint32_t
{
    OK = 0x0,
    LicenseIssue = 0x1,
    Modified = 0x2,
    Tampered = 0x4,
    Disabled = 0x8,
};

enum class PackageTypes : uint32_t
{
    None = 0x0,
    Main = 0x1,
    Framework = 0x2,
    Resource = 0x4,
    Bundle = 0x8,
    Xap = 0x10,
    Optional = 0x20,
};

enum class RemovalOptions : uint32_t
{
    None = 0x0,
    PreserveApplicationData = 0x1000,
    RemoveForAllUsers = 0x80000,
};

struct IDeploymentResult;
struct IDeploymentResult2;
struct IPackageManager;
struct IPackageManager2;
struct IPackageManager3;
struct IPackageManager4;
struct IPackageManager5;
struct IPackageManager6;
struct IPackageManager7;
struct IPackageManager8;
struct IPackageManagerDebugSettings;
struct IPackageUserInformation;
struct IPackageVolume;
struct IPackageVolume2;
struct DeploymentResult;
struct PackageManager;
struct PackageManagerDebugSettings;
struct PackageUserInformation;
struct PackageVolume;
struct DeploymentProgress;

}

namespace winrt::impl {

template<> struct is_enum_flag<Windows::Management::Deployment::AddPackageByAppInstallerOptions> : std::true_type {};
template<> struct is_enum_flag<Windows::Management::Deployment::DeploymentOptions> : std::true_type {};
template<> struct is_enum_flag<Windows::Management::Deployment::PackageStatus> : std::true_type {};
template<> struct is_enum_flag<Windows::Management::Deployment::PackageTypes> : std::true_type {};
template<> struct is_enum_flag<Windows::Management::Deployment::RemovalOptions> : std::true_type {};
template <> struct category<Windows::Management::Deployment::IDeploymentResult>{ using type = interface_category; };
template <> struct category<Windows::Management::Deployment::IDeploymentResult2>{ using type = interface_category; };
template <> struct category<Windows::Management::Deployment::IPackageManager>{ using type = interface_category; };
template <> struct category<Windows::Management::Deployment::IPackageManager2>{ using type = interface_category; };
template <> struct category<Windows::Management::Deployment::IPackageManager3>{ using type = interface_category; };
template <> struct category<Windows::Management::Deployment::IPackageManager4>{ using type = interface_category; };
template <> struct category<Windows::Management::Deployment::IPackageManager5>{ using type = interface_category; };
template <> struct category<Windows::Management::Deployment::IPackageManager6>{ using type = interface_category; };
template <> struct category<Windows::Management::Deployment::IPackageManager7>{ using type = interface_category; };
template <> struct category<Windows::Management::Deployment::IPackageManager8>{ using type = interface_category; };
template <> struct category<Windows::Management::Deployment::IPackageManagerDebugSettings>{ using type = interface_category; };
template <> struct category<Windows::Management::Deployment::IPackageUserInformation>{ using type = interface_category; };
template <> struct category<Windows::Management::Deployment::IPackageVolume>{ using type = interface_category; };
template <> struct category<Windows::Management::Deployment::IPackageVolume2>{ using type = interface_category; };
template <> struct category<Windows::Management::Deployment::DeploymentResult>{ using type = class_category; };
template <> struct category<Windows::Management::Deployment::PackageManager>{ using type = class_category; };
template <> struct category<Windows::Management::Deployment::PackageManagerDebugSettings>{ using type = class_category; };
template <> struct category<Windows::Management::Deployment::PackageUserInformation>{ using type = class_category; };
template <> struct category<Windows::Management::Deployment::PackageVolume>{ using type = class_category; };
template <> struct category<Windows::Management::Deployment::AddPackageByAppInstallerOptions>{ using type = enum_category; };
template <> struct category<Windows::Management::Deployment::DeploymentOptions>{ using type = enum_category; };
template <> struct category<Windows::Management::Deployment::DeploymentProgressState>{ using type = enum_category; };
template <> struct category<Windows::Management::Deployment::PackageInstallState>{ using type = enum_category; };
template <> struct category<Windows::Management::Deployment::PackageState>{ using type = enum_category; };
template <> struct category<Windows::Management::Deployment::PackageStatus>{ using type = enum_category; };
template <> struct category<Windows::Management::Deployment::PackageTypes>{ using type = enum_category; };
template <> struct category<Windows::Management::Deployment::RemovalOptions>{ using type = enum_category; };
template <> struct category<Windows::Management::Deployment::DeploymentProgress>{ using type = struct_category<Windows::Management::Deployment::DeploymentProgressState,uint32_t>; };
template <> struct name<Windows::Management::Deployment::IDeploymentResult>{ static constexpr auto & value{ L"Windows.Management.Deployment.IDeploymentResult" }; };
template <> struct name<Windows::Management::Deployment::IDeploymentResult2>{ static constexpr auto & value{ L"Windows.Management.Deployment.IDeploymentResult2" }; };
template <> struct name<Windows::Management::Deployment::IPackageManager>{ static constexpr auto & value{ L"Windows.Management.Deployment.IPackageManager" }; };
template <> struct name<Windows::Management::Deployment::IPackageManager2>{ static constexpr auto & value{ L"Windows.Management.Deployment.IPackageManager2" }; };
template <> struct name<Windows::Management::Deployment::IPackageManager3>{ static constexpr auto & value{ L"Windows.Management.Deployment.IPackageManager3" }; };
template <> struct name<Windows::Management::Deployment::IPackageManager4>{ static constexpr auto & value{ L"Windows.Management.Deployment.IPackageManager4" }; };
template <> struct name<Windows::Management::Deployment::IPackageManager5>{ static constexpr auto & value{ L"Windows.Management.Deployment.IPackageManager5" }; };
template <> struct name<Windows::Management::Deployment::IPackageManager6>{ static constexpr auto & value{ L"Windows.Management.Deployment.IPackageManager6" }; };
template <> struct name<Windows::Management::Deployment::IPackageManager7>{ static constexpr auto & value{ L"Windows.Management.Deployment.IPackageManager7" }; };
template <> struct name<Windows::Management::Deployment::IPackageManager8>{ static constexpr auto & value{ L"Windows.Management.Deployment.IPackageManager8" }; };
template <> struct name<Windows::Management::Deployment::IPackageManagerDebugSettings>{ static constexpr auto & value{ L"Windows.Management.Deployment.IPackageManagerDebugSettings" }; };
template <> struct name<Windows::Management::Deployment::IPackageUserInformation>{ static constexpr auto & value{ L"Windows.Management.Deployment.IPackageUserInformation" }; };
template <> struct name<Windows::Management::Deployment::IPackageVolume>{ static constexpr auto & value{ L"Windows.Management.Deployment.IPackageVolume" }; };
template <> struct name<Windows::Management::Deployment::IPackageVolume2>{ static constexpr auto & value{ L"Windows.Management.Deployment.IPackageVolume2" }; };
template <> struct name<Windows::Management::Deployment::DeploymentResult>{ static constexpr auto & value{ L"Windows.Management.Deployment.DeploymentResult" }; };
template <> struct name<Windows::Management::Deployment::PackageManager>{ static constexpr auto & value{ L"Windows.Management.Deployment.PackageManager" }; };
template <> struct name<Windows::Management::Deployment::PackageManagerDebugSettings>{ static constexpr auto & value{ L"Windows.Management.Deployment.PackageManagerDebugSettings" }; };
template <> struct name<Windows::Management::Deployment::PackageUserInformation>{ static constexpr auto & value{ L"Windows.Management.Deployment.PackageUserInformation" }; };
template <> struct name<Windows::Management::Deployment::PackageVolume>{ static constexpr auto & value{ L"Windows.Management.Deployment.PackageVolume" }; };
template <> struct name<Windows::Management::Deployment::AddPackageByAppInstallerOptions>{ static constexpr auto & value{ L"Windows.Management.Deployment.AddPackageByAppInstallerOptions" }; };
template <> struct name<Windows::Management::Deployment::DeploymentOptions>{ static constexpr auto & value{ L"Windows.Management.Deployment.DeploymentOptions" }; };
template <> struct name<Windows::Management::Deployment::DeploymentProgressState>{ static constexpr auto & value{ L"Windows.Management.Deployment.DeploymentProgressState" }; };
template <> struct name<Windows::Management::Deployment::PackageInstallState>{ static constexpr auto & value{ L"Windows.Management.Deployment.PackageInstallState" }; };
template <> struct name<Windows::Management::Deployment::PackageState>{ static constexpr auto & value{ L"Windows.Management.Deployment.PackageState" }; };
template <> struct name<Windows::Management::Deployment::PackageStatus>{ static constexpr auto & value{ L"Windows.Management.Deployment.PackageStatus" }; };
template <> struct name<Windows::Management::Deployment::PackageTypes>{ static constexpr auto & value{ L"Windows.Management.Deployment.PackageTypes" }; };
template <> struct name<Windows::Management::Deployment::RemovalOptions>{ static constexpr auto & value{ L"Windows.Management.Deployment.RemovalOptions" }; };
template <> struct name<Windows::Management::Deployment::DeploymentProgress>{ static constexpr auto & value{ L"Windows.Management.Deployment.DeploymentProgress" }; };
template <> struct guid_storage<Windows::Management::Deployment::IDeploymentResult>{ static constexpr guid value{ 0x2563B9AE,0xB77D,0x4C1F,{ 0x8A,0x7B,0x20,0xE6,0xAD,0x51,0x5E,0xF3 } }; };
template <> struct guid_storage<Windows::Management::Deployment::IDeploymentResult2>{ static constexpr guid value{ 0xFC0E715C,0x5A01,0x4BD7,{ 0xBC,0xF1,0x38,0x1C,0x8C,0x82,0xE0,0x4A } }; };
template <> struct guid_storage<Windows::Management::Deployment::IPackageManager>{ static constexpr guid value{ 0x9A7D4B65,0x5E8F,0x4FC7,{ 0xA2,0xE5,0x7F,0x69,0x25,0xCB,0x8B,0x53 } }; };
template <> struct guid_storage<Windows::Management::Deployment::IPackageManager2>{ static constexpr guid value{ 0xF7AAD08D,0x0840,0x46F2,{ 0xB5,0xD8,0xCA,0xD4,0x76,0x93,0xA0,0x95 } }; };
template <> struct guid_storage<Windows::Management::Deployment::IPackageManager3>{ static constexpr guid value{ 0xDAAD9948,0x36F1,0x41A7,{ 0x91,0x88,0xBC,0x26,0x3E,0x0D,0xCB,0x72 } }; };
template <> struct guid_storage<Windows::Management::Deployment::IPackageManager4>{ static constexpr guid value{ 0x3C719963,0xBAB6,0x46BF,{ 0x8F,0xF7,0xDA,0x47,0x19,0x23,0x0A,0xE6 } }; };
template <> struct guid_storage<Windows::Management::Deployment::IPackageManager5>{ static constexpr guid value{ 0x711F3117,0x1AFD,0x4313,{ 0x97,0x8C,0x9B,0xB6,0xE1,0xB8,0x64,0xA7 } }; };
template <> struct guid_storage<Windows::Management::Deployment::IPackageManager6>{ static constexpr guid value{ 0x0847E909,0x53CD,0x4E4F,{ 0x83,0x2E,0x57,0xD1,0x80,0xF6,0xE4,0x47 } }; };
template <> struct guid_storage<Windows::Management::Deployment::IPackageManager7>{ static constexpr guid value{ 0xF28654F4,0x2BA7,0x4B80,{ 0x88,0xD6,0xBE,0x15,0xF9,0xA2,0x3F,0xBA } }; };
template <> struct guid_storage<Windows::Management::Deployment::IPackageManager8>{ static constexpr guid value{ 0xB8575330,0x1298,0x4EE2,{ 0x80,0xEE,0x7F,0x65,0x9C,0x5D,0x27,0x82 } }; };
template <> struct guid_storage<Windows::Management::Deployment::IPackageManagerDebugSettings>{ static constexpr guid value{ 0x1A611683,0xA988,0x4FCF,{ 0x8F,0x0F,0xCE,0x17,0x58,0x98,0xE8,0xEB } }; };
template <> struct guid_storage<Windows::Management::Deployment::IPackageUserInformation>{ static constexpr guid value{ 0xF6383423,0xFA09,0x4CBC,{ 0x90,0x55,0x15,0xCA,0x27,0x5E,0x2E,0x7E } }; };
template <> struct guid_storage<Windows::Management::Deployment::IPackageVolume>{ static constexpr guid value{ 0xCF2672C3,0x1A40,0x4450,{ 0x97,0x39,0x2A,0xCE,0x2E,0x89,0x88,0x53 } }; };
template <> struct guid_storage<Windows::Management::Deployment::IPackageVolume2>{ static constexpr guid value{ 0x46ABCF2E,0x9DD4,0x47A2,{ 0xAB,0x8C,0xC6,0x40,0x83,0x49,0xBC,0xD8 } }; };
template <> struct default_interface<Windows::Management::Deployment::DeploymentResult>{ using type = Windows::Management::Deployment::IDeploymentResult; };
template <> struct default_interface<Windows::Management::Deployment::PackageManager>{ using type = Windows::Management::Deployment::IPackageManager; };
template <> struct default_interface<Windows::Management::Deployment::PackageManagerDebugSettings>{ using type = Windows::Management::Deployment::IPackageManagerDebugSettings; };
template <> struct default_interface<Windows::Management::Deployment::PackageUserInformation>{ using type = Windows::Management::Deployment::IPackageUserInformation; };
template <> struct default_interface<Windows::Management::Deployment::PackageVolume>{ using type = Windows::Management::Deployment::IPackageVolume; };

template <> struct abi<Windows::Management::Deployment::IDeploymentResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ErrorText(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ActivityId(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ExtendedErrorCode(winrt::hresult* value) noexcept = 0;
};};

template <> struct abi<Windows::Management::Deployment::IDeploymentResult2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsRegistered(bool* value) noexcept = 0;
};};

template <> struct abi<Windows::Management::Deployment::IPackageManager>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL AddPackageAsync(void* packageUri, void* dependencyPackageUris, Windows::Management::Deployment::DeploymentOptions deploymentOptions, void** deploymentOperation) noexcept = 0;
    virtual int32_t WINRT_CALL UpdatePackageAsync(void* packageUri, void* dependencyPackageUris, Windows::Management::Deployment::DeploymentOptions deploymentOptions, void** deploymentOperation) noexcept = 0;
    virtual int32_t WINRT_CALL RemovePackageAsync(void* packageFullName, void** deploymentOperation) noexcept = 0;
    virtual int32_t WINRT_CALL StagePackageAsync(void* packageUri, void* dependencyPackageUris, void** deploymentOperation) noexcept = 0;
    virtual int32_t WINRT_CALL RegisterPackageAsync(void* manifestUri, void* dependencyPackageUris, Windows::Management::Deployment::DeploymentOptions deploymentOptions, void** deploymentOperation) noexcept = 0;
    virtual int32_t WINRT_CALL FindPackages(void** packageCollection) noexcept = 0;
    virtual int32_t WINRT_CALL FindPackagesByUserSecurityId(void* userSecurityId, void** packageCollection) noexcept = 0;
    virtual int32_t WINRT_CALL FindPackagesByNamePublisher(void* packageName, void* packagePublisher, void** packageCollection) noexcept = 0;
    virtual int32_t WINRT_CALL FindPackagesByUserSecurityIdNamePublisher(void* userSecurityId, void* packageName, void* packagePublisher, void** packageCollection) noexcept = 0;
    virtual int32_t WINRT_CALL FindUsers(void* packageFullName, void** users) noexcept = 0;
    virtual int32_t WINRT_CALL SetPackageState(void* packageFullName, Windows::Management::Deployment::PackageState packageState) noexcept = 0;
    virtual int32_t WINRT_CALL FindPackageByPackageFullName(void* packageFullName, void** packageInformation) noexcept = 0;
    virtual int32_t WINRT_CALL CleanupPackageForUserAsync(void* packageName, void* userSecurityId, void** deploymentOperation) noexcept = 0;
    virtual int32_t WINRT_CALL FindPackagesByPackageFamilyName(void* packageFamilyName, void** packageCollection) noexcept = 0;
    virtual int32_t WINRT_CALL FindPackagesByUserSecurityIdPackageFamilyName(void* userSecurityId, void* packageFamilyName, void** packageCollection) noexcept = 0;
    virtual int32_t WINRT_CALL FindPackageByUserSecurityIdPackageFullName(void* userSecurityId, void* packageFullName, void** packageInformation) noexcept = 0;
};};

template <> struct abi<Windows::Management::Deployment::IPackageManager2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL RemovePackageWithOptionsAsync(void* packageFullName, Windows::Management::Deployment::RemovalOptions removalOptions, void** deploymentOperation) noexcept = 0;
    virtual int32_t WINRT_CALL StagePackageWithOptionsAsync(void* packageUri, void* dependencyPackageUris, Windows::Management::Deployment::DeploymentOptions deploymentOptions, void** deploymentOperation) noexcept = 0;
    virtual int32_t WINRT_CALL RegisterPackageByFullNameAsync(void* mainPackageFullName, void* dependencyPackageFullNames, Windows::Management::Deployment::DeploymentOptions deploymentOptions, void** deploymentOperation) noexcept = 0;
    virtual int32_t WINRT_CALL FindPackagesWithPackageTypes(Windows::Management::Deployment::PackageTypes packageTypes, void** packageCollection) noexcept = 0;
    virtual int32_t WINRT_CALL FindPackagesByUserSecurityIdWithPackageTypes(void* userSecurityId, Windows::Management::Deployment::PackageTypes packageTypes, void** packageCollection) noexcept = 0;
    virtual int32_t WINRT_CALL FindPackagesByNamePublisherWithPackageTypes(void* packageName, void* packagePublisher, Windows::Management::Deployment::PackageTypes packageTypes, void** packageCollection) noexcept = 0;
    virtual int32_t WINRT_CALL FindPackagesByUserSecurityIdNamePublisherWithPackageTypes(void* userSecurityId, void* packageName, void* packagePublisher, Windows::Management::Deployment::PackageTypes packageTypes, void** packageCollection) noexcept = 0;
    virtual int32_t WINRT_CALL FindPackagesByPackageFamilyNameWithPackageTypes(void* packageFamilyName, Windows::Management::Deployment::PackageTypes packageTypes, void** packageCollection) noexcept = 0;
    virtual int32_t WINRT_CALL FindPackagesByUserSecurityIdPackageFamilyNameWithPackageTypes(void* userSecurityId, void* packageFamilyName, Windows::Management::Deployment::PackageTypes packageTypes, void** packageCollection) noexcept = 0;
    virtual int32_t WINRT_CALL StageUserDataAsync(void* packageFullName, void** deploymentOperation) noexcept = 0;
};};

template <> struct abi<Windows::Management::Deployment::IPackageManager3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL AddPackageVolumeAsync(void* packageStorePath, void** packageVolume) noexcept = 0;
    virtual int32_t WINRT_CALL AddPackageToVolumeAsync(void* packageUri, void* dependencyPackageUris, Windows::Management::Deployment::DeploymentOptions deploymentOptions, void* targetVolume, void** deploymentOperation) noexcept = 0;
    virtual int32_t WINRT_CALL ClearPackageStatus(void* packageFullName, Windows::Management::Deployment::PackageStatus status) noexcept = 0;
    virtual int32_t WINRT_CALL RegisterPackageWithAppDataVolumeAsync(void* manifestUri, void* dependencyPackageUris, Windows::Management::Deployment::DeploymentOptions deploymentOptions, void* appDataVolume, void** deploymentOperation) noexcept = 0;
    virtual int32_t WINRT_CALL FindPackageVolumeByName(void* volumeName, void** volume) noexcept = 0;
    virtual int32_t WINRT_CALL FindPackageVolumes(void** volumeCollection) noexcept = 0;
    virtual int32_t WINRT_CALL GetDefaultPackageVolume(void** volume) noexcept = 0;
    virtual int32_t WINRT_CALL MovePackageToVolumeAsync(void* packageFullName, Windows::Management::Deployment::DeploymentOptions deploymentOptions, void* targetVolume, void** deploymentOperation) noexcept = 0;
    virtual int32_t WINRT_CALL RemovePackageVolumeAsync(void* volume, void** deploymentOperation) noexcept = 0;
    virtual int32_t WINRT_CALL SetDefaultPackageVolume(void* volume) noexcept = 0;
    virtual int32_t WINRT_CALL SetPackageStatus(void* packageFullName, Windows::Management::Deployment::PackageStatus status) noexcept = 0;
    virtual int32_t WINRT_CALL SetPackageVolumeOfflineAsync(void* packageVolume, void** deploymentOperation) noexcept = 0;
    virtual int32_t WINRT_CALL SetPackageVolumeOnlineAsync(void* packageVolume, void** deploymentOperation) noexcept = 0;
    virtual int32_t WINRT_CALL StagePackageToVolumeAsync(void* packageUri, void* dependencyPackageUris, Windows::Management::Deployment::DeploymentOptions deploymentOptions, void* targetVolume, void** deploymentOperation) noexcept = 0;
    virtual int32_t WINRT_CALL StageUserDataWithOptionsAsync(void* packageFullName, Windows::Management::Deployment::DeploymentOptions deploymentOptions, void** deploymentOperation) noexcept = 0;
};};

template <> struct abi<Windows::Management::Deployment::IPackageManager4>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetPackageVolumesAsync(void** operation) noexcept = 0;
};};

template <> struct abi<Windows::Management::Deployment::IPackageManager5>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL AddPackageToVolumeAndOptionalPackagesAsync(void* packageUri, void* dependencyPackageUris, Windows::Management::Deployment::DeploymentOptions deploymentOptions, void* targetVolume, void* optionalPackageFamilyNames, void* externalPackageUris, void** deploymentOperation) noexcept = 0;
    virtual int32_t WINRT_CALL StagePackageToVolumeAndOptionalPackagesAsync(void* packageUri, void* dependencyPackageUris, Windows::Management::Deployment::DeploymentOptions deploymentOptions, void* targetVolume, void* optionalPackageFamilyNames, void* externalPackageUris, void** deploymentOperation) noexcept = 0;
    virtual int32_t WINRT_CALL RegisterPackageByFamilyNameAndOptionalPackagesAsync(void* mainPackageFamilyName, void* dependencyPackageFamilyNames, Windows::Management::Deployment::DeploymentOptions deploymentOptions, void* appDataVolume, void* optionalPackageFamilyNames, void** deploymentOperation) noexcept = 0;
    virtual int32_t WINRT_CALL get_DebugSettings(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Management::Deployment::IPackageManager6>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL ProvisionPackageForAllUsersAsync(void* packageFamilyName, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL AddPackageByAppInstallerFileAsync(void* appInstallerFileUri, Windows::Management::Deployment::AddPackageByAppInstallerOptions options, void* targetVolume, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL RequestAddPackageByAppInstallerFileAsync(void* appInstallerFileUri, Windows::Management::Deployment::AddPackageByAppInstallerOptions options, void* targetVolume, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL AddPackageToVolumeAndRelatedSetAsync(void* packageUri, void* dependencyPackageUris, Windows::Management::Deployment::DeploymentOptions options, void* targetVolume, void* optionalPackageFamilyNames, void* packageUrisToInstall, void* relatedPackageUris, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL StagePackageToVolumeAndRelatedSetAsync(void* packageUri, void* dependencyPackageUris, Windows::Management::Deployment::DeploymentOptions options, void* targetVolume, void* optionalPackageFamilyNames, void* packageUrisToInstall, void* relatedPackageUris, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL RequestAddPackageAsync(void* packageUri, void* dependencyPackageUris, Windows::Management::Deployment::DeploymentOptions deploymentOptions, void* targetVolume, void* optionalPackageFamilyNames, void* relatedPackageUris, void** operation) noexcept = 0;
};};

template <> struct abi<Windows::Management::Deployment::IPackageManager7>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL RequestAddPackageAndRelatedSetAsync(void* packageUri, void* dependencyPackageUris, Windows::Management::Deployment::DeploymentOptions deploymentOptions, void* targetVolume, void* optionalPackageFamilyNames, void* relatedPackageUris, void* packageUrisToInstall, void** operation) noexcept = 0;
};};

template <> struct abi<Windows::Management::Deployment::IPackageManager8>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL DeprovisionPackageForAllUsersAsync(void* packageFamilyName, void** operation) noexcept = 0;
};};

template <> struct abi<Windows::Management::Deployment::IPackageManagerDebugSettings>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL SetContentGroupStateAsync(void* package, void* contentGroupName, Windows::ApplicationModel::PackageContentGroupState state, void** action) noexcept = 0;
    virtual int32_t WINRT_CALL SetContentGroupStateWithPercentageAsync(void* package, void* contentGroupName, Windows::ApplicationModel::PackageContentGroupState state, double completionPercentage, void** action) noexcept = 0;
};};

template <> struct abi<Windows::Management::Deployment::IPackageUserInformation>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_UserSecurityId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_InstallState(Windows::Management::Deployment::PackageInstallState* value) noexcept = 0;
};};

template <> struct abi<Windows::Management::Deployment::IPackageVolume>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsOffline(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsSystemVolume(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MountPoint(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Name(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PackageStorePath(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SupportsHardLinks(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL FindPackages(void** packageCollection) noexcept = 0;
    virtual int32_t WINRT_CALL FindPackagesByNamePublisher(void* packageName, void* packagePublisher, void** packageCollection) noexcept = 0;
    virtual int32_t WINRT_CALL FindPackagesByPackageFamilyName(void* packageFamilyName, void** packageCollection) noexcept = 0;
    virtual int32_t WINRT_CALL FindPackagesWithPackageTypes(Windows::Management::Deployment::PackageTypes packageTypes, void** packageCollection) noexcept = 0;
    virtual int32_t WINRT_CALL FindPackagesByNamePublisherWithPackagesTypes(Windows::Management::Deployment::PackageTypes packageTypes, void* packageName, void* packagePublisher, void** packageCollection) noexcept = 0;
    virtual int32_t WINRT_CALL FindPackagesByPackageFamilyNameWithPackageTypes(Windows::Management::Deployment::PackageTypes packageTypes, void* packageFamilyName, void** packageCollection) noexcept = 0;
    virtual int32_t WINRT_CALL FindPackageByPackageFullName(void* packageFullName, void** packageCollection) noexcept = 0;
    virtual int32_t WINRT_CALL FindPackagesByUserSecurityId(void* userSecurityId, void** packageCollection) noexcept = 0;
    virtual int32_t WINRT_CALL FindPackagesByUserSecurityIdNamePublisher(void* userSecurityId, void* packageName, void* packagePublisher, void** packageCollection) noexcept = 0;
    virtual int32_t WINRT_CALL FindPackagesByUserSecurityIdPackageFamilyName(void* userSecurityId, void* packageFamilyName, void** packageCollection) noexcept = 0;
    virtual int32_t WINRT_CALL FindPackagesByUserSecurityIdWithPackageTypes(void* userSecurityId, Windows::Management::Deployment::PackageTypes packageTypes, void** packageCollection) noexcept = 0;
    virtual int32_t WINRT_CALL FindPackagesByUserSecurityIdNamePublisherWithPackageTypes(void* userSecurityId, Windows::Management::Deployment::PackageTypes packageTypes, void* packageName, void* packagePublisher, void** packageCollection) noexcept = 0;
    virtual int32_t WINRT_CALL FindPackagesByUserSecurityIdPackageFamilyNameWithPackagesTypes(void* userSecurityId, Windows::Management::Deployment::PackageTypes packageTypes, void* packageFamilyName, void** packageCollection) noexcept = 0;
    virtual int32_t WINRT_CALL FindPackageByUserSecurityIdPackageFullName(void* userSecurityId, void* packageFullName, void** packageCollection) noexcept = 0;
};};

template <> struct abi<Windows::Management::Deployment::IPackageVolume2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsFullTrustPackageSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsAppxInstallSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL GetAvailableSpaceAsync(void** operation) noexcept = 0;
};};

template <typename D>
struct consume_Windows_Management_Deployment_IDeploymentResult
{
    hstring ErrorText() const;
    winrt::guid ActivityId() const;
    winrt::hresult ExtendedErrorCode() const;
};
template <> struct consume<Windows::Management::Deployment::IDeploymentResult> { template <typename D> using type = consume_Windows_Management_Deployment_IDeploymentResult<D>; };

template <typename D>
struct consume_Windows_Management_Deployment_IDeploymentResult2
{
    bool IsRegistered() const;
};
template <> struct consume<Windows::Management::Deployment::IDeploymentResult2> { template <typename D> using type = consume_Windows_Management_Deployment_IDeploymentResult2<D>; };

template <typename D>
struct consume_Windows_Management_Deployment_IPackageManager
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> AddPackageAsync(Windows::Foundation::Uri const& packageUri, param::async_iterable<Windows::Foundation::Uri> const& dependencyPackageUris, Windows::Management::Deployment::DeploymentOptions const& deploymentOptions) const;
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> UpdatePackageAsync(Windows::Foundation::Uri const& packageUri, param::async_iterable<Windows::Foundation::Uri> const& dependencyPackageUris, Windows::Management::Deployment::DeploymentOptions const& deploymentOptions) const;
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> RemovePackageAsync(param::hstring const& packageFullName) const;
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> StagePackageAsync(Windows::Foundation::Uri const& packageUri, param::async_iterable<Windows::Foundation::Uri> const& dependencyPackageUris) const;
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> RegisterPackageAsync(Windows::Foundation::Uri const& manifestUri, param::async_iterable<Windows::Foundation::Uri> const& dependencyPackageUris, Windows::Management::Deployment::DeploymentOptions const& deploymentOptions) const;
    Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Package> FindPackages() const;
    Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Package> FindPackagesForUser(param::hstring const& userSecurityId) const;
    Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Package> FindPackages(param::hstring const& packageName, param::hstring const& packagePublisher) const;
    Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Package> FindPackagesForUser(param::hstring const& userSecurityId, param::hstring const& packageName, param::hstring const& packagePublisher) const;
    Windows::Foundation::Collections::IIterable<Windows::Management::Deployment::PackageUserInformation> FindUsers(param::hstring const& packageFullName) const;
    void SetPackageState(param::hstring const& packageFullName, Windows::Management::Deployment::PackageState const& packageState) const;
    Windows::ApplicationModel::Package FindPackage(param::hstring const& packageFullName) const;
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> CleanupPackageForUserAsync(param::hstring const& packageName, param::hstring const& userSecurityId) const;
    Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Package> FindPackages(param::hstring const& packageFamilyName) const;
    Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Package> FindPackagesForUser(param::hstring const& userSecurityId, param::hstring const& packageFamilyName) const;
    Windows::ApplicationModel::Package FindPackageForUser(param::hstring const& userSecurityId, param::hstring const& packageFullName) const;
};
template <> struct consume<Windows::Management::Deployment::IPackageManager> { template <typename D> using type = consume_Windows_Management_Deployment_IPackageManager<D>; };

template <typename D>
struct consume_Windows_Management_Deployment_IPackageManager2
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> RemovePackageAsync(param::hstring const& packageFullName, Windows::Management::Deployment::RemovalOptions const& removalOptions) const;
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> StagePackageAsync(Windows::Foundation::Uri const& packageUri, param::async_iterable<Windows::Foundation::Uri> const& dependencyPackageUris, Windows::Management::Deployment::DeploymentOptions const& deploymentOptions) const;
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> RegisterPackageByFullNameAsync(param::hstring const& mainPackageFullName, param::async_iterable<hstring> const& dependencyPackageFullNames, Windows::Management::Deployment::DeploymentOptions const& deploymentOptions) const;
    Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Package> FindPackagesWithPackageTypes(Windows::Management::Deployment::PackageTypes const& packageTypes) const;
    Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Package> FindPackagesForUserWithPackageTypes(param::hstring const& userSecurityId, Windows::Management::Deployment::PackageTypes const& packageTypes) const;
    Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Package> FindPackagesWithPackageTypes(param::hstring const& packageName, param::hstring const& packagePublisher, Windows::Management::Deployment::PackageTypes const& packageTypes) const;
    Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Package> FindPackagesForUserWithPackageTypes(param::hstring const& userSecurityId, param::hstring const& packageName, param::hstring const& packagePublisher, Windows::Management::Deployment::PackageTypes const& packageTypes) const;
    Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Package> FindPackagesWithPackageTypes(param::hstring const& packageFamilyName, Windows::Management::Deployment::PackageTypes const& packageTypes) const;
    Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Package> FindPackagesForUserWithPackageTypes(param::hstring const& userSecurityId, param::hstring const& packageFamilyName, Windows::Management::Deployment::PackageTypes const& packageTypes) const;
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> StageUserDataAsync(param::hstring const& packageFullName) const;
};
template <> struct consume<Windows::Management::Deployment::IPackageManager2> { template <typename D> using type = consume_Windows_Management_Deployment_IPackageManager2<D>; };

template <typename D>
struct consume_Windows_Management_Deployment_IPackageManager3
{
    Windows::Foundation::IAsyncOperation<Windows::Management::Deployment::PackageVolume> AddPackageVolumeAsync(param::hstring const& packageStorePath) const;
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> AddPackageAsync(Windows::Foundation::Uri const& packageUri, param::async_iterable<Windows::Foundation::Uri> const& dependencyPackageUris, Windows::Management::Deployment::DeploymentOptions const& deploymentOptions, Windows::Management::Deployment::PackageVolume const& targetVolume) const;
    void ClearPackageStatus(param::hstring const& packageFullName, Windows::Management::Deployment::PackageStatus const& status) const;
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> RegisterPackageAsync(Windows::Foundation::Uri const& manifestUri, param::async_iterable<Windows::Foundation::Uri> const& dependencyPackageUris, Windows::Management::Deployment::DeploymentOptions const& deploymentOptions, Windows::Management::Deployment::PackageVolume const& appDataVolume) const;
    Windows::Management::Deployment::PackageVolume FindPackageVolume(param::hstring const& volumeName) const;
    Windows::Foundation::Collections::IIterable<Windows::Management::Deployment::PackageVolume> FindPackageVolumes() const;
    Windows::Management::Deployment::PackageVolume GetDefaultPackageVolume() const;
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> MovePackageToVolumeAsync(param::hstring const& packageFullName, Windows::Management::Deployment::DeploymentOptions const& deploymentOptions, Windows::Management::Deployment::PackageVolume const& targetVolume) const;
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> RemovePackageVolumeAsync(Windows::Management::Deployment::PackageVolume const& volume) const;
    void SetDefaultPackageVolume(Windows::Management::Deployment::PackageVolume const& volume) const;
    void SetPackageStatus(param::hstring const& packageFullName, Windows::Management::Deployment::PackageStatus const& status) const;
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> SetPackageVolumeOfflineAsync(Windows::Management::Deployment::PackageVolume const& packageVolume) const;
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> SetPackageVolumeOnlineAsync(Windows::Management::Deployment::PackageVolume const& packageVolume) const;
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> StagePackageAsync(Windows::Foundation::Uri const& packageUri, param::async_iterable<Windows::Foundation::Uri> const& dependencyPackageUris, Windows::Management::Deployment::DeploymentOptions const& deploymentOptions, Windows::Management::Deployment::PackageVolume const& targetVolume) const;
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> StageUserDataAsync(param::hstring const& packageFullName, Windows::Management::Deployment::DeploymentOptions const& deploymentOptions) const;
};
template <> struct consume<Windows::Management::Deployment::IPackageManager3> { template <typename D> using type = consume_Windows_Management_Deployment_IPackageManager3<D>; };

template <typename D>
struct consume_Windows_Management_Deployment_IPackageManager4
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Management::Deployment::PackageVolume>> GetPackageVolumesAsync() const;
};
template <> struct consume<Windows::Management::Deployment::IPackageManager4> { template <typename D> using type = consume_Windows_Management_Deployment_IPackageManager4<D>; };

template <typename D>
struct consume_Windows_Management_Deployment_IPackageManager5
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> AddPackageAsync(Windows::Foundation::Uri const& packageUri, param::async_iterable<Windows::Foundation::Uri> const& dependencyPackageUris, Windows::Management::Deployment::DeploymentOptions const& deploymentOptions, Windows::Management::Deployment::PackageVolume const& targetVolume, param::async_iterable<hstring> const& optionalPackageFamilyNames, param::async_iterable<Windows::Foundation::Uri> const& externalPackageUris) const;
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> StagePackageAsync(Windows::Foundation::Uri const& packageUri, param::async_iterable<Windows::Foundation::Uri> const& dependencyPackageUris, Windows::Management::Deployment::DeploymentOptions const& deploymentOptions, Windows::Management::Deployment::PackageVolume const& targetVolume, param::async_iterable<hstring> const& optionalPackageFamilyNames, param::async_iterable<Windows::Foundation::Uri> const& externalPackageUris) const;
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> RegisterPackageByFamilyNameAsync(param::hstring const& mainPackageFamilyName, param::async_iterable<hstring> const& dependencyPackageFamilyNames, Windows::Management::Deployment::DeploymentOptions const& deploymentOptions, Windows::Management::Deployment::PackageVolume const& appDataVolume, param::async_iterable<hstring> const& optionalPackageFamilyNames) const;
    Windows::Management::Deployment::PackageManagerDebugSettings DebugSettings() const;
};
template <> struct consume<Windows::Management::Deployment::IPackageManager5> { template <typename D> using type = consume_Windows_Management_Deployment_IPackageManager5<D>; };

template <typename D>
struct consume_Windows_Management_Deployment_IPackageManager6
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> ProvisionPackageForAllUsersAsync(param::hstring const& packageFamilyName) const;
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> AddPackageByAppInstallerFileAsync(Windows::Foundation::Uri const& appInstallerFileUri, Windows::Management::Deployment::AddPackageByAppInstallerOptions const& options, Windows::Management::Deployment::PackageVolume const& targetVolume) const;
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> RequestAddPackageByAppInstallerFileAsync(Windows::Foundation::Uri const& appInstallerFileUri, Windows::Management::Deployment::AddPackageByAppInstallerOptions const& options, Windows::Management::Deployment::PackageVolume const& targetVolume) const;
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> AddPackageAsync(Windows::Foundation::Uri const& packageUri, param::async_iterable<Windows::Foundation::Uri> const& dependencyPackageUris, Windows::Management::Deployment::DeploymentOptions const& options, Windows::Management::Deployment::PackageVolume const& targetVolume, param::async_iterable<hstring> const& optionalPackageFamilyNames, param::async_iterable<Windows::Foundation::Uri> const& packageUrisToInstall, param::async_iterable<Windows::Foundation::Uri> const& relatedPackageUris) const;
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> StagePackageAsync(Windows::Foundation::Uri const& packageUri, param::async_iterable<Windows::Foundation::Uri> const& dependencyPackageUris, Windows::Management::Deployment::DeploymentOptions const& options, Windows::Management::Deployment::PackageVolume const& targetVolume, param::async_iterable<hstring> const& optionalPackageFamilyNames, param::async_iterable<Windows::Foundation::Uri> const& packageUrisToInstall, param::async_iterable<Windows::Foundation::Uri> const& relatedPackageUris) const;
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> RequestAddPackageAsync(Windows::Foundation::Uri const& packageUri, param::async_iterable<Windows::Foundation::Uri> const& dependencyPackageUris, Windows::Management::Deployment::DeploymentOptions const& deploymentOptions, Windows::Management::Deployment::PackageVolume const& targetVolume, param::async_iterable<hstring> const& optionalPackageFamilyNames, param::async_iterable<Windows::Foundation::Uri> const& relatedPackageUris) const;
};
template <> struct consume<Windows::Management::Deployment::IPackageManager6> { template <typename D> using type = consume_Windows_Management_Deployment_IPackageManager6<D>; };

template <typename D>
struct consume_Windows_Management_Deployment_IPackageManager7
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> RequestAddPackageAsync(Windows::Foundation::Uri const& packageUri, param::async_iterable<Windows::Foundation::Uri> const& dependencyPackageUris, Windows::Management::Deployment::DeploymentOptions const& deploymentOptions, Windows::Management::Deployment::PackageVolume const& targetVolume, param::async_iterable<hstring> const& optionalPackageFamilyNames, param::async_iterable<Windows::Foundation::Uri> const& relatedPackageUris, param::async_iterable<Windows::Foundation::Uri> const& packageUrisToInstall) const;
};
template <> struct consume<Windows::Management::Deployment::IPackageManager7> { template <typename D> using type = consume_Windows_Management_Deployment_IPackageManager7<D>; };

template <typename D>
struct consume_Windows_Management_Deployment_IPackageManager8
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Management::Deployment::DeploymentResult, Windows::Management::Deployment::DeploymentProgress> DeprovisionPackageForAllUsersAsync(param::hstring const& packageFamilyName) const;
};
template <> struct consume<Windows::Management::Deployment::IPackageManager8> { template <typename D> using type = consume_Windows_Management_Deployment_IPackageManager8<D>; };

template <typename D>
struct consume_Windows_Management_Deployment_IPackageManagerDebugSettings
{
    Windows::Foundation::IAsyncAction SetContentGroupStateAsync(Windows::ApplicationModel::Package const& package, param::hstring const& contentGroupName, Windows::ApplicationModel::PackageContentGroupState const& state) const;
    Windows::Foundation::IAsyncAction SetContentGroupStateAsync(Windows::ApplicationModel::Package const& package, param::hstring const& contentGroupName, Windows::ApplicationModel::PackageContentGroupState const& state, double completionPercentage) const;
};
template <> struct consume<Windows::Management::Deployment::IPackageManagerDebugSettings> { template <typename D> using type = consume_Windows_Management_Deployment_IPackageManagerDebugSettings<D>; };

template <typename D>
struct consume_Windows_Management_Deployment_IPackageUserInformation
{
    hstring UserSecurityId() const;
    Windows::Management::Deployment::PackageInstallState InstallState() const;
};
template <> struct consume<Windows::Management::Deployment::IPackageUserInformation> { template <typename D> using type = consume_Windows_Management_Deployment_IPackageUserInformation<D>; };

template <typename D>
struct consume_Windows_Management_Deployment_IPackageVolume
{
    bool IsOffline() const;
    bool IsSystemVolume() const;
    hstring MountPoint() const;
    hstring Name() const;
    hstring PackageStorePath() const;
    bool SupportsHardLinks() const;
    Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Package> FindPackages() const;
    Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Package> FindPackages(param::hstring const& packageName, param::hstring const& packagePublisher) const;
    Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Package> FindPackages(param::hstring const& packageFamilyName) const;
    Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Package> FindPackagesWithPackageTypes(Windows::Management::Deployment::PackageTypes const& packageTypes) const;
    Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Package> FindPackagesWithPackageTypes(Windows::Management::Deployment::PackageTypes const& packageTypes, param::hstring const& packageName, param::hstring const& packagePublisher) const;
    Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Package> FindPackagesWithPackageTypes(Windows::Management::Deployment::PackageTypes const& packageTypes, param::hstring const& packageFamilyName) const;
    Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Package> FindPackage(param::hstring const& packageFullName) const;
    Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Package> FindPackagesForUser(param::hstring const& userSecurityId) const;
    Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Package> FindPackagesForUser(param::hstring const& userSecurityId, param::hstring const& packageName, param::hstring const& packagePublisher) const;
    Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Package> FindPackagesForUser(param::hstring const& userSecurityId, param::hstring const& packageFamilyName) const;
    Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Package> FindPackagesForUserWithPackageTypes(param::hstring const& userSecurityId, Windows::Management::Deployment::PackageTypes const& packageTypes) const;
    Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Package> FindPackagesForUserWithPackageTypes(param::hstring const& userSecurityId, Windows::Management::Deployment::PackageTypes const& packageTypes, param::hstring const& packageName, param::hstring const& packagePublisher) const;
    Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Package> FindPackagesForUserWithPackageTypes(param::hstring const& userSecurityId, Windows::Management::Deployment::PackageTypes const& packageTypes, param::hstring const& packageFamilyName) const;
    Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Package> FindPackageForUser(param::hstring const& userSecurityId, param::hstring const& packageFullName) const;
};
template <> struct consume<Windows::Management::Deployment::IPackageVolume> { template <typename D> using type = consume_Windows_Management_Deployment_IPackageVolume<D>; };

template <typename D>
struct consume_Windows_Management_Deployment_IPackageVolume2
{
    bool IsFullTrustPackageSupported() const;
    bool IsAppxInstallSupported() const;
    Windows::Foundation::IAsyncOperation<uint64_t> GetAvailableSpaceAsync() const;
};
template <> struct consume<Windows::Management::Deployment::IPackageVolume2> { template <typename D> using type = consume_Windows_Management_Deployment_IPackageVolume2<D>; };

struct struct_Windows_Management_Deployment_DeploymentProgress
{
    Windows::Management::Deployment::DeploymentProgressState state;
    uint32_t percentage;
};
template <> struct abi<Windows::Management::Deployment::DeploymentProgress>{ using type = struct_Windows_Management_Deployment_DeploymentProgress; };


}
