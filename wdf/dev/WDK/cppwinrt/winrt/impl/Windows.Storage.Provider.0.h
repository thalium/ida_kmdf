// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Foundation {

struct Uri;

}

WINRT_EXPORT namespace winrt::Windows::Storage {

struct IStorageFile;
struct IStorageFolder;
struct IStorageItem;
struct StorageFile;

}

WINRT_EXPORT namespace winrt::Windows::Storage::Streams {

struct IBuffer;

}

WINRT_EXPORT namespace winrt::Windows::Storage::Provider {

enum class CachedFileOptions : uint32_t
{
    None = 0x0,
    RequireUpdateOnAccess = 0x1,
    UseCachedFileWhenOffline = 0x2,
    DenyAccessWhenOffline = 0x4,
};

enum class CachedFileTarget : int32_t
{
    Local = 0,
    Remote = 1,
};

enum class FileUpdateStatus : int32_t
{
    Incomplete = 0,
    Complete = 1,
    UserInputNeeded = 2,
    CurrentlyUnavailable = 3,
    Failed = 4,
    CompleteAndRenamed = 5,
};

enum class ReadActivationMode : int32_t
{
    NotNeeded = 0,
    BeforeAccess = 1,
};

enum class StorageProviderHardlinkPolicy : uint32_t
{
    None = 0x0,
    Allowed = 0x1,
};

enum class StorageProviderHydrationPolicy : int32_t
{
    Partial = 0,
    Progressive = 1,
    Full = 2,
    AlwaysFull = 3,
};

enum class StorageProviderHydrationPolicyModifier : uint32_t
{
    None = 0x0,
    ValidationRequired = 0x1,
    StreamingAllowed = 0x2,
    AutoDehydrationAllowed = 0x4,
};

enum class StorageProviderInSyncPolicy : uint32_t
{
    Default = 0x0,
    FileCreationTime = 0x1,
    FileReadOnlyAttribute = 0x2,
    FileHiddenAttribute = 0x4,
    FileSystemAttribute = 0x8,
    DirectoryCreationTime = 0x10,
    DirectoryReadOnlyAttribute = 0x20,
    DirectoryHiddenAttribute = 0x40,
    DirectorySystemAttribute = 0x80,
    FileLastWriteTime = 0x100,
    DirectoryLastWriteTime = 0x200,
    PreserveInsyncForSyncEngine = 0x80000000,
};

enum class StorageProviderPopulationPolicy : int32_t
{
    Full = 1,
    AlwaysFull = 2,
};

enum class StorageProviderProtectionMode : int32_t
{
    Unknown = 0,
    Personal = 1,
};

enum class StorageProviderUriSourceStatus : int32_t
{
    Success = 0,
    NoSyncRoot = 1,
    FileNotFound = 2,
};

enum class UIStatus : int32_t
{
    Unavailable = 0,
    Hidden = 1,
    Visible = 2,
    Complete = 3,
};

enum class WriteActivationMode : int32_t
{
    ReadOnly = 0,
    NotNeeded = 1,
    AfterWrite = 2,
};

struct ICachedFileUpdaterStatics;
struct ICachedFileUpdaterUI;
struct ICachedFileUpdaterUI2;
struct IFileUpdateRequest;
struct IFileUpdateRequest2;
struct IFileUpdateRequestDeferral;
struct IFileUpdateRequestedEventArgs;
struct IStorageProviderGetContentInfoForPathResult;
struct IStorageProviderGetPathForContentUriResult;
struct IStorageProviderItemPropertiesStatics;
struct IStorageProviderItemProperty;
struct IStorageProviderItemPropertyDefinition;
struct IStorageProviderItemPropertySource;
struct IStorageProviderPropertyCapabilities;
struct IStorageProviderSyncRootInfo;
struct IStorageProviderSyncRootInfo2;
struct IStorageProviderSyncRootManagerStatics;
struct IStorageProviderUriSource;
struct CachedFileUpdater;
struct CachedFileUpdaterUI;
struct FileUpdateRequest;
struct FileUpdateRequestDeferral;
struct FileUpdateRequestedEventArgs;
struct StorageProviderGetContentInfoForPathResult;
struct StorageProviderGetPathForContentUriResult;
struct StorageProviderItemProperties;
struct StorageProviderItemProperty;
struct StorageProviderItemPropertyDefinition;
struct StorageProviderSyncRootInfo;
struct StorageProviderSyncRootManager;

}

namespace winrt::impl {

template<> struct is_enum_flag<Windows::Storage::Provider::CachedFileOptions> : std::true_type {};
template<> struct is_enum_flag<Windows::Storage::Provider::StorageProviderHardlinkPolicy> : std::true_type {};
template<> struct is_enum_flag<Windows::Storage::Provider::StorageProviderHydrationPolicyModifier> : std::true_type {};
template<> struct is_enum_flag<Windows::Storage::Provider::StorageProviderInSyncPolicy> : std::true_type {};
template <> struct category<Windows::Storage::Provider::ICachedFileUpdaterStatics>{ using type = interface_category; };
template <> struct category<Windows::Storage::Provider::ICachedFileUpdaterUI>{ using type = interface_category; };
template <> struct category<Windows::Storage::Provider::ICachedFileUpdaterUI2>{ using type = interface_category; };
template <> struct category<Windows::Storage::Provider::IFileUpdateRequest>{ using type = interface_category; };
template <> struct category<Windows::Storage::Provider::IFileUpdateRequest2>{ using type = interface_category; };
template <> struct category<Windows::Storage::Provider::IFileUpdateRequestDeferral>{ using type = interface_category; };
template <> struct category<Windows::Storage::Provider::IFileUpdateRequestedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Storage::Provider::IStorageProviderGetContentInfoForPathResult>{ using type = interface_category; };
template <> struct category<Windows::Storage::Provider::IStorageProviderGetPathForContentUriResult>{ using type = interface_category; };
template <> struct category<Windows::Storage::Provider::IStorageProviderItemPropertiesStatics>{ using type = interface_category; };
template <> struct category<Windows::Storage::Provider::IStorageProviderItemProperty>{ using type = interface_category; };
template <> struct category<Windows::Storage::Provider::IStorageProviderItemPropertyDefinition>{ using type = interface_category; };
template <> struct category<Windows::Storage::Provider::IStorageProviderItemPropertySource>{ using type = interface_category; };
template <> struct category<Windows::Storage::Provider::IStorageProviderPropertyCapabilities>{ using type = interface_category; };
template <> struct category<Windows::Storage::Provider::IStorageProviderSyncRootInfo>{ using type = interface_category; };
template <> struct category<Windows::Storage::Provider::IStorageProviderSyncRootInfo2>{ using type = interface_category; };
template <> struct category<Windows::Storage::Provider::IStorageProviderSyncRootManagerStatics>{ using type = interface_category; };
template <> struct category<Windows::Storage::Provider::IStorageProviderUriSource>{ using type = interface_category; };
template <> struct category<Windows::Storage::Provider::CachedFileUpdater>{ using type = class_category; };
template <> struct category<Windows::Storage::Provider::CachedFileUpdaterUI>{ using type = class_category; };
template <> struct category<Windows::Storage::Provider::FileUpdateRequest>{ using type = class_category; };
template <> struct category<Windows::Storage::Provider::FileUpdateRequestDeferral>{ using type = class_category; };
template <> struct category<Windows::Storage::Provider::FileUpdateRequestedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Storage::Provider::StorageProviderGetContentInfoForPathResult>{ using type = class_category; };
template <> struct category<Windows::Storage::Provider::StorageProviderGetPathForContentUriResult>{ using type = class_category; };
template <> struct category<Windows::Storage::Provider::StorageProviderItemProperties>{ using type = class_category; };
template <> struct category<Windows::Storage::Provider::StorageProviderItemProperty>{ using type = class_category; };
template <> struct category<Windows::Storage::Provider::StorageProviderItemPropertyDefinition>{ using type = class_category; };
template <> struct category<Windows::Storage::Provider::StorageProviderSyncRootInfo>{ using type = class_category; };
template <> struct category<Windows::Storage::Provider::StorageProviderSyncRootManager>{ using type = class_category; };
template <> struct category<Windows::Storage::Provider::CachedFileOptions>{ using type = enum_category; };
template <> struct category<Windows::Storage::Provider::CachedFileTarget>{ using type = enum_category; };
template <> struct category<Windows::Storage::Provider::FileUpdateStatus>{ using type = enum_category; };
template <> struct category<Windows::Storage::Provider::ReadActivationMode>{ using type = enum_category; };
template <> struct category<Windows::Storage::Provider::StorageProviderHardlinkPolicy>{ using type = enum_category; };
template <> struct category<Windows::Storage::Provider::StorageProviderHydrationPolicy>{ using type = enum_category; };
template <> struct category<Windows::Storage::Provider::StorageProviderHydrationPolicyModifier>{ using type = enum_category; };
template <> struct category<Windows::Storage::Provider::StorageProviderInSyncPolicy>{ using type = enum_category; };
template <> struct category<Windows::Storage::Provider::StorageProviderPopulationPolicy>{ using type = enum_category; };
template <> struct category<Windows::Storage::Provider::StorageProviderProtectionMode>{ using type = enum_category; };
template <> struct category<Windows::Storage::Provider::StorageProviderUriSourceStatus>{ using type = enum_category; };
template <> struct category<Windows::Storage::Provider::UIStatus>{ using type = enum_category; };
template <> struct category<Windows::Storage::Provider::WriteActivationMode>{ using type = enum_category; };
template <> struct name<Windows::Storage::Provider::ICachedFileUpdaterStatics>{ static constexpr auto & value{ L"Windows.Storage.Provider.ICachedFileUpdaterStatics" }; };
template <> struct name<Windows::Storage::Provider::ICachedFileUpdaterUI>{ static constexpr auto & value{ L"Windows.Storage.Provider.ICachedFileUpdaterUI" }; };
template <> struct name<Windows::Storage::Provider::ICachedFileUpdaterUI2>{ static constexpr auto & value{ L"Windows.Storage.Provider.ICachedFileUpdaterUI2" }; };
template <> struct name<Windows::Storage::Provider::IFileUpdateRequest>{ static constexpr auto & value{ L"Windows.Storage.Provider.IFileUpdateRequest" }; };
template <> struct name<Windows::Storage::Provider::IFileUpdateRequest2>{ static constexpr auto & value{ L"Windows.Storage.Provider.IFileUpdateRequest2" }; };
template <> struct name<Windows::Storage::Provider::IFileUpdateRequestDeferral>{ static constexpr auto & value{ L"Windows.Storage.Provider.IFileUpdateRequestDeferral" }; };
template <> struct name<Windows::Storage::Provider::IFileUpdateRequestedEventArgs>{ static constexpr auto & value{ L"Windows.Storage.Provider.IFileUpdateRequestedEventArgs" }; };
template <> struct name<Windows::Storage::Provider::IStorageProviderGetContentInfoForPathResult>{ static constexpr auto & value{ L"Windows.Storage.Provider.IStorageProviderGetContentInfoForPathResult" }; };
template <> struct name<Windows::Storage::Provider::IStorageProviderGetPathForContentUriResult>{ static constexpr auto & value{ L"Windows.Storage.Provider.IStorageProviderGetPathForContentUriResult" }; };
template <> struct name<Windows::Storage::Provider::IStorageProviderItemPropertiesStatics>{ static constexpr auto & value{ L"Windows.Storage.Provider.IStorageProviderItemPropertiesStatics" }; };
template <> struct name<Windows::Storage::Provider::IStorageProviderItemProperty>{ static constexpr auto & value{ L"Windows.Storage.Provider.IStorageProviderItemProperty" }; };
template <> struct name<Windows::Storage::Provider::IStorageProviderItemPropertyDefinition>{ static constexpr auto & value{ L"Windows.Storage.Provider.IStorageProviderItemPropertyDefinition" }; };
template <> struct name<Windows::Storage::Provider::IStorageProviderItemPropertySource>{ static constexpr auto & value{ L"Windows.Storage.Provider.IStorageProviderItemPropertySource" }; };
template <> struct name<Windows::Storage::Provider::IStorageProviderPropertyCapabilities>{ static constexpr auto & value{ L"Windows.Storage.Provider.IStorageProviderPropertyCapabilities" }; };
template <> struct name<Windows::Storage::Provider::IStorageProviderSyncRootInfo>{ static constexpr auto & value{ L"Windows.Storage.Provider.IStorageProviderSyncRootInfo" }; };
template <> struct name<Windows::Storage::Provider::IStorageProviderSyncRootInfo2>{ static constexpr auto & value{ L"Windows.Storage.Provider.IStorageProviderSyncRootInfo2" }; };
template <> struct name<Windows::Storage::Provider::IStorageProviderSyncRootManagerStatics>{ static constexpr auto & value{ L"Windows.Storage.Provider.IStorageProviderSyncRootManagerStatics" }; };
template <> struct name<Windows::Storage::Provider::IStorageProviderUriSource>{ static constexpr auto & value{ L"Windows.Storage.Provider.IStorageProviderUriSource" }; };
template <> struct name<Windows::Storage::Provider::CachedFileUpdater>{ static constexpr auto & value{ L"Windows.Storage.Provider.CachedFileUpdater" }; };
template <> struct name<Windows::Storage::Provider::CachedFileUpdaterUI>{ static constexpr auto & value{ L"Windows.Storage.Provider.CachedFileUpdaterUI" }; };
template <> struct name<Windows::Storage::Provider::FileUpdateRequest>{ static constexpr auto & value{ L"Windows.Storage.Provider.FileUpdateRequest" }; };
template <> struct name<Windows::Storage::Provider::FileUpdateRequestDeferral>{ static constexpr auto & value{ L"Windows.Storage.Provider.FileUpdateRequestDeferral" }; };
template <> struct name<Windows::Storage::Provider::FileUpdateRequestedEventArgs>{ static constexpr auto & value{ L"Windows.Storage.Provider.FileUpdateRequestedEventArgs" }; };
template <> struct name<Windows::Storage::Provider::StorageProviderGetContentInfoForPathResult>{ static constexpr auto & value{ L"Windows.Storage.Provider.StorageProviderGetContentInfoForPathResult" }; };
template <> struct name<Windows::Storage::Provider::StorageProviderGetPathForContentUriResult>{ static constexpr auto & value{ L"Windows.Storage.Provider.StorageProviderGetPathForContentUriResult" }; };
template <> struct name<Windows::Storage::Provider::StorageProviderItemProperties>{ static constexpr auto & value{ L"Windows.Storage.Provider.StorageProviderItemProperties" }; };
template <> struct name<Windows::Storage::Provider::StorageProviderItemProperty>{ static constexpr auto & value{ L"Windows.Storage.Provider.StorageProviderItemProperty" }; };
template <> struct name<Windows::Storage::Provider::StorageProviderItemPropertyDefinition>{ static constexpr auto & value{ L"Windows.Storage.Provider.StorageProviderItemPropertyDefinition" }; };
template <> struct name<Windows::Storage::Provider::StorageProviderSyncRootInfo>{ static constexpr auto & value{ L"Windows.Storage.Provider.StorageProviderSyncRootInfo" }; };
template <> struct name<Windows::Storage::Provider::StorageProviderSyncRootManager>{ static constexpr auto & value{ L"Windows.Storage.Provider.StorageProviderSyncRootManager" }; };
template <> struct name<Windows::Storage::Provider::CachedFileOptions>{ static constexpr auto & value{ L"Windows.Storage.Provider.CachedFileOptions" }; };
template <> struct name<Windows::Storage::Provider::CachedFileTarget>{ static constexpr auto & value{ L"Windows.Storage.Provider.CachedFileTarget" }; };
template <> struct name<Windows::Storage::Provider::FileUpdateStatus>{ static constexpr auto & value{ L"Windows.Storage.Provider.FileUpdateStatus" }; };
template <> struct name<Windows::Storage::Provider::ReadActivationMode>{ static constexpr auto & value{ L"Windows.Storage.Provider.ReadActivationMode" }; };
template <> struct name<Windows::Storage::Provider::StorageProviderHardlinkPolicy>{ static constexpr auto & value{ L"Windows.Storage.Provider.StorageProviderHardlinkPolicy" }; };
template <> struct name<Windows::Storage::Provider::StorageProviderHydrationPolicy>{ static constexpr auto & value{ L"Windows.Storage.Provider.StorageProviderHydrationPolicy" }; };
template <> struct name<Windows::Storage::Provider::StorageProviderHydrationPolicyModifier>{ static constexpr auto & value{ L"Windows.Storage.Provider.StorageProviderHydrationPolicyModifier" }; };
template <> struct name<Windows::Storage::Provider::StorageProviderInSyncPolicy>{ static constexpr auto & value{ L"Windows.Storage.Provider.StorageProviderInSyncPolicy" }; };
template <> struct name<Windows::Storage::Provider::StorageProviderPopulationPolicy>{ static constexpr auto & value{ L"Windows.Storage.Provider.StorageProviderPopulationPolicy" }; };
template <> struct name<Windows::Storage::Provider::StorageProviderProtectionMode>{ static constexpr auto & value{ L"Windows.Storage.Provider.StorageProviderProtectionMode" }; };
template <> struct name<Windows::Storage::Provider::StorageProviderUriSourceStatus>{ static constexpr auto & value{ L"Windows.Storage.Provider.StorageProviderUriSourceStatus" }; };
template <> struct name<Windows::Storage::Provider::UIStatus>{ static constexpr auto & value{ L"Windows.Storage.Provider.UIStatus" }; };
template <> struct name<Windows::Storage::Provider::WriteActivationMode>{ static constexpr auto & value{ L"Windows.Storage.Provider.WriteActivationMode" }; };
template <> struct guid_storage<Windows::Storage::Provider::ICachedFileUpdaterStatics>{ static constexpr guid value{ 0x9FC90920,0x7BCF,0x4888,{ 0xA8,0x1E,0x10,0x2D,0x70,0x34,0xD7,0xCE } }; };
template <> struct guid_storage<Windows::Storage::Provider::ICachedFileUpdaterUI>{ static constexpr guid value{ 0x9E6F41E6,0xBAF2,0x4A97,{ 0xB6,0x00,0x93,0x33,0xF5,0xDF,0x80,0xFD } }; };
template <> struct guid_storage<Windows::Storage::Provider::ICachedFileUpdaterUI2>{ static constexpr guid value{ 0x8856A21C,0x8699,0x4340,{ 0x9F,0x49,0xF7,0xCA,0xD7,0xFE,0x89,0x91 } }; };
template <> struct guid_storage<Windows::Storage::Provider::IFileUpdateRequest>{ static constexpr guid value{ 0x40C82536,0xC1FE,0x4D93,{ 0xA7,0x92,0x1E,0x73,0x6B,0xC7,0x08,0x37 } }; };
template <> struct guid_storage<Windows::Storage::Provider::IFileUpdateRequest2>{ static constexpr guid value{ 0x82484648,0xBDBE,0x447B,{ 0xA2,0xEE,0x7A,0xFE,0x6A,0x03,0x2A,0x94 } }; };
template <> struct guid_storage<Windows::Storage::Provider::IFileUpdateRequestDeferral>{ static constexpr guid value{ 0xFFCEDB2B,0x8ADE,0x44A5,{ 0xBB,0x00,0x16,0x4C,0x4E,0x72,0xF1,0x3A } }; };
template <> struct guid_storage<Windows::Storage::Provider::IFileUpdateRequestedEventArgs>{ static constexpr guid value{ 0x7B0A9342,0x3905,0x438D,{ 0xAA,0xEF,0x78,0xAE,0x26,0x5F,0x8D,0xD2 } }; };
template <> struct guid_storage<Windows::Storage::Provider::IStorageProviderGetContentInfoForPathResult>{ static constexpr guid value{ 0x2564711D,0xAA89,0x4D12,{ 0x82,0xE3,0xF7,0x2A,0x92,0xE3,0x39,0x66 } }; };
template <> struct guid_storage<Windows::Storage::Provider::IStorageProviderGetPathForContentUriResult>{ static constexpr guid value{ 0x63711A9D,0x4118,0x45A6,{ 0xAC,0xB6,0x22,0xC4,0x9D,0x01,0x9F,0x40 } }; };
template <> struct guid_storage<Windows::Storage::Provider::IStorageProviderItemPropertiesStatics>{ static constexpr guid value{ 0x2D2C1C97,0x2704,0x4729,{ 0x8F,0xA9,0x7E,0x6B,0x8E,0x15,0x8C,0x2F } }; };
template <> struct guid_storage<Windows::Storage::Provider::IStorageProviderItemProperty>{ static constexpr guid value{ 0x476CB558,0x730B,0x4188,{ 0xB7,0xB5,0x63,0xB7,0x16,0xED,0x47,0x6D } }; };
template <> struct guid_storage<Windows::Storage::Provider::IStorageProviderItemPropertyDefinition>{ static constexpr guid value{ 0xC5B383BB,0xFF1F,0x4298,{ 0x83,0x1E,0xFF,0x1C,0x08,0x08,0x96,0x90 } }; };
template <> struct guid_storage<Windows::Storage::Provider::IStorageProviderItemPropertySource>{ static constexpr guid value{ 0x8F6F9C3E,0xF632,0x4A9B,{ 0x8D,0x99,0xD2,0xD7,0xA1,0x1D,0xF5,0x6A } }; };
template <> struct guid_storage<Windows::Storage::Provider::IStorageProviderPropertyCapabilities>{ static constexpr guid value{ 0x658D2F0E,0x63B7,0x4567,{ 0xAC,0xF9,0x51,0xAB,0xE3,0x01,0xDD,0xA5 } }; };
template <> struct guid_storage<Windows::Storage::Provider::IStorageProviderSyncRootInfo>{ static constexpr guid value{ 0x7C1305C4,0x99F9,0x41AC,{ 0x89,0x04,0xAB,0x05,0x5D,0x65,0x49,0x26 } }; };
template <> struct guid_storage<Windows::Storage::Provider::IStorageProviderSyncRootInfo2>{ static constexpr guid value{ 0xCF51B023,0x7CF1,0x5166,{ 0xBD,0xBA,0xEF,0xD9,0x5F,0x52,0x9E,0x31 } }; };
template <> struct guid_storage<Windows::Storage::Provider::IStorageProviderSyncRootManagerStatics>{ static constexpr guid value{ 0x3E99FBBF,0x8FE3,0x4B40,{ 0xAB,0xC7,0xF6,0xFC,0x3D,0x74,0xC9,0x8E } }; };
template <> struct guid_storage<Windows::Storage::Provider::IStorageProviderUriSource>{ static constexpr guid value{ 0xB29806D1,0x8BE0,0x4962,{ 0x8B,0xB6,0x0D,0x4C,0x2E,0x14,0xD4,0x7A } }; };
template <> struct default_interface<Windows::Storage::Provider::CachedFileUpdaterUI>{ using type = Windows::Storage::Provider::ICachedFileUpdaterUI; };
template <> struct default_interface<Windows::Storage::Provider::FileUpdateRequest>{ using type = Windows::Storage::Provider::IFileUpdateRequest; };
template <> struct default_interface<Windows::Storage::Provider::FileUpdateRequestDeferral>{ using type = Windows::Storage::Provider::IFileUpdateRequestDeferral; };
template <> struct default_interface<Windows::Storage::Provider::FileUpdateRequestedEventArgs>{ using type = Windows::Storage::Provider::IFileUpdateRequestedEventArgs; };
template <> struct default_interface<Windows::Storage::Provider::StorageProviderGetContentInfoForPathResult>{ using type = Windows::Storage::Provider::IStorageProviderGetContentInfoForPathResult; };
template <> struct default_interface<Windows::Storage::Provider::StorageProviderGetPathForContentUriResult>{ using type = Windows::Storage::Provider::IStorageProviderGetPathForContentUriResult; };
template <> struct default_interface<Windows::Storage::Provider::StorageProviderItemProperty>{ using type = Windows::Storage::Provider::IStorageProviderItemProperty; };
template <> struct default_interface<Windows::Storage::Provider::StorageProviderItemPropertyDefinition>{ using type = Windows::Storage::Provider::IStorageProviderItemPropertyDefinition; };
template <> struct default_interface<Windows::Storage::Provider::StorageProviderSyncRootInfo>{ using type = Windows::Storage::Provider::IStorageProviderSyncRootInfo; };

template <> struct abi<Windows::Storage::Provider::ICachedFileUpdaterStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL SetUpdateInformation(void* file, void* contentId, Windows::Storage::Provider::ReadActivationMode readMode, Windows::Storage::Provider::WriteActivationMode writeMode, Windows::Storage::Provider::CachedFileOptions options) noexcept = 0;
};};

template <> struct abi<Windows::Storage::Provider::ICachedFileUpdaterUI>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Title(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Title(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_UpdateTarget(Windows::Storage::Provider::CachedFileTarget* value) noexcept = 0;
    virtual int32_t WINRT_CALL add_FileUpdateRequested(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_FileUpdateRequested(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_UIRequested(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_UIRequested(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL get_UIStatus(Windows::Storage::Provider::UIStatus* value) noexcept = 0;
};};

template <> struct abi<Windows::Storage::Provider::ICachedFileUpdaterUI2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_UpdateRequest(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetDeferral(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Storage::Provider::IFileUpdateRequest>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ContentId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_File(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Status(Windows::Storage::Provider::FileUpdateStatus* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Status(Windows::Storage::Provider::FileUpdateStatus value) noexcept = 0;
    virtual int32_t WINRT_CALL GetDeferral(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL UpdateLocalFile(void* value) noexcept = 0;
};};

template <> struct abi<Windows::Storage::Provider::IFileUpdateRequest2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_UserInputNeededMessage(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_UserInputNeededMessage(void* value) noexcept = 0;
};};

template <> struct abi<Windows::Storage::Provider::IFileUpdateRequestDeferral>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Complete() noexcept = 0;
};};

template <> struct abi<Windows::Storage::Provider::IFileUpdateRequestedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Request(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Storage::Provider::IStorageProviderGetContentInfoForPathResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Status(Windows::Storage::Provider::StorageProviderUriSourceStatus* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Status(Windows::Storage::Provider::StorageProviderUriSourceStatus value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ContentUri(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ContentUri(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ContentId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ContentId(void* value) noexcept = 0;
};};

template <> struct abi<Windows::Storage::Provider::IStorageProviderGetPathForContentUriResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Status(Windows::Storage::Provider::StorageProviderUriSourceStatus* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Status(Windows::Storage::Provider::StorageProviderUriSourceStatus value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Path(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Path(void* value) noexcept = 0;
};};

template <> struct abi<Windows::Storage::Provider::IStorageProviderItemPropertiesStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL SetAsync(void* item, void* itemProperties, void** operation) noexcept = 0;
};};

template <> struct abi<Windows::Storage::Provider::IStorageProviderItemProperty>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL put_Id(int32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Id(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Value(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Value(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IconResource(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IconResource(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Storage::Provider::IStorageProviderItemPropertyDefinition>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Id(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Id(int32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DisplayNameResource(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_DisplayNameResource(void* value) noexcept = 0;
};};

template <> struct abi<Windows::Storage::Provider::IStorageProviderItemPropertySource>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetItemProperties(void* itemPath, void** result) noexcept = 0;
};};

template <> struct abi<Windows::Storage::Provider::IStorageProviderPropertyCapabilities>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL IsPropertySupported(void* propertyCanonicalName, bool* isSupported) noexcept = 0;
};};

template <> struct abi<Windows::Storage::Provider::IStorageProviderSyncRootInfo>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Id(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Id(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Context(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Context(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Path(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Path(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DisplayNameResource(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_DisplayNameResource(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IconResource(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IconResource(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HydrationPolicy(Windows::Storage::Provider::StorageProviderHydrationPolicy* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_HydrationPolicy(Windows::Storage::Provider::StorageProviderHydrationPolicy value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HydrationPolicyModifier(Windows::Storage::Provider::StorageProviderHydrationPolicyModifier* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_HydrationPolicyModifier(Windows::Storage::Provider::StorageProviderHydrationPolicyModifier value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PopulationPolicy(Windows::Storage::Provider::StorageProviderPopulationPolicy* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_PopulationPolicy(Windows::Storage::Provider::StorageProviderPopulationPolicy value) noexcept = 0;
    virtual int32_t WINRT_CALL get_InSyncPolicy(Windows::Storage::Provider::StorageProviderInSyncPolicy* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_InSyncPolicy(Windows::Storage::Provider::StorageProviderInSyncPolicy value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HardlinkPolicy(Windows::Storage::Provider::StorageProviderHardlinkPolicy* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_HardlinkPolicy(Windows::Storage::Provider::StorageProviderHardlinkPolicy value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ShowSiblingsAsGroup(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ShowSiblingsAsGroup(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Version(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Version(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ProtectionMode(Windows::Storage::Provider::StorageProviderProtectionMode* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ProtectionMode(Windows::Storage::Provider::StorageProviderProtectionMode value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AllowPinning(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_AllowPinning(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_StorageProviderItemPropertyDefinitions(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RecycleBinUri(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_RecycleBinUri(void* value) noexcept = 0;
};};

template <> struct abi<Windows::Storage::Provider::IStorageProviderSyncRootInfo2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ProviderId(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ProviderId(winrt::guid value) noexcept = 0;
};};

template <> struct abi<Windows::Storage::Provider::IStorageProviderSyncRootManagerStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Register(void* syncRootInformation) noexcept = 0;
    virtual int32_t WINRT_CALL Unregister(void* id) noexcept = 0;
    virtual int32_t WINRT_CALL GetSyncRootInformationForFolder(void* folder, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL GetSyncRootInformationForId(void* id, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL GetCurrentSyncRoots(void** result) noexcept = 0;
};};

template <> struct abi<Windows::Storage::Provider::IStorageProviderUriSource>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetPathForContentUri(void* contentUri, void* result) noexcept = 0;
    virtual int32_t WINRT_CALL GetContentInfoForPath(void* path, void* result) noexcept = 0;
};};

template <typename D>
struct consume_Windows_Storage_Provider_ICachedFileUpdaterStatics
{
    void SetUpdateInformation(Windows::Storage::IStorageFile const& file, param::hstring const& contentId, Windows::Storage::Provider::ReadActivationMode const& readMode, Windows::Storage::Provider::WriteActivationMode const& writeMode, Windows::Storage::Provider::CachedFileOptions const& options) const;
};
template <> struct consume<Windows::Storage::Provider::ICachedFileUpdaterStatics> { template <typename D> using type = consume_Windows_Storage_Provider_ICachedFileUpdaterStatics<D>; };

template <typename D>
struct consume_Windows_Storage_Provider_ICachedFileUpdaterUI
{
    hstring Title() const;
    void Title(param::hstring const& value) const;
    Windows::Storage::Provider::CachedFileTarget UpdateTarget() const;
    winrt::event_token FileUpdateRequested(Windows::Foundation::TypedEventHandler<Windows::Storage::Provider::CachedFileUpdaterUI, Windows::Storage::Provider::FileUpdateRequestedEventArgs> const& handler) const;
    using FileUpdateRequested_revoker = impl::event_revoker<Windows::Storage::Provider::ICachedFileUpdaterUI, &impl::abi_t<Windows::Storage::Provider::ICachedFileUpdaterUI>::remove_FileUpdateRequested>;
    FileUpdateRequested_revoker FileUpdateRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Storage::Provider::CachedFileUpdaterUI, Windows::Storage::Provider::FileUpdateRequestedEventArgs> const& handler) const;
    void FileUpdateRequested(winrt::event_token const& token) const noexcept;
    winrt::event_token UIRequested(Windows::Foundation::TypedEventHandler<Windows::Storage::Provider::CachedFileUpdaterUI, Windows::Foundation::IInspectable> const& handler) const;
    using UIRequested_revoker = impl::event_revoker<Windows::Storage::Provider::ICachedFileUpdaterUI, &impl::abi_t<Windows::Storage::Provider::ICachedFileUpdaterUI>::remove_UIRequested>;
    UIRequested_revoker UIRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Storage::Provider::CachedFileUpdaterUI, Windows::Foundation::IInspectable> const& handler) const;
    void UIRequested(winrt::event_token const& token) const noexcept;
    Windows::Storage::Provider::UIStatus UIStatus() const;
};
template <> struct consume<Windows::Storage::Provider::ICachedFileUpdaterUI> { template <typename D> using type = consume_Windows_Storage_Provider_ICachedFileUpdaterUI<D>; };

template <typename D>
struct consume_Windows_Storage_Provider_ICachedFileUpdaterUI2
{
    Windows::Storage::Provider::FileUpdateRequest UpdateRequest() const;
    Windows::Storage::Provider::FileUpdateRequestDeferral GetDeferral() const;
};
template <> struct consume<Windows::Storage::Provider::ICachedFileUpdaterUI2> { template <typename D> using type = consume_Windows_Storage_Provider_ICachedFileUpdaterUI2<D>; };

template <typename D>
struct consume_Windows_Storage_Provider_IFileUpdateRequest
{
    hstring ContentId() const;
    Windows::Storage::StorageFile File() const;
    Windows::Storage::Provider::FileUpdateStatus Status() const;
    void Status(Windows::Storage::Provider::FileUpdateStatus const& value) const;
    Windows::Storage::Provider::FileUpdateRequestDeferral GetDeferral() const;
    void UpdateLocalFile(Windows::Storage::IStorageFile const& value) const;
};
template <> struct consume<Windows::Storage::Provider::IFileUpdateRequest> { template <typename D> using type = consume_Windows_Storage_Provider_IFileUpdateRequest<D>; };

template <typename D>
struct consume_Windows_Storage_Provider_IFileUpdateRequest2
{
    hstring UserInputNeededMessage() const;
    void UserInputNeededMessage(param::hstring const& value) const;
};
template <> struct consume<Windows::Storage::Provider::IFileUpdateRequest2> { template <typename D> using type = consume_Windows_Storage_Provider_IFileUpdateRequest2<D>; };

template <typename D>
struct consume_Windows_Storage_Provider_IFileUpdateRequestDeferral
{
    void Complete() const;
};
template <> struct consume<Windows::Storage::Provider::IFileUpdateRequestDeferral> { template <typename D> using type = consume_Windows_Storage_Provider_IFileUpdateRequestDeferral<D>; };

template <typename D>
struct consume_Windows_Storage_Provider_IFileUpdateRequestedEventArgs
{
    Windows::Storage::Provider::FileUpdateRequest Request() const;
};
template <> struct consume<Windows::Storage::Provider::IFileUpdateRequestedEventArgs> { template <typename D> using type = consume_Windows_Storage_Provider_IFileUpdateRequestedEventArgs<D>; };

template <typename D>
struct consume_Windows_Storage_Provider_IStorageProviderGetContentInfoForPathResult
{
    Windows::Storage::Provider::StorageProviderUriSourceStatus Status() const;
    void Status(Windows::Storage::Provider::StorageProviderUriSourceStatus const& value) const;
    hstring ContentUri() const;
    void ContentUri(param::hstring const& value) const;
    hstring ContentId() const;
    void ContentId(param::hstring const& value) const;
};
template <> struct consume<Windows::Storage::Provider::IStorageProviderGetContentInfoForPathResult> { template <typename D> using type = consume_Windows_Storage_Provider_IStorageProviderGetContentInfoForPathResult<D>; };

template <typename D>
struct consume_Windows_Storage_Provider_IStorageProviderGetPathForContentUriResult
{
    Windows::Storage::Provider::StorageProviderUriSourceStatus Status() const;
    void Status(Windows::Storage::Provider::StorageProviderUriSourceStatus const& value) const;
    hstring Path() const;
    void Path(param::hstring const& value) const;
};
template <> struct consume<Windows::Storage::Provider::IStorageProviderGetPathForContentUriResult> { template <typename D> using type = consume_Windows_Storage_Provider_IStorageProviderGetPathForContentUriResult<D>; };

template <typename D>
struct consume_Windows_Storage_Provider_IStorageProviderItemPropertiesStatics
{
    Windows::Foundation::IAsyncAction SetAsync(Windows::Storage::IStorageItem const& item, param::async_iterable<Windows::Storage::Provider::StorageProviderItemProperty> const& itemProperties) const;
};
template <> struct consume<Windows::Storage::Provider::IStorageProviderItemPropertiesStatics> { template <typename D> using type = consume_Windows_Storage_Provider_IStorageProviderItemPropertiesStatics<D>; };

template <typename D>
struct consume_Windows_Storage_Provider_IStorageProviderItemProperty
{
    void Id(int32_t value) const;
    int32_t Id() const;
    void Value(param::hstring const& value) const;
    hstring Value() const;
    void IconResource(param::hstring const& value) const;
    hstring IconResource() const;
};
template <> struct consume<Windows::Storage::Provider::IStorageProviderItemProperty> { template <typename D> using type = consume_Windows_Storage_Provider_IStorageProviderItemProperty<D>; };

template <typename D>
struct consume_Windows_Storage_Provider_IStorageProviderItemPropertyDefinition
{
    int32_t Id() const;
    void Id(int32_t value) const;
    hstring DisplayNameResource() const;
    void DisplayNameResource(param::hstring const& value) const;
};
template <> struct consume<Windows::Storage::Provider::IStorageProviderItemPropertyDefinition> { template <typename D> using type = consume_Windows_Storage_Provider_IStorageProviderItemPropertyDefinition<D>; };

template <typename D>
struct consume_Windows_Storage_Provider_IStorageProviderItemPropertySource
{
    Windows::Foundation::Collections::IIterable<Windows::Storage::Provider::StorageProviderItemProperty> GetItemProperties(param::hstring const& itemPath) const;
};
template <> struct consume<Windows::Storage::Provider::IStorageProviderItemPropertySource> { template <typename D> using type = consume_Windows_Storage_Provider_IStorageProviderItemPropertySource<D>; };

template <typename D>
struct consume_Windows_Storage_Provider_IStorageProviderPropertyCapabilities
{
    bool IsPropertySupported(param::hstring const& propertyCanonicalName) const;
};
template <> struct consume<Windows::Storage::Provider::IStorageProviderPropertyCapabilities> { template <typename D> using type = consume_Windows_Storage_Provider_IStorageProviderPropertyCapabilities<D>; };

template <typename D>
struct consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo
{
    hstring Id() const;
    void Id(param::hstring const& value) const;
    Windows::Storage::Streams::IBuffer Context() const;
    void Context(Windows::Storage::Streams::IBuffer const& value) const;
    Windows::Storage::IStorageFolder Path() const;
    void Path(Windows::Storage::IStorageFolder const& value) const;
    hstring DisplayNameResource() const;
    void DisplayNameResource(param::hstring const& value) const;
    hstring IconResource() const;
    void IconResource(param::hstring const& value) const;
    Windows::Storage::Provider::StorageProviderHydrationPolicy HydrationPolicy() const;
    void HydrationPolicy(Windows::Storage::Provider::StorageProviderHydrationPolicy const& value) const;
    Windows::Storage::Provider::StorageProviderHydrationPolicyModifier HydrationPolicyModifier() const;
    void HydrationPolicyModifier(Windows::Storage::Provider::StorageProviderHydrationPolicyModifier const& value) const;
    Windows::Storage::Provider::StorageProviderPopulationPolicy PopulationPolicy() const;
    void PopulationPolicy(Windows::Storage::Provider::StorageProviderPopulationPolicy const& value) const;
    Windows::Storage::Provider::StorageProviderInSyncPolicy InSyncPolicy() const;
    void InSyncPolicy(Windows::Storage::Provider::StorageProviderInSyncPolicy const& value) const;
    Windows::Storage::Provider::StorageProviderHardlinkPolicy HardlinkPolicy() const;
    void HardlinkPolicy(Windows::Storage::Provider::StorageProviderHardlinkPolicy const& value) const;
    bool ShowSiblingsAsGroup() const;
    void ShowSiblingsAsGroup(bool value) const;
    hstring Version() const;
    void Version(param::hstring const& value) const;
    Windows::Storage::Provider::StorageProviderProtectionMode ProtectionMode() const;
    void ProtectionMode(Windows::Storage::Provider::StorageProviderProtectionMode const& value) const;
    bool AllowPinning() const;
    void AllowPinning(bool value) const;
    Windows::Foundation::Collections::IVector<Windows::Storage::Provider::StorageProviderItemPropertyDefinition> StorageProviderItemPropertyDefinitions() const;
    Windows::Foundation::Uri RecycleBinUri() const;
    void RecycleBinUri(Windows::Foundation::Uri const& value) const;
};
template <> struct consume<Windows::Storage::Provider::IStorageProviderSyncRootInfo> { template <typename D> using type = consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo<D>; };

template <typename D>
struct consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo2
{
    winrt::guid ProviderId() const;
    void ProviderId(winrt::guid const& value) const;
};
template <> struct consume<Windows::Storage::Provider::IStorageProviderSyncRootInfo2> { template <typename D> using type = consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo2<D>; };

template <typename D>
struct consume_Windows_Storage_Provider_IStorageProviderSyncRootManagerStatics
{
    void Register(Windows::Storage::Provider::StorageProviderSyncRootInfo const& syncRootInformation) const;
    void Unregister(param::hstring const& id) const;
    Windows::Storage::Provider::StorageProviderSyncRootInfo GetSyncRootInformationForFolder(Windows::Storage::IStorageFolder const& folder) const;
    Windows::Storage::Provider::StorageProviderSyncRootInfo GetSyncRootInformationForId(param::hstring const& id) const;
    Windows::Foundation::Collections::IVectorView<Windows::Storage::Provider::StorageProviderSyncRootInfo> GetCurrentSyncRoots() const;
};
template <> struct consume<Windows::Storage::Provider::IStorageProviderSyncRootManagerStatics> { template <typename D> using type = consume_Windows_Storage_Provider_IStorageProviderSyncRootManagerStatics<D>; };

template <typename D>
struct consume_Windows_Storage_Provider_IStorageProviderUriSource
{
    void GetPathForContentUri(param::hstring const& contentUri, Windows::Storage::Provider::StorageProviderGetPathForContentUriResult const& result) const;
    void GetContentInfoForPath(param::hstring const& path, Windows::Storage::Provider::StorageProviderGetContentInfoForPathResult const& result) const;
};
template <> struct consume<Windows::Storage::Provider::IStorageProviderUriSource> { template <typename D> using type = consume_Windows_Storage_Provider_IStorageProviderUriSource<D>; };

}
