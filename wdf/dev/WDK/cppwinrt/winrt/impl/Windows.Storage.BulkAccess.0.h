// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Storage {

enum class CreationCollisionOption;
enum class FileAccessMode;
enum class FileAttributes : unsigned;
enum class NameCollisionOption;
enum class StorageDeleteOption;
enum class StorageItemTypes : unsigned;
enum class StorageOpenOptions : unsigned;
struct IStorageFile;
struct IStorageFolder;
struct IStorageItem;
struct StorageFile;
struct StorageFolder;
struct StorageProvider;
struct StorageStreamTransaction;

}

WINRT_EXPORT namespace winrt::Windows::Storage::FileProperties {

enum class ThumbnailMode;
enum class ThumbnailOptions : unsigned;
struct BasicProperties;
struct DocumentProperties;
struct ImageProperties;
struct MusicProperties;
struct StorageItemContentProperties;
struct StorageItemThumbnail;
struct VideoProperties;

}

WINRT_EXPORT namespace winrt::Windows::Storage::Search {

enum class CommonFileQuery;
enum class CommonFolderQuery;
enum class IndexedState;
struct IStorageQueryResultBase;
struct QueryOptions;
struct StorageFileQueryResult;
struct StorageFolderQueryResult;
struct StorageItemQueryResult;

}

WINRT_EXPORT namespace winrt::Windows::Storage::Streams {

struct IInputStream;
struct IRandomAccessStream;
struct IRandomAccessStreamWithContentType;

}

WINRT_EXPORT namespace winrt::Windows::Storage::BulkAccess {

struct IFileInformationFactory;
struct IFileInformationFactoryFactory;
struct IStorageItemInformation;
struct FileInformation;
struct FileInformationFactory;
struct FolderInformation;

}

namespace winrt::impl {

template <> struct category<Windows::Storage::BulkAccess::IFileInformationFactory>{ using type = interface_category; };
template <> struct category<Windows::Storage::BulkAccess::IFileInformationFactoryFactory>{ using type = interface_category; };
template <> struct category<Windows::Storage::BulkAccess::IStorageItemInformation>{ using type = interface_category; };
template <> struct category<Windows::Storage::BulkAccess::FileInformation>{ using type = class_category; };
template <> struct category<Windows::Storage::BulkAccess::FileInformationFactory>{ using type = class_category; };
template <> struct category<Windows::Storage::BulkAccess::FolderInformation>{ using type = class_category; };
template <> struct name<Windows::Storage::BulkAccess::IFileInformationFactory>{ static constexpr auto & value{ L"Windows.Storage.BulkAccess.IFileInformationFactory" }; };
template <> struct name<Windows::Storage::BulkAccess::IFileInformationFactoryFactory>{ static constexpr auto & value{ L"Windows.Storage.BulkAccess.IFileInformationFactoryFactory" }; };
template <> struct name<Windows::Storage::BulkAccess::IStorageItemInformation>{ static constexpr auto & value{ L"Windows.Storage.BulkAccess.IStorageItemInformation" }; };
template <> struct name<Windows::Storage::BulkAccess::FileInformation>{ static constexpr auto & value{ L"Windows.Storage.BulkAccess.FileInformation" }; };
template <> struct name<Windows::Storage::BulkAccess::FileInformationFactory>{ static constexpr auto & value{ L"Windows.Storage.BulkAccess.FileInformationFactory" }; };
template <> struct name<Windows::Storage::BulkAccess::FolderInformation>{ static constexpr auto & value{ L"Windows.Storage.BulkAccess.FolderInformation" }; };
template <> struct guid_storage<Windows::Storage::BulkAccess::IFileInformationFactory>{ static constexpr guid value{ 0x401D88BE,0x960F,0x4D6D,{ 0xA7,0xD0,0x1A,0x38,0x61,0xE7,0x6C,0x83 } }; };
template <> struct guid_storage<Windows::Storage::BulkAccess::IFileInformationFactoryFactory>{ static constexpr guid value{ 0x84EA0E7D,0xE4A2,0x4F00,{ 0x8A,0xFA,0xAF,0x5E,0x0F,0x82,0x6B,0xD5 } }; };
template <> struct guid_storage<Windows::Storage::BulkAccess::IStorageItemInformation>{ static constexpr guid value{ 0x87A5CB8B,0x8972,0x4F40,{ 0x8D,0xE0,0xD8,0x6F,0xB1,0x79,0xD8,0xFA } }; };
template <> struct default_interface<Windows::Storage::BulkAccess::FileInformation>{ using type = Windows::Storage::BulkAccess::IStorageItemInformation; };
template <> struct default_interface<Windows::Storage::BulkAccess::FileInformationFactory>{ using type = Windows::Storage::BulkAccess::IFileInformationFactory; };
template <> struct default_interface<Windows::Storage::BulkAccess::FolderInformation>{ using type = Windows::Storage::BulkAccess::IStorageItemInformation; };

template <> struct abi<Windows::Storage::BulkAccess::IFileInformationFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetItemsAsync(uint32_t startIndex, uint32_t maxItemsToRetrieve, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetItemsAsyncDefaultStartAndCount(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetFilesAsync(uint32_t startIndex, uint32_t maxItemsToRetrieve, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetFilesAsyncDefaultStartAndCount(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetFoldersAsync(uint32_t startIndex, uint32_t maxItemsToRetrieve, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetFoldersAsyncDefaultStartAndCount(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetVirtualizedItemsVector(void** vector) noexcept = 0;
    virtual int32_t WINRT_CALL GetVirtualizedFilesVector(void** vector) noexcept = 0;
    virtual int32_t WINRT_CALL GetVirtualizedFoldersVector(void** vector) noexcept = 0;
};};

template <> struct abi<Windows::Storage::BulkAccess::IFileInformationFactoryFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateWithMode(void* queryResult, Windows::Storage::FileProperties::ThumbnailMode mode, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateWithModeAndSize(void* queryResult, Windows::Storage::FileProperties::ThumbnailMode mode, uint32_t requestedThumbnailSize, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateWithModeAndSizeAndOptions(void* queryResult, Windows::Storage::FileProperties::ThumbnailMode mode, uint32_t requestedThumbnailSize, Windows::Storage::FileProperties::ThumbnailOptions thumbnailOptions, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateWithModeAndSizeAndOptionsAndFlags(void* queryResult, Windows::Storage::FileProperties::ThumbnailMode mode, uint32_t requestedThumbnailSize, Windows::Storage::FileProperties::ThumbnailOptions thumbnailOptions, bool delayLoad, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Storage::BulkAccess::IStorageItemInformation>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_MusicProperties(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_VideoProperties(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ImageProperties(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DocumentProperties(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BasicProperties(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Thumbnail(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL add_ThumbnailUpdated(void* changedHandler, winrt::event_token* eventCookie) noexcept = 0;
    virtual int32_t WINRT_CALL remove_ThumbnailUpdated(winrt::event_token eventCookie) noexcept = 0;
    virtual int32_t WINRT_CALL add_PropertiesUpdated(void* changedHandler, winrt::event_token* eventCookie) noexcept = 0;
    virtual int32_t WINRT_CALL remove_PropertiesUpdated(winrt::event_token eventCookie) noexcept = 0;
};};

template <typename D>
struct consume_Windows_Storage_BulkAccess_IFileInformationFactory
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::BulkAccess::IStorageItemInformation>> GetItemsAsync(uint32_t startIndex, uint32_t maxItemsToRetrieve) const;
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::BulkAccess::IStorageItemInformation>> GetItemsAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::BulkAccess::FileInformation>> GetFilesAsync(uint32_t startIndex, uint32_t maxItemsToRetrieve) const;
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::BulkAccess::FileInformation>> GetFilesAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::BulkAccess::FolderInformation>> GetFoldersAsync(uint32_t startIndex, uint32_t maxItemsToRetrieve) const;
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::BulkAccess::FolderInformation>> GetFoldersAsync() const;
    Windows::Foundation::IInspectable GetVirtualizedItemsVector() const;
    Windows::Foundation::IInspectable GetVirtualizedFilesVector() const;
    Windows::Foundation::IInspectable GetVirtualizedFoldersVector() const;
};
template <> struct consume<Windows::Storage::BulkAccess::IFileInformationFactory> { template <typename D> using type = consume_Windows_Storage_BulkAccess_IFileInformationFactory<D>; };

template <typename D>
struct consume_Windows_Storage_BulkAccess_IFileInformationFactoryFactory
{
    Windows::Storage::BulkAccess::FileInformationFactory CreateWithMode(Windows::Storage::Search::IStorageQueryResultBase const& queryResult, Windows::Storage::FileProperties::ThumbnailMode const& mode) const;
    Windows::Storage::BulkAccess::FileInformationFactory CreateWithModeAndSize(Windows::Storage::Search::IStorageQueryResultBase const& queryResult, Windows::Storage::FileProperties::ThumbnailMode const& mode, uint32_t requestedThumbnailSize) const;
    Windows::Storage::BulkAccess::FileInformationFactory CreateWithModeAndSizeAndOptions(Windows::Storage::Search::IStorageQueryResultBase const& queryResult, Windows::Storage::FileProperties::ThumbnailMode const& mode, uint32_t requestedThumbnailSize, Windows::Storage::FileProperties::ThumbnailOptions const& thumbnailOptions) const;
    Windows::Storage::BulkAccess::FileInformationFactory CreateWithModeAndSizeAndOptionsAndFlags(Windows::Storage::Search::IStorageQueryResultBase const& queryResult, Windows::Storage::FileProperties::ThumbnailMode const& mode, uint32_t requestedThumbnailSize, Windows::Storage::FileProperties::ThumbnailOptions const& thumbnailOptions, bool delayLoad) const;
};
template <> struct consume<Windows::Storage::BulkAccess::IFileInformationFactoryFactory> { template <typename D> using type = consume_Windows_Storage_BulkAccess_IFileInformationFactoryFactory<D>; };

template <typename D>
struct consume_Windows_Storage_BulkAccess_IStorageItemInformation
{
    Windows::Storage::FileProperties::MusicProperties MusicProperties() const;
    Windows::Storage::FileProperties::VideoProperties VideoProperties() const;
    Windows::Storage::FileProperties::ImageProperties ImageProperties() const;
    Windows::Storage::FileProperties::DocumentProperties DocumentProperties() const;
    Windows::Storage::FileProperties::BasicProperties BasicProperties() const;
    Windows::Storage::FileProperties::StorageItemThumbnail Thumbnail() const;
    winrt::event_token ThumbnailUpdated(Windows::Foundation::TypedEventHandler<Windows::Storage::BulkAccess::IStorageItemInformation, Windows::Foundation::IInspectable> const& changedHandler) const;
    using ThumbnailUpdated_revoker = impl::event_revoker<Windows::Storage::BulkAccess::IStorageItemInformation, &impl::abi_t<Windows::Storage::BulkAccess::IStorageItemInformation>::remove_ThumbnailUpdated>;
    ThumbnailUpdated_revoker ThumbnailUpdated(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Storage::BulkAccess::IStorageItemInformation, Windows::Foundation::IInspectable> const& changedHandler) const;
    void ThumbnailUpdated(winrt::event_token const& eventCookie) const noexcept;
    winrt::event_token PropertiesUpdated(Windows::Foundation::TypedEventHandler<Windows::Storage::BulkAccess::IStorageItemInformation, Windows::Foundation::IInspectable> const& changedHandler) const;
    using PropertiesUpdated_revoker = impl::event_revoker<Windows::Storage::BulkAccess::IStorageItemInformation, &impl::abi_t<Windows::Storage::BulkAccess::IStorageItemInformation>::remove_PropertiesUpdated>;
    PropertiesUpdated_revoker PropertiesUpdated(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Storage::BulkAccess::IStorageItemInformation, Windows::Foundation::IInspectable> const& changedHandler) const;
    void PropertiesUpdated(winrt::event_token const& eventCookie) const noexcept;
};
template <> struct consume<Windows::Storage::BulkAccess::IStorageItemInformation> { template <typename D> using type = consume_Windows_Storage_BulkAccess_IStorageItemInformation<D>; };

}
