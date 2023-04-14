// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Storage.2.h"
#include "winrt/impl/Windows.Storage.FileProperties.2.h"
#include "winrt/impl/Windows.Storage.Search.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Storage.BulkAccess.2.h"
#include "winrt/Windows.Storage.h"

namespace winrt::impl {

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::BulkAccess::IStorageItemInformation>> consume_Windows_Storage_BulkAccess_IFileInformationFactory<D>::GetItemsAsync(uint32_t startIndex, uint32_t maxItemsToRetrieve) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::BulkAccess::IStorageItemInformation>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::BulkAccess::IFileInformationFactory)->GetItemsAsync(startIndex, maxItemsToRetrieve, put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::BulkAccess::IStorageItemInformation>> consume_Windows_Storage_BulkAccess_IFileInformationFactory<D>::GetItemsAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::BulkAccess::IStorageItemInformation>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::BulkAccess::IFileInformationFactory)->GetItemsAsyncDefaultStartAndCount(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::BulkAccess::FileInformation>> consume_Windows_Storage_BulkAccess_IFileInformationFactory<D>::GetFilesAsync(uint32_t startIndex, uint32_t maxItemsToRetrieve) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::BulkAccess::FileInformation>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::BulkAccess::IFileInformationFactory)->GetFilesAsync(startIndex, maxItemsToRetrieve, put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::BulkAccess::FileInformation>> consume_Windows_Storage_BulkAccess_IFileInformationFactory<D>::GetFilesAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::BulkAccess::FileInformation>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::BulkAccess::IFileInformationFactory)->GetFilesAsyncDefaultStartAndCount(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::BulkAccess::FolderInformation>> consume_Windows_Storage_BulkAccess_IFileInformationFactory<D>::GetFoldersAsync(uint32_t startIndex, uint32_t maxItemsToRetrieve) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::BulkAccess::FolderInformation>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::BulkAccess::IFileInformationFactory)->GetFoldersAsync(startIndex, maxItemsToRetrieve, put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::BulkAccess::FolderInformation>> consume_Windows_Storage_BulkAccess_IFileInformationFactory<D>::GetFoldersAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::BulkAccess::FolderInformation>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::BulkAccess::IFileInformationFactory)->GetFoldersAsyncDefaultStartAndCount(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_Storage_BulkAccess_IFileInformationFactory<D>::GetVirtualizedItemsVector() const
{
    Windows::Foundation::IInspectable vector{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::BulkAccess::IFileInformationFactory)->GetVirtualizedItemsVector(put_abi(vector)));
    return vector;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_Storage_BulkAccess_IFileInformationFactory<D>::GetVirtualizedFilesVector() const
{
    Windows::Foundation::IInspectable vector{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::BulkAccess::IFileInformationFactory)->GetVirtualizedFilesVector(put_abi(vector)));
    return vector;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_Storage_BulkAccess_IFileInformationFactory<D>::GetVirtualizedFoldersVector() const
{
    Windows::Foundation::IInspectable vector{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::BulkAccess::IFileInformationFactory)->GetVirtualizedFoldersVector(put_abi(vector)));
    return vector;
}

template <typename D> Windows::Storage::BulkAccess::FileInformationFactory consume_Windows_Storage_BulkAccess_IFileInformationFactoryFactory<D>::CreateWithMode(Windows::Storage::Search::IStorageQueryResultBase const& queryResult, Windows::Storage::FileProperties::ThumbnailMode const& mode) const
{
    Windows::Storage::BulkAccess::FileInformationFactory value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::BulkAccess::IFileInformationFactoryFactory)->CreateWithMode(get_abi(queryResult), get_abi(mode), put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::BulkAccess::FileInformationFactory consume_Windows_Storage_BulkAccess_IFileInformationFactoryFactory<D>::CreateWithModeAndSize(Windows::Storage::Search::IStorageQueryResultBase const& queryResult, Windows::Storage::FileProperties::ThumbnailMode const& mode, uint32_t requestedThumbnailSize) const
{
    Windows::Storage::BulkAccess::FileInformationFactory value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::BulkAccess::IFileInformationFactoryFactory)->CreateWithModeAndSize(get_abi(queryResult), get_abi(mode), requestedThumbnailSize, put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::BulkAccess::FileInformationFactory consume_Windows_Storage_BulkAccess_IFileInformationFactoryFactory<D>::CreateWithModeAndSizeAndOptions(Windows::Storage::Search::IStorageQueryResultBase const& queryResult, Windows::Storage::FileProperties::ThumbnailMode const& mode, uint32_t requestedThumbnailSize, Windows::Storage::FileProperties::ThumbnailOptions const& thumbnailOptions) const
{
    Windows::Storage::BulkAccess::FileInformationFactory value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::BulkAccess::IFileInformationFactoryFactory)->CreateWithModeAndSizeAndOptions(get_abi(queryResult), get_abi(mode), requestedThumbnailSize, get_abi(thumbnailOptions), put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::BulkAccess::FileInformationFactory consume_Windows_Storage_BulkAccess_IFileInformationFactoryFactory<D>::CreateWithModeAndSizeAndOptionsAndFlags(Windows::Storage::Search::IStorageQueryResultBase const& queryResult, Windows::Storage::FileProperties::ThumbnailMode const& mode, uint32_t requestedThumbnailSize, Windows::Storage::FileProperties::ThumbnailOptions const& thumbnailOptions, bool delayLoad) const
{
    Windows::Storage::BulkAccess::FileInformationFactory value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::BulkAccess::IFileInformationFactoryFactory)->CreateWithModeAndSizeAndOptionsAndFlags(get_abi(queryResult), get_abi(mode), requestedThumbnailSize, get_abi(thumbnailOptions), delayLoad, put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::FileProperties::MusicProperties consume_Windows_Storage_BulkAccess_IStorageItemInformation<D>::MusicProperties() const
{
    Windows::Storage::FileProperties::MusicProperties value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::BulkAccess::IStorageItemInformation)->get_MusicProperties(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::FileProperties::VideoProperties consume_Windows_Storage_BulkAccess_IStorageItemInformation<D>::VideoProperties() const
{
    Windows::Storage::FileProperties::VideoProperties value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::BulkAccess::IStorageItemInformation)->get_VideoProperties(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::FileProperties::ImageProperties consume_Windows_Storage_BulkAccess_IStorageItemInformation<D>::ImageProperties() const
{
    Windows::Storage::FileProperties::ImageProperties value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::BulkAccess::IStorageItemInformation)->get_ImageProperties(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::FileProperties::DocumentProperties consume_Windows_Storage_BulkAccess_IStorageItemInformation<D>::DocumentProperties() const
{
    Windows::Storage::FileProperties::DocumentProperties value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::BulkAccess::IStorageItemInformation)->get_DocumentProperties(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::FileProperties::BasicProperties consume_Windows_Storage_BulkAccess_IStorageItemInformation<D>::BasicProperties() const
{
    Windows::Storage::FileProperties::BasicProperties value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::BulkAccess::IStorageItemInformation)->get_BasicProperties(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::FileProperties::StorageItemThumbnail consume_Windows_Storage_BulkAccess_IStorageItemInformation<D>::Thumbnail() const
{
    Windows::Storage::FileProperties::StorageItemThumbnail value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::BulkAccess::IStorageItemInformation)->get_Thumbnail(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Storage_BulkAccess_IStorageItemInformation<D>::ThumbnailUpdated(Windows::Foundation::TypedEventHandler<Windows::Storage::BulkAccess::IStorageItemInformation, Windows::Foundation::IInspectable> const& changedHandler) const
{
    winrt::event_token eventCookie{};
    check_hresult(WINRT_SHIM(Windows::Storage::BulkAccess::IStorageItemInformation)->add_ThumbnailUpdated(get_abi(changedHandler), put_abi(eventCookie)));
    return eventCookie;
}

template <typename D> typename consume_Windows_Storage_BulkAccess_IStorageItemInformation<D>::ThumbnailUpdated_revoker consume_Windows_Storage_BulkAccess_IStorageItemInformation<D>::ThumbnailUpdated(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Storage::BulkAccess::IStorageItemInformation, Windows::Foundation::IInspectable> const& changedHandler) const
{
    return impl::make_event_revoker<D, ThumbnailUpdated_revoker>(this, ThumbnailUpdated(changedHandler));
}

template <typename D> void consume_Windows_Storage_BulkAccess_IStorageItemInformation<D>::ThumbnailUpdated(winrt::event_token const& eventCookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Storage::BulkAccess::IStorageItemInformation)->remove_ThumbnailUpdated(get_abi(eventCookie)));
}

template <typename D> winrt::event_token consume_Windows_Storage_BulkAccess_IStorageItemInformation<D>::PropertiesUpdated(Windows::Foundation::TypedEventHandler<Windows::Storage::BulkAccess::IStorageItemInformation, Windows::Foundation::IInspectable> const& changedHandler) const
{
    winrt::event_token eventCookie{};
    check_hresult(WINRT_SHIM(Windows::Storage::BulkAccess::IStorageItemInformation)->add_PropertiesUpdated(get_abi(changedHandler), put_abi(eventCookie)));
    return eventCookie;
}

template <typename D> typename consume_Windows_Storage_BulkAccess_IStorageItemInformation<D>::PropertiesUpdated_revoker consume_Windows_Storage_BulkAccess_IStorageItemInformation<D>::PropertiesUpdated(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Storage::BulkAccess::IStorageItemInformation, Windows::Foundation::IInspectable> const& changedHandler) const
{
    return impl::make_event_revoker<D, PropertiesUpdated_revoker>(this, PropertiesUpdated(changedHandler));
}

template <typename D> void consume_Windows_Storage_BulkAccess_IStorageItemInformation<D>::PropertiesUpdated(winrt::event_token const& eventCookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Storage::BulkAccess::IStorageItemInformation)->remove_PropertiesUpdated(get_abi(eventCookie)));
}

template <typename D>
struct produce<D, Windows::Storage::BulkAccess::IFileInformationFactory> : produce_base<D, Windows::Storage::BulkAccess::IFileInformationFactory>
{
    int32_t WINRT_CALL GetItemsAsync(uint32_t startIndex, uint32_t maxItemsToRetrieve, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetItemsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::BulkAccess::IStorageItemInformation>>), uint32_t, uint32_t);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::BulkAccess::IStorageItemInformation>>>(this->shim().GetItemsAsync(startIndex, maxItemsToRetrieve));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetItemsAsyncDefaultStartAndCount(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetItemsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::BulkAccess::IStorageItemInformation>>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::BulkAccess::IStorageItemInformation>>>(this->shim().GetItemsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetFilesAsync(uint32_t startIndex, uint32_t maxItemsToRetrieve, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetFilesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::BulkAccess::FileInformation>>), uint32_t, uint32_t);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::BulkAccess::FileInformation>>>(this->shim().GetFilesAsync(startIndex, maxItemsToRetrieve));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetFilesAsyncDefaultStartAndCount(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetFilesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::BulkAccess::FileInformation>>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::BulkAccess::FileInformation>>>(this->shim().GetFilesAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetFoldersAsync(uint32_t startIndex, uint32_t maxItemsToRetrieve, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetFoldersAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::BulkAccess::FolderInformation>>), uint32_t, uint32_t);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::BulkAccess::FolderInformation>>>(this->shim().GetFoldersAsync(startIndex, maxItemsToRetrieve));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetFoldersAsyncDefaultStartAndCount(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetFoldersAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::BulkAccess::FolderInformation>>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::BulkAccess::FolderInformation>>>(this->shim().GetFoldersAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetVirtualizedItemsVector(void** vector) noexcept final
    {
        try
        {
            *vector = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetVirtualizedItemsVector, WINRT_WRAP(Windows::Foundation::IInspectable));
            *vector = detach_from<Windows::Foundation::IInspectable>(this->shim().GetVirtualizedItemsVector());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetVirtualizedFilesVector(void** vector) noexcept final
    {
        try
        {
            *vector = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetVirtualizedFilesVector, WINRT_WRAP(Windows::Foundation::IInspectable));
            *vector = detach_from<Windows::Foundation::IInspectable>(this->shim().GetVirtualizedFilesVector());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetVirtualizedFoldersVector(void** vector) noexcept final
    {
        try
        {
            *vector = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetVirtualizedFoldersVector, WINRT_WRAP(Windows::Foundation::IInspectable));
            *vector = detach_from<Windows::Foundation::IInspectable>(this->shim().GetVirtualizedFoldersVector());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::BulkAccess::IFileInformationFactoryFactory> : produce_base<D, Windows::Storage::BulkAccess::IFileInformationFactoryFactory>
{
    int32_t WINRT_CALL CreateWithMode(void* queryResult, Windows::Storage::FileProperties::ThumbnailMode mode, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithMode, WINRT_WRAP(Windows::Storage::BulkAccess::FileInformationFactory), Windows::Storage::Search::IStorageQueryResultBase const&, Windows::Storage::FileProperties::ThumbnailMode const&);
            *value = detach_from<Windows::Storage::BulkAccess::FileInformationFactory>(this->shim().CreateWithMode(*reinterpret_cast<Windows::Storage::Search::IStorageQueryResultBase const*>(&queryResult), *reinterpret_cast<Windows::Storage::FileProperties::ThumbnailMode const*>(&mode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithModeAndSize(void* queryResult, Windows::Storage::FileProperties::ThumbnailMode mode, uint32_t requestedThumbnailSize, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithModeAndSize, WINRT_WRAP(Windows::Storage::BulkAccess::FileInformationFactory), Windows::Storage::Search::IStorageQueryResultBase const&, Windows::Storage::FileProperties::ThumbnailMode const&, uint32_t);
            *value = detach_from<Windows::Storage::BulkAccess::FileInformationFactory>(this->shim().CreateWithModeAndSize(*reinterpret_cast<Windows::Storage::Search::IStorageQueryResultBase const*>(&queryResult), *reinterpret_cast<Windows::Storage::FileProperties::ThumbnailMode const*>(&mode), requestedThumbnailSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithModeAndSizeAndOptions(void* queryResult, Windows::Storage::FileProperties::ThumbnailMode mode, uint32_t requestedThumbnailSize, Windows::Storage::FileProperties::ThumbnailOptions thumbnailOptions, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithModeAndSizeAndOptions, WINRT_WRAP(Windows::Storage::BulkAccess::FileInformationFactory), Windows::Storage::Search::IStorageQueryResultBase const&, Windows::Storage::FileProperties::ThumbnailMode const&, uint32_t, Windows::Storage::FileProperties::ThumbnailOptions const&);
            *value = detach_from<Windows::Storage::BulkAccess::FileInformationFactory>(this->shim().CreateWithModeAndSizeAndOptions(*reinterpret_cast<Windows::Storage::Search::IStorageQueryResultBase const*>(&queryResult), *reinterpret_cast<Windows::Storage::FileProperties::ThumbnailMode const*>(&mode), requestedThumbnailSize, *reinterpret_cast<Windows::Storage::FileProperties::ThumbnailOptions const*>(&thumbnailOptions)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithModeAndSizeAndOptionsAndFlags(void* queryResult, Windows::Storage::FileProperties::ThumbnailMode mode, uint32_t requestedThumbnailSize, Windows::Storage::FileProperties::ThumbnailOptions thumbnailOptions, bool delayLoad, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithModeAndSizeAndOptionsAndFlags, WINRT_WRAP(Windows::Storage::BulkAccess::FileInformationFactory), Windows::Storage::Search::IStorageQueryResultBase const&, Windows::Storage::FileProperties::ThumbnailMode const&, uint32_t, Windows::Storage::FileProperties::ThumbnailOptions const&, bool);
            *value = detach_from<Windows::Storage::BulkAccess::FileInformationFactory>(this->shim().CreateWithModeAndSizeAndOptionsAndFlags(*reinterpret_cast<Windows::Storage::Search::IStorageQueryResultBase const*>(&queryResult), *reinterpret_cast<Windows::Storage::FileProperties::ThumbnailMode const*>(&mode), requestedThumbnailSize, *reinterpret_cast<Windows::Storage::FileProperties::ThumbnailOptions const*>(&thumbnailOptions), delayLoad));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::BulkAccess::IStorageItemInformation> : produce_base<D, Windows::Storage::BulkAccess::IStorageItemInformation>
{
    int32_t WINRT_CALL get_MusicProperties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MusicProperties, WINRT_WRAP(Windows::Storage::FileProperties::MusicProperties));
            *value = detach_from<Windows::Storage::FileProperties::MusicProperties>(this->shim().MusicProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VideoProperties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoProperties, WINRT_WRAP(Windows::Storage::FileProperties::VideoProperties));
            *value = detach_from<Windows::Storage::FileProperties::VideoProperties>(this->shim().VideoProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ImageProperties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ImageProperties, WINRT_WRAP(Windows::Storage::FileProperties::ImageProperties));
            *value = detach_from<Windows::Storage::FileProperties::ImageProperties>(this->shim().ImageProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DocumentProperties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DocumentProperties, WINRT_WRAP(Windows::Storage::FileProperties::DocumentProperties));
            *value = detach_from<Windows::Storage::FileProperties::DocumentProperties>(this->shim().DocumentProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BasicProperties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BasicProperties, WINRT_WRAP(Windows::Storage::FileProperties::BasicProperties));
            *value = detach_from<Windows::Storage::FileProperties::BasicProperties>(this->shim().BasicProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Thumbnail(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Thumbnail, WINRT_WRAP(Windows::Storage::FileProperties::StorageItemThumbnail));
            *value = detach_from<Windows::Storage::FileProperties::StorageItemThumbnail>(this->shim().Thumbnail());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_ThumbnailUpdated(void* changedHandler, winrt::event_token* eventCookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ThumbnailUpdated, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Storage::BulkAccess::IStorageItemInformation, Windows::Foundation::IInspectable> const&);
            *eventCookie = detach_from<winrt::event_token>(this->shim().ThumbnailUpdated(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Storage::BulkAccess::IStorageItemInformation, Windows::Foundation::IInspectable> const*>(&changedHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ThumbnailUpdated(winrt::event_token eventCookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ThumbnailUpdated, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ThumbnailUpdated(*reinterpret_cast<winrt::event_token const*>(&eventCookie));
        return 0;
    }

    int32_t WINRT_CALL add_PropertiesUpdated(void* changedHandler, winrt::event_token* eventCookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PropertiesUpdated, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Storage::BulkAccess::IStorageItemInformation, Windows::Foundation::IInspectable> const&);
            *eventCookie = detach_from<winrt::event_token>(this->shim().PropertiesUpdated(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Storage::BulkAccess::IStorageItemInformation, Windows::Foundation::IInspectable> const*>(&changedHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PropertiesUpdated(winrt::event_token eventCookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PropertiesUpdated, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PropertiesUpdated(*reinterpret_cast<winrt::event_token const*>(&eventCookie));
        return 0;
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Storage::BulkAccess {

inline FileInformationFactory::FileInformationFactory(Windows::Storage::Search::IStorageQueryResultBase const& queryResult, Windows::Storage::FileProperties::ThumbnailMode const& mode) :
    FileInformationFactory(impl::call_factory<FileInformationFactory, Windows::Storage::BulkAccess::IFileInformationFactoryFactory>([&](auto&& f) { return f.CreateWithMode(queryResult, mode); }))
{}

inline FileInformationFactory::FileInformationFactory(Windows::Storage::Search::IStorageQueryResultBase const& queryResult, Windows::Storage::FileProperties::ThumbnailMode const& mode, uint32_t requestedThumbnailSize) :
    FileInformationFactory(impl::call_factory<FileInformationFactory, Windows::Storage::BulkAccess::IFileInformationFactoryFactory>([&](auto&& f) { return f.CreateWithModeAndSize(queryResult, mode, requestedThumbnailSize); }))
{}

inline FileInformationFactory::FileInformationFactory(Windows::Storage::Search::IStorageQueryResultBase const& queryResult, Windows::Storage::FileProperties::ThumbnailMode const& mode, uint32_t requestedThumbnailSize, Windows::Storage::FileProperties::ThumbnailOptions const& thumbnailOptions) :
    FileInformationFactory(impl::call_factory<FileInformationFactory, Windows::Storage::BulkAccess::IFileInformationFactoryFactory>([&](auto&& f) { return f.CreateWithModeAndSizeAndOptions(queryResult, mode, requestedThumbnailSize, thumbnailOptions); }))
{}

inline FileInformationFactory::FileInformationFactory(Windows::Storage::Search::IStorageQueryResultBase const& queryResult, Windows::Storage::FileProperties::ThumbnailMode const& mode, uint32_t requestedThumbnailSize, Windows::Storage::FileProperties::ThumbnailOptions const& thumbnailOptions, bool delayLoad) :
    FileInformationFactory(impl::call_factory<FileInformationFactory, Windows::Storage::BulkAccess::IFileInformationFactoryFactory>([&](auto&& f) { return f.CreateWithModeAndSizeAndOptionsAndFlags(queryResult, mode, requestedThumbnailSize, thumbnailOptions, delayLoad); }))
{}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Storage::BulkAccess::IFileInformationFactory> : winrt::impl::hash_base<winrt::Windows::Storage::BulkAccess::IFileInformationFactory> {};
template<> struct hash<winrt::Windows::Storage::BulkAccess::IFileInformationFactoryFactory> : winrt::impl::hash_base<winrt::Windows::Storage::BulkAccess::IFileInformationFactoryFactory> {};
template<> struct hash<winrt::Windows::Storage::BulkAccess::IStorageItemInformation> : winrt::impl::hash_base<winrt::Windows::Storage::BulkAccess::IStorageItemInformation> {};
template<> struct hash<winrt::Windows::Storage::BulkAccess::FileInformation> : winrt::impl::hash_base<winrt::Windows::Storage::BulkAccess::FileInformation> {};
template<> struct hash<winrt::Windows::Storage::BulkAccess::FileInformationFactory> : winrt::impl::hash_base<winrt::Windows::Storage::BulkAccess::FileInformationFactory> {};
template<> struct hash<winrt::Windows::Storage::BulkAccess::FolderInformation> : winrt::impl::hash_base<winrt::Windows::Storage::BulkAccess::FolderInformation> {};

}
