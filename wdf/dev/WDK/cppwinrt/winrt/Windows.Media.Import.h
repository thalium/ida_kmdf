// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Storage.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Media.Import.2.h"
#include "winrt/Windows.Media.h"

namespace winrt::impl {

template <typename D> Windows::Media::Import::PhotoImportSession consume_Windows_Media_Import_IPhotoImportDeleteImportedItemsFromSourceResult<D>::Session() const
{
    Windows::Media::Import::PhotoImportSession value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportDeleteImportedItemsFromSourceResult)->get_Session(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Media_Import_IPhotoImportDeleteImportedItemsFromSourceResult<D>::HasSucceeded() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportDeleteImportedItemsFromSourceResult)->get_HasSucceeded(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Media::Import::PhotoImportItem> consume_Windows_Media_Import_IPhotoImportDeleteImportedItemsFromSourceResult<D>::DeletedItems() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Media::Import::PhotoImportItem> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportDeleteImportedItemsFromSourceResult)->get_DeletedItems(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Import_IPhotoImportDeleteImportedItemsFromSourceResult<D>::PhotosCount() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportDeleteImportedItemsFromSourceResult)->get_PhotosCount(&value));
    return value;
}

template <typename D> uint64_t consume_Windows_Media_Import_IPhotoImportDeleteImportedItemsFromSourceResult<D>::PhotosSizeInBytes() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportDeleteImportedItemsFromSourceResult)->get_PhotosSizeInBytes(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Import_IPhotoImportDeleteImportedItemsFromSourceResult<D>::VideosCount() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportDeleteImportedItemsFromSourceResult)->get_VideosCount(&value));
    return value;
}

template <typename D> uint64_t consume_Windows_Media_Import_IPhotoImportDeleteImportedItemsFromSourceResult<D>::VideosSizeInBytes() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportDeleteImportedItemsFromSourceResult)->get_VideosSizeInBytes(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Import_IPhotoImportDeleteImportedItemsFromSourceResult<D>::SidecarsCount() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportDeleteImportedItemsFromSourceResult)->get_SidecarsCount(&value));
    return value;
}

template <typename D> uint64_t consume_Windows_Media_Import_IPhotoImportDeleteImportedItemsFromSourceResult<D>::SidecarsSizeInBytes() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportDeleteImportedItemsFromSourceResult)->get_SidecarsSizeInBytes(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Import_IPhotoImportDeleteImportedItemsFromSourceResult<D>::SiblingsCount() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportDeleteImportedItemsFromSourceResult)->get_SiblingsCount(&value));
    return value;
}

template <typename D> uint64_t consume_Windows_Media_Import_IPhotoImportDeleteImportedItemsFromSourceResult<D>::SiblingsSizeInBytes() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportDeleteImportedItemsFromSourceResult)->get_SiblingsSizeInBytes(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Import_IPhotoImportDeleteImportedItemsFromSourceResult<D>::TotalCount() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportDeleteImportedItemsFromSourceResult)->get_TotalCount(&value));
    return value;
}

template <typename D> uint64_t consume_Windows_Media_Import_IPhotoImportDeleteImportedItemsFromSourceResult<D>::TotalSizeInBytes() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportDeleteImportedItemsFromSourceResult)->get_TotalSizeInBytes(&value));
    return value;
}

template <typename D> Windows::Media::Import::PhotoImportSession consume_Windows_Media_Import_IPhotoImportFindItemsResult<D>::Session() const
{
    Windows::Media::Import::PhotoImportSession value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportFindItemsResult)->get_Session(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Media_Import_IPhotoImportFindItemsResult<D>::HasSucceeded() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportFindItemsResult)->get_HasSucceeded(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Media::Import::PhotoImportItem> consume_Windows_Media_Import_IPhotoImportFindItemsResult<D>::FoundItems() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Media::Import::PhotoImportItem> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportFindItemsResult)->get_FoundItems(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Import_IPhotoImportFindItemsResult<D>::PhotosCount() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportFindItemsResult)->get_PhotosCount(&value));
    return value;
}

template <typename D> uint64_t consume_Windows_Media_Import_IPhotoImportFindItemsResult<D>::PhotosSizeInBytes() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportFindItemsResult)->get_PhotosSizeInBytes(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Import_IPhotoImportFindItemsResult<D>::VideosCount() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportFindItemsResult)->get_VideosCount(&value));
    return value;
}

template <typename D> uint64_t consume_Windows_Media_Import_IPhotoImportFindItemsResult<D>::VideosSizeInBytes() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportFindItemsResult)->get_VideosSizeInBytes(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Import_IPhotoImportFindItemsResult<D>::SidecarsCount() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportFindItemsResult)->get_SidecarsCount(&value));
    return value;
}

template <typename D> uint64_t consume_Windows_Media_Import_IPhotoImportFindItemsResult<D>::SidecarsSizeInBytes() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportFindItemsResult)->get_SidecarsSizeInBytes(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Import_IPhotoImportFindItemsResult<D>::SiblingsCount() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportFindItemsResult)->get_SiblingsCount(&value));
    return value;
}

template <typename D> uint64_t consume_Windows_Media_Import_IPhotoImportFindItemsResult<D>::SiblingsSizeInBytes() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportFindItemsResult)->get_SiblingsSizeInBytes(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Import_IPhotoImportFindItemsResult<D>::TotalCount() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportFindItemsResult)->get_TotalCount(&value));
    return value;
}

template <typename D> uint64_t consume_Windows_Media_Import_IPhotoImportFindItemsResult<D>::TotalSizeInBytes() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportFindItemsResult)->get_TotalSizeInBytes(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Import_IPhotoImportFindItemsResult<D>::SelectAll() const
{
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportFindItemsResult)->SelectAll());
}

template <typename D> void consume_Windows_Media_Import_IPhotoImportFindItemsResult<D>::SelectNone() const
{
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportFindItemsResult)->SelectNone());
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_Import_IPhotoImportFindItemsResult<D>::SelectNewAsync() const
{
    Windows::Foundation::IAsyncAction action{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportFindItemsResult)->SelectNewAsync(put_abi(action)));
    return action;
}

template <typename D> void consume_Windows_Media_Import_IPhotoImportFindItemsResult<D>::SetImportMode(Windows::Media::Import::PhotoImportImportMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportFindItemsResult)->SetImportMode(get_abi(value)));
}

template <typename D> Windows::Media::Import::PhotoImportImportMode consume_Windows_Media_Import_IPhotoImportFindItemsResult<D>::ImportMode() const
{
    Windows::Media::Import::PhotoImportImportMode value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportFindItemsResult)->get_ImportMode(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Import_IPhotoImportFindItemsResult<D>::SelectedPhotosCount() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportFindItemsResult)->get_SelectedPhotosCount(&value));
    return value;
}

template <typename D> uint64_t consume_Windows_Media_Import_IPhotoImportFindItemsResult<D>::SelectedPhotosSizeInBytes() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportFindItemsResult)->get_SelectedPhotosSizeInBytes(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Import_IPhotoImportFindItemsResult<D>::SelectedVideosCount() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportFindItemsResult)->get_SelectedVideosCount(&value));
    return value;
}

template <typename D> uint64_t consume_Windows_Media_Import_IPhotoImportFindItemsResult<D>::SelectedVideosSizeInBytes() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportFindItemsResult)->get_SelectedVideosSizeInBytes(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Import_IPhotoImportFindItemsResult<D>::SelectedSidecarsCount() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportFindItemsResult)->get_SelectedSidecarsCount(&value));
    return value;
}

template <typename D> uint64_t consume_Windows_Media_Import_IPhotoImportFindItemsResult<D>::SelectedSidecarsSizeInBytes() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportFindItemsResult)->get_SelectedSidecarsSizeInBytes(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Import_IPhotoImportFindItemsResult<D>::SelectedSiblingsCount() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportFindItemsResult)->get_SelectedSiblingsCount(&value));
    return value;
}

template <typename D> uint64_t consume_Windows_Media_Import_IPhotoImportFindItemsResult<D>::SelectedSiblingsSizeInBytes() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportFindItemsResult)->get_SelectedSiblingsSizeInBytes(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Import_IPhotoImportFindItemsResult<D>::SelectedTotalCount() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportFindItemsResult)->get_SelectedTotalCount(&value));
    return value;
}

template <typename D> uint64_t consume_Windows_Media_Import_IPhotoImportFindItemsResult<D>::SelectedTotalSizeInBytes() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportFindItemsResult)->get_SelectedTotalSizeInBytes(&value));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Media_Import_IPhotoImportFindItemsResult<D>::SelectionChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Import::PhotoImportFindItemsResult, Windows::Media::Import::PhotoImportSelectionChangedEventArgs> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportFindItemsResult)->add_SelectionChanged(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Import_IPhotoImportFindItemsResult<D>::SelectionChanged_revoker consume_Windows_Media_Import_IPhotoImportFindItemsResult<D>::SelectionChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Import::PhotoImportFindItemsResult, Windows::Media::Import::PhotoImportSelectionChangedEventArgs> const& value) const
{
    return impl::make_event_revoker<D, SelectionChanged_revoker>(this, SelectionChanged(value));
}

template <typename D> void consume_Windows_Media_Import_IPhotoImportFindItemsResult<D>::SelectionChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Import::IPhotoImportFindItemsResult)->remove_SelectionChanged(get_abi(token)));
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Media::Import::PhotoImportImportItemsResult, Windows::Media::Import::PhotoImportProgress> consume_Windows_Media_Import_IPhotoImportFindItemsResult<D>::ImportItemsAsync() const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Media::Import::PhotoImportImportItemsResult, Windows::Media::Import::PhotoImportProgress> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportFindItemsResult)->ImportItemsAsync(put_abi(operation)));
    return operation;
}

template <typename D> winrt::event_token consume_Windows_Media_Import_IPhotoImportFindItemsResult<D>::ItemImported(Windows::Foundation::TypedEventHandler<Windows::Media::Import::PhotoImportFindItemsResult, Windows::Media::Import::PhotoImportItemImportedEventArgs> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportFindItemsResult)->add_ItemImported(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Import_IPhotoImportFindItemsResult<D>::ItemImported_revoker consume_Windows_Media_Import_IPhotoImportFindItemsResult<D>::ItemImported(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Import::PhotoImportFindItemsResult, Windows::Media::Import::PhotoImportItemImportedEventArgs> const& value) const
{
    return impl::make_event_revoker<D, ItemImported_revoker>(this, ItemImported(value));
}

template <typename D> void consume_Windows_Media_Import_IPhotoImportFindItemsResult<D>::ItemImported(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Import::IPhotoImportFindItemsResult)->remove_ItemImported(get_abi(token)));
}

template <typename D> void consume_Windows_Media_Import_IPhotoImportFindItemsResult2<D>::AddItemsInDateRangeToSelection(Windows::Foundation::DateTime const& rangeStart, Windows::Foundation::TimeSpan const& rangeLength) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportFindItemsResult2)->AddItemsInDateRangeToSelection(get_abi(rangeStart), get_abi(rangeLength)));
}

template <typename D> Windows::Media::Import::PhotoImportSession consume_Windows_Media_Import_IPhotoImportImportItemsResult<D>::Session() const
{
    Windows::Media::Import::PhotoImportSession value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportImportItemsResult)->get_Session(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Media_Import_IPhotoImportImportItemsResult<D>::HasSucceeded() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportImportItemsResult)->get_HasSucceeded(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Media::Import::PhotoImportItem> consume_Windows_Media_Import_IPhotoImportImportItemsResult<D>::ImportedItems() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Media::Import::PhotoImportItem> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportImportItemsResult)->get_ImportedItems(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Import_IPhotoImportImportItemsResult<D>::PhotosCount() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportImportItemsResult)->get_PhotosCount(&value));
    return value;
}

template <typename D> uint64_t consume_Windows_Media_Import_IPhotoImportImportItemsResult<D>::PhotosSizeInBytes() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportImportItemsResult)->get_PhotosSizeInBytes(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Import_IPhotoImportImportItemsResult<D>::VideosCount() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportImportItemsResult)->get_VideosCount(&value));
    return value;
}

template <typename D> uint64_t consume_Windows_Media_Import_IPhotoImportImportItemsResult<D>::VideosSizeInBytes() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportImportItemsResult)->get_VideosSizeInBytes(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Import_IPhotoImportImportItemsResult<D>::SidecarsCount() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportImportItemsResult)->get_SidecarsCount(&value));
    return value;
}

template <typename D> uint64_t consume_Windows_Media_Import_IPhotoImportImportItemsResult<D>::SidecarsSizeInBytes() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportImportItemsResult)->get_SidecarsSizeInBytes(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Import_IPhotoImportImportItemsResult<D>::SiblingsCount() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportImportItemsResult)->get_SiblingsCount(&value));
    return value;
}

template <typename D> uint64_t consume_Windows_Media_Import_IPhotoImportImportItemsResult<D>::SiblingsSizeInBytes() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportImportItemsResult)->get_SiblingsSizeInBytes(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Import_IPhotoImportImportItemsResult<D>::TotalCount() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportImportItemsResult)->get_TotalCount(&value));
    return value;
}

template <typename D> uint64_t consume_Windows_Media_Import_IPhotoImportImportItemsResult<D>::TotalSizeInBytes() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportImportItemsResult)->get_TotalSizeInBytes(&value));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Media::Import::PhotoImportDeleteImportedItemsFromSourceResult, double> consume_Windows_Media_Import_IPhotoImportImportItemsResult<D>::DeleteImportedItemsFromSourceAsync() const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Media::Import::PhotoImportDeleteImportedItemsFromSourceResult, double> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportImportItemsResult)->DeleteImportedItemsFromSourceAsync(put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Media_Import_IPhotoImportItem<D>::Name() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportItem)->get_Name(put_abi(value)));
    return value;
}

template <typename D> uint64_t consume_Windows_Media_Import_IPhotoImportItem<D>::ItemKey() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportItem)->get_ItemKey(&value));
    return value;
}

template <typename D> Windows::Media::Import::PhotoImportContentType consume_Windows_Media_Import_IPhotoImportItem<D>::ContentType() const
{
    Windows::Media::Import::PhotoImportContentType value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportItem)->get_ContentType(put_abi(value)));
    return value;
}

template <typename D> uint64_t consume_Windows_Media_Import_IPhotoImportItem<D>::SizeInBytes() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportItem)->get_SizeInBytes(&value));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_Media_Import_IPhotoImportItem<D>::Date() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportItem)->get_Date(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Import::PhotoImportSidecar consume_Windows_Media_Import_IPhotoImportItem<D>::Sibling() const
{
    Windows::Media::Import::PhotoImportSidecar value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportItem)->get_Sibling(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Media::Import::PhotoImportSidecar> consume_Windows_Media_Import_IPhotoImportItem<D>::Sidecars() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Media::Import::PhotoImportSidecar> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportItem)->get_Sidecars(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Media::Import::PhotoImportVideoSegment> consume_Windows_Media_Import_IPhotoImportItem<D>::VideoSegments() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Media::Import::PhotoImportVideoSegment> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportItem)->get_VideoSegments(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Media_Import_IPhotoImportItem<D>::IsSelected() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportItem)->get_IsSelected(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Import_IPhotoImportItem<D>::IsSelected(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportItem)->put_IsSelected(value));
}

template <typename D> Windows::Storage::Streams::IRandomAccessStreamReference consume_Windows_Media_Import_IPhotoImportItem<D>::Thumbnail() const
{
    Windows::Storage::Streams::IRandomAccessStreamReference value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportItem)->get_Thumbnail(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<hstring> consume_Windows_Media_Import_IPhotoImportItem<D>::ImportedFileNames() const
{
    Windows::Foundation::Collections::IVectorView<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportItem)->get_ImportedFileNames(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<hstring> consume_Windows_Media_Import_IPhotoImportItem<D>::DeletedFileNames() const
{
    Windows::Foundation::Collections::IVectorView<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportItem)->get_DeletedFileNames(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Import_IPhotoImportItem2<D>::Path() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportItem2)->get_Path(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Import::PhotoImportItem consume_Windows_Media_Import_IPhotoImportItemImportedEventArgs<D>::ImportedItem() const
{
    Windows::Media::Import::PhotoImportItem value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportItemImportedEventArgs)->get_ImportedItem(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Media_Import_IPhotoImportManagerStatics<D>::IsSupportedAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportManagerStatics)->IsSupportedAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Media::Import::PhotoImportSource>> consume_Windows_Media_Import_IPhotoImportManagerStatics<D>::FindAllSourcesAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Media::Import::PhotoImportSource>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportManagerStatics)->FindAllSourcesAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Media::Import::PhotoImportOperation> consume_Windows_Media_Import_IPhotoImportManagerStatics<D>::GetPendingOperations() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Media::Import::PhotoImportOperation> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportManagerStatics)->GetPendingOperations(put_abi(result)));
    return result;
}

template <typename D> Windows::Media::Import::PhotoImportStage consume_Windows_Media_Import_IPhotoImportOperation<D>::Stage() const
{
    Windows::Media::Import::PhotoImportStage value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportOperation)->get_Stage(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Import::PhotoImportSession consume_Windows_Media_Import_IPhotoImportOperation<D>::Session() const
{
    Windows::Media::Import::PhotoImportSession value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportOperation)->get_Session(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Media::Import::PhotoImportFindItemsResult, uint32_t> consume_Windows_Media_Import_IPhotoImportOperation<D>::ContinueFindingItemsAsync() const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Media::Import::PhotoImportFindItemsResult, uint32_t> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportOperation)->get_ContinueFindingItemsAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Media::Import::PhotoImportImportItemsResult, Windows::Media::Import::PhotoImportProgress> consume_Windows_Media_Import_IPhotoImportOperation<D>::ContinueImportingItemsAsync() const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Media::Import::PhotoImportImportItemsResult, Windows::Media::Import::PhotoImportProgress> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportOperation)->get_ContinueImportingItemsAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Media::Import::PhotoImportDeleteImportedItemsFromSourceResult, double> consume_Windows_Media_Import_IPhotoImportOperation<D>::ContinueDeletingImportedItemsFromSourceAsync() const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Media::Import::PhotoImportDeleteImportedItemsFromSourceResult, double> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportOperation)->get_ContinueDeletingImportedItemsFromSourceAsync(put_abi(operation)));
    return operation;
}

template <typename D> bool consume_Windows_Media_Import_IPhotoImportSelectionChangedEventArgs<D>::IsSelectionEmpty() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportSelectionChangedEventArgs)->get_IsSelectionEmpty(&value));
    return value;
}

template <typename D> Windows::Media::Import::PhotoImportSource consume_Windows_Media_Import_IPhotoImportSession<D>::Source() const
{
    Windows::Media::Import::PhotoImportSource value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportSession)->get_Source(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Media_Import_IPhotoImportSession<D>::SessionId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportSession)->get_SessionId(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Import_IPhotoImportSession<D>::DestinationFolder(Windows::Storage::IStorageFolder const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportSession)->put_DestinationFolder(get_abi(value)));
}

template <typename D> Windows::Storage::IStorageFolder consume_Windows_Media_Import_IPhotoImportSession<D>::DestinationFolder() const
{
    Windows::Storage::IStorageFolder value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportSession)->get_DestinationFolder(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Import_IPhotoImportSession<D>::AppendSessionDateToDestinationFolder(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportSession)->put_AppendSessionDateToDestinationFolder(value));
}

template <typename D> bool consume_Windows_Media_Import_IPhotoImportSession<D>::AppendSessionDateToDestinationFolder() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportSession)->get_AppendSessionDateToDestinationFolder(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Import_IPhotoImportSession<D>::SubfolderCreationMode(Windows::Media::Import::PhotoImportSubfolderCreationMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportSession)->put_SubfolderCreationMode(get_abi(value)));
}

template <typename D> Windows::Media::Import::PhotoImportSubfolderCreationMode consume_Windows_Media_Import_IPhotoImportSession<D>::SubfolderCreationMode() const
{
    Windows::Media::Import::PhotoImportSubfolderCreationMode value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportSession)->get_SubfolderCreationMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Import_IPhotoImportSession<D>::DestinationFileNamePrefix(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportSession)->put_DestinationFileNamePrefix(get_abi(value)));
}

template <typename D> hstring consume_Windows_Media_Import_IPhotoImportSession<D>::DestinationFileNamePrefix() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportSession)->get_DestinationFileNamePrefix(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Media::Import::PhotoImportFindItemsResult, uint32_t> consume_Windows_Media_Import_IPhotoImportSession<D>::FindItemsAsync(Windows::Media::Import::PhotoImportContentTypeFilter const& contentTypeFilter, Windows::Media::Import::PhotoImportItemSelectionMode const& itemSelectionMode) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Media::Import::PhotoImportFindItemsResult, uint32_t> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportSession)->FindItemsAsync(get_abi(contentTypeFilter), get_abi(itemSelectionMode), put_abi(operation)));
    return operation;
}

template <typename D> void consume_Windows_Media_Import_IPhotoImportSession2<D>::SubfolderDateFormat(Windows::Media::Import::PhotoImportSubfolderDateFormat const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportSession2)->put_SubfolderDateFormat(get_abi(value)));
}

template <typename D> Windows::Media::Import::PhotoImportSubfolderDateFormat consume_Windows_Media_Import_IPhotoImportSession2<D>::SubfolderDateFormat() const
{
    Windows::Media::Import::PhotoImportSubfolderDateFormat value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportSession2)->get_SubfolderDateFormat(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Import_IPhotoImportSession2<D>::RememberDeselectedItems(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportSession2)->put_RememberDeselectedItems(value));
}

template <typename D> bool consume_Windows_Media_Import_IPhotoImportSession2<D>::RememberDeselectedItems() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportSession2)->get_RememberDeselectedItems(&value));
    return value;
}

template <typename D> hstring consume_Windows_Media_Import_IPhotoImportSidecar<D>::Name() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportSidecar)->get_Name(put_abi(value)));
    return value;
}

template <typename D> uint64_t consume_Windows_Media_Import_IPhotoImportSidecar<D>::SizeInBytes() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportSidecar)->get_SizeInBytes(&value));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_Media_Import_IPhotoImportSidecar<D>::Date() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportSidecar)->get_Date(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Import_IPhotoImportSource<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportSource)->get_Id(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Import_IPhotoImportSource<D>::DisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportSource)->get_DisplayName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Import_IPhotoImportSource<D>::Description() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportSource)->get_Description(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Import_IPhotoImportSource<D>::Manufacturer() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportSource)->get_Manufacturer(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Import_IPhotoImportSource<D>::Model() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportSource)->get_Model(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Import_IPhotoImportSource<D>::SerialNumber() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportSource)->get_SerialNumber(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Import_IPhotoImportSource<D>::ConnectionProtocol() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportSource)->get_ConnectionProtocol(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Import::PhotoImportConnectionTransport consume_Windows_Media_Import_IPhotoImportSource<D>::ConnectionTransport() const
{
    Windows::Media::Import::PhotoImportConnectionTransport value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportSource)->get_ConnectionTransport(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Import::PhotoImportSourceType consume_Windows_Media_Import_IPhotoImportSource<D>::Type() const
{
    Windows::Media::Import::PhotoImportSourceType value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportSource)->get_Type(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Import::PhotoImportPowerSource consume_Windows_Media_Import_IPhotoImportSource<D>::PowerSource() const
{
    Windows::Media::Import::PhotoImportPowerSource value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportSource)->get_PowerSource(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<uint32_t> consume_Windows_Media_Import_IPhotoImportSource<D>::BatteryLevelPercent() const
{
    Windows::Foundation::IReference<uint32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportSource)->get_BatteryLevelPercent(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::DateTime> consume_Windows_Media_Import_IPhotoImportSource<D>::DateTime() const
{
    Windows::Foundation::IReference<Windows::Foundation::DateTime> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportSource)->get_DateTime(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Media::Import::PhotoImportStorageMedium> consume_Windows_Media_Import_IPhotoImportSource<D>::StorageMedia() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Media::Import::PhotoImportStorageMedium> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportSource)->get_StorageMedia(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<bool> consume_Windows_Media_Import_IPhotoImportSource<D>::IsLocked() const
{
    Windows::Foundation::IReference<bool> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportSource)->get_IsLocked(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Media_Import_IPhotoImportSource<D>::IsMassStorage() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportSource)->get_IsMassStorage(&value));
    return value;
}

template <typename D> Windows::Storage::Streams::IRandomAccessStreamReference consume_Windows_Media_Import_IPhotoImportSource<D>::Thumbnail() const
{
    Windows::Storage::Streams::IRandomAccessStreamReference value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportSource)->get_Thumbnail(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Import::PhotoImportSession consume_Windows_Media_Import_IPhotoImportSource<D>::CreateImportSession() const
{
    Windows::Media::Import::PhotoImportSession result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportSource)->CreateImportSession(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::Import::PhotoImportSource> consume_Windows_Media_Import_IPhotoImportSourceStatics<D>::FromIdAsync(param::hstring const& sourceId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::Import::PhotoImportSource> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportSourceStatics)->FromIdAsync(get_abi(sourceId), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::Import::PhotoImportSource> consume_Windows_Media_Import_IPhotoImportSourceStatics<D>::FromFolderAsync(Windows::Storage::IStorageFolder const& sourceRootFolder) const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::Import::PhotoImportSource> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportSourceStatics)->FromFolderAsync(get_abi(sourceRootFolder), put_abi(operation)));
    return operation;
}

template <typename D> hstring consume_Windows_Media_Import_IPhotoImportStorageMedium<D>::Name() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportStorageMedium)->get_Name(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Import_IPhotoImportStorageMedium<D>::Description() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportStorageMedium)->get_Description(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Import_IPhotoImportStorageMedium<D>::SerialNumber() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportStorageMedium)->get_SerialNumber(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Import::PhotoImportStorageMediumType consume_Windows_Media_Import_IPhotoImportStorageMedium<D>::StorageMediumType() const
{
    Windows::Media::Import::PhotoImportStorageMediumType value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportStorageMedium)->get_StorageMediumType(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Import::PhotoImportAccessMode consume_Windows_Media_Import_IPhotoImportStorageMedium<D>::SupportedAccessMode() const
{
    Windows::Media::Import::PhotoImportAccessMode value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportStorageMedium)->get_SupportedAccessMode(put_abi(value)));
    return value;
}

template <typename D> uint64_t consume_Windows_Media_Import_IPhotoImportStorageMedium<D>::CapacityInBytes() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportStorageMedium)->get_CapacityInBytes(&value));
    return value;
}

template <typename D> uint64_t consume_Windows_Media_Import_IPhotoImportStorageMedium<D>::AvailableSpaceInBytes() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportStorageMedium)->get_AvailableSpaceInBytes(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Import_IPhotoImportStorageMedium<D>::Refresh() const
{
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportStorageMedium)->Refresh());
}

template <typename D> hstring consume_Windows_Media_Import_IPhotoImportVideoSegment<D>::Name() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportVideoSegment)->get_Name(put_abi(value)));
    return value;
}

template <typename D> uint64_t consume_Windows_Media_Import_IPhotoImportVideoSegment<D>::SizeInBytes() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportVideoSegment)->get_SizeInBytes(&value));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_Media_Import_IPhotoImportVideoSegment<D>::Date() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportVideoSegment)->get_Date(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Import::PhotoImportSidecar consume_Windows_Media_Import_IPhotoImportVideoSegment<D>::Sibling() const
{
    Windows::Media::Import::PhotoImportSidecar value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportVideoSegment)->get_Sibling(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Media::Import::PhotoImportSidecar> consume_Windows_Media_Import_IPhotoImportVideoSegment<D>::Sidecars() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Media::Import::PhotoImportSidecar> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Import::IPhotoImportVideoSegment)->get_Sidecars(put_abi(value)));
    return value;
}

template <typename D>
struct produce<D, Windows::Media::Import::IPhotoImportDeleteImportedItemsFromSourceResult> : produce_base<D, Windows::Media::Import::IPhotoImportDeleteImportedItemsFromSourceResult>
{
    int32_t WINRT_CALL get_Session(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Session, WINRT_WRAP(Windows::Media::Import::PhotoImportSession));
            *value = detach_from<Windows::Media::Import::PhotoImportSession>(this->shim().Session());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HasSucceeded(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HasSucceeded, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().HasSucceeded());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DeletedItems(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeletedItems, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Media::Import::PhotoImportItem>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Media::Import::PhotoImportItem>>(this->shim().DeletedItems());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PhotosCount(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PhotosCount, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().PhotosCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PhotosSizeInBytes(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PhotosSizeInBytes, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().PhotosSizeInBytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VideosCount(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideosCount, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().VideosCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VideosSizeInBytes(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideosSizeInBytes, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().VideosSizeInBytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SidecarsCount(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SidecarsCount, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().SidecarsCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SidecarsSizeInBytes(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SidecarsSizeInBytes, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().SidecarsSizeInBytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SiblingsCount(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SiblingsCount, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().SiblingsCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SiblingsSizeInBytes(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SiblingsSizeInBytes, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().SiblingsSizeInBytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TotalCount(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TotalCount, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().TotalCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TotalSizeInBytes(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TotalSizeInBytes, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().TotalSizeInBytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Import::IPhotoImportFindItemsResult> : produce_base<D, Windows::Media::Import::IPhotoImportFindItemsResult>
{
    int32_t WINRT_CALL get_Session(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Session, WINRT_WRAP(Windows::Media::Import::PhotoImportSession));
            *value = detach_from<Windows::Media::Import::PhotoImportSession>(this->shim().Session());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HasSucceeded(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HasSucceeded, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().HasSucceeded());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FoundItems(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FoundItems, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Media::Import::PhotoImportItem>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Media::Import::PhotoImportItem>>(this->shim().FoundItems());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PhotosCount(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PhotosCount, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().PhotosCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PhotosSizeInBytes(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PhotosSizeInBytes, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().PhotosSizeInBytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VideosCount(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideosCount, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().VideosCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VideosSizeInBytes(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideosSizeInBytes, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().VideosSizeInBytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SidecarsCount(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SidecarsCount, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().SidecarsCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SidecarsSizeInBytes(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SidecarsSizeInBytes, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().SidecarsSizeInBytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SiblingsCount(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SiblingsCount, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().SiblingsCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SiblingsSizeInBytes(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SiblingsSizeInBytes, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().SiblingsSizeInBytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TotalCount(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TotalCount, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().TotalCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TotalSizeInBytes(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TotalSizeInBytes, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().TotalSizeInBytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SelectAll() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectAll, WINRT_WRAP(void));
            this->shim().SelectAll();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SelectNone() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectNone, WINRT_WRAP(void));
            this->shim().SelectNone();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SelectNewAsync(void** action) noexcept final
    {
        try
        {
            *action = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectNewAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *action = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SelectNewAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetImportMode(Windows::Media::Import::PhotoImportImportMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetImportMode, WINRT_WRAP(void), Windows::Media::Import::PhotoImportImportMode const&);
            this->shim().SetImportMode(*reinterpret_cast<Windows::Media::Import::PhotoImportImportMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ImportMode(Windows::Media::Import::PhotoImportImportMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ImportMode, WINRT_WRAP(Windows::Media::Import::PhotoImportImportMode));
            *value = detach_from<Windows::Media::Import::PhotoImportImportMode>(this->shim().ImportMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SelectedPhotosCount(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedPhotosCount, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().SelectedPhotosCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SelectedPhotosSizeInBytes(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedPhotosSizeInBytes, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().SelectedPhotosSizeInBytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SelectedVideosCount(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedVideosCount, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().SelectedVideosCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SelectedVideosSizeInBytes(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedVideosSizeInBytes, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().SelectedVideosSizeInBytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SelectedSidecarsCount(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedSidecarsCount, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().SelectedSidecarsCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SelectedSidecarsSizeInBytes(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedSidecarsSizeInBytes, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().SelectedSidecarsSizeInBytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SelectedSiblingsCount(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedSiblingsCount, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().SelectedSiblingsCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SelectedSiblingsSizeInBytes(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedSiblingsSizeInBytes, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().SelectedSiblingsSizeInBytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SelectedTotalCount(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedTotalCount, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().SelectedTotalCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SelectedTotalSizeInBytes(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedTotalSizeInBytes, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().SelectedTotalSizeInBytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_SelectionChanged(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectionChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Import::PhotoImportFindItemsResult, Windows::Media::Import::PhotoImportSelectionChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().SelectionChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Import::PhotoImportFindItemsResult, Windows::Media::Import::PhotoImportSelectionChangedEventArgs> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_SelectionChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(SelectionChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().SelectionChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL ImportItemsAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ImportItemsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Media::Import::PhotoImportImportItemsResult, Windows::Media::Import::PhotoImportProgress>));
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Media::Import::PhotoImportImportItemsResult, Windows::Media::Import::PhotoImportProgress>>(this->shim().ImportItemsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_ItemImported(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ItemImported, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Import::PhotoImportFindItemsResult, Windows::Media::Import::PhotoImportItemImportedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ItemImported(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Import::PhotoImportFindItemsResult, Windows::Media::Import::PhotoImportItemImportedEventArgs> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ItemImported(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ItemImported, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ItemImported(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Media::Import::IPhotoImportFindItemsResult2> : produce_base<D, Windows::Media::Import::IPhotoImportFindItemsResult2>
{
    int32_t WINRT_CALL AddItemsInDateRangeToSelection(Windows::Foundation::DateTime rangeStart, Windows::Foundation::TimeSpan rangeLength) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddItemsInDateRangeToSelection, WINRT_WRAP(void), Windows::Foundation::DateTime const&, Windows::Foundation::TimeSpan const&);
            this->shim().AddItemsInDateRangeToSelection(*reinterpret_cast<Windows::Foundation::DateTime const*>(&rangeStart), *reinterpret_cast<Windows::Foundation::TimeSpan const*>(&rangeLength));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Import::IPhotoImportImportItemsResult> : produce_base<D, Windows::Media::Import::IPhotoImportImportItemsResult>
{
    int32_t WINRT_CALL get_Session(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Session, WINRT_WRAP(Windows::Media::Import::PhotoImportSession));
            *value = detach_from<Windows::Media::Import::PhotoImportSession>(this->shim().Session());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HasSucceeded(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HasSucceeded, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().HasSucceeded());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ImportedItems(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ImportedItems, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Media::Import::PhotoImportItem>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Media::Import::PhotoImportItem>>(this->shim().ImportedItems());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PhotosCount(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PhotosCount, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().PhotosCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PhotosSizeInBytes(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PhotosSizeInBytes, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().PhotosSizeInBytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VideosCount(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideosCount, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().VideosCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VideosSizeInBytes(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideosSizeInBytes, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().VideosSizeInBytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SidecarsCount(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SidecarsCount, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().SidecarsCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SidecarsSizeInBytes(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SidecarsSizeInBytes, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().SidecarsSizeInBytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SiblingsCount(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SiblingsCount, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().SiblingsCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SiblingsSizeInBytes(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SiblingsSizeInBytes, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().SiblingsSizeInBytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TotalCount(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TotalCount, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().TotalCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TotalSizeInBytes(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TotalSizeInBytes, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().TotalSizeInBytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DeleteImportedItemsFromSourceAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeleteImportedItemsFromSourceAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Media::Import::PhotoImportDeleteImportedItemsFromSourceResult, double>));
            *result = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Media::Import::PhotoImportDeleteImportedItemsFromSourceResult, double>>(this->shim().DeleteImportedItemsFromSourceAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Import::IPhotoImportItem> : produce_base<D, Windows::Media::Import::IPhotoImportItem>
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

    int32_t WINRT_CALL get_ItemKey(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ItemKey, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().ItemKey());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ContentType(Windows::Media::Import::PhotoImportContentType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentType, WINRT_WRAP(Windows::Media::Import::PhotoImportContentType));
            *value = detach_from<Windows::Media::Import::PhotoImportContentType>(this->shim().ContentType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SizeInBytes(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SizeInBytes, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().SizeInBytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Date(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Date, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().Date());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Sibling(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Sibling, WINRT_WRAP(Windows::Media::Import::PhotoImportSidecar));
            *value = detach_from<Windows::Media::Import::PhotoImportSidecar>(this->shim().Sibling());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Sidecars(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Sidecars, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Media::Import::PhotoImportSidecar>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Media::Import::PhotoImportSidecar>>(this->shim().Sidecars());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VideoSegments(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoSegments, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Media::Import::PhotoImportVideoSegment>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Media::Import::PhotoImportVideoSegment>>(this->shim().VideoSegments());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsSelected(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSelected, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsSelected());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsSelected(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSelected, WINRT_WRAP(void), bool);
            this->shim().IsSelected(value);
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
            WINRT_ASSERT_DECLARATION(Thumbnail, WINRT_WRAP(Windows::Storage::Streams::IRandomAccessStreamReference));
            *value = detach_from<Windows::Storage::Streams::IRandomAccessStreamReference>(this->shim().Thumbnail());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ImportedFileNames(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ImportedFileNames, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().ImportedFileNames());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DeletedFileNames(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeletedFileNames, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().DeletedFileNames());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Import::IPhotoImportItem2> : produce_base<D, Windows::Media::Import::IPhotoImportItem2>
{
    int32_t WINRT_CALL get_Path(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Path, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Path());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Import::IPhotoImportItemImportedEventArgs> : produce_base<D, Windows::Media::Import::IPhotoImportItemImportedEventArgs>
{
    int32_t WINRT_CALL get_ImportedItem(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ImportedItem, WINRT_WRAP(Windows::Media::Import::PhotoImportItem));
            *value = detach_from<Windows::Media::Import::PhotoImportItem>(this->shim().ImportedItem());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Import::IPhotoImportManagerStatics> : produce_base<D, Windows::Media::Import::IPhotoImportManagerStatics>
{
    int32_t WINRT_CALL IsSupportedAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSupportedAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().IsSupportedAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindAllSourcesAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindAllSourcesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Media::Import::PhotoImportSource>>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Media::Import::PhotoImportSource>>>(this->shim().FindAllSourcesAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetPendingOperations(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetPendingOperations, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Media::Import::PhotoImportOperation>));
            *result = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Media::Import::PhotoImportOperation>>(this->shim().GetPendingOperations());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Import::IPhotoImportOperation> : produce_base<D, Windows::Media::Import::IPhotoImportOperation>
{
    int32_t WINRT_CALL get_Stage(Windows::Media::Import::PhotoImportStage* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Stage, WINRT_WRAP(Windows::Media::Import::PhotoImportStage));
            *value = detach_from<Windows::Media::Import::PhotoImportStage>(this->shim().Stage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Session(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Session, WINRT_WRAP(Windows::Media::Import::PhotoImportSession));
            *value = detach_from<Windows::Media::Import::PhotoImportSession>(this->shim().Session());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ContinueFindingItemsAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContinueFindingItemsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Media::Import::PhotoImportFindItemsResult, uint32_t>));
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Media::Import::PhotoImportFindItemsResult, uint32_t>>(this->shim().ContinueFindingItemsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ContinueImportingItemsAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContinueImportingItemsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Media::Import::PhotoImportImportItemsResult, Windows::Media::Import::PhotoImportProgress>));
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Media::Import::PhotoImportImportItemsResult, Windows::Media::Import::PhotoImportProgress>>(this->shim().ContinueImportingItemsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ContinueDeletingImportedItemsFromSourceAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContinueDeletingImportedItemsFromSourceAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Media::Import::PhotoImportDeleteImportedItemsFromSourceResult, double>));
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Media::Import::PhotoImportDeleteImportedItemsFromSourceResult, double>>(this->shim().ContinueDeletingImportedItemsFromSourceAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Import::IPhotoImportSelectionChangedEventArgs> : produce_base<D, Windows::Media::Import::IPhotoImportSelectionChangedEventArgs>
{
    int32_t WINRT_CALL get_IsSelectionEmpty(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSelectionEmpty, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsSelectionEmpty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Import::IPhotoImportSession> : produce_base<D, Windows::Media::Import::IPhotoImportSession>
{
    int32_t WINRT_CALL get_Source(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Source, WINRT_WRAP(Windows::Media::Import::PhotoImportSource));
            *value = detach_from<Windows::Media::Import::PhotoImportSource>(this->shim().Source());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SessionId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SessionId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().SessionId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DestinationFolder(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DestinationFolder, WINRT_WRAP(void), Windows::Storage::IStorageFolder const&);
            this->shim().DestinationFolder(*reinterpret_cast<Windows::Storage::IStorageFolder const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DestinationFolder(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DestinationFolder, WINRT_WRAP(Windows::Storage::IStorageFolder));
            *value = detach_from<Windows::Storage::IStorageFolder>(this->shim().DestinationFolder());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AppendSessionDateToDestinationFolder(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppendSessionDateToDestinationFolder, WINRT_WRAP(void), bool);
            this->shim().AppendSessionDateToDestinationFolder(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AppendSessionDateToDestinationFolder(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppendSessionDateToDestinationFolder, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AppendSessionDateToDestinationFolder());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SubfolderCreationMode(Windows::Media::Import::PhotoImportSubfolderCreationMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SubfolderCreationMode, WINRT_WRAP(void), Windows::Media::Import::PhotoImportSubfolderCreationMode const&);
            this->shim().SubfolderCreationMode(*reinterpret_cast<Windows::Media::Import::PhotoImportSubfolderCreationMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SubfolderCreationMode(Windows::Media::Import::PhotoImportSubfolderCreationMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SubfolderCreationMode, WINRT_WRAP(Windows::Media::Import::PhotoImportSubfolderCreationMode));
            *value = detach_from<Windows::Media::Import::PhotoImportSubfolderCreationMode>(this->shim().SubfolderCreationMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DestinationFileNamePrefix(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DestinationFileNamePrefix, WINRT_WRAP(void), hstring const&);
            this->shim().DestinationFileNamePrefix(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DestinationFileNamePrefix(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DestinationFileNamePrefix, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DestinationFileNamePrefix());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindItemsAsync(Windows::Media::Import::PhotoImportContentTypeFilter contentTypeFilter, Windows::Media::Import::PhotoImportItemSelectionMode itemSelectionMode, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindItemsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Media::Import::PhotoImportFindItemsResult, uint32_t>), Windows::Media::Import::PhotoImportContentTypeFilter const, Windows::Media::Import::PhotoImportItemSelectionMode const);
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Media::Import::PhotoImportFindItemsResult, uint32_t>>(this->shim().FindItemsAsync(*reinterpret_cast<Windows::Media::Import::PhotoImportContentTypeFilter const*>(&contentTypeFilter), *reinterpret_cast<Windows::Media::Import::PhotoImportItemSelectionMode const*>(&itemSelectionMode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Import::IPhotoImportSession2> : produce_base<D, Windows::Media::Import::IPhotoImportSession2>
{
    int32_t WINRT_CALL put_SubfolderDateFormat(Windows::Media::Import::PhotoImportSubfolderDateFormat value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SubfolderDateFormat, WINRT_WRAP(void), Windows::Media::Import::PhotoImportSubfolderDateFormat const&);
            this->shim().SubfolderDateFormat(*reinterpret_cast<Windows::Media::Import::PhotoImportSubfolderDateFormat const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SubfolderDateFormat(Windows::Media::Import::PhotoImportSubfolderDateFormat* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SubfolderDateFormat, WINRT_WRAP(Windows::Media::Import::PhotoImportSubfolderDateFormat));
            *value = detach_from<Windows::Media::Import::PhotoImportSubfolderDateFormat>(this->shim().SubfolderDateFormat());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RememberDeselectedItems(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RememberDeselectedItems, WINRT_WRAP(void), bool);
            this->shim().RememberDeselectedItems(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RememberDeselectedItems(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RememberDeselectedItems, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().RememberDeselectedItems());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Import::IPhotoImportSidecar> : produce_base<D, Windows::Media::Import::IPhotoImportSidecar>
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

    int32_t WINRT_CALL get_SizeInBytes(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SizeInBytes, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().SizeInBytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Date(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Date, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().Date());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Import::IPhotoImportSource> : produce_base<D, Windows::Media::Import::IPhotoImportSource>
{
    int32_t WINRT_CALL get_Id(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Id, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DisplayName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DisplayName());
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

    int32_t WINRT_CALL get_Manufacturer(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Manufacturer, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Manufacturer());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Model(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Model, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Model());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SerialNumber(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SerialNumber, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SerialNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ConnectionProtocol(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConnectionProtocol, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ConnectionProtocol());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ConnectionTransport(Windows::Media::Import::PhotoImportConnectionTransport* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConnectionTransport, WINRT_WRAP(Windows::Media::Import::PhotoImportConnectionTransport));
            *value = detach_from<Windows::Media::Import::PhotoImportConnectionTransport>(this->shim().ConnectionTransport());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Type(Windows::Media::Import::PhotoImportSourceType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Type, WINRT_WRAP(Windows::Media::Import::PhotoImportSourceType));
            *value = detach_from<Windows::Media::Import::PhotoImportSourceType>(this->shim().Type());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PowerSource(Windows::Media::Import::PhotoImportPowerSource* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PowerSource, WINRT_WRAP(Windows::Media::Import::PhotoImportPowerSource));
            *value = detach_from<Windows::Media::Import::PhotoImportPowerSource>(this->shim().PowerSource());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BatteryLevelPercent(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BatteryLevelPercent, WINRT_WRAP(Windows::Foundation::IReference<uint32_t>));
            *value = detach_from<Windows::Foundation::IReference<uint32_t>>(this->shim().BatteryLevelPercent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DateTime(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DateTime, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::DateTime>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::DateTime>>(this->shim().DateTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StorageMedia(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StorageMedia, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Media::Import::PhotoImportStorageMedium>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Media::Import::PhotoImportStorageMedium>>(this->shim().StorageMedia());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsLocked(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsLocked, WINRT_WRAP(Windows::Foundation::IReference<bool>));
            *value = detach_from<Windows::Foundation::IReference<bool>>(this->shim().IsLocked());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsMassStorage(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsMassStorage, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsMassStorage());
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
            WINRT_ASSERT_DECLARATION(Thumbnail, WINRT_WRAP(Windows::Storage::Streams::IRandomAccessStreamReference));
            *value = detach_from<Windows::Storage::Streams::IRandomAccessStreamReference>(this->shim().Thumbnail());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateImportSession(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateImportSession, WINRT_WRAP(Windows::Media::Import::PhotoImportSession));
            *result = detach_from<Windows::Media::Import::PhotoImportSession>(this->shim().CreateImportSession());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Import::IPhotoImportSourceStatics> : produce_base<D, Windows::Media::Import::IPhotoImportSourceStatics>
{
    int32_t WINRT_CALL FromIdAsync(void* sourceId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::Import::PhotoImportSource>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::Import::PhotoImportSource>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&sourceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FromFolderAsync(void* sourceRootFolder, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromFolderAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::Import::PhotoImportSource>), Windows::Storage::IStorageFolder const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::Import::PhotoImportSource>>(this->shim().FromFolderAsync(*reinterpret_cast<Windows::Storage::IStorageFolder const*>(&sourceRootFolder)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Import::IPhotoImportStorageMedium> : produce_base<D, Windows::Media::Import::IPhotoImportStorageMedium>
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

    int32_t WINRT_CALL get_SerialNumber(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SerialNumber, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SerialNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StorageMediumType(Windows::Media::Import::PhotoImportStorageMediumType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StorageMediumType, WINRT_WRAP(Windows::Media::Import::PhotoImportStorageMediumType));
            *value = detach_from<Windows::Media::Import::PhotoImportStorageMediumType>(this->shim().StorageMediumType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportedAccessMode(Windows::Media::Import::PhotoImportAccessMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedAccessMode, WINRT_WRAP(Windows::Media::Import::PhotoImportAccessMode));
            *value = detach_from<Windows::Media::Import::PhotoImportAccessMode>(this->shim().SupportedAccessMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CapacityInBytes(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CapacityInBytes, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().CapacityInBytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AvailableSpaceInBytes(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AvailableSpaceInBytes, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().AvailableSpaceInBytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Refresh() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Refresh, WINRT_WRAP(void));
            this->shim().Refresh();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Import::IPhotoImportVideoSegment> : produce_base<D, Windows::Media::Import::IPhotoImportVideoSegment>
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

    int32_t WINRT_CALL get_SizeInBytes(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SizeInBytes, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().SizeInBytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Date(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Date, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().Date());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Sibling(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Sibling, WINRT_WRAP(Windows::Media::Import::PhotoImportSidecar));
            *value = detach_from<Windows::Media::Import::PhotoImportSidecar>(this->shim().Sibling());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Sidecars(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Sidecars, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Media::Import::PhotoImportSidecar>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Media::Import::PhotoImportSidecar>>(this->shim().Sidecars());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Media::Import {

inline Windows::Foundation::IAsyncOperation<bool> PhotoImportManager::IsSupportedAsync()
{
    return impl::call_factory<PhotoImportManager, Windows::Media::Import::IPhotoImportManagerStatics>([&](auto&& f) { return f.IsSupportedAsync(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Media::Import::PhotoImportSource>> PhotoImportManager::FindAllSourcesAsync()
{
    return impl::call_factory<PhotoImportManager, Windows::Media::Import::IPhotoImportManagerStatics>([&](auto&& f) { return f.FindAllSourcesAsync(); });
}

inline Windows::Foundation::Collections::IVectorView<Windows::Media::Import::PhotoImportOperation> PhotoImportManager::GetPendingOperations()
{
    return impl::call_factory<PhotoImportManager, Windows::Media::Import::IPhotoImportManagerStatics>([&](auto&& f) { return f.GetPendingOperations(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Media::Import::PhotoImportSource> PhotoImportSource::FromIdAsync(param::hstring const& sourceId)
{
    return impl::call_factory<PhotoImportSource, Windows::Media::Import::IPhotoImportSourceStatics>([&](auto&& f) { return f.FromIdAsync(sourceId); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Media::Import::PhotoImportSource> PhotoImportSource::FromFolderAsync(Windows::Storage::IStorageFolder const& sourceRootFolder)
{
    return impl::call_factory<PhotoImportSource, Windows::Media::Import::IPhotoImportSourceStatics>([&](auto&& f) { return f.FromFolderAsync(sourceRootFolder); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Media::Import::IPhotoImportDeleteImportedItemsFromSourceResult> : winrt::impl::hash_base<winrt::Windows::Media::Import::IPhotoImportDeleteImportedItemsFromSourceResult> {};
template<> struct hash<winrt::Windows::Media::Import::IPhotoImportFindItemsResult> : winrt::impl::hash_base<winrt::Windows::Media::Import::IPhotoImportFindItemsResult> {};
template<> struct hash<winrt::Windows::Media::Import::IPhotoImportFindItemsResult2> : winrt::impl::hash_base<winrt::Windows::Media::Import::IPhotoImportFindItemsResult2> {};
template<> struct hash<winrt::Windows::Media::Import::IPhotoImportImportItemsResult> : winrt::impl::hash_base<winrt::Windows::Media::Import::IPhotoImportImportItemsResult> {};
template<> struct hash<winrt::Windows::Media::Import::IPhotoImportItem> : winrt::impl::hash_base<winrt::Windows::Media::Import::IPhotoImportItem> {};
template<> struct hash<winrt::Windows::Media::Import::IPhotoImportItem2> : winrt::impl::hash_base<winrt::Windows::Media::Import::IPhotoImportItem2> {};
template<> struct hash<winrt::Windows::Media::Import::IPhotoImportItemImportedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Import::IPhotoImportItemImportedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Import::IPhotoImportManagerStatics> : winrt::impl::hash_base<winrt::Windows::Media::Import::IPhotoImportManagerStatics> {};
template<> struct hash<winrt::Windows::Media::Import::IPhotoImportOperation> : winrt::impl::hash_base<winrt::Windows::Media::Import::IPhotoImportOperation> {};
template<> struct hash<winrt::Windows::Media::Import::IPhotoImportSelectionChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Import::IPhotoImportSelectionChangedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Import::IPhotoImportSession> : winrt::impl::hash_base<winrt::Windows::Media::Import::IPhotoImportSession> {};
template<> struct hash<winrt::Windows::Media::Import::IPhotoImportSession2> : winrt::impl::hash_base<winrt::Windows::Media::Import::IPhotoImportSession2> {};
template<> struct hash<winrt::Windows::Media::Import::IPhotoImportSidecar> : winrt::impl::hash_base<winrt::Windows::Media::Import::IPhotoImportSidecar> {};
template<> struct hash<winrt::Windows::Media::Import::IPhotoImportSource> : winrt::impl::hash_base<winrt::Windows::Media::Import::IPhotoImportSource> {};
template<> struct hash<winrt::Windows::Media::Import::IPhotoImportSourceStatics> : winrt::impl::hash_base<winrt::Windows::Media::Import::IPhotoImportSourceStatics> {};
template<> struct hash<winrt::Windows::Media::Import::IPhotoImportStorageMedium> : winrt::impl::hash_base<winrt::Windows::Media::Import::IPhotoImportStorageMedium> {};
template<> struct hash<winrt::Windows::Media::Import::IPhotoImportVideoSegment> : winrt::impl::hash_base<winrt::Windows::Media::Import::IPhotoImportVideoSegment> {};
template<> struct hash<winrt::Windows::Media::Import::PhotoImportDeleteImportedItemsFromSourceResult> : winrt::impl::hash_base<winrt::Windows::Media::Import::PhotoImportDeleteImportedItemsFromSourceResult> {};
template<> struct hash<winrt::Windows::Media::Import::PhotoImportFindItemsResult> : winrt::impl::hash_base<winrt::Windows::Media::Import::PhotoImportFindItemsResult> {};
template<> struct hash<winrt::Windows::Media::Import::PhotoImportImportItemsResult> : winrt::impl::hash_base<winrt::Windows::Media::Import::PhotoImportImportItemsResult> {};
template<> struct hash<winrt::Windows::Media::Import::PhotoImportItem> : winrt::impl::hash_base<winrt::Windows::Media::Import::PhotoImportItem> {};
template<> struct hash<winrt::Windows::Media::Import::PhotoImportItemImportedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Import::PhotoImportItemImportedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Import::PhotoImportManager> : winrt::impl::hash_base<winrt::Windows::Media::Import::PhotoImportManager> {};
template<> struct hash<winrt::Windows::Media::Import::PhotoImportOperation> : winrt::impl::hash_base<winrt::Windows::Media::Import::PhotoImportOperation> {};
template<> struct hash<winrt::Windows::Media::Import::PhotoImportSelectionChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Import::PhotoImportSelectionChangedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Import::PhotoImportSession> : winrt::impl::hash_base<winrt::Windows::Media::Import::PhotoImportSession> {};
template<> struct hash<winrt::Windows::Media::Import::PhotoImportSidecar> : winrt::impl::hash_base<winrt::Windows::Media::Import::PhotoImportSidecar> {};
template<> struct hash<winrt::Windows::Media::Import::PhotoImportSource> : winrt::impl::hash_base<winrt::Windows::Media::Import::PhotoImportSource> {};
template<> struct hash<winrt::Windows::Media::Import::PhotoImportStorageMedium> : winrt::impl::hash_base<winrt::Windows::Media::Import::PhotoImportStorageMedium> {};
template<> struct hash<winrt::Windows::Media::Import::PhotoImportVideoSegment> : winrt::impl::hash_base<winrt::Windows::Media::Import::PhotoImportVideoSegment> {};

}
