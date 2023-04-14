// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Data.Text.2.h"
#include "winrt/impl/Windows.Storage.2.h"
#include "winrt/impl/Windows.Storage.FileProperties.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Storage.Search.2.h"
#include "winrt/Windows.Storage.h"

namespace winrt::impl {

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Storage_Search_IContentIndexer<D>::AddAsync(Windows::Storage::Search::IIndexableContent const& indexableContent) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IContentIndexer)->AddAsync(get_abi(indexableContent), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Storage_Search_IContentIndexer<D>::UpdateAsync(Windows::Storage::Search::IIndexableContent const& indexableContent) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IContentIndexer)->UpdateAsync(get_abi(indexableContent), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Storage_Search_IContentIndexer<D>::DeleteAsync(param::hstring const& contentId) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IContentIndexer)->DeleteAsync(get_abi(contentId), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Storage_Search_IContentIndexer<D>::DeleteMultipleAsync(param::async_iterable<hstring> const& contentIds) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IContentIndexer)->DeleteMultipleAsync(get_abi(contentIds), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Storage_Search_IContentIndexer<D>::DeleteAllAsync() const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IContentIndexer)->DeleteAllAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable>> consume_Windows_Storage_Search_IContentIndexer<D>::RetrievePropertiesAsync(param::hstring const& contentId, param::async_iterable<hstring> const& propertiesToRetrieve) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IContentIndexer)->RetrievePropertiesAsync(get_abi(contentId), get_abi(propertiesToRetrieve), put_abi(operation)));
    return operation;
}

template <typename D> uint64_t consume_Windows_Storage_Search_IContentIndexer<D>::Revision() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IContentIndexer)->get_Revision(&value));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<uint32_t> consume_Windows_Storage_Search_IContentIndexerQuery<D>::GetCountAsync() const
{
    Windows::Foundation::IAsyncOperation<uint32_t> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IContentIndexerQuery)->GetCountAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable>>> consume_Windows_Storage_Search_IContentIndexerQuery<D>::GetPropertiesAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable>>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IContentIndexerQuery)->GetPropertiesAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable>>> consume_Windows_Storage_Search_IContentIndexerQuery<D>::GetPropertiesAsync(uint32_t startIndex, uint32_t maxItems) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable>>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IContentIndexerQuery)->GetPropertiesRangeAsync(startIndex, maxItems, put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::Search::IIndexableContent>> consume_Windows_Storage_Search_IContentIndexerQuery<D>::GetAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::Search::IIndexableContent>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IContentIndexerQuery)->GetAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::Search::IIndexableContent>> consume_Windows_Storage_Search_IContentIndexerQuery<D>::GetAsync(uint32_t startIndex, uint32_t maxItems) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::Search::IIndexableContent>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IContentIndexerQuery)->GetRangeAsync(startIndex, maxItems, put_abi(operation)));
    return operation;
}

template <typename D> Windows::Storage::StorageFolder consume_Windows_Storage_Search_IContentIndexerQuery<D>::QueryFolder() const
{
    Windows::Storage::StorageFolder value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IContentIndexerQuery)->get_QueryFolder(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Search::ContentIndexerQuery consume_Windows_Storage_Search_IContentIndexerQueryOperations<D>::CreateQuery(param::hstring const& searchFilter, param::iterable<hstring> const& propertiesToRetrieve, param::iterable<Windows::Storage::Search::SortEntry> const& sortOrder, param::hstring const& searchFilterLanguage) const
{
    Windows::Storage::Search::ContentIndexerQuery query{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IContentIndexerQueryOperations)->CreateQueryWithSortOrderAndLanguage(get_abi(searchFilter), get_abi(propertiesToRetrieve), get_abi(sortOrder), get_abi(searchFilterLanguage), put_abi(query)));
    return query;
}

template <typename D> Windows::Storage::Search::ContentIndexerQuery consume_Windows_Storage_Search_IContentIndexerQueryOperations<D>::CreateQuery(param::hstring const& searchFilter, param::iterable<hstring> const& propertiesToRetrieve, param::iterable<Windows::Storage::Search::SortEntry> const& sortOrder) const
{
    Windows::Storage::Search::ContentIndexerQuery query{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IContentIndexerQueryOperations)->CreateQueryWithSortOrder(get_abi(searchFilter), get_abi(propertiesToRetrieve), get_abi(sortOrder), put_abi(query)));
    return query;
}

template <typename D> Windows::Storage::Search::ContentIndexerQuery consume_Windows_Storage_Search_IContentIndexerQueryOperations<D>::CreateQuery(param::hstring const& searchFilter, param::iterable<hstring> const& propertiesToRetrieve) const
{
    Windows::Storage::Search::ContentIndexerQuery query{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IContentIndexerQueryOperations)->CreateQuery(get_abi(searchFilter), get_abi(propertiesToRetrieve), put_abi(query)));
    return query;
}

template <typename D> Windows::Storage::Search::ContentIndexer consume_Windows_Storage_Search_IContentIndexerStatics<D>::GetIndexer(param::hstring const& indexName) const
{
    Windows::Storage::Search::ContentIndexer index{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IContentIndexerStatics)->GetIndexerWithName(get_abi(indexName), put_abi(index)));
    return index;
}

template <typename D> Windows::Storage::Search::ContentIndexer consume_Windows_Storage_Search_IContentIndexerStatics<D>::GetIndexer() const
{
    Windows::Storage::Search::ContentIndexer index{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IContentIndexerStatics)->GetIndexer(put_abi(index)));
    return index;
}

template <typename D> hstring consume_Windows_Storage_Search_IIndexableContent<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IIndexableContent)->get_Id(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Storage_Search_IIndexableContent<D>::Id(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IIndexableContent)->put_Id(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IMap<hstring, Windows::Foundation::IInspectable> consume_Windows_Storage_Search_IIndexableContent<D>::Properties() const
{
    Windows::Foundation::Collections::IMap<hstring, Windows::Foundation::IInspectable> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IIndexableContent)->get_Properties(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IRandomAccessStream consume_Windows_Storage_Search_IIndexableContent<D>::Stream() const
{
    Windows::Storage::Streams::IRandomAccessStream value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IIndexableContent)->get_Stream(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Storage_Search_IIndexableContent<D>::Stream(Windows::Storage::Streams::IRandomAccessStream const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IIndexableContent)->put_Stream(get_abi(value)));
}

template <typename D> hstring consume_Windows_Storage_Search_IIndexableContent<D>::StreamContentType() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IIndexableContent)->get_StreamContentType(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Storage_Search_IIndexableContent<D>::StreamContentType(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IIndexableContent)->put_StreamContentType(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVector<hstring> consume_Windows_Storage_Search_IQueryOptions<D>::FileTypeFilter() const
{
    Windows::Foundation::Collections::IVector<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IQueryOptions)->get_FileTypeFilter(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Search::FolderDepth consume_Windows_Storage_Search_IQueryOptions<D>::FolderDepth() const
{
    Windows::Storage::Search::FolderDepth value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IQueryOptions)->get_FolderDepth(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Storage_Search_IQueryOptions<D>::FolderDepth(Windows::Storage::Search::FolderDepth const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IQueryOptions)->put_FolderDepth(get_abi(value)));
}

template <typename D> hstring consume_Windows_Storage_Search_IQueryOptions<D>::ApplicationSearchFilter() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IQueryOptions)->get_ApplicationSearchFilter(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Storage_Search_IQueryOptions<D>::ApplicationSearchFilter(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IQueryOptions)->put_ApplicationSearchFilter(get_abi(value)));
}

template <typename D> hstring consume_Windows_Storage_Search_IQueryOptions<D>::UserSearchFilter() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IQueryOptions)->get_UserSearchFilter(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Storage_Search_IQueryOptions<D>::UserSearchFilter(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IQueryOptions)->put_UserSearchFilter(get_abi(value)));
}

template <typename D> hstring consume_Windows_Storage_Search_IQueryOptions<D>::Language() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IQueryOptions)->get_Language(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Storage_Search_IQueryOptions<D>::Language(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IQueryOptions)->put_Language(get_abi(value)));
}

template <typename D> Windows::Storage::Search::IndexerOption consume_Windows_Storage_Search_IQueryOptions<D>::IndexerOption() const
{
    Windows::Storage::Search::IndexerOption value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IQueryOptions)->get_IndexerOption(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Storage_Search_IQueryOptions<D>::IndexerOption(Windows::Storage::Search::IndexerOption const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IQueryOptions)->put_IndexerOption(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::Storage::Search::SortEntry> consume_Windows_Storage_Search_IQueryOptions<D>::SortOrder() const
{
    Windows::Foundation::Collections::IVector<Windows::Storage::Search::SortEntry> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IQueryOptions)->get_SortOrder(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_Search_IQueryOptions<D>::GroupPropertyName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IQueryOptions)->get_GroupPropertyName(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Search::DateStackOption consume_Windows_Storage_Search_IQueryOptions<D>::DateStackOption() const
{
    Windows::Storage::Search::DateStackOption value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IQueryOptions)->get_DateStackOption(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_Search_IQueryOptions<D>::SaveToString() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IQueryOptions)->SaveToString(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Storage_Search_IQueryOptions<D>::LoadFromString(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IQueryOptions)->LoadFromString(get_abi(value)));
}

template <typename D> void consume_Windows_Storage_Search_IQueryOptions<D>::SetThumbnailPrefetch(Windows::Storage::FileProperties::ThumbnailMode const& mode, uint32_t requestedSize, Windows::Storage::FileProperties::ThumbnailOptions const& options) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IQueryOptions)->SetThumbnailPrefetch(get_abi(mode), requestedSize, get_abi(options)));
}

template <typename D> void consume_Windows_Storage_Search_IQueryOptions<D>::SetPropertyPrefetch(Windows::Storage::FileProperties::PropertyPrefetchOptions const& options, param::iterable<hstring> const& propertiesToRetrieve) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IQueryOptions)->SetPropertyPrefetch(get_abi(options), get_abi(propertiesToRetrieve)));
}

template <typename D> Windows::Storage::Search::QueryOptions consume_Windows_Storage_Search_IQueryOptionsFactory<D>::CreateCommonFileQuery(Windows::Storage::Search::CommonFileQuery const& query, param::iterable<hstring> const& fileTypeFilter) const
{
    Windows::Storage::Search::QueryOptions queryOptions{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IQueryOptionsFactory)->CreateCommonFileQuery(get_abi(query), get_abi(fileTypeFilter), put_abi(queryOptions)));
    return queryOptions;
}

template <typename D> Windows::Storage::Search::QueryOptions consume_Windows_Storage_Search_IQueryOptionsFactory<D>::CreateCommonFolderQuery(Windows::Storage::Search::CommonFolderQuery const& query) const
{
    Windows::Storage::Search::QueryOptions queryOptions{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IQueryOptionsFactory)->CreateCommonFolderQuery(get_abi(query), put_abi(queryOptions)));
    return queryOptions;
}

template <typename D> Windows::Foundation::Collections::IVector<hstring> consume_Windows_Storage_Search_IQueryOptionsWithProviderFilter<D>::StorageProviderIdFilter() const
{
    Windows::Foundation::Collections::IVector<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IQueryOptionsWithProviderFilter)->get_StorageProviderIdFilter(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::StorageFile>> consume_Windows_Storage_Search_IStorageFileQueryResult<D>::GetFilesAsync(uint32_t startIndex, uint32_t maxNumberOfItems) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::StorageFile>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IStorageFileQueryResult)->GetFilesAsync(startIndex, maxNumberOfItems, put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::StorageFile>> consume_Windows_Storage_Search_IStorageFileQueryResult<D>::GetFilesAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::StorageFile>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IStorageFileQueryResult)->GetFilesAsyncDefaultStartAndCount(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::Collections::IMap<hstring, Windows::Foundation::Collections::IVectorView<Windows::Data::Text::TextSegment>> consume_Windows_Storage_Search_IStorageFileQueryResult2<D>::GetMatchingPropertiesWithRanges(Windows::Storage::StorageFile const& file) const
{
    Windows::Foundation::Collections::IMap<hstring, Windows::Foundation::Collections::IVectorView<Windows::Data::Text::TextSegment>> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IStorageFileQueryResult2)->GetMatchingPropertiesWithRanges(get_abi(file), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::Search::IndexedState> consume_Windows_Storage_Search_IStorageFolderQueryOperations<D>::GetIndexedStateAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::Search::IndexedState> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IStorageFolderQueryOperations)->GetIndexedStateAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Storage::Search::StorageFileQueryResult consume_Windows_Storage_Search_IStorageFolderQueryOperations<D>::CreateFileQuery() const
{
    Windows::Storage::Search::StorageFileQueryResult value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IStorageFolderQueryOperations)->CreateFileQueryOverloadDefault(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Search::StorageFileQueryResult consume_Windows_Storage_Search_IStorageFolderQueryOperations<D>::CreateFileQuery(Windows::Storage::Search::CommonFileQuery const& query) const
{
    Windows::Storage::Search::StorageFileQueryResult value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IStorageFolderQueryOperations)->CreateFileQuery(get_abi(query), put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Search::StorageFileQueryResult consume_Windows_Storage_Search_IStorageFolderQueryOperations<D>::CreateFileQueryWithOptions(Windows::Storage::Search::QueryOptions const& queryOptions) const
{
    Windows::Storage::Search::StorageFileQueryResult value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IStorageFolderQueryOperations)->CreateFileQueryWithOptions(get_abi(queryOptions), put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Search::StorageFolderQueryResult consume_Windows_Storage_Search_IStorageFolderQueryOperations<D>::CreateFolderQuery() const
{
    Windows::Storage::Search::StorageFolderQueryResult value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IStorageFolderQueryOperations)->CreateFolderQueryOverloadDefault(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Search::StorageFolderQueryResult consume_Windows_Storage_Search_IStorageFolderQueryOperations<D>::CreateFolderQuery(Windows::Storage::Search::CommonFolderQuery const& query) const
{
    Windows::Storage::Search::StorageFolderQueryResult value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IStorageFolderQueryOperations)->CreateFolderQuery(get_abi(query), put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Search::StorageFolderQueryResult consume_Windows_Storage_Search_IStorageFolderQueryOperations<D>::CreateFolderQueryWithOptions(Windows::Storage::Search::QueryOptions const& queryOptions) const
{
    Windows::Storage::Search::StorageFolderQueryResult value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IStorageFolderQueryOperations)->CreateFolderQueryWithOptions(get_abi(queryOptions), put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Search::StorageItemQueryResult consume_Windows_Storage_Search_IStorageFolderQueryOperations<D>::CreateItemQuery() const
{
    Windows::Storage::Search::StorageItemQueryResult value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IStorageFolderQueryOperations)->CreateItemQuery(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Search::StorageItemQueryResult consume_Windows_Storage_Search_IStorageFolderQueryOperations<D>::CreateItemQueryWithOptions(Windows::Storage::Search::QueryOptions const& queryOptions) const
{
    Windows::Storage::Search::StorageItemQueryResult value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IStorageFolderQueryOperations)->CreateItemQueryWithOptions(get_abi(queryOptions), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::StorageFile>> consume_Windows_Storage_Search_IStorageFolderQueryOperations<D>::GetFilesAsync(Windows::Storage::Search::CommonFileQuery const& query, uint32_t startIndex, uint32_t maxItemsToRetrieve) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::StorageFile>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IStorageFolderQueryOperations)->GetFilesAsync(get_abi(query), startIndex, maxItemsToRetrieve, put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::StorageFile>> consume_Windows_Storage_Search_IStorageFolderQueryOperations<D>::GetFilesAsync(Windows::Storage::Search::CommonFileQuery const& query) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::StorageFile>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IStorageFolderQueryOperations)->GetFilesAsyncOverloadDefaultStartAndCount(get_abi(query), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::StorageFolder>> consume_Windows_Storage_Search_IStorageFolderQueryOperations<D>::GetFoldersAsync(Windows::Storage::Search::CommonFolderQuery const& query, uint32_t startIndex, uint32_t maxItemsToRetrieve) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::StorageFolder>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IStorageFolderQueryOperations)->GetFoldersAsync(get_abi(query), startIndex, maxItemsToRetrieve, put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::StorageFolder>> consume_Windows_Storage_Search_IStorageFolderQueryOperations<D>::GetFoldersAsync(Windows::Storage::Search::CommonFolderQuery const& query) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::StorageFolder>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IStorageFolderQueryOperations)->GetFoldersAsyncOverloadDefaultStartAndCount(get_abi(query), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::IStorageItem>> consume_Windows_Storage_Search_IStorageFolderQueryOperations<D>::GetItemsAsync(uint32_t startIndex, uint32_t maxItemsToRetrieve) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::IStorageItem>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IStorageFolderQueryOperations)->GetItemsAsync(startIndex, maxItemsToRetrieve, put_abi(operation)));
    return operation;
}

template <typename D> bool consume_Windows_Storage_Search_IStorageFolderQueryOperations<D>::AreQueryOptionsSupported(Windows::Storage::Search::QueryOptions const& queryOptions) const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IStorageFolderQueryOperations)->AreQueryOptionsSupported(get_abi(queryOptions), &value));
    return value;
}

template <typename D> bool consume_Windows_Storage_Search_IStorageFolderQueryOperations<D>::IsCommonFolderQuerySupported(Windows::Storage::Search::CommonFolderQuery const& query) const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IStorageFolderQueryOperations)->IsCommonFolderQuerySupported(get_abi(query), &value));
    return value;
}

template <typename D> bool consume_Windows_Storage_Search_IStorageFolderQueryOperations<D>::IsCommonFileQuerySupported(Windows::Storage::Search::CommonFileQuery const& query) const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IStorageFolderQueryOperations)->IsCommonFileQuerySupported(get_abi(query), &value));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::StorageFolder>> consume_Windows_Storage_Search_IStorageFolderQueryResult<D>::GetFoldersAsync(uint32_t startIndex, uint32_t maxNumberOfItems) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::StorageFolder>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IStorageFolderQueryResult)->GetFoldersAsync(startIndex, maxNumberOfItems, put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::StorageFolder>> consume_Windows_Storage_Search_IStorageFolderQueryResult<D>::GetFoldersAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::StorageFolder>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IStorageFolderQueryResult)->GetFoldersAsyncDefaultStartAndCount(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::IStorageItem>> consume_Windows_Storage_Search_IStorageItemQueryResult<D>::GetItemsAsync(uint32_t startIndex, uint32_t maxNumberOfItems) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::IStorageItem>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IStorageItemQueryResult)->GetItemsAsync(startIndex, maxNumberOfItems, put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::IStorageItem>> consume_Windows_Storage_Search_IStorageItemQueryResult<D>::GetItemsAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::IStorageItem>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IStorageItemQueryResult)->GetItemsAsyncDefaultStartAndCount(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Storage::StorageFolder consume_Windows_Storage_Search_IStorageLibraryChangeTrackerTriggerDetails<D>::Folder() const
{
    Windows::Storage::StorageFolder value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IStorageLibraryChangeTrackerTriggerDetails)->get_Folder(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::StorageLibraryChangeTracker consume_Windows_Storage_Search_IStorageLibraryChangeTrackerTriggerDetails<D>::ChangeTracker() const
{
    Windows::Storage::StorageLibraryChangeTracker value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IStorageLibraryChangeTrackerTriggerDetails)->get_ChangeTracker(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::StorageFolder consume_Windows_Storage_Search_IStorageLibraryContentChangedTriggerDetails<D>::Folder() const
{
    Windows::Storage::StorageFolder value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IStorageLibraryContentChangedTriggerDetails)->get_Folder(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Search::StorageItemQueryResult consume_Windows_Storage_Search_IStorageLibraryContentChangedTriggerDetails<D>::CreateModifiedSinceQuery(Windows::Foundation::DateTime const& lastQueryTime) const
{
    Windows::Storage::Search::StorageItemQueryResult result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IStorageLibraryContentChangedTriggerDetails)->CreateModifiedSinceQuery(get_abi(lastQueryTime), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<uint32_t> consume_Windows_Storage_Search_IStorageQueryResultBase<D>::GetItemCountAsync() const
{
    Windows::Foundation::IAsyncOperation<uint32_t> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IStorageQueryResultBase)->GetItemCountAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Storage::StorageFolder consume_Windows_Storage_Search_IStorageQueryResultBase<D>::Folder() const
{
    Windows::Storage::StorageFolder container{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IStorageQueryResultBase)->get_Folder(put_abi(container)));
    return container;
}

template <typename D> winrt::event_token consume_Windows_Storage_Search_IStorageQueryResultBase<D>::ContentsChanged(Windows::Foundation::TypedEventHandler<Windows::Storage::Search::IStorageQueryResultBase, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token eventCookie{};
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IStorageQueryResultBase)->add_ContentsChanged(get_abi(handler), put_abi(eventCookie)));
    return eventCookie;
}

template <typename D> typename consume_Windows_Storage_Search_IStorageQueryResultBase<D>::ContentsChanged_revoker consume_Windows_Storage_Search_IStorageQueryResultBase<D>::ContentsChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Storage::Search::IStorageQueryResultBase, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, ContentsChanged_revoker>(this, ContentsChanged(handler));
}

template <typename D> void consume_Windows_Storage_Search_IStorageQueryResultBase<D>::ContentsChanged(winrt::event_token const& eventCookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Storage::Search::IStorageQueryResultBase)->remove_ContentsChanged(get_abi(eventCookie)));
}

template <typename D> winrt::event_token consume_Windows_Storage_Search_IStorageQueryResultBase<D>::OptionsChanged(Windows::Foundation::TypedEventHandler<Windows::Storage::Search::IStorageQueryResultBase, Windows::Foundation::IInspectable> const& changedHandler) const
{
    winrt::event_token eventCookie{};
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IStorageQueryResultBase)->add_OptionsChanged(get_abi(changedHandler), put_abi(eventCookie)));
    return eventCookie;
}

template <typename D> typename consume_Windows_Storage_Search_IStorageQueryResultBase<D>::OptionsChanged_revoker consume_Windows_Storage_Search_IStorageQueryResultBase<D>::OptionsChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Storage::Search::IStorageQueryResultBase, Windows::Foundation::IInspectable> const& changedHandler) const
{
    return impl::make_event_revoker<D, OptionsChanged_revoker>(this, OptionsChanged(changedHandler));
}

template <typename D> void consume_Windows_Storage_Search_IStorageQueryResultBase<D>::OptionsChanged(winrt::event_token const& eventCookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Storage::Search::IStorageQueryResultBase)->remove_OptionsChanged(get_abi(eventCookie)));
}

template <typename D> Windows::Foundation::IAsyncOperation<uint32_t> consume_Windows_Storage_Search_IStorageQueryResultBase<D>::FindStartIndexAsync(Windows::Foundation::IInspectable const& value) const
{
    Windows::Foundation::IAsyncOperation<uint32_t> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IStorageQueryResultBase)->FindStartIndexAsync(get_abi(value), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Storage::Search::QueryOptions consume_Windows_Storage_Search_IStorageQueryResultBase<D>::GetCurrentQueryOptions() const
{
    Windows::Storage::Search::QueryOptions value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IStorageQueryResultBase)->GetCurrentQueryOptions(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Storage_Search_IStorageQueryResultBase<D>::ApplyNewQueryOptions(Windows::Storage::Search::QueryOptions const& newQueryOptions) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IStorageQueryResultBase)->ApplyNewQueryOptions(get_abi(newQueryOptions)));
}

template <typename D> hstring consume_Windows_Storage_Search_IValueAndLanguage<D>::Language() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IValueAndLanguage)->get_Language(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Storage_Search_IValueAndLanguage<D>::Language(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IValueAndLanguage)->put_Language(get_abi(value)));
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_Storage_Search_IValueAndLanguage<D>::Value() const
{
    Windows::Foundation::IInspectable value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IValueAndLanguage)->get_Value(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Storage_Search_IValueAndLanguage<D>::Value(Windows::Foundation::IInspectable const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Search::IValueAndLanguage)->put_Value(get_abi(value)));
}

template <typename D>
struct produce<D, Windows::Storage::Search::IContentIndexer> : produce_base<D, Windows::Storage::Search::IContentIndexer>
{
    int32_t WINRT_CALL AddAsync(void* indexableContent, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Storage::Search::IIndexableContent const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().AddAsync(*reinterpret_cast<Windows::Storage::Search::IIndexableContent const*>(&indexableContent)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UpdateAsync(void* indexableContent, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpdateAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Storage::Search::IIndexableContent const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().UpdateAsync(*reinterpret_cast<Windows::Storage::Search::IIndexableContent const*>(&indexableContent)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DeleteAsync(void* contentId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeleteAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().DeleteAsync(*reinterpret_cast<hstring const*>(&contentId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DeleteMultipleAsync(void* contentIds, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeleteMultipleAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Foundation::Collections::IIterable<hstring> const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().DeleteMultipleAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&contentIds)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DeleteAllAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeleteAllAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().DeleteAllAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RetrievePropertiesAsync(void* contentId, void* propertiesToRetrieve, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RetrievePropertiesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable>>), hstring const, Windows::Foundation::Collections::IIterable<hstring> const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable>>>(this->shim().RetrievePropertiesAsync(*reinterpret_cast<hstring const*>(&contentId), *reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&propertiesToRetrieve)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Revision(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Revision, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().Revision());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::Search::IContentIndexerQuery> : produce_base<D, Windows::Storage::Search::IContentIndexerQuery>
{
    int32_t WINRT_CALL GetCountAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCountAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<uint32_t>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<uint32_t>>(this->shim().GetCountAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetPropertiesAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetPropertiesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable>>>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable>>>>(this->shim().GetPropertiesAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetPropertiesRangeAsync(uint32_t startIndex, uint32_t maxItems, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetPropertiesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable>>>), uint32_t, uint32_t);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable>>>>(this->shim().GetPropertiesAsync(startIndex, maxItems));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::Search::IIndexableContent>>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::Search::IIndexableContent>>>(this->shim().GetAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetRangeAsync(uint32_t startIndex, uint32_t maxItems, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::Search::IIndexableContent>>), uint32_t, uint32_t);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::Search::IIndexableContent>>>(this->shim().GetAsync(startIndex, maxItems));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_QueryFolder(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(QueryFolder, WINRT_WRAP(Windows::Storage::StorageFolder));
            *value = detach_from<Windows::Storage::StorageFolder>(this->shim().QueryFolder());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::Search::IContentIndexerQueryOperations> : produce_base<D, Windows::Storage::Search::IContentIndexerQueryOperations>
{
    int32_t WINRT_CALL CreateQueryWithSortOrderAndLanguage(void* searchFilter, void* propertiesToRetrieve, void* sortOrder, void* searchFilterLanguage, void** query) noexcept final
    {
        try
        {
            *query = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateQuery, WINRT_WRAP(Windows::Storage::Search::ContentIndexerQuery), hstring const&, Windows::Foundation::Collections::IIterable<hstring> const&, Windows::Foundation::Collections::IIterable<Windows::Storage::Search::SortEntry> const&, hstring const&);
            *query = detach_from<Windows::Storage::Search::ContentIndexerQuery>(this->shim().CreateQuery(*reinterpret_cast<hstring const*>(&searchFilter), *reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&propertiesToRetrieve), *reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Storage::Search::SortEntry> const*>(&sortOrder), *reinterpret_cast<hstring const*>(&searchFilterLanguage)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateQueryWithSortOrder(void* searchFilter, void* propertiesToRetrieve, void* sortOrder, void** query) noexcept final
    {
        try
        {
            *query = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateQuery, WINRT_WRAP(Windows::Storage::Search::ContentIndexerQuery), hstring const&, Windows::Foundation::Collections::IIterable<hstring> const&, Windows::Foundation::Collections::IIterable<Windows::Storage::Search::SortEntry> const&);
            *query = detach_from<Windows::Storage::Search::ContentIndexerQuery>(this->shim().CreateQuery(*reinterpret_cast<hstring const*>(&searchFilter), *reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&propertiesToRetrieve), *reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Storage::Search::SortEntry> const*>(&sortOrder)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateQuery(void* searchFilter, void* propertiesToRetrieve, void** query) noexcept final
    {
        try
        {
            *query = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateQuery, WINRT_WRAP(Windows::Storage::Search::ContentIndexerQuery), hstring const&, Windows::Foundation::Collections::IIterable<hstring> const&);
            *query = detach_from<Windows::Storage::Search::ContentIndexerQuery>(this->shim().CreateQuery(*reinterpret_cast<hstring const*>(&searchFilter), *reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&propertiesToRetrieve)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::Search::IContentIndexerStatics> : produce_base<D, Windows::Storage::Search::IContentIndexerStatics>
{
    int32_t WINRT_CALL GetIndexerWithName(void* indexName, void** index) noexcept final
    {
        try
        {
            *index = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetIndexer, WINRT_WRAP(Windows::Storage::Search::ContentIndexer), hstring const&);
            *index = detach_from<Windows::Storage::Search::ContentIndexer>(this->shim().GetIndexer(*reinterpret_cast<hstring const*>(&indexName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetIndexer(void** index) noexcept final
    {
        try
        {
            *index = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetIndexer, WINRT_WRAP(Windows::Storage::Search::ContentIndexer));
            *index = detach_from<Windows::Storage::Search::ContentIndexer>(this->shim().GetIndexer());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::Search::IIndexableContent> : produce_base<D, Windows::Storage::Search::IIndexableContent>
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

    int32_t WINRT_CALL put_Id(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Id, WINRT_WRAP(void), hstring const&);
            this->shim().Id(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Properties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Properties, WINRT_WRAP(Windows::Foundation::Collections::IMap<hstring, Windows::Foundation::IInspectable>));
            *value = detach_from<Windows::Foundation::Collections::IMap<hstring, Windows::Foundation::IInspectable>>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Stream(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Stream, WINRT_WRAP(Windows::Storage::Streams::IRandomAccessStream));
            *value = detach_from<Windows::Storage::Streams::IRandomAccessStream>(this->shim().Stream());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Stream(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Stream, WINRT_WRAP(void), Windows::Storage::Streams::IRandomAccessStream const&);
            this->shim().Stream(*reinterpret_cast<Windows::Storage::Streams::IRandomAccessStream const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StreamContentType(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StreamContentType, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().StreamContentType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_StreamContentType(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StreamContentType, WINRT_WRAP(void), hstring const&);
            this->shim().StreamContentType(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::Search::IQueryOptions> : produce_base<D, Windows::Storage::Search::IQueryOptions>
{
    int32_t WINRT_CALL get_FileTypeFilter(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FileTypeFilter, WINRT_WRAP(Windows::Foundation::Collections::IVector<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVector<hstring>>(this->shim().FileTypeFilter());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FolderDepth(Windows::Storage::Search::FolderDepth* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FolderDepth, WINRT_WRAP(Windows::Storage::Search::FolderDepth));
            *value = detach_from<Windows::Storage::Search::FolderDepth>(this->shim().FolderDepth());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FolderDepth(Windows::Storage::Search::FolderDepth value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FolderDepth, WINRT_WRAP(void), Windows::Storage::Search::FolderDepth const&);
            this->shim().FolderDepth(*reinterpret_cast<Windows::Storage::Search::FolderDepth const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ApplicationSearchFilter(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ApplicationSearchFilter, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ApplicationSearchFilter());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ApplicationSearchFilter(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ApplicationSearchFilter, WINRT_WRAP(void), hstring const&);
            this->shim().ApplicationSearchFilter(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UserSearchFilter(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UserSearchFilter, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().UserSearchFilter());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_UserSearchFilter(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UserSearchFilter, WINRT_WRAP(void), hstring const&);
            this->shim().UserSearchFilter(*reinterpret_cast<hstring const*>(&value));
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

    int32_t WINRT_CALL put_Language(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Language, WINRT_WRAP(void), hstring const&);
            this->shim().Language(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IndexerOption(Windows::Storage::Search::IndexerOption* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IndexerOption, WINRT_WRAP(Windows::Storage::Search::IndexerOption));
            *value = detach_from<Windows::Storage::Search::IndexerOption>(this->shim().IndexerOption());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IndexerOption(Windows::Storage::Search::IndexerOption value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IndexerOption, WINRT_WRAP(void), Windows::Storage::Search::IndexerOption const&);
            this->shim().IndexerOption(*reinterpret_cast<Windows::Storage::Search::IndexerOption const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SortOrder(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SortOrder, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::Storage::Search::SortEntry>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::Storage::Search::SortEntry>>(this->shim().SortOrder());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_GroupPropertyName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GroupPropertyName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().GroupPropertyName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DateStackOption(Windows::Storage::Search::DateStackOption* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DateStackOption, WINRT_WRAP(Windows::Storage::Search::DateStackOption));
            *value = detach_from<Windows::Storage::Search::DateStackOption>(this->shim().DateStackOption());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SaveToString(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SaveToString, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SaveToString());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL LoadFromString(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LoadFromString, WINRT_WRAP(void), hstring const&);
            this->shim().LoadFromString(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetThumbnailPrefetch(Windows::Storage::FileProperties::ThumbnailMode mode, uint32_t requestedSize, Windows::Storage::FileProperties::ThumbnailOptions options) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetThumbnailPrefetch, WINRT_WRAP(void), Windows::Storage::FileProperties::ThumbnailMode const&, uint32_t, Windows::Storage::FileProperties::ThumbnailOptions const&);
            this->shim().SetThumbnailPrefetch(*reinterpret_cast<Windows::Storage::FileProperties::ThumbnailMode const*>(&mode), requestedSize, *reinterpret_cast<Windows::Storage::FileProperties::ThumbnailOptions const*>(&options));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetPropertyPrefetch(Windows::Storage::FileProperties::PropertyPrefetchOptions options, void* propertiesToRetrieve) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetPropertyPrefetch, WINRT_WRAP(void), Windows::Storage::FileProperties::PropertyPrefetchOptions const&, Windows::Foundation::Collections::IIterable<hstring> const&);
            this->shim().SetPropertyPrefetch(*reinterpret_cast<Windows::Storage::FileProperties::PropertyPrefetchOptions const*>(&options), *reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&propertiesToRetrieve));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::Search::IQueryOptionsFactory> : produce_base<D, Windows::Storage::Search::IQueryOptionsFactory>
{
    int32_t WINRT_CALL CreateCommonFileQuery(Windows::Storage::Search::CommonFileQuery query, void* fileTypeFilter, void** queryOptions) noexcept final
    {
        try
        {
            *queryOptions = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateCommonFileQuery, WINRT_WRAP(Windows::Storage::Search::QueryOptions), Windows::Storage::Search::CommonFileQuery const&, Windows::Foundation::Collections::IIterable<hstring> const&);
            *queryOptions = detach_from<Windows::Storage::Search::QueryOptions>(this->shim().CreateCommonFileQuery(*reinterpret_cast<Windows::Storage::Search::CommonFileQuery const*>(&query), *reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&fileTypeFilter)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateCommonFolderQuery(Windows::Storage::Search::CommonFolderQuery query, void** queryOptions) noexcept final
    {
        try
        {
            *queryOptions = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateCommonFolderQuery, WINRT_WRAP(Windows::Storage::Search::QueryOptions), Windows::Storage::Search::CommonFolderQuery const&);
            *queryOptions = detach_from<Windows::Storage::Search::QueryOptions>(this->shim().CreateCommonFolderQuery(*reinterpret_cast<Windows::Storage::Search::CommonFolderQuery const*>(&query)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::Search::IQueryOptionsWithProviderFilter> : produce_base<D, Windows::Storage::Search::IQueryOptionsWithProviderFilter>
{
    int32_t WINRT_CALL get_StorageProviderIdFilter(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StorageProviderIdFilter, WINRT_WRAP(Windows::Foundation::Collections::IVector<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVector<hstring>>(this->shim().StorageProviderIdFilter());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::Search::IStorageFileQueryResult> : produce_base<D, Windows::Storage::Search::IStorageFileQueryResult>
{
    int32_t WINRT_CALL GetFilesAsync(uint32_t startIndex, uint32_t maxNumberOfItems, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetFilesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::StorageFile>>), uint32_t, uint32_t);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::StorageFile>>>(this->shim().GetFilesAsync(startIndex, maxNumberOfItems));
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
            WINRT_ASSERT_DECLARATION(GetFilesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::StorageFile>>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::StorageFile>>>(this->shim().GetFilesAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::Search::IStorageFileQueryResult2> : produce_base<D, Windows::Storage::Search::IStorageFileQueryResult2>
{
    int32_t WINRT_CALL GetMatchingPropertiesWithRanges(void* file, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetMatchingPropertiesWithRanges, WINRT_WRAP(Windows::Foundation::Collections::IMap<hstring, Windows::Foundation::Collections::IVectorView<Windows::Data::Text::TextSegment>>), Windows::Storage::StorageFile const&);
            *result = detach_from<Windows::Foundation::Collections::IMap<hstring, Windows::Foundation::Collections::IVectorView<Windows::Data::Text::TextSegment>>>(this->shim().GetMatchingPropertiesWithRanges(*reinterpret_cast<Windows::Storage::StorageFile const*>(&file)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::Search::IStorageFolderQueryOperations> : produce_base<D, Windows::Storage::Search::IStorageFolderQueryOperations>
{
    int32_t WINRT_CALL GetIndexedStateAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetIndexedStateAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::Search::IndexedState>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::Search::IndexedState>>(this->shim().GetIndexedStateAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFileQueryOverloadDefault(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFileQuery, WINRT_WRAP(Windows::Storage::Search::StorageFileQueryResult));
            *value = detach_from<Windows::Storage::Search::StorageFileQueryResult>(this->shim().CreateFileQuery());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFileQuery(Windows::Storage::Search::CommonFileQuery query, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFileQuery, WINRT_WRAP(Windows::Storage::Search::StorageFileQueryResult), Windows::Storage::Search::CommonFileQuery const&);
            *value = detach_from<Windows::Storage::Search::StorageFileQueryResult>(this->shim().CreateFileQuery(*reinterpret_cast<Windows::Storage::Search::CommonFileQuery const*>(&query)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFileQueryWithOptions(void* queryOptions, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFileQueryWithOptions, WINRT_WRAP(Windows::Storage::Search::StorageFileQueryResult), Windows::Storage::Search::QueryOptions const&);
            *value = detach_from<Windows::Storage::Search::StorageFileQueryResult>(this->shim().CreateFileQueryWithOptions(*reinterpret_cast<Windows::Storage::Search::QueryOptions const*>(&queryOptions)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFolderQueryOverloadDefault(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFolderQuery, WINRT_WRAP(Windows::Storage::Search::StorageFolderQueryResult));
            *value = detach_from<Windows::Storage::Search::StorageFolderQueryResult>(this->shim().CreateFolderQuery());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFolderQuery(Windows::Storage::Search::CommonFolderQuery query, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFolderQuery, WINRT_WRAP(Windows::Storage::Search::StorageFolderQueryResult), Windows::Storage::Search::CommonFolderQuery const&);
            *value = detach_from<Windows::Storage::Search::StorageFolderQueryResult>(this->shim().CreateFolderQuery(*reinterpret_cast<Windows::Storage::Search::CommonFolderQuery const*>(&query)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFolderQueryWithOptions(void* queryOptions, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFolderQueryWithOptions, WINRT_WRAP(Windows::Storage::Search::StorageFolderQueryResult), Windows::Storage::Search::QueryOptions const&);
            *value = detach_from<Windows::Storage::Search::StorageFolderQueryResult>(this->shim().CreateFolderQueryWithOptions(*reinterpret_cast<Windows::Storage::Search::QueryOptions const*>(&queryOptions)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateItemQuery(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateItemQuery, WINRT_WRAP(Windows::Storage::Search::StorageItemQueryResult));
            *value = detach_from<Windows::Storage::Search::StorageItemQueryResult>(this->shim().CreateItemQuery());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateItemQueryWithOptions(void* queryOptions, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateItemQueryWithOptions, WINRT_WRAP(Windows::Storage::Search::StorageItemQueryResult), Windows::Storage::Search::QueryOptions const&);
            *value = detach_from<Windows::Storage::Search::StorageItemQueryResult>(this->shim().CreateItemQueryWithOptions(*reinterpret_cast<Windows::Storage::Search::QueryOptions const*>(&queryOptions)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetFilesAsync(Windows::Storage::Search::CommonFileQuery query, uint32_t startIndex, uint32_t maxItemsToRetrieve, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetFilesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::StorageFile>>), Windows::Storage::Search::CommonFileQuery const, uint32_t, uint32_t);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::StorageFile>>>(this->shim().GetFilesAsync(*reinterpret_cast<Windows::Storage::Search::CommonFileQuery const*>(&query), startIndex, maxItemsToRetrieve));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetFilesAsyncOverloadDefaultStartAndCount(Windows::Storage::Search::CommonFileQuery query, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetFilesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::StorageFile>>), Windows::Storage::Search::CommonFileQuery const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::StorageFile>>>(this->shim().GetFilesAsync(*reinterpret_cast<Windows::Storage::Search::CommonFileQuery const*>(&query)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetFoldersAsync(Windows::Storage::Search::CommonFolderQuery query, uint32_t startIndex, uint32_t maxItemsToRetrieve, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetFoldersAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::StorageFolder>>), Windows::Storage::Search::CommonFolderQuery const, uint32_t, uint32_t);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::StorageFolder>>>(this->shim().GetFoldersAsync(*reinterpret_cast<Windows::Storage::Search::CommonFolderQuery const*>(&query), startIndex, maxItemsToRetrieve));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetFoldersAsyncOverloadDefaultStartAndCount(Windows::Storage::Search::CommonFolderQuery query, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetFoldersAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::StorageFolder>>), Windows::Storage::Search::CommonFolderQuery const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::StorageFolder>>>(this->shim().GetFoldersAsync(*reinterpret_cast<Windows::Storage::Search::CommonFolderQuery const*>(&query)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetItemsAsync(uint32_t startIndex, uint32_t maxItemsToRetrieve, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetItemsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::IStorageItem>>), uint32_t, uint32_t);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::IStorageItem>>>(this->shim().GetItemsAsync(startIndex, maxItemsToRetrieve));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AreQueryOptionsSupported(void* queryOptions, bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AreQueryOptionsSupported, WINRT_WRAP(bool), Windows::Storage::Search::QueryOptions const&);
            *value = detach_from<bool>(this->shim().AreQueryOptionsSupported(*reinterpret_cast<Windows::Storage::Search::QueryOptions const*>(&queryOptions)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsCommonFolderQuerySupported(Windows::Storage::Search::CommonFolderQuery query, bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsCommonFolderQuerySupported, WINRT_WRAP(bool), Windows::Storage::Search::CommonFolderQuery const&);
            *value = detach_from<bool>(this->shim().IsCommonFolderQuerySupported(*reinterpret_cast<Windows::Storage::Search::CommonFolderQuery const*>(&query)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsCommonFileQuerySupported(Windows::Storage::Search::CommonFileQuery query, bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsCommonFileQuerySupported, WINRT_WRAP(bool), Windows::Storage::Search::CommonFileQuery const&);
            *value = detach_from<bool>(this->shim().IsCommonFileQuerySupported(*reinterpret_cast<Windows::Storage::Search::CommonFileQuery const*>(&query)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::Search::IStorageFolderQueryResult> : produce_base<D, Windows::Storage::Search::IStorageFolderQueryResult>
{
    int32_t WINRT_CALL GetFoldersAsync(uint32_t startIndex, uint32_t maxNumberOfItems, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetFoldersAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::StorageFolder>>), uint32_t, uint32_t);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::StorageFolder>>>(this->shim().GetFoldersAsync(startIndex, maxNumberOfItems));
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
            WINRT_ASSERT_DECLARATION(GetFoldersAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::StorageFolder>>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::StorageFolder>>>(this->shim().GetFoldersAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::Search::IStorageItemQueryResult> : produce_base<D, Windows::Storage::Search::IStorageItemQueryResult>
{
    int32_t WINRT_CALL GetItemsAsync(uint32_t startIndex, uint32_t maxNumberOfItems, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetItemsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::IStorageItem>>), uint32_t, uint32_t);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::IStorageItem>>>(this->shim().GetItemsAsync(startIndex, maxNumberOfItems));
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
            WINRT_ASSERT_DECLARATION(GetItemsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::IStorageItem>>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::IStorageItem>>>(this->shim().GetItemsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::Search::IStorageLibraryChangeTrackerTriggerDetails> : produce_base<D, Windows::Storage::Search::IStorageLibraryChangeTrackerTriggerDetails>
{
    int32_t WINRT_CALL get_Folder(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Folder, WINRT_WRAP(Windows::Storage::StorageFolder));
            *value = detach_from<Windows::Storage::StorageFolder>(this->shim().Folder());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ChangeTracker(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChangeTracker, WINRT_WRAP(Windows::Storage::StorageLibraryChangeTracker));
            *value = detach_from<Windows::Storage::StorageLibraryChangeTracker>(this->shim().ChangeTracker());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::Search::IStorageLibraryContentChangedTriggerDetails> : produce_base<D, Windows::Storage::Search::IStorageLibraryContentChangedTriggerDetails>
{
    int32_t WINRT_CALL get_Folder(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Folder, WINRT_WRAP(Windows::Storage::StorageFolder));
            *value = detach_from<Windows::Storage::StorageFolder>(this->shim().Folder());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateModifiedSinceQuery(Windows::Foundation::DateTime lastQueryTime, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateModifiedSinceQuery, WINRT_WRAP(Windows::Storage::Search::StorageItemQueryResult), Windows::Foundation::DateTime const&);
            *result = detach_from<Windows::Storage::Search::StorageItemQueryResult>(this->shim().CreateModifiedSinceQuery(*reinterpret_cast<Windows::Foundation::DateTime const*>(&lastQueryTime)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::Search::IStorageQueryResultBase> : produce_base<D, Windows::Storage::Search::IStorageQueryResultBase>
{
    int32_t WINRT_CALL GetItemCountAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetItemCountAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<uint32_t>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<uint32_t>>(this->shim().GetItemCountAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Folder(void** container) noexcept final
    {
        try
        {
            *container = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Folder, WINRT_WRAP(Windows::Storage::StorageFolder));
            *container = detach_from<Windows::Storage::StorageFolder>(this->shim().Folder());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_ContentsChanged(void* handler, winrt::event_token* eventCookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentsChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Storage::Search::IStorageQueryResultBase, Windows::Foundation::IInspectable> const&);
            *eventCookie = detach_from<winrt::event_token>(this->shim().ContentsChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Storage::Search::IStorageQueryResultBase, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ContentsChanged(winrt::event_token eventCookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ContentsChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ContentsChanged(*reinterpret_cast<winrt::event_token const*>(&eventCookie));
        return 0;
    }

    int32_t WINRT_CALL add_OptionsChanged(void* changedHandler, winrt::event_token* eventCookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OptionsChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Storage::Search::IStorageQueryResultBase, Windows::Foundation::IInspectable> const&);
            *eventCookie = detach_from<winrt::event_token>(this->shim().OptionsChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Storage::Search::IStorageQueryResultBase, Windows::Foundation::IInspectable> const*>(&changedHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_OptionsChanged(winrt::event_token eventCookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(OptionsChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().OptionsChanged(*reinterpret_cast<winrt::event_token const*>(&eventCookie));
        return 0;
    }

    int32_t WINRT_CALL FindStartIndexAsync(void* value, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindStartIndexAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<uint32_t>), Windows::Foundation::IInspectable const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<uint32_t>>(this->shim().FindStartIndexAsync(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetCurrentQueryOptions(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCurrentQueryOptions, WINRT_WRAP(Windows::Storage::Search::QueryOptions));
            *value = detach_from<Windows::Storage::Search::QueryOptions>(this->shim().GetCurrentQueryOptions());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ApplyNewQueryOptions(void* newQueryOptions) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ApplyNewQueryOptions, WINRT_WRAP(void), Windows::Storage::Search::QueryOptions const&);
            this->shim().ApplyNewQueryOptions(*reinterpret_cast<Windows::Storage::Search::QueryOptions const*>(&newQueryOptions));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::Search::IValueAndLanguage> : produce_base<D, Windows::Storage::Search::IValueAndLanguage>
{
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

    int32_t WINRT_CALL put_Language(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Language, WINRT_WRAP(void), hstring const&);
            this->shim().Language(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Value(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Value, WINRT_WRAP(Windows::Foundation::IInspectable));
            *value = detach_from<Windows::Foundation::IInspectable>(this->shim().Value());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Value(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Value, WINRT_WRAP(void), Windows::Foundation::IInspectable const&);
            this->shim().Value(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Storage::Search {

inline Windows::Storage::Search::ContentIndexer ContentIndexer::GetIndexer(param::hstring const& indexName)
{
    return impl::call_factory<ContentIndexer, Windows::Storage::Search::IContentIndexerStatics>([&](auto&& f) { return f.GetIndexer(indexName); });
}

inline Windows::Storage::Search::ContentIndexer ContentIndexer::GetIndexer()
{
    return impl::call_factory<ContentIndexer, Windows::Storage::Search::IContentIndexerStatics>([&](auto&& f) { return f.GetIndexer(); });
}

inline IndexableContent::IndexableContent() :
    IndexableContent(impl::call_factory<IndexableContent>([](auto&& f) { return f.template ActivateInstance<IndexableContent>(); }))
{}

inline QueryOptions::QueryOptions() :
    QueryOptions(impl::call_factory<QueryOptions>([](auto&& f) { return f.template ActivateInstance<QueryOptions>(); }))
{}

inline QueryOptions::QueryOptions(Windows::Storage::Search::CommonFileQuery const& query, param::iterable<hstring> const& fileTypeFilter) :
    QueryOptions(impl::call_factory<QueryOptions, Windows::Storage::Search::IQueryOptionsFactory>([&](auto&& f) { return f.CreateCommonFileQuery(query, fileTypeFilter); }))
{}

inline QueryOptions::QueryOptions(Windows::Storage::Search::CommonFolderQuery const& query) :
    QueryOptions(impl::call_factory<QueryOptions, Windows::Storage::Search::IQueryOptionsFactory>([&](auto&& f) { return f.CreateCommonFolderQuery(query); }))
{}

inline ValueAndLanguage::ValueAndLanguage() :
    ValueAndLanguage(impl::call_factory<ValueAndLanguage>([](auto&& f) { return f.template ActivateInstance<ValueAndLanguage>(); }))
{}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Storage::Search::IContentIndexer> : winrt::impl::hash_base<winrt::Windows::Storage::Search::IContentIndexer> {};
template<> struct hash<winrt::Windows::Storage::Search::IContentIndexerQuery> : winrt::impl::hash_base<winrt::Windows::Storage::Search::IContentIndexerQuery> {};
template<> struct hash<winrt::Windows::Storage::Search::IContentIndexerQueryOperations> : winrt::impl::hash_base<winrt::Windows::Storage::Search::IContentIndexerQueryOperations> {};
template<> struct hash<winrt::Windows::Storage::Search::IContentIndexerStatics> : winrt::impl::hash_base<winrt::Windows::Storage::Search::IContentIndexerStatics> {};
template<> struct hash<winrt::Windows::Storage::Search::IIndexableContent> : winrt::impl::hash_base<winrt::Windows::Storage::Search::IIndexableContent> {};
template<> struct hash<winrt::Windows::Storage::Search::IQueryOptions> : winrt::impl::hash_base<winrt::Windows::Storage::Search::IQueryOptions> {};
template<> struct hash<winrt::Windows::Storage::Search::IQueryOptionsFactory> : winrt::impl::hash_base<winrt::Windows::Storage::Search::IQueryOptionsFactory> {};
template<> struct hash<winrt::Windows::Storage::Search::IQueryOptionsWithProviderFilter> : winrt::impl::hash_base<winrt::Windows::Storage::Search::IQueryOptionsWithProviderFilter> {};
template<> struct hash<winrt::Windows::Storage::Search::IStorageFileQueryResult> : winrt::impl::hash_base<winrt::Windows::Storage::Search::IStorageFileQueryResult> {};
template<> struct hash<winrt::Windows::Storage::Search::IStorageFileQueryResult2> : winrt::impl::hash_base<winrt::Windows::Storage::Search::IStorageFileQueryResult2> {};
template<> struct hash<winrt::Windows::Storage::Search::IStorageFolderQueryOperations> : winrt::impl::hash_base<winrt::Windows::Storage::Search::IStorageFolderQueryOperations> {};
template<> struct hash<winrt::Windows::Storage::Search::IStorageFolderQueryResult> : winrt::impl::hash_base<winrt::Windows::Storage::Search::IStorageFolderQueryResult> {};
template<> struct hash<winrt::Windows::Storage::Search::IStorageItemQueryResult> : winrt::impl::hash_base<winrt::Windows::Storage::Search::IStorageItemQueryResult> {};
template<> struct hash<winrt::Windows::Storage::Search::IStorageLibraryChangeTrackerTriggerDetails> : winrt::impl::hash_base<winrt::Windows::Storage::Search::IStorageLibraryChangeTrackerTriggerDetails> {};
template<> struct hash<winrt::Windows::Storage::Search::IStorageLibraryContentChangedTriggerDetails> : winrt::impl::hash_base<winrt::Windows::Storage::Search::IStorageLibraryContentChangedTriggerDetails> {};
template<> struct hash<winrt::Windows::Storage::Search::IStorageQueryResultBase> : winrt::impl::hash_base<winrt::Windows::Storage::Search::IStorageQueryResultBase> {};
template<> struct hash<winrt::Windows::Storage::Search::IValueAndLanguage> : winrt::impl::hash_base<winrt::Windows::Storage::Search::IValueAndLanguage> {};
template<> struct hash<winrt::Windows::Storage::Search::ContentIndexer> : winrt::impl::hash_base<winrt::Windows::Storage::Search::ContentIndexer> {};
template<> struct hash<winrt::Windows::Storage::Search::ContentIndexerQuery> : winrt::impl::hash_base<winrt::Windows::Storage::Search::ContentIndexerQuery> {};
template<> struct hash<winrt::Windows::Storage::Search::IndexableContent> : winrt::impl::hash_base<winrt::Windows::Storage::Search::IndexableContent> {};
template<> struct hash<winrt::Windows::Storage::Search::QueryOptions> : winrt::impl::hash_base<winrt::Windows::Storage::Search::QueryOptions> {};
template<> struct hash<winrt::Windows::Storage::Search::SortEntryVector> : winrt::impl::hash_base<winrt::Windows::Storage::Search::SortEntryVector> {};
template<> struct hash<winrt::Windows::Storage::Search::StorageFileQueryResult> : winrt::impl::hash_base<winrt::Windows::Storage::Search::StorageFileQueryResult> {};
template<> struct hash<winrt::Windows::Storage::Search::StorageFolderQueryResult> : winrt::impl::hash_base<winrt::Windows::Storage::Search::StorageFolderQueryResult> {};
template<> struct hash<winrt::Windows::Storage::Search::StorageItemQueryResult> : winrt::impl::hash_base<winrt::Windows::Storage::Search::StorageItemQueryResult> {};
template<> struct hash<winrt::Windows::Storage::Search::StorageLibraryChangeTrackerTriggerDetails> : winrt::impl::hash_base<winrt::Windows::Storage::Search::StorageLibraryChangeTrackerTriggerDetails> {};
template<> struct hash<winrt::Windows::Storage::Search::StorageLibraryContentChangedTriggerDetails> : winrt::impl::hash_base<winrt::Windows::Storage::Search::StorageLibraryContentChangedTriggerDetails> {};
template<> struct hash<winrt::Windows::Storage::Search::ValueAndLanguage> : winrt::impl::hash_base<winrt::Windows::Storage::Search::ValueAndLanguage> {};

}
