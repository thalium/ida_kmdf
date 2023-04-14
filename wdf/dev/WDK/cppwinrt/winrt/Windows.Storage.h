// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Storage.FileProperties.2.h"
#include "winrt/impl/Windows.Storage.Provider.2.h"
#include "winrt/impl/Windows.Storage.Search.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.Storage.2.h"

namespace winrt::impl {

template <typename D> hstring consume_Windows_Storage_IAppDataPaths<D>::Cookies() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::IAppDataPaths)->get_Cookies(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_IAppDataPaths<D>::Desktop() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::IAppDataPaths)->get_Desktop(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_IAppDataPaths<D>::Documents() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::IAppDataPaths)->get_Documents(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_IAppDataPaths<D>::Favorites() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::IAppDataPaths)->get_Favorites(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_IAppDataPaths<D>::History() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::IAppDataPaths)->get_History(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_IAppDataPaths<D>::InternetCache() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::IAppDataPaths)->get_InternetCache(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_IAppDataPaths<D>::LocalAppData() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::IAppDataPaths)->get_LocalAppData(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_IAppDataPaths<D>::ProgramData() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::IAppDataPaths)->get_ProgramData(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_IAppDataPaths<D>::RoamingAppData() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::IAppDataPaths)->get_RoamingAppData(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::AppDataPaths consume_Windows_Storage_IAppDataPathsStatics<D>::GetForUser(Windows::System::User const& user) const
{
    Windows::Storage::AppDataPaths result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IAppDataPathsStatics)->GetForUser(get_abi(user), put_abi(result)));
    return result;
}

template <typename D> Windows::Storage::AppDataPaths consume_Windows_Storage_IAppDataPathsStatics<D>::GetDefault() const
{
    Windows::Storage::AppDataPaths result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IAppDataPathsStatics)->GetDefault(put_abi(result)));
    return result;
}

template <typename D> uint32_t consume_Windows_Storage_IApplicationData<D>::Version() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Storage::IApplicationData)->get_Version(&value));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Storage_IApplicationData<D>::SetVersionAsync(uint32_t desiredVersion, Windows::Storage::ApplicationDataSetVersionHandler const& handler) const
{
    Windows::Foundation::IAsyncAction setVersionOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IApplicationData)->SetVersionAsync(desiredVersion, get_abi(handler), put_abi(setVersionOperation)));
    return setVersionOperation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Storage_IApplicationData<D>::ClearAsync() const
{
    Windows::Foundation::IAsyncAction clearOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IApplicationData)->ClearAllAsync(put_abi(clearOperation)));
    return clearOperation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Storage_IApplicationData<D>::ClearAsync(Windows::Storage::ApplicationDataLocality const& locality) const
{
    Windows::Foundation::IAsyncAction clearOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IApplicationData)->ClearAsync(get_abi(locality), put_abi(clearOperation)));
    return clearOperation;
}

template <typename D> Windows::Storage::ApplicationDataContainer consume_Windows_Storage_IApplicationData<D>::LocalSettings() const
{
    Windows::Storage::ApplicationDataContainer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IApplicationData)->get_LocalSettings(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::ApplicationDataContainer consume_Windows_Storage_IApplicationData<D>::RoamingSettings() const
{
    Windows::Storage::ApplicationDataContainer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IApplicationData)->get_RoamingSettings(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::StorageFolder consume_Windows_Storage_IApplicationData<D>::LocalFolder() const
{
    Windows::Storage::StorageFolder value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IApplicationData)->get_LocalFolder(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::StorageFolder consume_Windows_Storage_IApplicationData<D>::RoamingFolder() const
{
    Windows::Storage::StorageFolder value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IApplicationData)->get_RoamingFolder(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::StorageFolder consume_Windows_Storage_IApplicationData<D>::TemporaryFolder() const
{
    Windows::Storage::StorageFolder value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IApplicationData)->get_TemporaryFolder(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Storage_IApplicationData<D>::DataChanged(Windows::Foundation::TypedEventHandler<Windows::Storage::ApplicationData, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Storage::IApplicationData)->add_DataChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Storage_IApplicationData<D>::DataChanged_revoker consume_Windows_Storage_IApplicationData<D>::DataChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Storage::ApplicationData, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, DataChanged_revoker>(this, DataChanged(handler));
}

template <typename D> void consume_Windows_Storage_IApplicationData<D>::DataChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Storage::IApplicationData)->remove_DataChanged(get_abi(token)));
}

template <typename D> void consume_Windows_Storage_IApplicationData<D>::SignalDataChanged() const
{
    check_hresult(WINRT_SHIM(Windows::Storage::IApplicationData)->SignalDataChanged());
}

template <typename D> uint64_t consume_Windows_Storage_IApplicationData<D>::RoamingStorageQuota() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::Storage::IApplicationData)->get_RoamingStorageQuota(&value));
    return value;
}

template <typename D> Windows::Storage::StorageFolder consume_Windows_Storage_IApplicationData2<D>::LocalCacheFolder() const
{
    Windows::Storage::StorageFolder value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IApplicationData2)->get_LocalCacheFolder(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::StorageFolder consume_Windows_Storage_IApplicationData3<D>::GetPublisherCacheFolder(param::hstring const& folderName) const
{
    Windows::Storage::StorageFolder value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IApplicationData3)->GetPublisherCacheFolder(get_abi(folderName), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Storage_IApplicationData3<D>::ClearPublisherCacheFolderAsync(param::hstring const& folderName) const
{
    Windows::Foundation::IAsyncAction clearOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IApplicationData3)->ClearPublisherCacheFolderAsync(get_abi(folderName), put_abi(clearOperation)));
    return clearOperation;
}

template <typename D> Windows::Storage::StorageFolder consume_Windows_Storage_IApplicationData3<D>::SharedLocalFolder() const
{
    Windows::Storage::StorageFolder value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IApplicationData3)->get_SharedLocalFolder(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_IApplicationDataContainer<D>::Name() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::IApplicationDataContainer)->get_Name(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::ApplicationDataLocality consume_Windows_Storage_IApplicationDataContainer<D>::Locality() const
{
    Windows::Storage::ApplicationDataLocality value{};
    check_hresult(WINRT_SHIM(Windows::Storage::IApplicationDataContainer)->get_Locality(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IPropertySet consume_Windows_Storage_IApplicationDataContainer<D>::Values() const
{
    Windows::Foundation::Collections::IPropertySet value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IApplicationDataContainer)->get_Values(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IMapView<hstring, Windows::Storage::ApplicationDataContainer> consume_Windows_Storage_IApplicationDataContainer<D>::Containers() const
{
    Windows::Foundation::Collections::IMapView<hstring, Windows::Storage::ApplicationDataContainer> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IApplicationDataContainer)->get_Containers(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::ApplicationDataContainer consume_Windows_Storage_IApplicationDataContainer<D>::CreateContainer(param::hstring const& name, Windows::Storage::ApplicationDataCreateDisposition const& disposition) const
{
    Windows::Storage::ApplicationDataContainer container{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IApplicationDataContainer)->CreateContainer(get_abi(name), get_abi(disposition), put_abi(container)));
    return container;
}

template <typename D> void consume_Windows_Storage_IApplicationDataContainer<D>::DeleteContainer(param::hstring const& name) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::IApplicationDataContainer)->DeleteContainer(get_abi(name)));
}

template <typename D> Windows::Storage::ApplicationData consume_Windows_Storage_IApplicationDataStatics<D>::Current() const
{
    Windows::Storage::ApplicationData value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IApplicationDataStatics)->get_Current(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::ApplicationData> consume_Windows_Storage_IApplicationDataStatics2<D>::GetForUserAsync(Windows::System::User const& user) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::ApplicationData> getForUserOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IApplicationDataStatics2)->GetForUserAsync(get_abi(user), put_abi(getForUserOperation)));
    return getForUserOperation;
}

template <typename D> void consume_Windows_Storage_ICachedFileManagerStatics<D>::DeferUpdates(Windows::Storage::IStorageFile const& file) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::ICachedFileManagerStatics)->DeferUpdates(get_abi(file)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::Provider::FileUpdateStatus> consume_Windows_Storage_ICachedFileManagerStatics<D>::CompleteUpdatesAsync(Windows::Storage::IStorageFile const& file) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::Provider::FileUpdateStatus> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::ICachedFileManagerStatics)->CompleteUpdatesAsync(get_abi(file), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile> consume_Windows_Storage_IDownloadsFolderStatics<D>::CreateFileAsync(param::hstring const& desiredName) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IDownloadsFolderStatics)->CreateFileAsync(get_abi(desiredName), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFolder> consume_Windows_Storage_IDownloadsFolderStatics<D>::CreateFolderAsync(param::hstring const& desiredName) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFolder> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IDownloadsFolderStatics)->CreateFolderAsync(get_abi(desiredName), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile> consume_Windows_Storage_IDownloadsFolderStatics<D>::CreateFileAsync(param::hstring const& desiredName, Windows::Storage::CreationCollisionOption const& option) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IDownloadsFolderStatics)->CreateFileWithCollisionOptionAsync(get_abi(desiredName), get_abi(option), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFolder> consume_Windows_Storage_IDownloadsFolderStatics<D>::CreateFolderAsync(param::hstring const& desiredName, Windows::Storage::CreationCollisionOption const& option) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFolder> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IDownloadsFolderStatics)->CreateFolderWithCollisionOptionAsync(get_abi(desiredName), get_abi(option), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile> consume_Windows_Storage_IDownloadsFolderStatics2<D>::CreateFileForUserAsync(Windows::System::User const& user, param::hstring const& desiredName) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IDownloadsFolderStatics2)->CreateFileForUserAsync(get_abi(user), get_abi(desiredName), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFolder> consume_Windows_Storage_IDownloadsFolderStatics2<D>::CreateFolderForUserAsync(Windows::System::User const& user, param::hstring const& desiredName) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFolder> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IDownloadsFolderStatics2)->CreateFolderForUserAsync(get_abi(user), get_abi(desiredName), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile> consume_Windows_Storage_IDownloadsFolderStatics2<D>::CreateFileForUserAsync(Windows::System::User const& user, param::hstring const& desiredName, Windows::Storage::CreationCollisionOption const& option) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IDownloadsFolderStatics2)->CreateFileForUserWithCollisionOptionAsync(get_abi(user), get_abi(desiredName), get_abi(option), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFolder> consume_Windows_Storage_IDownloadsFolderStatics2<D>::CreateFolderForUserAsync(Windows::System::User const& user, param::hstring const& desiredName, Windows::Storage::CreationCollisionOption const& option) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFolder> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IDownloadsFolderStatics2)->CreateFolderForUserWithCollisionOptionAsync(get_abi(user), get_abi(desiredName), get_abi(option), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<hstring> consume_Windows_Storage_IFileIOStatics<D>::ReadTextAsync(Windows::Storage::IStorageFile const& file) const
{
    Windows::Foundation::IAsyncOperation<hstring> textOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IFileIOStatics)->ReadTextAsync(get_abi(file), put_abi(textOperation)));
    return textOperation;
}

template <typename D> Windows::Foundation::IAsyncOperation<hstring> consume_Windows_Storage_IFileIOStatics<D>::ReadTextAsync(Windows::Storage::IStorageFile const& file, Windows::Storage::Streams::UnicodeEncoding const& encoding) const
{
    Windows::Foundation::IAsyncOperation<hstring> textOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IFileIOStatics)->ReadTextWithEncodingAsync(get_abi(file), get_abi(encoding), put_abi(textOperation)));
    return textOperation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Storage_IFileIOStatics<D>::WriteTextAsync(Windows::Storage::IStorageFile const& file, param::hstring const& contents) const
{
    Windows::Foundation::IAsyncAction textOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IFileIOStatics)->WriteTextAsync(get_abi(file), get_abi(contents), put_abi(textOperation)));
    return textOperation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Storage_IFileIOStatics<D>::WriteTextAsync(Windows::Storage::IStorageFile const& file, param::hstring const& contents, Windows::Storage::Streams::UnicodeEncoding const& encoding) const
{
    Windows::Foundation::IAsyncAction textOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IFileIOStatics)->WriteTextWithEncodingAsync(get_abi(file), get_abi(contents), get_abi(encoding), put_abi(textOperation)));
    return textOperation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Storage_IFileIOStatics<D>::AppendTextAsync(Windows::Storage::IStorageFile const& file, param::hstring const& contents) const
{
    Windows::Foundation::IAsyncAction textOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IFileIOStatics)->AppendTextAsync(get_abi(file), get_abi(contents), put_abi(textOperation)));
    return textOperation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Storage_IFileIOStatics<D>::AppendTextAsync(Windows::Storage::IStorageFile const& file, param::hstring const& contents, Windows::Storage::Streams::UnicodeEncoding const& encoding) const
{
    Windows::Foundation::IAsyncAction textOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IFileIOStatics)->AppendTextWithEncodingAsync(get_abi(file), get_abi(contents), get_abi(encoding), put_abi(textOperation)));
    return textOperation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<hstring>> consume_Windows_Storage_IFileIOStatics<D>::ReadLinesAsync(Windows::Storage::IStorageFile const& file) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<hstring>> linesOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IFileIOStatics)->ReadLinesAsync(get_abi(file), put_abi(linesOperation)));
    return linesOperation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<hstring>> consume_Windows_Storage_IFileIOStatics<D>::ReadLinesAsync(Windows::Storage::IStorageFile const& file, Windows::Storage::Streams::UnicodeEncoding const& encoding) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<hstring>> linesOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IFileIOStatics)->ReadLinesWithEncodingAsync(get_abi(file), get_abi(encoding), put_abi(linesOperation)));
    return linesOperation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Storage_IFileIOStatics<D>::WriteLinesAsync(Windows::Storage::IStorageFile const& file, param::async_iterable<hstring> const& lines) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IFileIOStatics)->WriteLinesAsync(get_abi(file), get_abi(lines), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Storage_IFileIOStatics<D>::WriteLinesAsync(Windows::Storage::IStorageFile const& file, param::async_iterable<hstring> const& lines, Windows::Storage::Streams::UnicodeEncoding const& encoding) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IFileIOStatics)->WriteLinesWithEncodingAsync(get_abi(file), get_abi(lines), get_abi(encoding), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Storage_IFileIOStatics<D>::AppendLinesAsync(Windows::Storage::IStorageFile const& file, param::async_iterable<hstring> const& lines) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IFileIOStatics)->AppendLinesAsync(get_abi(file), get_abi(lines), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Storage_IFileIOStatics<D>::AppendLinesAsync(Windows::Storage::IStorageFile const& file, param::async_iterable<hstring> const& lines, Windows::Storage::Streams::UnicodeEncoding const& encoding) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IFileIOStatics)->AppendLinesWithEncodingAsync(get_abi(file), get_abi(lines), get_abi(encoding), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer> consume_Windows_Storage_IFileIOStatics<D>::ReadBufferAsync(Windows::Storage::IStorageFile const& file) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IFileIOStatics)->ReadBufferAsync(get_abi(file), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Storage_IFileIOStatics<D>::WriteBufferAsync(Windows::Storage::IStorageFile const& file, Windows::Storage::Streams::IBuffer const& buffer) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IFileIOStatics)->WriteBufferAsync(get_abi(file), get_abi(buffer), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Storage_IFileIOStatics<D>::WriteBytesAsync(Windows::Storage::IStorageFile const& file, array_view<uint8_t const> buffer) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IFileIOStatics)->WriteBytesAsync(get_abi(file), buffer.size(), get_abi(buffer), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Storage::StorageFolder consume_Windows_Storage_IKnownFoldersCameraRollStatics<D>::CameraRoll() const
{
    Windows::Storage::StorageFolder value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IKnownFoldersCameraRollStatics)->get_CameraRoll(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::StorageFolder consume_Windows_Storage_IKnownFoldersPlaylistsStatics<D>::Playlists() const
{
    Windows::Storage::StorageFolder value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IKnownFoldersPlaylistsStatics)->get_Playlists(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::StorageFolder consume_Windows_Storage_IKnownFoldersSavedPicturesStatics<D>::SavedPictures() const
{
    Windows::Storage::StorageFolder value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IKnownFoldersSavedPicturesStatics)->get_SavedPictures(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::StorageFolder consume_Windows_Storage_IKnownFoldersStatics<D>::MusicLibrary() const
{
    Windows::Storage::StorageFolder value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IKnownFoldersStatics)->get_MusicLibrary(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::StorageFolder consume_Windows_Storage_IKnownFoldersStatics<D>::PicturesLibrary() const
{
    Windows::Storage::StorageFolder value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IKnownFoldersStatics)->get_PicturesLibrary(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::StorageFolder consume_Windows_Storage_IKnownFoldersStatics<D>::VideosLibrary() const
{
    Windows::Storage::StorageFolder value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IKnownFoldersStatics)->get_VideosLibrary(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::StorageFolder consume_Windows_Storage_IKnownFoldersStatics<D>::DocumentsLibrary() const
{
    Windows::Storage::StorageFolder value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IKnownFoldersStatics)->get_DocumentsLibrary(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::StorageFolder consume_Windows_Storage_IKnownFoldersStatics<D>::HomeGroup() const
{
    Windows::Storage::StorageFolder value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IKnownFoldersStatics)->get_HomeGroup(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::StorageFolder consume_Windows_Storage_IKnownFoldersStatics<D>::RemovableDevices() const
{
    Windows::Storage::StorageFolder value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IKnownFoldersStatics)->get_RemovableDevices(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::StorageFolder consume_Windows_Storage_IKnownFoldersStatics<D>::MediaServerDevices() const
{
    Windows::Storage::StorageFolder value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IKnownFoldersStatics)->get_MediaServerDevices(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::StorageFolder consume_Windows_Storage_IKnownFoldersStatics2<D>::Objects3D() const
{
    Windows::Storage::StorageFolder value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IKnownFoldersStatics2)->get_Objects3D(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::StorageFolder consume_Windows_Storage_IKnownFoldersStatics2<D>::AppCaptures() const
{
    Windows::Storage::StorageFolder value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IKnownFoldersStatics2)->get_AppCaptures(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::StorageFolder consume_Windows_Storage_IKnownFoldersStatics2<D>::RecordedCalls() const
{
    Windows::Storage::StorageFolder value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IKnownFoldersStatics2)->get_RecordedCalls(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFolder> consume_Windows_Storage_IKnownFoldersStatics3<D>::GetFolderForUserAsync(Windows::System::User const& user, Windows::Storage::KnownFolderId const& folderId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFolder> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IKnownFoldersStatics3)->GetFolderForUserAsync(get_abi(user), get_abi(folderId), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<hstring> consume_Windows_Storage_IPathIOStatics<D>::ReadTextAsync(param::hstring const& absolutePath) const
{
    Windows::Foundation::IAsyncOperation<hstring> textOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IPathIOStatics)->ReadTextAsync(get_abi(absolutePath), put_abi(textOperation)));
    return textOperation;
}

template <typename D> Windows::Foundation::IAsyncOperation<hstring> consume_Windows_Storage_IPathIOStatics<D>::ReadTextAsync(param::hstring const& absolutePath, Windows::Storage::Streams::UnicodeEncoding const& encoding) const
{
    Windows::Foundation::IAsyncOperation<hstring> textOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IPathIOStatics)->ReadTextWithEncodingAsync(get_abi(absolutePath), get_abi(encoding), put_abi(textOperation)));
    return textOperation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Storage_IPathIOStatics<D>::WriteTextAsync(param::hstring const& absolutePath, param::hstring const& contents) const
{
    Windows::Foundation::IAsyncAction textOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IPathIOStatics)->WriteTextAsync(get_abi(absolutePath), get_abi(contents), put_abi(textOperation)));
    return textOperation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Storage_IPathIOStatics<D>::WriteTextAsync(param::hstring const& absolutePath, param::hstring const& contents, Windows::Storage::Streams::UnicodeEncoding const& encoding) const
{
    Windows::Foundation::IAsyncAction textOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IPathIOStatics)->WriteTextWithEncodingAsync(get_abi(absolutePath), get_abi(contents), get_abi(encoding), put_abi(textOperation)));
    return textOperation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Storage_IPathIOStatics<D>::AppendTextAsync(param::hstring const& absolutePath, param::hstring const& contents) const
{
    Windows::Foundation::IAsyncAction textOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IPathIOStatics)->AppendTextAsync(get_abi(absolutePath), get_abi(contents), put_abi(textOperation)));
    return textOperation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Storage_IPathIOStatics<D>::AppendTextAsync(param::hstring const& absolutePath, param::hstring const& contents, Windows::Storage::Streams::UnicodeEncoding const& encoding) const
{
    Windows::Foundation::IAsyncAction textOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IPathIOStatics)->AppendTextWithEncodingAsync(get_abi(absolutePath), get_abi(contents), get_abi(encoding), put_abi(textOperation)));
    return textOperation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<hstring>> consume_Windows_Storage_IPathIOStatics<D>::ReadLinesAsync(param::hstring const& absolutePath) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<hstring>> linesOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IPathIOStatics)->ReadLinesAsync(get_abi(absolutePath), put_abi(linesOperation)));
    return linesOperation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<hstring>> consume_Windows_Storage_IPathIOStatics<D>::ReadLinesAsync(param::hstring const& absolutePath, Windows::Storage::Streams::UnicodeEncoding const& encoding) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<hstring>> linesOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IPathIOStatics)->ReadLinesWithEncodingAsync(get_abi(absolutePath), get_abi(encoding), put_abi(linesOperation)));
    return linesOperation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Storage_IPathIOStatics<D>::WriteLinesAsync(param::hstring const& absolutePath, param::async_iterable<hstring> const& lines) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IPathIOStatics)->WriteLinesAsync(get_abi(absolutePath), get_abi(lines), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Storage_IPathIOStatics<D>::WriteLinesAsync(param::hstring const& absolutePath, param::async_iterable<hstring> const& lines, Windows::Storage::Streams::UnicodeEncoding const& encoding) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IPathIOStatics)->WriteLinesWithEncodingAsync(get_abi(absolutePath), get_abi(lines), get_abi(encoding), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Storage_IPathIOStatics<D>::AppendLinesAsync(param::hstring const& absolutePath, param::async_iterable<hstring> const& lines) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IPathIOStatics)->AppendLinesAsync(get_abi(absolutePath), get_abi(lines), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Storage_IPathIOStatics<D>::AppendLinesAsync(param::hstring const& absolutePath, param::async_iterable<hstring> const& lines, Windows::Storage::Streams::UnicodeEncoding const& encoding) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IPathIOStatics)->AppendLinesWithEncodingAsync(get_abi(absolutePath), get_abi(lines), get_abi(encoding), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer> consume_Windows_Storage_IPathIOStatics<D>::ReadBufferAsync(param::hstring const& absolutePath) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IPathIOStatics)->ReadBufferAsync(get_abi(absolutePath), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Storage_IPathIOStatics<D>::WriteBufferAsync(param::hstring const& absolutePath, Windows::Storage::Streams::IBuffer const& buffer) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IPathIOStatics)->WriteBufferAsync(get_abi(absolutePath), get_abi(buffer), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Storage_IPathIOStatics<D>::WriteBytesAsync(param::hstring const& absolutePath, array_view<uint8_t const> buffer) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IPathIOStatics)->WriteBytesAsync(get_abi(absolutePath), buffer.size(), get_abi(buffer), put_abi(operation)));
    return operation;
}

template <typename D> void consume_Windows_Storage_ISetVersionDeferral<D>::Complete() const
{
    check_hresult(WINRT_SHIM(Windows::Storage::ISetVersionDeferral)->Complete());
}

template <typename D> uint32_t consume_Windows_Storage_ISetVersionRequest<D>::CurrentVersion() const
{
    uint32_t currentVersion{};
    check_hresult(WINRT_SHIM(Windows::Storage::ISetVersionRequest)->get_CurrentVersion(&currentVersion));
    return currentVersion;
}

template <typename D> uint32_t consume_Windows_Storage_ISetVersionRequest<D>::DesiredVersion() const
{
    uint32_t desiredVersion{};
    check_hresult(WINRT_SHIM(Windows::Storage::ISetVersionRequest)->get_DesiredVersion(&desiredVersion));
    return desiredVersion;
}

template <typename D> Windows::Storage::SetVersionDeferral consume_Windows_Storage_ISetVersionRequest<D>::GetDeferral() const
{
    Windows::Storage::SetVersionDeferral deferral{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::ISetVersionRequest)->GetDeferral(put_abi(deferral)));
    return deferral;
}

template <typename D> hstring consume_Windows_Storage_IStorageFile<D>::FileType() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageFile)->get_FileType(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_IStorageFile<D>::ContentType() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageFile)->get_ContentType(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStream> consume_Windows_Storage_IStorageFile<D>::OpenAsync(Windows::Storage::FileAccessMode const& accessMode) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStream> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageFile)->OpenAsync(get_abi(accessMode), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::StorageStreamTransaction> consume_Windows_Storage_IStorageFile<D>::OpenTransactedWriteAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::StorageStreamTransaction> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageFile)->OpenTransactedWriteAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile> consume_Windows_Storage_IStorageFile<D>::CopyAsync(Windows::Storage::IStorageFolder const& destinationFolder) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageFile)->CopyOverloadDefaultNameAndOptions(get_abi(destinationFolder), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile> consume_Windows_Storage_IStorageFile<D>::CopyAsync(Windows::Storage::IStorageFolder const& destinationFolder, param::hstring const& desiredNewName) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageFile)->CopyOverloadDefaultOptions(get_abi(destinationFolder), get_abi(desiredNewName), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile> consume_Windows_Storage_IStorageFile<D>::CopyAsync(Windows::Storage::IStorageFolder const& destinationFolder, param::hstring const& desiredNewName, Windows::Storage::NameCollisionOption const& option) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageFile)->CopyOverload(get_abi(destinationFolder), get_abi(desiredNewName), get_abi(option), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Storage_IStorageFile<D>::CopyAndReplaceAsync(Windows::Storage::IStorageFile const& fileToReplace) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageFile)->CopyAndReplaceAsync(get_abi(fileToReplace), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Storage_IStorageFile<D>::MoveAsync(Windows::Storage::IStorageFolder const& destinationFolder) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageFile)->MoveOverloadDefaultNameAndOptions(get_abi(destinationFolder), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Storage_IStorageFile<D>::MoveAsync(Windows::Storage::IStorageFolder const& destinationFolder, param::hstring const& desiredNewName) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageFile)->MoveOverloadDefaultOptions(get_abi(destinationFolder), get_abi(desiredNewName), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Storage_IStorageFile<D>::MoveAsync(Windows::Storage::IStorageFolder const& destinationFolder, param::hstring const& desiredNewName, Windows::Storage::NameCollisionOption const& option) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageFile)->MoveOverload(get_abi(destinationFolder), get_abi(desiredNewName), get_abi(option), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Storage_IStorageFile<D>::MoveAndReplaceAsync(Windows::Storage::IStorageFile const& fileToReplace) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageFile)->MoveAndReplaceAsync(get_abi(fileToReplace), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStream> consume_Windows_Storage_IStorageFile2<D>::OpenAsync(Windows::Storage::FileAccessMode const& accessMode, Windows::Storage::StorageOpenOptions const& options) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStream> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageFile2)->OpenWithOptionsAsync(get_abi(accessMode), get_abi(options), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::StorageStreamTransaction> consume_Windows_Storage_IStorageFile2<D>::OpenTransactedWriteAsync(Windows::Storage::StorageOpenOptions const& options) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::StorageStreamTransaction> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageFile2)->OpenTransactedWriteWithOptionsAsync(get_abi(options), put_abi(operation)));
    return operation;
}

template <typename D> bool consume_Windows_Storage_IStorageFilePropertiesWithAvailability<D>::IsAvailable() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageFilePropertiesWithAvailability)->get_IsAvailable(&value));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile> consume_Windows_Storage_IStorageFileStatics<D>::GetFileFromPathAsync(param::hstring const& path) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageFileStatics)->GetFileFromPathAsync(get_abi(path), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile> consume_Windows_Storage_IStorageFileStatics<D>::GetFileFromApplicationUriAsync(Windows::Foundation::Uri const& uri) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageFileStatics)->GetFileFromApplicationUriAsync(get_abi(uri), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile> consume_Windows_Storage_IStorageFileStatics<D>::CreateStreamedFileAsync(param::hstring const& displayNameWithExtension, Windows::Storage::StreamedFileDataRequestedHandler const& dataRequested, Windows::Storage::Streams::IRandomAccessStreamReference const& thumbnail) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageFileStatics)->CreateStreamedFileAsync(get_abi(displayNameWithExtension), get_abi(dataRequested), get_abi(thumbnail), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile> consume_Windows_Storage_IStorageFileStatics<D>::ReplaceWithStreamedFileAsync(Windows::Storage::IStorageFile const& fileToReplace, Windows::Storage::StreamedFileDataRequestedHandler const& dataRequested, Windows::Storage::Streams::IRandomAccessStreamReference const& thumbnail) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageFileStatics)->ReplaceWithStreamedFileAsync(get_abi(fileToReplace), get_abi(dataRequested), get_abi(thumbnail), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile> consume_Windows_Storage_IStorageFileStatics<D>::CreateStreamedFileFromUriAsync(param::hstring const& displayNameWithExtension, Windows::Foundation::Uri const& uri, Windows::Storage::Streams::IRandomAccessStreamReference const& thumbnail) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageFileStatics)->CreateStreamedFileFromUriAsync(get_abi(displayNameWithExtension), get_abi(uri), get_abi(thumbnail), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile> consume_Windows_Storage_IStorageFileStatics<D>::ReplaceWithStreamedFileFromUriAsync(Windows::Storage::IStorageFile const& fileToReplace, Windows::Foundation::Uri const& uri, Windows::Storage::Streams::IRandomAccessStreamReference const& thumbnail) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageFileStatics)->ReplaceWithStreamedFileFromUriAsync(get_abi(fileToReplace), get_abi(uri), get_abi(thumbnail), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile> consume_Windows_Storage_IStorageFolder<D>::CreateFileAsync(param::hstring const& desiredName) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageFolder)->CreateFileAsyncOverloadDefaultOptions(get_abi(desiredName), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile> consume_Windows_Storage_IStorageFolder<D>::CreateFileAsync(param::hstring const& desiredName, Windows::Storage::CreationCollisionOption const& options) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageFolder)->CreateFileAsync(get_abi(desiredName), get_abi(options), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFolder> consume_Windows_Storage_IStorageFolder<D>::CreateFolderAsync(param::hstring const& desiredName) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFolder> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageFolder)->CreateFolderAsyncOverloadDefaultOptions(get_abi(desiredName), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFolder> consume_Windows_Storage_IStorageFolder<D>::CreateFolderAsync(param::hstring const& desiredName, Windows::Storage::CreationCollisionOption const& options) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFolder> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageFolder)->CreateFolderAsync(get_abi(desiredName), get_abi(options), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile> consume_Windows_Storage_IStorageFolder<D>::GetFileAsync(param::hstring const& name) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageFolder)->GetFileAsync(get_abi(name), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFolder> consume_Windows_Storage_IStorageFolder<D>::GetFolderAsync(param::hstring const& name) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFolder> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageFolder)->GetFolderAsync(get_abi(name), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::IStorageItem> consume_Windows_Storage_IStorageFolder<D>::GetItemAsync(param::hstring const& name) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::IStorageItem> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageFolder)->GetItemAsync(get_abi(name), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::StorageFile>> consume_Windows_Storage_IStorageFolder<D>::GetFilesAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::StorageFile>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageFolder)->GetFilesAsyncOverloadDefaultOptionsStartAndCount(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::StorageFolder>> consume_Windows_Storage_IStorageFolder<D>::GetFoldersAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::StorageFolder>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageFolder)->GetFoldersAsyncOverloadDefaultOptionsStartAndCount(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::IStorageItem>> consume_Windows_Storage_IStorageFolder<D>::GetItemsAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::IStorageItem>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageFolder)->GetItemsAsyncOverloadDefaultStartAndCount(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::IStorageItem> consume_Windows_Storage_IStorageFolder2<D>::TryGetItemAsync(param::hstring const& name) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::IStorageItem> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageFolder2)->TryGetItemAsync(get_abi(name), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Storage::StorageLibraryChangeTracker consume_Windows_Storage_IStorageFolder3<D>::TryGetChangeTracker() const
{
    Windows::Storage::StorageLibraryChangeTracker result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageFolder3)->TryGetChangeTracker(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFolder> consume_Windows_Storage_IStorageFolderStatics<D>::GetFolderFromPathAsync(param::hstring const& path) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFolder> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageFolderStatics)->GetFolderFromPathAsync(get_abi(path), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Storage_IStorageItem<D>::RenameAsync(param::hstring const& desiredName) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageItem)->RenameAsyncOverloadDefaultOptions(get_abi(desiredName), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Storage_IStorageItem<D>::RenameAsync(param::hstring const& desiredName, Windows::Storage::NameCollisionOption const& option) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageItem)->RenameAsync(get_abi(desiredName), get_abi(option), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Storage_IStorageItem<D>::DeleteAsync() const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageItem)->DeleteAsyncOverloadDefaultOptions(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Storage_IStorageItem<D>::DeleteAsync(Windows::Storage::StorageDeleteOption const& option) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageItem)->DeleteAsync(get_abi(option), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::FileProperties::BasicProperties> consume_Windows_Storage_IStorageItem<D>::GetBasicPropertiesAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::FileProperties::BasicProperties> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageItem)->GetBasicPropertiesAsync(put_abi(operation)));
    return operation;
}

template <typename D> hstring consume_Windows_Storage_IStorageItem<D>::Name() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageItem)->get_Name(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_IStorageItem<D>::Path() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageItem)->get_Path(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::FileAttributes consume_Windows_Storage_IStorageItem<D>::Attributes() const
{
    Windows::Storage::FileAttributes value{};
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageItem)->get_Attributes(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_Storage_IStorageItem<D>::DateCreated() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageItem)->get_DateCreated(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Storage_IStorageItem<D>::IsOfType(Windows::Storage::StorageItemTypes const& type) const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageItem)->IsOfType(get_abi(type), &value));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFolder> consume_Windows_Storage_IStorageItem2<D>::GetParentAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFolder> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageItem2)->GetParentAsync(put_abi(operation)));
    return operation;
}

template <typename D> bool consume_Windows_Storage_IStorageItem2<D>::IsEqual(Windows::Storage::IStorageItem const& item) const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageItem2)->IsEqual(get_abi(item), &value));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::FileProperties::StorageItemThumbnail> consume_Windows_Storage_IStorageItemProperties<D>::GetThumbnailAsync(Windows::Storage::FileProperties::ThumbnailMode const& mode) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::FileProperties::StorageItemThumbnail> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageItemProperties)->GetThumbnailAsyncOverloadDefaultSizeDefaultOptions(get_abi(mode), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::FileProperties::StorageItemThumbnail> consume_Windows_Storage_IStorageItemProperties<D>::GetThumbnailAsync(Windows::Storage::FileProperties::ThumbnailMode const& mode, uint32_t requestedSize) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::FileProperties::StorageItemThumbnail> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageItemProperties)->GetThumbnailAsyncOverloadDefaultOptions(get_abi(mode), requestedSize, put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::FileProperties::StorageItemThumbnail> consume_Windows_Storage_IStorageItemProperties<D>::GetThumbnailAsync(Windows::Storage::FileProperties::ThumbnailMode const& mode, uint32_t requestedSize, Windows::Storage::FileProperties::ThumbnailOptions const& options) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::FileProperties::StorageItemThumbnail> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageItemProperties)->GetThumbnailAsync(get_abi(mode), requestedSize, get_abi(options), put_abi(operation)));
    return operation;
}

template <typename D> hstring consume_Windows_Storage_IStorageItemProperties<D>::DisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageItemProperties)->get_DisplayName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_IStorageItemProperties<D>::DisplayType() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageItemProperties)->get_DisplayType(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_IStorageItemProperties<D>::FolderRelativeId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageItemProperties)->get_FolderRelativeId(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::FileProperties::StorageItemContentProperties consume_Windows_Storage_IStorageItemProperties<D>::Properties() const
{
    Windows::Storage::FileProperties::StorageItemContentProperties value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageItemProperties)->get_Properties(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::FileProperties::StorageItemThumbnail> consume_Windows_Storage_IStorageItemProperties2<D>::GetScaledImageAsThumbnailAsync(Windows::Storage::FileProperties::ThumbnailMode const& mode) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::FileProperties::StorageItemThumbnail> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageItemProperties2)->GetScaledImageAsThumbnailAsyncOverloadDefaultSizeDefaultOptions(get_abi(mode), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::FileProperties::StorageItemThumbnail> consume_Windows_Storage_IStorageItemProperties2<D>::GetScaledImageAsThumbnailAsync(Windows::Storage::FileProperties::ThumbnailMode const& mode, uint32_t requestedSize) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::FileProperties::StorageItemThumbnail> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageItemProperties2)->GetScaledImageAsThumbnailAsyncOverloadDefaultOptions(get_abi(mode), requestedSize, put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::FileProperties::StorageItemThumbnail> consume_Windows_Storage_IStorageItemProperties2<D>::GetScaledImageAsThumbnailAsync(Windows::Storage::FileProperties::ThumbnailMode const& mode, uint32_t requestedSize, Windows::Storage::FileProperties::ThumbnailOptions const& options) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::FileProperties::StorageItemThumbnail> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageItemProperties2)->GetScaledImageAsThumbnailAsync(get_abi(mode), requestedSize, get_abi(options), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Storage::StorageProvider consume_Windows_Storage_IStorageItemPropertiesWithProvider<D>::Provider() const
{
    Windows::Storage::StorageProvider value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageItemPropertiesWithProvider)->get_Provider(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFolder> consume_Windows_Storage_IStorageLibrary<D>::RequestAddFolderAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFolder> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageLibrary)->RequestAddFolderAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Storage_IStorageLibrary<D>::RequestRemoveFolderAsync(Windows::Storage::StorageFolder const& folder) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageLibrary)->RequestRemoveFolderAsync(get_abi(folder), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::Collections::IObservableVector<Windows::Storage::StorageFolder> consume_Windows_Storage_IStorageLibrary<D>::Folders() const
{
    Windows::Foundation::Collections::IObservableVector<Windows::Storage::StorageFolder> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageLibrary)->get_Folders(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::StorageFolder consume_Windows_Storage_IStorageLibrary<D>::SaveFolder() const
{
    Windows::Storage::StorageFolder value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageLibrary)->get_SaveFolder(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Storage_IStorageLibrary<D>::DefinitionChanged(Windows::Foundation::TypedEventHandler<Windows::Storage::StorageLibrary, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token eventCookie{};
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageLibrary)->add_DefinitionChanged(get_abi(handler), put_abi(eventCookie)));
    return eventCookie;
}

template <typename D> typename consume_Windows_Storage_IStorageLibrary<D>::DefinitionChanged_revoker consume_Windows_Storage_IStorageLibrary<D>::DefinitionChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Storage::StorageLibrary, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, DefinitionChanged_revoker>(this, DefinitionChanged(handler));
}

template <typename D> void consume_Windows_Storage_IStorageLibrary<D>::DefinitionChanged(winrt::event_token const& eventCookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Storage::IStorageLibrary)->remove_DefinitionChanged(get_abi(eventCookie)));
}

template <typename D> Windows::Storage::StorageLibraryChangeTracker consume_Windows_Storage_IStorageLibrary2<D>::ChangeTracker() const
{
    Windows::Storage::StorageLibraryChangeTracker value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageLibrary2)->get_ChangeTracker(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Storage_IStorageLibrary3<D>::AreFolderSuggestionsAvailableAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageLibrary3)->AreFolderSuggestionsAvailableAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Storage::StorageLibraryChangeType consume_Windows_Storage_IStorageLibraryChange<D>::ChangeType() const
{
    Windows::Storage::StorageLibraryChangeType value{};
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageLibraryChange)->get_ChangeType(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_IStorageLibraryChange<D>::Path() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageLibraryChange)->get_Path(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_IStorageLibraryChange<D>::PreviousPath() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageLibraryChange)->get_PreviousPath(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Storage_IStorageLibraryChange<D>::IsOfType(Windows::Storage::StorageItemTypes const& type) const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageLibraryChange)->IsOfType(get_abi(type), &value));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::IStorageItem> consume_Windows_Storage_IStorageLibraryChange<D>::GetStorageItemAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::IStorageItem> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageLibraryChange)->GetStorageItemAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::StorageLibraryChange>> consume_Windows_Storage_IStorageLibraryChangeReader<D>::ReadBatchAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::StorageLibraryChange>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageLibraryChangeReader)->ReadBatchAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Storage_IStorageLibraryChangeReader<D>::AcceptChangesAsync() const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageLibraryChangeReader)->AcceptChangesAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Storage::StorageLibraryChangeReader consume_Windows_Storage_IStorageLibraryChangeTracker<D>::GetChangeReader() const
{
    Windows::Storage::StorageLibraryChangeReader value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageLibraryChangeTracker)->GetChangeReader(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Storage_IStorageLibraryChangeTracker<D>::Enable() const
{
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageLibraryChangeTracker)->Enable());
}

template <typename D> void consume_Windows_Storage_IStorageLibraryChangeTracker<D>::Reset() const
{
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageLibraryChangeTracker)->Reset());
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::StorageLibrary> consume_Windows_Storage_IStorageLibraryStatics<D>::GetLibraryAsync(Windows::Storage::KnownLibraryId const& libraryId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::StorageLibrary> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageLibraryStatics)->GetLibraryAsync(get_abi(libraryId), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::StorageLibrary> consume_Windows_Storage_IStorageLibraryStatics2<D>::GetLibraryForUserAsync(Windows::System::User const& user, Windows::Storage::KnownLibraryId const& libraryId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::StorageLibrary> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageLibraryStatics2)->GetLibraryForUserAsync(get_abi(user), get_abi(libraryId), put_abi(operation)));
    return operation;
}

template <typename D> hstring consume_Windows_Storage_IStorageProvider<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageProvider)->get_Id(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_IStorageProvider<D>::DisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageProvider)->get_DisplayName(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Storage_IStorageProvider2<D>::IsPropertySupportedForPartialFileAsync(param::hstring const& propertyCanonicalName) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageProvider2)->IsPropertySupportedForPartialFileAsync(get_abi(propertyCanonicalName), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Storage::Streams::IRandomAccessStream consume_Windows_Storage_IStorageStreamTransaction<D>::Stream() const
{
    Windows::Storage::Streams::IRandomAccessStream value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageStreamTransaction)->get_Stream(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Storage_IStorageStreamTransaction<D>::CommitAsync() const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IStorageStreamTransaction)->CommitAsync(put_abi(operation)));
    return operation;
}

template <typename D> void consume_Windows_Storage_IStreamedFileDataRequest<D>::FailAndClose(Windows::Storage::StreamedFileFailureMode const& failureMode) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::IStreamedFileDataRequest)->FailAndClose(get_abi(failureMode)));
}

template <typename D> hstring consume_Windows_Storage_ISystemAudioProperties<D>::EncodingBitrate() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::ISystemAudioProperties)->get_EncodingBitrate(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_ISystemDataPaths<D>::Fonts() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::ISystemDataPaths)->get_Fonts(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_ISystemDataPaths<D>::ProgramData() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::ISystemDataPaths)->get_ProgramData(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_ISystemDataPaths<D>::Public() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::ISystemDataPaths)->get_Public(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_ISystemDataPaths<D>::PublicDesktop() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::ISystemDataPaths)->get_PublicDesktop(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_ISystemDataPaths<D>::PublicDocuments() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::ISystemDataPaths)->get_PublicDocuments(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_ISystemDataPaths<D>::PublicDownloads() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::ISystemDataPaths)->get_PublicDownloads(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_ISystemDataPaths<D>::PublicMusic() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::ISystemDataPaths)->get_PublicMusic(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_ISystemDataPaths<D>::PublicPictures() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::ISystemDataPaths)->get_PublicPictures(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_ISystemDataPaths<D>::PublicVideos() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::ISystemDataPaths)->get_PublicVideos(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_ISystemDataPaths<D>::System() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::ISystemDataPaths)->get_System(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_ISystemDataPaths<D>::SystemHost() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::ISystemDataPaths)->get_SystemHost(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_ISystemDataPaths<D>::SystemX86() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::ISystemDataPaths)->get_SystemX86(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_ISystemDataPaths<D>::SystemX64() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::ISystemDataPaths)->get_SystemX64(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_ISystemDataPaths<D>::SystemArm() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::ISystemDataPaths)->get_SystemArm(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_ISystemDataPaths<D>::UserProfiles() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::ISystemDataPaths)->get_UserProfiles(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_ISystemDataPaths<D>::Windows() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::ISystemDataPaths)->get_Windows(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::SystemDataPaths consume_Windows_Storage_ISystemDataPathsStatics<D>::GetDefault() const
{
    Windows::Storage::SystemDataPaths result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::ISystemDataPathsStatics)->GetDefault(put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Storage_ISystemGPSProperties<D>::LatitudeDecimal() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::ISystemGPSProperties)->get_LatitudeDecimal(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_ISystemGPSProperties<D>::LongitudeDecimal() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::ISystemGPSProperties)->get_LongitudeDecimal(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_ISystemImageProperties<D>::HorizontalSize() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::ISystemImageProperties)->get_HorizontalSize(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_ISystemImageProperties<D>::VerticalSize() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::ISystemImageProperties)->get_VerticalSize(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_ISystemMediaProperties<D>::Duration() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::ISystemMediaProperties)->get_Duration(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_ISystemMediaProperties<D>::Producer() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::ISystemMediaProperties)->get_Producer(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_ISystemMediaProperties<D>::Publisher() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::ISystemMediaProperties)->get_Publisher(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_ISystemMediaProperties<D>::SubTitle() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::ISystemMediaProperties)->get_SubTitle(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_ISystemMediaProperties<D>::Writer() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::ISystemMediaProperties)->get_Writer(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_ISystemMediaProperties<D>::Year() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::ISystemMediaProperties)->get_Year(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_ISystemMusicProperties<D>::AlbumArtist() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::ISystemMusicProperties)->get_AlbumArtist(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_ISystemMusicProperties<D>::AlbumTitle() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::ISystemMusicProperties)->get_AlbumTitle(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_ISystemMusicProperties<D>::Artist() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::ISystemMusicProperties)->get_Artist(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_ISystemMusicProperties<D>::Composer() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::ISystemMusicProperties)->get_Composer(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_ISystemMusicProperties<D>::Conductor() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::ISystemMusicProperties)->get_Conductor(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_ISystemMusicProperties<D>::DisplayArtist() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::ISystemMusicProperties)->get_DisplayArtist(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_ISystemMusicProperties<D>::Genre() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::ISystemMusicProperties)->get_Genre(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_ISystemMusicProperties<D>::TrackNumber() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::ISystemMusicProperties)->get_TrackNumber(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_ISystemPhotoProperties<D>::CameraManufacturer() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::ISystemPhotoProperties)->get_CameraManufacturer(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_ISystemPhotoProperties<D>::CameraModel() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::ISystemPhotoProperties)->get_CameraModel(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_ISystemPhotoProperties<D>::DateTaken() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::ISystemPhotoProperties)->get_DateTaken(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_ISystemPhotoProperties<D>::Orientation() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::ISystemPhotoProperties)->get_Orientation(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_ISystemPhotoProperties<D>::PeopleNames() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::ISystemPhotoProperties)->get_PeopleNames(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_ISystemProperties<D>::Author() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::ISystemProperties)->get_Author(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_ISystemProperties<D>::Comment() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::ISystemProperties)->get_Comment(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_ISystemProperties<D>::ItemNameDisplay() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::ISystemProperties)->get_ItemNameDisplay(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_ISystemProperties<D>::Keywords() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::ISystemProperties)->get_Keywords(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_ISystemProperties<D>::Rating() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::ISystemProperties)->get_Rating(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_ISystemProperties<D>::Title() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::ISystemProperties)->get_Title(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::SystemAudioProperties consume_Windows_Storage_ISystemProperties<D>::Audio() const
{
    Windows::Storage::SystemAudioProperties value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::ISystemProperties)->get_Audio(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::SystemGPSProperties consume_Windows_Storage_ISystemProperties<D>::GPS() const
{
    Windows::Storage::SystemGPSProperties value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::ISystemProperties)->get_GPS(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::SystemMediaProperties consume_Windows_Storage_ISystemProperties<D>::Media() const
{
    Windows::Storage::SystemMediaProperties value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::ISystemProperties)->get_Media(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::SystemMusicProperties consume_Windows_Storage_ISystemProperties<D>::Music() const
{
    Windows::Storage::SystemMusicProperties value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::ISystemProperties)->get_Music(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::SystemPhotoProperties consume_Windows_Storage_ISystemProperties<D>::Photo() const
{
    Windows::Storage::SystemPhotoProperties value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::ISystemProperties)->get_Photo(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::SystemVideoProperties consume_Windows_Storage_ISystemProperties<D>::Video() const
{
    Windows::Storage::SystemVideoProperties value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::ISystemProperties)->get_Video(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::SystemImageProperties consume_Windows_Storage_ISystemProperties<D>::Image() const
{
    Windows::Storage::SystemImageProperties value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::ISystemProperties)->get_Image(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_ISystemVideoProperties<D>::Director() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::ISystemVideoProperties)->get_Director(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_ISystemVideoProperties<D>::FrameHeight() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::ISystemVideoProperties)->get_FrameHeight(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_ISystemVideoProperties<D>::FrameWidth() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::ISystemVideoProperties)->get_FrameWidth(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_ISystemVideoProperties<D>::Orientation() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::ISystemVideoProperties)->get_Orientation(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_ISystemVideoProperties<D>::TotalBitrate() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::ISystemVideoProperties)->get_TotalBitrate(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_IUserDataPaths<D>::CameraRoll() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::IUserDataPaths)->get_CameraRoll(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_IUserDataPaths<D>::Cookies() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::IUserDataPaths)->get_Cookies(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_IUserDataPaths<D>::Desktop() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::IUserDataPaths)->get_Desktop(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_IUserDataPaths<D>::Documents() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::IUserDataPaths)->get_Documents(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_IUserDataPaths<D>::Downloads() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::IUserDataPaths)->get_Downloads(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_IUserDataPaths<D>::Favorites() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::IUserDataPaths)->get_Favorites(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_IUserDataPaths<D>::History() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::IUserDataPaths)->get_History(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_IUserDataPaths<D>::InternetCache() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::IUserDataPaths)->get_InternetCache(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_IUserDataPaths<D>::LocalAppData() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::IUserDataPaths)->get_LocalAppData(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_IUserDataPaths<D>::LocalAppDataLow() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::IUserDataPaths)->get_LocalAppDataLow(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_IUserDataPaths<D>::Music() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::IUserDataPaths)->get_Music(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_IUserDataPaths<D>::Pictures() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::IUserDataPaths)->get_Pictures(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_IUserDataPaths<D>::Profile() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::IUserDataPaths)->get_Profile(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_IUserDataPaths<D>::Recent() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::IUserDataPaths)->get_Recent(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_IUserDataPaths<D>::RoamingAppData() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::IUserDataPaths)->get_RoamingAppData(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_IUserDataPaths<D>::SavedPictures() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::IUserDataPaths)->get_SavedPictures(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_IUserDataPaths<D>::Screenshots() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::IUserDataPaths)->get_Screenshots(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_IUserDataPaths<D>::Templates() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::IUserDataPaths)->get_Templates(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_IUserDataPaths<D>::Videos() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::IUserDataPaths)->get_Videos(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::UserDataPaths consume_Windows_Storage_IUserDataPathsStatics<D>::GetForUser(Windows::System::User const& user) const
{
    Windows::Storage::UserDataPaths result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IUserDataPathsStatics)->GetForUser(get_abi(user), put_abi(result)));
    return result;
}

template <typename D> Windows::Storage::UserDataPaths consume_Windows_Storage_IUserDataPathsStatics<D>::GetDefault() const
{
    Windows::Storage::UserDataPaths result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::IUserDataPathsStatics)->GetDefault(put_abi(result)));
    return result;
}

template <> struct delegate<Windows::Storage::ApplicationDataSetVersionHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::Storage::ApplicationDataSetVersionHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::Storage::ApplicationDataSetVersionHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* setVersionRequest) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Storage::SetVersionRequest const*>(&setVersionRequest));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <> struct delegate<Windows::Storage::StreamedFileDataRequestedHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::Storage::StreamedFileDataRequestedHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::Storage::StreamedFileDataRequestedHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* stream) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Storage::StreamedFileDataRequest const*>(&stream));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <typename D>
struct produce<D, Windows::Storage::IAppDataPaths> : produce_base<D, Windows::Storage::IAppDataPaths>
{
    int32_t WINRT_CALL get_Cookies(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Cookies, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Cookies());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Desktop(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Desktop, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Desktop());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Documents(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Documents, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Documents());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Favorites(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Favorites, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Favorites());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_History(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(History, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().History());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InternetCache(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InternetCache, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().InternetCache());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LocalAppData(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LocalAppData, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().LocalAppData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProgramData(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProgramData, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ProgramData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RoamingAppData(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RoamingAppData, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().RoamingAppData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::IAppDataPathsStatics> : produce_base<D, Windows::Storage::IAppDataPathsStatics>
{
    int32_t WINRT_CALL GetForUser(void* user, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForUser, WINRT_WRAP(Windows::Storage::AppDataPaths), Windows::System::User const&);
            *result = detach_from<Windows::Storage::AppDataPaths>(this->shim().GetForUser(*reinterpret_cast<Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDefault(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefault, WINRT_WRAP(Windows::Storage::AppDataPaths));
            *result = detach_from<Windows::Storage::AppDataPaths>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::IApplicationData> : produce_base<D, Windows::Storage::IApplicationData>
{
    int32_t WINRT_CALL get_Version(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Version, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Version());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetVersionAsync(uint32_t desiredVersion, void* handler, void** setVersionOperation) noexcept final
    {
        try
        {
            *setVersionOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetVersionAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), uint32_t, Windows::Storage::ApplicationDataSetVersionHandler const);
            *setVersionOperation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SetVersionAsync(desiredVersion, *reinterpret_cast<Windows::Storage::ApplicationDataSetVersionHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ClearAllAsync(void** clearOperation) noexcept final
    {
        try
        {
            *clearOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClearAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *clearOperation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ClearAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ClearAsync(Windows::Storage::ApplicationDataLocality locality, void** clearOperation) noexcept final
    {
        try
        {
            *clearOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClearAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Storage::ApplicationDataLocality const);
            *clearOperation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ClearAsync(*reinterpret_cast<Windows::Storage::ApplicationDataLocality const*>(&locality)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LocalSettings(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LocalSettings, WINRT_WRAP(Windows::Storage::ApplicationDataContainer));
            *value = detach_from<Windows::Storage::ApplicationDataContainer>(this->shim().LocalSettings());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RoamingSettings(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RoamingSettings, WINRT_WRAP(Windows::Storage::ApplicationDataContainer));
            *value = detach_from<Windows::Storage::ApplicationDataContainer>(this->shim().RoamingSettings());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LocalFolder(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LocalFolder, WINRT_WRAP(Windows::Storage::StorageFolder));
            *value = detach_from<Windows::Storage::StorageFolder>(this->shim().LocalFolder());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RoamingFolder(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RoamingFolder, WINRT_WRAP(Windows::Storage::StorageFolder));
            *value = detach_from<Windows::Storage::StorageFolder>(this->shim().RoamingFolder());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TemporaryFolder(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TemporaryFolder, WINRT_WRAP(Windows::Storage::StorageFolder));
            *value = detach_from<Windows::Storage::StorageFolder>(this->shim().TemporaryFolder());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_DataChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DataChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Storage::ApplicationData, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().DataChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Storage::ApplicationData, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_DataChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(DataChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().DataChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL SignalDataChanged() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SignalDataChanged, WINRT_WRAP(void));
            this->shim().SignalDataChanged();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RoamingStorageQuota(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RoamingStorageQuota, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().RoamingStorageQuota());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::IApplicationData2> : produce_base<D, Windows::Storage::IApplicationData2>
{
    int32_t WINRT_CALL get_LocalCacheFolder(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LocalCacheFolder, WINRT_WRAP(Windows::Storage::StorageFolder));
            *value = detach_from<Windows::Storage::StorageFolder>(this->shim().LocalCacheFolder());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::IApplicationData3> : produce_base<D, Windows::Storage::IApplicationData3>
{
    int32_t WINRT_CALL GetPublisherCacheFolder(void* folderName, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetPublisherCacheFolder, WINRT_WRAP(Windows::Storage::StorageFolder), hstring const&);
            *value = detach_from<Windows::Storage::StorageFolder>(this->shim().GetPublisherCacheFolder(*reinterpret_cast<hstring const*>(&folderName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ClearPublisherCacheFolderAsync(void* folderName, void** clearOperation) noexcept final
    {
        try
        {
            *clearOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClearPublisherCacheFolderAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), hstring const);
            *clearOperation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ClearPublisherCacheFolderAsync(*reinterpret_cast<hstring const*>(&folderName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SharedLocalFolder(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SharedLocalFolder, WINRT_WRAP(Windows::Storage::StorageFolder));
            *value = detach_from<Windows::Storage::StorageFolder>(this->shim().SharedLocalFolder());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::IApplicationDataContainer> : produce_base<D, Windows::Storage::IApplicationDataContainer>
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

    int32_t WINRT_CALL get_Locality(Windows::Storage::ApplicationDataLocality* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Locality, WINRT_WRAP(Windows::Storage::ApplicationDataLocality));
            *value = detach_from<Windows::Storage::ApplicationDataLocality>(this->shim().Locality());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Values(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Values, WINRT_WRAP(Windows::Foundation::Collections::IPropertySet));
            *value = detach_from<Windows::Foundation::Collections::IPropertySet>(this->shim().Values());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Containers(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Containers, WINRT_WRAP(Windows::Foundation::Collections::IMapView<hstring, Windows::Storage::ApplicationDataContainer>));
            *value = detach_from<Windows::Foundation::Collections::IMapView<hstring, Windows::Storage::ApplicationDataContainer>>(this->shim().Containers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateContainer(void* name, Windows::Storage::ApplicationDataCreateDisposition disposition, void** container) noexcept final
    {
        try
        {
            *container = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateContainer, WINRT_WRAP(Windows::Storage::ApplicationDataContainer), hstring const&, Windows::Storage::ApplicationDataCreateDisposition const&);
            *container = detach_from<Windows::Storage::ApplicationDataContainer>(this->shim().CreateContainer(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<Windows::Storage::ApplicationDataCreateDisposition const*>(&disposition)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DeleteContainer(void* name) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeleteContainer, WINRT_WRAP(void), hstring const&);
            this->shim().DeleteContainer(*reinterpret_cast<hstring const*>(&name));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::IApplicationDataStatics> : produce_base<D, Windows::Storage::IApplicationDataStatics>
{
    int32_t WINRT_CALL get_Current(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Current, WINRT_WRAP(Windows::Storage::ApplicationData));
            *value = detach_from<Windows::Storage::ApplicationData>(this->shim().Current());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::IApplicationDataStatics2> : produce_base<D, Windows::Storage::IApplicationDataStatics2>
{
    int32_t WINRT_CALL GetForUserAsync(void* user, void** getForUserOperation) noexcept final
    {
        try
        {
            *getForUserOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForUserAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::ApplicationData>), Windows::System::User const);
            *getForUserOperation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::ApplicationData>>(this->shim().GetForUserAsync(*reinterpret_cast<Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::ICachedFileManagerStatics> : produce_base<D, Windows::Storage::ICachedFileManagerStatics>
{
    int32_t WINRT_CALL DeferUpdates(void* file) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeferUpdates, WINRT_WRAP(void), Windows::Storage::IStorageFile const&);
            this->shim().DeferUpdates(*reinterpret_cast<Windows::Storage::IStorageFile const*>(&file));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CompleteUpdatesAsync(void* file, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CompleteUpdatesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::Provider::FileUpdateStatus>), Windows::Storage::IStorageFile const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::Provider::FileUpdateStatus>>(this->shim().CompleteUpdatesAsync(*reinterpret_cast<Windows::Storage::IStorageFile const*>(&file)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::IDownloadsFolderStatics> : produce_base<D, Windows::Storage::IDownloadsFolderStatics>
{
    int32_t WINRT_CALL CreateFileAsync(void* desiredName, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFileAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile>>(this->shim().CreateFileAsync(*reinterpret_cast<hstring const*>(&desiredName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFolderAsync(void* desiredName, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFolderAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFolder>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFolder>>(this->shim().CreateFolderAsync(*reinterpret_cast<hstring const*>(&desiredName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFileWithCollisionOptionAsync(void* desiredName, Windows::Storage::CreationCollisionOption option, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFileAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile>), hstring const, Windows::Storage::CreationCollisionOption const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile>>(this->shim().CreateFileAsync(*reinterpret_cast<hstring const*>(&desiredName), *reinterpret_cast<Windows::Storage::CreationCollisionOption const*>(&option)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFolderWithCollisionOptionAsync(void* desiredName, Windows::Storage::CreationCollisionOption option, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFolderAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFolder>), hstring const, Windows::Storage::CreationCollisionOption const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFolder>>(this->shim().CreateFolderAsync(*reinterpret_cast<hstring const*>(&desiredName), *reinterpret_cast<Windows::Storage::CreationCollisionOption const*>(&option)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::IDownloadsFolderStatics2> : produce_base<D, Windows::Storage::IDownloadsFolderStatics2>
{
    int32_t WINRT_CALL CreateFileForUserAsync(void* user, void* desiredName, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFileForUserAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile>), Windows::System::User const, hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile>>(this->shim().CreateFileForUserAsync(*reinterpret_cast<Windows::System::User const*>(&user), *reinterpret_cast<hstring const*>(&desiredName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFolderForUserAsync(void* user, void* desiredName, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFolderForUserAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFolder>), Windows::System::User const, hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFolder>>(this->shim().CreateFolderForUserAsync(*reinterpret_cast<Windows::System::User const*>(&user), *reinterpret_cast<hstring const*>(&desiredName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFileForUserWithCollisionOptionAsync(void* user, void* desiredName, Windows::Storage::CreationCollisionOption option, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFileForUserAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile>), Windows::System::User const, hstring const, Windows::Storage::CreationCollisionOption const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile>>(this->shim().CreateFileForUserAsync(*reinterpret_cast<Windows::System::User const*>(&user), *reinterpret_cast<hstring const*>(&desiredName), *reinterpret_cast<Windows::Storage::CreationCollisionOption const*>(&option)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFolderForUserWithCollisionOptionAsync(void* user, void* desiredName, Windows::Storage::CreationCollisionOption option, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFolderForUserAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFolder>), Windows::System::User const, hstring const, Windows::Storage::CreationCollisionOption const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFolder>>(this->shim().CreateFolderForUserAsync(*reinterpret_cast<Windows::System::User const*>(&user), *reinterpret_cast<hstring const*>(&desiredName), *reinterpret_cast<Windows::Storage::CreationCollisionOption const*>(&option)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::IFileIOStatics> : produce_base<D, Windows::Storage::IFileIOStatics>
{
    int32_t WINRT_CALL ReadTextAsync(void* file, void** textOperation) noexcept final
    {
        try
        {
            *textOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadTextAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<hstring>), Windows::Storage::IStorageFile const);
            *textOperation = detach_from<Windows::Foundation::IAsyncOperation<hstring>>(this->shim().ReadTextAsync(*reinterpret_cast<Windows::Storage::IStorageFile const*>(&file)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReadTextWithEncodingAsync(void* file, Windows::Storage::Streams::UnicodeEncoding encoding, void** textOperation) noexcept final
    {
        try
        {
            *textOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadTextAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<hstring>), Windows::Storage::IStorageFile const, Windows::Storage::Streams::UnicodeEncoding const);
            *textOperation = detach_from<Windows::Foundation::IAsyncOperation<hstring>>(this->shim().ReadTextAsync(*reinterpret_cast<Windows::Storage::IStorageFile const*>(&file), *reinterpret_cast<Windows::Storage::Streams::UnicodeEncoding const*>(&encoding)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL WriteTextAsync(void* file, void* contents, void** textOperation) noexcept final
    {
        try
        {
            *textOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WriteTextAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Storage::IStorageFile const, hstring const);
            *textOperation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().WriteTextAsync(*reinterpret_cast<Windows::Storage::IStorageFile const*>(&file), *reinterpret_cast<hstring const*>(&contents)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL WriteTextWithEncodingAsync(void* file, void* contents, Windows::Storage::Streams::UnicodeEncoding encoding, void** textOperation) noexcept final
    {
        try
        {
            *textOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WriteTextAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Storage::IStorageFile const, hstring const, Windows::Storage::Streams::UnicodeEncoding const);
            *textOperation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().WriteTextAsync(*reinterpret_cast<Windows::Storage::IStorageFile const*>(&file), *reinterpret_cast<hstring const*>(&contents), *reinterpret_cast<Windows::Storage::Streams::UnicodeEncoding const*>(&encoding)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AppendTextAsync(void* file, void* contents, void** textOperation) noexcept final
    {
        try
        {
            *textOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppendTextAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Storage::IStorageFile const, hstring const);
            *textOperation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().AppendTextAsync(*reinterpret_cast<Windows::Storage::IStorageFile const*>(&file), *reinterpret_cast<hstring const*>(&contents)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AppendTextWithEncodingAsync(void* file, void* contents, Windows::Storage::Streams::UnicodeEncoding encoding, void** textOperation) noexcept final
    {
        try
        {
            *textOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppendTextAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Storage::IStorageFile const, hstring const, Windows::Storage::Streams::UnicodeEncoding const);
            *textOperation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().AppendTextAsync(*reinterpret_cast<Windows::Storage::IStorageFile const*>(&file), *reinterpret_cast<hstring const*>(&contents), *reinterpret_cast<Windows::Storage::Streams::UnicodeEncoding const*>(&encoding)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReadLinesAsync(void* file, void** linesOperation) noexcept final
    {
        try
        {
            *linesOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadLinesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<hstring>>), Windows::Storage::IStorageFile const);
            *linesOperation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<hstring>>>(this->shim().ReadLinesAsync(*reinterpret_cast<Windows::Storage::IStorageFile const*>(&file)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReadLinesWithEncodingAsync(void* file, Windows::Storage::Streams::UnicodeEncoding encoding, void** linesOperation) noexcept final
    {
        try
        {
            *linesOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadLinesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<hstring>>), Windows::Storage::IStorageFile const, Windows::Storage::Streams::UnicodeEncoding const);
            *linesOperation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<hstring>>>(this->shim().ReadLinesAsync(*reinterpret_cast<Windows::Storage::IStorageFile const*>(&file), *reinterpret_cast<Windows::Storage::Streams::UnicodeEncoding const*>(&encoding)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL WriteLinesAsync(void* file, void* lines, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WriteLinesAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Storage::IStorageFile const, Windows::Foundation::Collections::IIterable<hstring> const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().WriteLinesAsync(*reinterpret_cast<Windows::Storage::IStorageFile const*>(&file), *reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&lines)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL WriteLinesWithEncodingAsync(void* file, void* lines, Windows::Storage::Streams::UnicodeEncoding encoding, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WriteLinesAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Storage::IStorageFile const, Windows::Foundation::Collections::IIterable<hstring> const, Windows::Storage::Streams::UnicodeEncoding const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().WriteLinesAsync(*reinterpret_cast<Windows::Storage::IStorageFile const*>(&file), *reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&lines), *reinterpret_cast<Windows::Storage::Streams::UnicodeEncoding const*>(&encoding)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AppendLinesAsync(void* file, void* lines, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppendLinesAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Storage::IStorageFile const, Windows::Foundation::Collections::IIterable<hstring> const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().AppendLinesAsync(*reinterpret_cast<Windows::Storage::IStorageFile const*>(&file), *reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&lines)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AppendLinesWithEncodingAsync(void* file, void* lines, Windows::Storage::Streams::UnicodeEncoding encoding, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppendLinesAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Storage::IStorageFile const, Windows::Foundation::Collections::IIterable<hstring> const, Windows::Storage::Streams::UnicodeEncoding const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().AppendLinesAsync(*reinterpret_cast<Windows::Storage::IStorageFile const*>(&file), *reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&lines), *reinterpret_cast<Windows::Storage::Streams::UnicodeEncoding const*>(&encoding)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReadBufferAsync(void* file, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadBufferAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer>), Windows::Storage::IStorageFile const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer>>(this->shim().ReadBufferAsync(*reinterpret_cast<Windows::Storage::IStorageFile const*>(&file)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL WriteBufferAsync(void* file, void* buffer, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WriteBufferAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Storage::IStorageFile const, Windows::Storage::Streams::IBuffer const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().WriteBufferAsync(*reinterpret_cast<Windows::Storage::IStorageFile const*>(&file), *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&buffer)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL WriteBytesAsync(void* file, uint32_t __bufferSize, uint8_t* buffer, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WriteBytesAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Storage::IStorageFile const, array_view<uint8_t const>);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().WriteBytesAsync(*reinterpret_cast<Windows::Storage::IStorageFile const*>(&file), array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(buffer), reinterpret_cast<uint8_t const *>(buffer) + __bufferSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::IKnownFoldersCameraRollStatics> : produce_base<D, Windows::Storage::IKnownFoldersCameraRollStatics>
{
    int32_t WINRT_CALL get_CameraRoll(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CameraRoll, WINRT_WRAP(Windows::Storage::StorageFolder));
            *value = detach_from<Windows::Storage::StorageFolder>(this->shim().CameraRoll());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::IKnownFoldersPlaylistsStatics> : produce_base<D, Windows::Storage::IKnownFoldersPlaylistsStatics>
{
    int32_t WINRT_CALL get_Playlists(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Playlists, WINRT_WRAP(Windows::Storage::StorageFolder));
            *value = detach_from<Windows::Storage::StorageFolder>(this->shim().Playlists());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::IKnownFoldersSavedPicturesStatics> : produce_base<D, Windows::Storage::IKnownFoldersSavedPicturesStatics>
{
    int32_t WINRT_CALL get_SavedPictures(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SavedPictures, WINRT_WRAP(Windows::Storage::StorageFolder));
            *value = detach_from<Windows::Storage::StorageFolder>(this->shim().SavedPictures());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::IKnownFoldersStatics> : produce_base<D, Windows::Storage::IKnownFoldersStatics>
{
    int32_t WINRT_CALL get_MusicLibrary(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MusicLibrary, WINRT_WRAP(Windows::Storage::StorageFolder));
            *value = detach_from<Windows::Storage::StorageFolder>(this->shim().MusicLibrary());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PicturesLibrary(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PicturesLibrary, WINRT_WRAP(Windows::Storage::StorageFolder));
            *value = detach_from<Windows::Storage::StorageFolder>(this->shim().PicturesLibrary());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VideosLibrary(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideosLibrary, WINRT_WRAP(Windows::Storage::StorageFolder));
            *value = detach_from<Windows::Storage::StorageFolder>(this->shim().VideosLibrary());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DocumentsLibrary(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DocumentsLibrary, WINRT_WRAP(Windows::Storage::StorageFolder));
            *value = detach_from<Windows::Storage::StorageFolder>(this->shim().DocumentsLibrary());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HomeGroup(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HomeGroup, WINRT_WRAP(Windows::Storage::StorageFolder));
            *value = detach_from<Windows::Storage::StorageFolder>(this->shim().HomeGroup());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RemovableDevices(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemovableDevices, WINRT_WRAP(Windows::Storage::StorageFolder));
            *value = detach_from<Windows::Storage::StorageFolder>(this->shim().RemovableDevices());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MediaServerDevices(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MediaServerDevices, WINRT_WRAP(Windows::Storage::StorageFolder));
            *value = detach_from<Windows::Storage::StorageFolder>(this->shim().MediaServerDevices());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::IKnownFoldersStatics2> : produce_base<D, Windows::Storage::IKnownFoldersStatics2>
{
    int32_t WINRT_CALL get_Objects3D(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Objects3D, WINRT_WRAP(Windows::Storage::StorageFolder));
            *value = detach_from<Windows::Storage::StorageFolder>(this->shim().Objects3D());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AppCaptures(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppCaptures, WINRT_WRAP(Windows::Storage::StorageFolder));
            *value = detach_from<Windows::Storage::StorageFolder>(this->shim().AppCaptures());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RecordedCalls(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RecordedCalls, WINRT_WRAP(Windows::Storage::StorageFolder));
            *value = detach_from<Windows::Storage::StorageFolder>(this->shim().RecordedCalls());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::IKnownFoldersStatics3> : produce_base<D, Windows::Storage::IKnownFoldersStatics3>
{
    int32_t WINRT_CALL GetFolderForUserAsync(void* user, Windows::Storage::KnownFolderId folderId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetFolderForUserAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFolder>), Windows::System::User const, Windows::Storage::KnownFolderId const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFolder>>(this->shim().GetFolderForUserAsync(*reinterpret_cast<Windows::System::User const*>(&user), *reinterpret_cast<Windows::Storage::KnownFolderId const*>(&folderId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::IPathIOStatics> : produce_base<D, Windows::Storage::IPathIOStatics>
{
    int32_t WINRT_CALL ReadTextAsync(void* absolutePath, void** textOperation) noexcept final
    {
        try
        {
            *textOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadTextAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<hstring>), hstring const);
            *textOperation = detach_from<Windows::Foundation::IAsyncOperation<hstring>>(this->shim().ReadTextAsync(*reinterpret_cast<hstring const*>(&absolutePath)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReadTextWithEncodingAsync(void* absolutePath, Windows::Storage::Streams::UnicodeEncoding encoding, void** textOperation) noexcept final
    {
        try
        {
            *textOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadTextAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<hstring>), hstring const, Windows::Storage::Streams::UnicodeEncoding const);
            *textOperation = detach_from<Windows::Foundation::IAsyncOperation<hstring>>(this->shim().ReadTextAsync(*reinterpret_cast<hstring const*>(&absolutePath), *reinterpret_cast<Windows::Storage::Streams::UnicodeEncoding const*>(&encoding)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL WriteTextAsync(void* absolutePath, void* contents, void** textOperation) noexcept final
    {
        try
        {
            *textOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WriteTextAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), hstring const, hstring const);
            *textOperation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().WriteTextAsync(*reinterpret_cast<hstring const*>(&absolutePath), *reinterpret_cast<hstring const*>(&contents)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL WriteTextWithEncodingAsync(void* absolutePath, void* contents, Windows::Storage::Streams::UnicodeEncoding encoding, void** textOperation) noexcept final
    {
        try
        {
            *textOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WriteTextAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), hstring const, hstring const, Windows::Storage::Streams::UnicodeEncoding const);
            *textOperation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().WriteTextAsync(*reinterpret_cast<hstring const*>(&absolutePath), *reinterpret_cast<hstring const*>(&contents), *reinterpret_cast<Windows::Storage::Streams::UnicodeEncoding const*>(&encoding)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AppendTextAsync(void* absolutePath, void* contents, void** textOperation) noexcept final
    {
        try
        {
            *textOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppendTextAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), hstring const, hstring const);
            *textOperation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().AppendTextAsync(*reinterpret_cast<hstring const*>(&absolutePath), *reinterpret_cast<hstring const*>(&contents)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AppendTextWithEncodingAsync(void* absolutePath, void* contents, Windows::Storage::Streams::UnicodeEncoding encoding, void** textOperation) noexcept final
    {
        try
        {
            *textOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppendTextAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), hstring const, hstring const, Windows::Storage::Streams::UnicodeEncoding const);
            *textOperation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().AppendTextAsync(*reinterpret_cast<hstring const*>(&absolutePath), *reinterpret_cast<hstring const*>(&contents), *reinterpret_cast<Windows::Storage::Streams::UnicodeEncoding const*>(&encoding)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReadLinesAsync(void* absolutePath, void** linesOperation) noexcept final
    {
        try
        {
            *linesOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadLinesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<hstring>>), hstring const);
            *linesOperation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<hstring>>>(this->shim().ReadLinesAsync(*reinterpret_cast<hstring const*>(&absolutePath)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReadLinesWithEncodingAsync(void* absolutePath, Windows::Storage::Streams::UnicodeEncoding encoding, void** linesOperation) noexcept final
    {
        try
        {
            *linesOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadLinesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<hstring>>), hstring const, Windows::Storage::Streams::UnicodeEncoding const);
            *linesOperation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<hstring>>>(this->shim().ReadLinesAsync(*reinterpret_cast<hstring const*>(&absolutePath), *reinterpret_cast<Windows::Storage::Streams::UnicodeEncoding const*>(&encoding)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL WriteLinesAsync(void* absolutePath, void* lines, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WriteLinesAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), hstring const, Windows::Foundation::Collections::IIterable<hstring> const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().WriteLinesAsync(*reinterpret_cast<hstring const*>(&absolutePath), *reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&lines)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL WriteLinesWithEncodingAsync(void* absolutePath, void* lines, Windows::Storage::Streams::UnicodeEncoding encoding, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WriteLinesAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), hstring const, Windows::Foundation::Collections::IIterable<hstring> const, Windows::Storage::Streams::UnicodeEncoding const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().WriteLinesAsync(*reinterpret_cast<hstring const*>(&absolutePath), *reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&lines), *reinterpret_cast<Windows::Storage::Streams::UnicodeEncoding const*>(&encoding)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AppendLinesAsync(void* absolutePath, void* lines, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppendLinesAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), hstring const, Windows::Foundation::Collections::IIterable<hstring> const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().AppendLinesAsync(*reinterpret_cast<hstring const*>(&absolutePath), *reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&lines)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AppendLinesWithEncodingAsync(void* absolutePath, void* lines, Windows::Storage::Streams::UnicodeEncoding encoding, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppendLinesAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), hstring const, Windows::Foundation::Collections::IIterable<hstring> const, Windows::Storage::Streams::UnicodeEncoding const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().AppendLinesAsync(*reinterpret_cast<hstring const*>(&absolutePath), *reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&lines), *reinterpret_cast<Windows::Storage::Streams::UnicodeEncoding const*>(&encoding)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReadBufferAsync(void* absolutePath, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadBufferAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer>>(this->shim().ReadBufferAsync(*reinterpret_cast<hstring const*>(&absolutePath)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL WriteBufferAsync(void* absolutePath, void* buffer, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WriteBufferAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), hstring const, Windows::Storage::Streams::IBuffer const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().WriteBufferAsync(*reinterpret_cast<hstring const*>(&absolutePath), *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&buffer)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL WriteBytesAsync(void* absolutePath, uint32_t __bufferSize, uint8_t* buffer, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WriteBytesAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), hstring const, array_view<uint8_t const>);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().WriteBytesAsync(*reinterpret_cast<hstring const*>(&absolutePath), array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(buffer), reinterpret_cast<uint8_t const *>(buffer) + __bufferSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::ISetVersionDeferral> : produce_base<D, Windows::Storage::ISetVersionDeferral>
{
    int32_t WINRT_CALL Complete() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Complete, WINRT_WRAP(void));
            this->shim().Complete();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::ISetVersionRequest> : produce_base<D, Windows::Storage::ISetVersionRequest>
{
    int32_t WINRT_CALL get_CurrentVersion(uint32_t* currentVersion) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CurrentVersion, WINRT_WRAP(uint32_t));
            *currentVersion = detach_from<uint32_t>(this->shim().CurrentVersion());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DesiredVersion(uint32_t* desiredVersion) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesiredVersion, WINRT_WRAP(uint32_t));
            *desiredVersion = detach_from<uint32_t>(this->shim().DesiredVersion());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeferral(void** deferral) noexcept final
    {
        try
        {
            *deferral = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeferral, WINRT_WRAP(Windows::Storage::SetVersionDeferral));
            *deferral = detach_from<Windows::Storage::SetVersionDeferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::IStorageFile> : produce_base<D, Windows::Storage::IStorageFile>
{
    int32_t WINRT_CALL get_FileType(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FileType, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().FileType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ContentType(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentType, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ContentType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL OpenAsync(Windows::Storage::FileAccessMode accessMode, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OpenAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStream>), Windows::Storage::FileAccessMode const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStream>>(this->shim().OpenAsync(*reinterpret_cast<Windows::Storage::FileAccessMode const*>(&accessMode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL OpenTransactedWriteAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OpenTransactedWriteAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::StorageStreamTransaction>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::StorageStreamTransaction>>(this->shim().OpenTransactedWriteAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CopyOverloadDefaultNameAndOptions(void* destinationFolder, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CopyAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile>), Windows::Storage::IStorageFolder const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile>>(this->shim().CopyAsync(*reinterpret_cast<Windows::Storage::IStorageFolder const*>(&destinationFolder)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CopyOverloadDefaultOptions(void* destinationFolder, void* desiredNewName, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CopyAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile>), Windows::Storage::IStorageFolder const, hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile>>(this->shim().CopyAsync(*reinterpret_cast<Windows::Storage::IStorageFolder const*>(&destinationFolder), *reinterpret_cast<hstring const*>(&desiredNewName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CopyOverload(void* destinationFolder, void* desiredNewName, Windows::Storage::NameCollisionOption option, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CopyAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile>), Windows::Storage::IStorageFolder const, hstring const, Windows::Storage::NameCollisionOption const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile>>(this->shim().CopyAsync(*reinterpret_cast<Windows::Storage::IStorageFolder const*>(&destinationFolder), *reinterpret_cast<hstring const*>(&desiredNewName), *reinterpret_cast<Windows::Storage::NameCollisionOption const*>(&option)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CopyAndReplaceAsync(void* fileToReplace, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CopyAndReplaceAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Storage::IStorageFile const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().CopyAndReplaceAsync(*reinterpret_cast<Windows::Storage::IStorageFile const*>(&fileToReplace)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL MoveOverloadDefaultNameAndOptions(void* destinationFolder, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MoveAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Storage::IStorageFolder const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().MoveAsync(*reinterpret_cast<Windows::Storage::IStorageFolder const*>(&destinationFolder)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL MoveOverloadDefaultOptions(void* destinationFolder, void* desiredNewName, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MoveAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Storage::IStorageFolder const, hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().MoveAsync(*reinterpret_cast<Windows::Storage::IStorageFolder const*>(&destinationFolder), *reinterpret_cast<hstring const*>(&desiredNewName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL MoveOverload(void* destinationFolder, void* desiredNewName, Windows::Storage::NameCollisionOption option, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MoveAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Storage::IStorageFolder const, hstring const, Windows::Storage::NameCollisionOption const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().MoveAsync(*reinterpret_cast<Windows::Storage::IStorageFolder const*>(&destinationFolder), *reinterpret_cast<hstring const*>(&desiredNewName), *reinterpret_cast<Windows::Storage::NameCollisionOption const*>(&option)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL MoveAndReplaceAsync(void* fileToReplace, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MoveAndReplaceAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Storage::IStorageFile const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().MoveAndReplaceAsync(*reinterpret_cast<Windows::Storage::IStorageFile const*>(&fileToReplace)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::IStorageFile2> : produce_base<D, Windows::Storage::IStorageFile2>
{
    int32_t WINRT_CALL OpenWithOptionsAsync(Windows::Storage::FileAccessMode accessMode, Windows::Storage::StorageOpenOptions options, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OpenAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStream>), Windows::Storage::FileAccessMode const, Windows::Storage::StorageOpenOptions const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStream>>(this->shim().OpenAsync(*reinterpret_cast<Windows::Storage::FileAccessMode const*>(&accessMode), *reinterpret_cast<Windows::Storage::StorageOpenOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL OpenTransactedWriteWithOptionsAsync(Windows::Storage::StorageOpenOptions options, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OpenTransactedWriteAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::StorageStreamTransaction>), Windows::Storage::StorageOpenOptions const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::StorageStreamTransaction>>(this->shim().OpenTransactedWriteAsync(*reinterpret_cast<Windows::Storage::StorageOpenOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::IStorageFilePropertiesWithAvailability> : produce_base<D, Windows::Storage::IStorageFilePropertiesWithAvailability>
{
    int32_t WINRT_CALL get_IsAvailable(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsAvailable, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsAvailable());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::IStorageFileStatics> : produce_base<D, Windows::Storage::IStorageFileStatics>
{
    int32_t WINRT_CALL GetFileFromPathAsync(void* path, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetFileFromPathAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile>>(this->shim().GetFileFromPathAsync(*reinterpret_cast<hstring const*>(&path)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetFileFromApplicationUriAsync(void* uri, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetFileFromApplicationUriAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile>), Windows::Foundation::Uri const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile>>(this->shim().GetFileFromApplicationUriAsync(*reinterpret_cast<Windows::Foundation::Uri const*>(&uri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateStreamedFileAsync(void* displayNameWithExtension, void* dataRequested, void* thumbnail, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateStreamedFileAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile>), hstring const, Windows::Storage::StreamedFileDataRequestedHandler const, Windows::Storage::Streams::IRandomAccessStreamReference const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile>>(this->shim().CreateStreamedFileAsync(*reinterpret_cast<hstring const*>(&displayNameWithExtension), *reinterpret_cast<Windows::Storage::StreamedFileDataRequestedHandler const*>(&dataRequested), *reinterpret_cast<Windows::Storage::Streams::IRandomAccessStreamReference const*>(&thumbnail)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReplaceWithStreamedFileAsync(void* fileToReplace, void* dataRequested, void* thumbnail, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReplaceWithStreamedFileAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile>), Windows::Storage::IStorageFile const, Windows::Storage::StreamedFileDataRequestedHandler const, Windows::Storage::Streams::IRandomAccessStreamReference const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile>>(this->shim().ReplaceWithStreamedFileAsync(*reinterpret_cast<Windows::Storage::IStorageFile const*>(&fileToReplace), *reinterpret_cast<Windows::Storage::StreamedFileDataRequestedHandler const*>(&dataRequested), *reinterpret_cast<Windows::Storage::Streams::IRandomAccessStreamReference const*>(&thumbnail)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateStreamedFileFromUriAsync(void* displayNameWithExtension, void* uri, void* thumbnail, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateStreamedFileFromUriAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile>), hstring const, Windows::Foundation::Uri const, Windows::Storage::Streams::IRandomAccessStreamReference const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile>>(this->shim().CreateStreamedFileFromUriAsync(*reinterpret_cast<hstring const*>(&displayNameWithExtension), *reinterpret_cast<Windows::Foundation::Uri const*>(&uri), *reinterpret_cast<Windows::Storage::Streams::IRandomAccessStreamReference const*>(&thumbnail)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReplaceWithStreamedFileFromUriAsync(void* fileToReplace, void* uri, void* thumbnail, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReplaceWithStreamedFileFromUriAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile>), Windows::Storage::IStorageFile const, Windows::Foundation::Uri const, Windows::Storage::Streams::IRandomAccessStreamReference const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile>>(this->shim().ReplaceWithStreamedFileFromUriAsync(*reinterpret_cast<Windows::Storage::IStorageFile const*>(&fileToReplace), *reinterpret_cast<Windows::Foundation::Uri const*>(&uri), *reinterpret_cast<Windows::Storage::Streams::IRandomAccessStreamReference const*>(&thumbnail)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::IStorageFolder> : produce_base<D, Windows::Storage::IStorageFolder>
{
    int32_t WINRT_CALL CreateFileAsyncOverloadDefaultOptions(void* desiredName, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFileAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile>>(this->shim().CreateFileAsync(*reinterpret_cast<hstring const*>(&desiredName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFileAsync(void* desiredName, Windows::Storage::CreationCollisionOption options, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFileAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile>), hstring const, Windows::Storage::CreationCollisionOption const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile>>(this->shim().CreateFileAsync(*reinterpret_cast<hstring const*>(&desiredName), *reinterpret_cast<Windows::Storage::CreationCollisionOption const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFolderAsyncOverloadDefaultOptions(void* desiredName, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFolderAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFolder>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFolder>>(this->shim().CreateFolderAsync(*reinterpret_cast<hstring const*>(&desiredName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFolderAsync(void* desiredName, Windows::Storage::CreationCollisionOption options, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFolderAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFolder>), hstring const, Windows::Storage::CreationCollisionOption const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFolder>>(this->shim().CreateFolderAsync(*reinterpret_cast<hstring const*>(&desiredName), *reinterpret_cast<Windows::Storage::CreationCollisionOption const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetFileAsync(void* name, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetFileAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile>>(this->shim().GetFileAsync(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetFolderAsync(void* name, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetFolderAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFolder>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFolder>>(this->shim().GetFolderAsync(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetItemAsync(void* name, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetItemAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::IStorageItem>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::IStorageItem>>(this->shim().GetItemAsync(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetFilesAsyncOverloadDefaultOptionsStartAndCount(void** operation) noexcept final
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

    int32_t WINRT_CALL GetFoldersAsyncOverloadDefaultOptionsStartAndCount(void** operation) noexcept final
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

    int32_t WINRT_CALL GetItemsAsyncOverloadDefaultStartAndCount(void** operation) noexcept final
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
struct produce<D, Windows::Storage::IStorageFolder2> : produce_base<D, Windows::Storage::IStorageFolder2>
{
    int32_t WINRT_CALL TryGetItemAsync(void* name, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryGetItemAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::IStorageItem>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::IStorageItem>>(this->shim().TryGetItemAsync(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::IStorageFolder3> : produce_base<D, Windows::Storage::IStorageFolder3>
{
    int32_t WINRT_CALL TryGetChangeTracker(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryGetChangeTracker, WINRT_WRAP(Windows::Storage::StorageLibraryChangeTracker));
            *result = detach_from<Windows::Storage::StorageLibraryChangeTracker>(this->shim().TryGetChangeTracker());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::IStorageFolderStatics> : produce_base<D, Windows::Storage::IStorageFolderStatics>
{
    int32_t WINRT_CALL GetFolderFromPathAsync(void* path, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetFolderFromPathAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFolder>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFolder>>(this->shim().GetFolderFromPathAsync(*reinterpret_cast<hstring const*>(&path)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::IStorageItem> : produce_base<D, Windows::Storage::IStorageItem>
{
    int32_t WINRT_CALL RenameAsyncOverloadDefaultOptions(void* desiredName, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RenameAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().RenameAsync(*reinterpret_cast<hstring const*>(&desiredName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RenameAsync(void* desiredName, Windows::Storage::NameCollisionOption option, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RenameAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), hstring const, Windows::Storage::NameCollisionOption const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().RenameAsync(*reinterpret_cast<hstring const*>(&desiredName), *reinterpret_cast<Windows::Storage::NameCollisionOption const*>(&option)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DeleteAsyncOverloadDefaultOptions(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeleteAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().DeleteAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DeleteAsync(Windows::Storage::StorageDeleteOption option, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeleteAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Storage::StorageDeleteOption const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().DeleteAsync(*reinterpret_cast<Windows::Storage::StorageDeleteOption const*>(&option)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetBasicPropertiesAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetBasicPropertiesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::FileProperties::BasicProperties>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::FileProperties::BasicProperties>>(this->shim().GetBasicPropertiesAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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

    int32_t WINRT_CALL get_Attributes(Windows::Storage::FileAttributes* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Attributes, WINRT_WRAP(Windows::Storage::FileAttributes));
            *value = detach_from<Windows::Storage::FileAttributes>(this->shim().Attributes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DateCreated(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DateCreated, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().DateCreated());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsOfType(Windows::Storage::StorageItemTypes type, bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsOfType, WINRT_WRAP(bool), Windows::Storage::StorageItemTypes const&);
            *value = detach_from<bool>(this->shim().IsOfType(*reinterpret_cast<Windows::Storage::StorageItemTypes const*>(&type)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::IStorageItem2> : produce_base<D, Windows::Storage::IStorageItem2>
{
    int32_t WINRT_CALL GetParentAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetParentAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFolder>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFolder>>(this->shim().GetParentAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsEqual(void* item, bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsEqual, WINRT_WRAP(bool), Windows::Storage::IStorageItem const&);
            *value = detach_from<bool>(this->shim().IsEqual(*reinterpret_cast<Windows::Storage::IStorageItem const*>(&item)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::IStorageItemProperties> : produce_base<D, Windows::Storage::IStorageItemProperties>
{
    int32_t WINRT_CALL GetThumbnailAsyncOverloadDefaultSizeDefaultOptions(Windows::Storage::FileProperties::ThumbnailMode mode, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetThumbnailAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::FileProperties::StorageItemThumbnail>), Windows::Storage::FileProperties::ThumbnailMode const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::FileProperties::StorageItemThumbnail>>(this->shim().GetThumbnailAsync(*reinterpret_cast<Windows::Storage::FileProperties::ThumbnailMode const*>(&mode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetThumbnailAsyncOverloadDefaultOptions(Windows::Storage::FileProperties::ThumbnailMode mode, uint32_t requestedSize, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetThumbnailAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::FileProperties::StorageItemThumbnail>), Windows::Storage::FileProperties::ThumbnailMode const, uint32_t);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::FileProperties::StorageItemThumbnail>>(this->shim().GetThumbnailAsync(*reinterpret_cast<Windows::Storage::FileProperties::ThumbnailMode const*>(&mode), requestedSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetThumbnailAsync(Windows::Storage::FileProperties::ThumbnailMode mode, uint32_t requestedSize, Windows::Storage::FileProperties::ThumbnailOptions options, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetThumbnailAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::FileProperties::StorageItemThumbnail>), Windows::Storage::FileProperties::ThumbnailMode const, uint32_t, Windows::Storage::FileProperties::ThumbnailOptions const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::FileProperties::StorageItemThumbnail>>(this->shim().GetThumbnailAsync(*reinterpret_cast<Windows::Storage::FileProperties::ThumbnailMode const*>(&mode), requestedSize, *reinterpret_cast<Windows::Storage::FileProperties::ThumbnailOptions const*>(&options)));
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

    int32_t WINRT_CALL get_DisplayType(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayType, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DisplayType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FolderRelativeId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FolderRelativeId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().FolderRelativeId());
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
            WINRT_ASSERT_DECLARATION(Properties, WINRT_WRAP(Windows::Storage::FileProperties::StorageItemContentProperties));
            *value = detach_from<Windows::Storage::FileProperties::StorageItemContentProperties>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::IStorageItemProperties2> : produce_base<D, Windows::Storage::IStorageItemProperties2>
{
    int32_t WINRT_CALL GetScaledImageAsThumbnailAsyncOverloadDefaultSizeDefaultOptions(Windows::Storage::FileProperties::ThumbnailMode mode, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetScaledImageAsThumbnailAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::FileProperties::StorageItemThumbnail>), Windows::Storage::FileProperties::ThumbnailMode const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::FileProperties::StorageItemThumbnail>>(this->shim().GetScaledImageAsThumbnailAsync(*reinterpret_cast<Windows::Storage::FileProperties::ThumbnailMode const*>(&mode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetScaledImageAsThumbnailAsyncOverloadDefaultOptions(Windows::Storage::FileProperties::ThumbnailMode mode, uint32_t requestedSize, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetScaledImageAsThumbnailAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::FileProperties::StorageItemThumbnail>), Windows::Storage::FileProperties::ThumbnailMode const, uint32_t);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::FileProperties::StorageItemThumbnail>>(this->shim().GetScaledImageAsThumbnailAsync(*reinterpret_cast<Windows::Storage::FileProperties::ThumbnailMode const*>(&mode), requestedSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetScaledImageAsThumbnailAsync(Windows::Storage::FileProperties::ThumbnailMode mode, uint32_t requestedSize, Windows::Storage::FileProperties::ThumbnailOptions options, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetScaledImageAsThumbnailAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::FileProperties::StorageItemThumbnail>), Windows::Storage::FileProperties::ThumbnailMode const, uint32_t, Windows::Storage::FileProperties::ThumbnailOptions const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::FileProperties::StorageItemThumbnail>>(this->shim().GetScaledImageAsThumbnailAsync(*reinterpret_cast<Windows::Storage::FileProperties::ThumbnailMode const*>(&mode), requestedSize, *reinterpret_cast<Windows::Storage::FileProperties::ThumbnailOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::IStorageItemPropertiesWithProvider> : produce_base<D, Windows::Storage::IStorageItemPropertiesWithProvider>
{
    int32_t WINRT_CALL get_Provider(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Provider, WINRT_WRAP(Windows::Storage::StorageProvider));
            *value = detach_from<Windows::Storage::StorageProvider>(this->shim().Provider());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::IStorageLibrary> : produce_base<D, Windows::Storage::IStorageLibrary>
{
    int32_t WINRT_CALL RequestAddFolderAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestAddFolderAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFolder>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFolder>>(this->shim().RequestAddFolderAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestRemoveFolderAsync(void* folder, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestRemoveFolderAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::Storage::StorageFolder const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().RequestRemoveFolderAsync(*reinterpret_cast<Windows::Storage::StorageFolder const*>(&folder)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Folders(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Folders, WINRT_WRAP(Windows::Foundation::Collections::IObservableVector<Windows::Storage::StorageFolder>));
            *value = detach_from<Windows::Foundation::Collections::IObservableVector<Windows::Storage::StorageFolder>>(this->shim().Folders());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SaveFolder(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SaveFolder, WINRT_WRAP(Windows::Storage::StorageFolder));
            *value = detach_from<Windows::Storage::StorageFolder>(this->shim().SaveFolder());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_DefinitionChanged(void* handler, winrt::event_token* eventCookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DefinitionChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Storage::StorageLibrary, Windows::Foundation::IInspectable> const&);
            *eventCookie = detach_from<winrt::event_token>(this->shim().DefinitionChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Storage::StorageLibrary, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_DefinitionChanged(winrt::event_token eventCookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(DefinitionChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().DefinitionChanged(*reinterpret_cast<winrt::event_token const*>(&eventCookie));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Storage::IStorageLibrary2> : produce_base<D, Windows::Storage::IStorageLibrary2>
{
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
struct produce<D, Windows::Storage::IStorageLibrary3> : produce_base<D, Windows::Storage::IStorageLibrary3>
{
    int32_t WINRT_CALL AreFolderSuggestionsAvailableAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AreFolderSuggestionsAvailableAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().AreFolderSuggestionsAvailableAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::IStorageLibraryChange> : produce_base<D, Windows::Storage::IStorageLibraryChange>
{
    int32_t WINRT_CALL get_ChangeType(Windows::Storage::StorageLibraryChangeType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChangeType, WINRT_WRAP(Windows::Storage::StorageLibraryChangeType));
            *value = detach_from<Windows::Storage::StorageLibraryChangeType>(this->shim().ChangeType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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

    int32_t WINRT_CALL get_PreviousPath(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PreviousPath, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().PreviousPath());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsOfType(Windows::Storage::StorageItemTypes type, bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsOfType, WINRT_WRAP(bool), Windows::Storage::StorageItemTypes const&);
            *value = detach_from<bool>(this->shim().IsOfType(*reinterpret_cast<Windows::Storage::StorageItemTypes const*>(&type)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetStorageItemAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetStorageItemAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::IStorageItem>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::IStorageItem>>(this->shim().GetStorageItemAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::IStorageLibraryChangeReader> : produce_base<D, Windows::Storage::IStorageLibraryChangeReader>
{
    int32_t WINRT_CALL ReadBatchAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadBatchAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::StorageLibraryChange>>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Storage::StorageLibraryChange>>>(this->shim().ReadBatchAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AcceptChangesAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AcceptChangesAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().AcceptChangesAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::IStorageLibraryChangeTracker> : produce_base<D, Windows::Storage::IStorageLibraryChangeTracker>
{
    int32_t WINRT_CALL GetChangeReader(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetChangeReader, WINRT_WRAP(Windows::Storage::StorageLibraryChangeReader));
            *value = detach_from<Windows::Storage::StorageLibraryChangeReader>(this->shim().GetChangeReader());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Enable() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Enable, WINRT_WRAP(void));
            this->shim().Enable();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Reset() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Reset, WINRT_WRAP(void));
            this->shim().Reset();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::IStorageLibraryStatics> : produce_base<D, Windows::Storage::IStorageLibraryStatics>
{
    int32_t WINRT_CALL GetLibraryAsync(Windows::Storage::KnownLibraryId libraryId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetLibraryAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::StorageLibrary>), Windows::Storage::KnownLibraryId const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::StorageLibrary>>(this->shim().GetLibraryAsync(*reinterpret_cast<Windows::Storage::KnownLibraryId const*>(&libraryId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::IStorageLibraryStatics2> : produce_base<D, Windows::Storage::IStorageLibraryStatics2>
{
    int32_t WINRT_CALL GetLibraryForUserAsync(void* user, Windows::Storage::KnownLibraryId libraryId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetLibraryForUserAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::StorageLibrary>), Windows::System::User const, Windows::Storage::KnownLibraryId const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::StorageLibrary>>(this->shim().GetLibraryForUserAsync(*reinterpret_cast<Windows::System::User const*>(&user), *reinterpret_cast<Windows::Storage::KnownLibraryId const*>(&libraryId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::IStorageProvider> : produce_base<D, Windows::Storage::IStorageProvider>
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
};

template <typename D>
struct produce<D, Windows::Storage::IStorageProvider2> : produce_base<D, Windows::Storage::IStorageProvider2>
{
    int32_t WINRT_CALL IsPropertySupportedForPartialFileAsync(void* propertyCanonicalName, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsPropertySupportedForPartialFileAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().IsPropertySupportedForPartialFileAsync(*reinterpret_cast<hstring const*>(&propertyCanonicalName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::IStorageStreamTransaction> : produce_base<D, Windows::Storage::IStorageStreamTransaction>
{
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

    int32_t WINRT_CALL CommitAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CommitAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().CommitAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::IStreamedFileDataRequest> : produce_base<D, Windows::Storage::IStreamedFileDataRequest>
{
    int32_t WINRT_CALL FailAndClose(Windows::Storage::StreamedFileFailureMode failureMode) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FailAndClose, WINRT_WRAP(void), Windows::Storage::StreamedFileFailureMode const&);
            this->shim().FailAndClose(*reinterpret_cast<Windows::Storage::StreamedFileFailureMode const*>(&failureMode));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::ISystemAudioProperties> : produce_base<D, Windows::Storage::ISystemAudioProperties>
{
    int32_t WINRT_CALL get_EncodingBitrate(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EncodingBitrate, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().EncodingBitrate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::ISystemDataPaths> : produce_base<D, Windows::Storage::ISystemDataPaths>
{
    int32_t WINRT_CALL get_Fonts(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Fonts, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Fonts());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProgramData(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProgramData, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ProgramData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Public(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Public, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Public());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PublicDesktop(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PublicDesktop, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().PublicDesktop());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PublicDocuments(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PublicDocuments, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().PublicDocuments());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PublicDownloads(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PublicDownloads, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().PublicDownloads());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PublicMusic(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PublicMusic, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().PublicMusic());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PublicPictures(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PublicPictures, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().PublicPictures());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PublicVideos(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PublicVideos, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().PublicVideos());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_System(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(System, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().System());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SystemHost(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SystemHost, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SystemHost());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SystemX86(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SystemX86, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SystemX86());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SystemX64(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SystemX64, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SystemX64());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SystemArm(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SystemArm, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SystemArm());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UserProfiles(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UserProfiles, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().UserProfiles());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Windows(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Windows, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Windows());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::ISystemDataPathsStatics> : produce_base<D, Windows::Storage::ISystemDataPathsStatics>
{
    int32_t WINRT_CALL GetDefault(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefault, WINRT_WRAP(Windows::Storage::SystemDataPaths));
            *result = detach_from<Windows::Storage::SystemDataPaths>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::ISystemGPSProperties> : produce_base<D, Windows::Storage::ISystemGPSProperties>
{
    int32_t WINRT_CALL get_LatitudeDecimal(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LatitudeDecimal, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().LatitudeDecimal());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LongitudeDecimal(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LongitudeDecimal, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().LongitudeDecimal());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::ISystemImageProperties> : produce_base<D, Windows::Storage::ISystemImageProperties>
{
    int32_t WINRT_CALL get_HorizontalSize(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HorizontalSize, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().HorizontalSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VerticalSize(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VerticalSize, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().VerticalSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::ISystemMediaProperties> : produce_base<D, Windows::Storage::ISystemMediaProperties>
{
    int32_t WINRT_CALL get_Duration(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Duration, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Duration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Producer(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Producer, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Producer());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Publisher(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Publisher, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Publisher());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SubTitle(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SubTitle, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SubTitle());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Writer(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Writer, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Writer());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Year(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Year, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Year());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::ISystemMusicProperties> : produce_base<D, Windows::Storage::ISystemMusicProperties>
{
    int32_t WINRT_CALL get_AlbumArtist(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AlbumArtist, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AlbumArtist());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AlbumTitle(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AlbumTitle, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AlbumTitle());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Artist(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Artist, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Artist());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Composer(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Composer, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Composer());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Conductor(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Conductor, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Conductor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DisplayArtist(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayArtist, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DisplayArtist());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Genre(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Genre, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Genre());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TrackNumber(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrackNumber, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().TrackNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::ISystemPhotoProperties> : produce_base<D, Windows::Storage::ISystemPhotoProperties>
{
    int32_t WINRT_CALL get_CameraManufacturer(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CameraManufacturer, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().CameraManufacturer());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CameraModel(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CameraModel, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().CameraModel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DateTaken(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DateTaken, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DateTaken());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Orientation(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Orientation, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Orientation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PeopleNames(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PeopleNames, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().PeopleNames());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::ISystemProperties> : produce_base<D, Windows::Storage::ISystemProperties>
{
    int32_t WINRT_CALL get_Author(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Author, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Author());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Comment(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Comment, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Comment());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ItemNameDisplay(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ItemNameDisplay, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ItemNameDisplay());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Keywords(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Keywords, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Keywords());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Rating(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Rating, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Rating());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Title(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Title, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Title());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Audio(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Audio, WINRT_WRAP(Windows::Storage::SystemAudioProperties));
            *value = detach_from<Windows::Storage::SystemAudioProperties>(this->shim().Audio());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_GPS(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GPS, WINRT_WRAP(Windows::Storage::SystemGPSProperties));
            *value = detach_from<Windows::Storage::SystemGPSProperties>(this->shim().GPS());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Media(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Media, WINRT_WRAP(Windows::Storage::SystemMediaProperties));
            *value = detach_from<Windows::Storage::SystemMediaProperties>(this->shim().Media());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Music(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Music, WINRT_WRAP(Windows::Storage::SystemMusicProperties));
            *value = detach_from<Windows::Storage::SystemMusicProperties>(this->shim().Music());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Photo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Photo, WINRT_WRAP(Windows::Storage::SystemPhotoProperties));
            *value = detach_from<Windows::Storage::SystemPhotoProperties>(this->shim().Photo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Video(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Video, WINRT_WRAP(Windows::Storage::SystemVideoProperties));
            *value = detach_from<Windows::Storage::SystemVideoProperties>(this->shim().Video());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Image(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Image, WINRT_WRAP(Windows::Storage::SystemImageProperties));
            *value = detach_from<Windows::Storage::SystemImageProperties>(this->shim().Image());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::ISystemVideoProperties> : produce_base<D, Windows::Storage::ISystemVideoProperties>
{
    int32_t WINRT_CALL get_Director(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Director, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Director());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FrameHeight(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FrameHeight, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().FrameHeight());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FrameWidth(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FrameWidth, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().FrameWidth());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Orientation(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Orientation, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Orientation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TotalBitrate(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TotalBitrate, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().TotalBitrate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::IUserDataPaths> : produce_base<D, Windows::Storage::IUserDataPaths>
{
    int32_t WINRT_CALL get_CameraRoll(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CameraRoll, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().CameraRoll());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Cookies(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Cookies, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Cookies());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Desktop(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Desktop, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Desktop());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Documents(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Documents, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Documents());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Downloads(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Downloads, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Downloads());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Favorites(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Favorites, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Favorites());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_History(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(History, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().History());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InternetCache(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InternetCache, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().InternetCache());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LocalAppData(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LocalAppData, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().LocalAppData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LocalAppDataLow(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LocalAppDataLow, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().LocalAppDataLow());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Music(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Music, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Music());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Pictures(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Pictures, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Pictures());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Profile(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Profile, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Profile());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Recent(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Recent, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Recent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RoamingAppData(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RoamingAppData, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().RoamingAppData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SavedPictures(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SavedPictures, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SavedPictures());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Screenshots(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Screenshots, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Screenshots());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Templates(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Templates, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Templates());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Videos(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Videos, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Videos());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::IUserDataPathsStatics> : produce_base<D, Windows::Storage::IUserDataPathsStatics>
{
    int32_t WINRT_CALL GetForUser(void* user, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForUser, WINRT_WRAP(Windows::Storage::UserDataPaths), Windows::System::User const&);
            *result = detach_from<Windows::Storage::UserDataPaths>(this->shim().GetForUser(*reinterpret_cast<Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDefault(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefault, WINRT_WRAP(Windows::Storage::UserDataPaths));
            *result = detach_from<Windows::Storage::UserDataPaths>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Storage {

inline Windows::Storage::AppDataPaths AppDataPaths::GetForUser(Windows::System::User const& user)
{
    return impl::call_factory<AppDataPaths, Windows::Storage::IAppDataPathsStatics>([&](auto&& f) { return f.GetForUser(user); });
}

inline Windows::Storage::AppDataPaths AppDataPaths::GetDefault()
{
    return impl::call_factory<AppDataPaths, Windows::Storage::IAppDataPathsStatics>([&](auto&& f) { return f.GetDefault(); });
}

inline Windows::Storage::ApplicationData ApplicationData::Current()
{
    return impl::call_factory<ApplicationData, Windows::Storage::IApplicationDataStatics>([&](auto&& f) { return f.Current(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Storage::ApplicationData> ApplicationData::GetForUserAsync(Windows::System::User const& user)
{
    return impl::call_factory<ApplicationData, Windows::Storage::IApplicationDataStatics2>([&](auto&& f) { return f.GetForUserAsync(user); });
}

inline ApplicationDataCompositeValue::ApplicationDataCompositeValue() :
    ApplicationDataCompositeValue(impl::call_factory<ApplicationDataCompositeValue>([](auto&& f) { return f.template ActivateInstance<ApplicationDataCompositeValue>(); }))
{}

inline void CachedFileManager::DeferUpdates(Windows::Storage::IStorageFile const& file)
{
    impl::call_factory<CachedFileManager, Windows::Storage::ICachedFileManagerStatics>([&](auto&& f) { return f.DeferUpdates(file); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Storage::Provider::FileUpdateStatus> CachedFileManager::CompleteUpdatesAsync(Windows::Storage::IStorageFile const& file)
{
    return impl::call_factory<CachedFileManager, Windows::Storage::ICachedFileManagerStatics>([&](auto&& f) { return f.CompleteUpdatesAsync(file); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile> DownloadsFolder::CreateFileAsync(param::hstring const& desiredName)
{
    return impl::call_factory<DownloadsFolder, Windows::Storage::IDownloadsFolderStatics>([&](auto&& f) { return f.CreateFileAsync(desiredName); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFolder> DownloadsFolder::CreateFolderAsync(param::hstring const& desiredName)
{
    return impl::call_factory<DownloadsFolder, Windows::Storage::IDownloadsFolderStatics>([&](auto&& f) { return f.CreateFolderAsync(desiredName); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile> DownloadsFolder::CreateFileAsync(param::hstring const& desiredName, Windows::Storage::CreationCollisionOption const& option)
{
    return impl::call_factory<DownloadsFolder, Windows::Storage::IDownloadsFolderStatics>([&](auto&& f) { return f.CreateFileAsync(desiredName, option); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFolder> DownloadsFolder::CreateFolderAsync(param::hstring const& desiredName, Windows::Storage::CreationCollisionOption const& option)
{
    return impl::call_factory<DownloadsFolder, Windows::Storage::IDownloadsFolderStatics>([&](auto&& f) { return f.CreateFolderAsync(desiredName, option); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile> DownloadsFolder::CreateFileForUserAsync(Windows::System::User const& user, param::hstring const& desiredName)
{
    return impl::call_factory<DownloadsFolder, Windows::Storage::IDownloadsFolderStatics2>([&](auto&& f) { return f.CreateFileForUserAsync(user, desiredName); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFolder> DownloadsFolder::CreateFolderForUserAsync(Windows::System::User const& user, param::hstring const& desiredName)
{
    return impl::call_factory<DownloadsFolder, Windows::Storage::IDownloadsFolderStatics2>([&](auto&& f) { return f.CreateFolderForUserAsync(user, desiredName); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile> DownloadsFolder::CreateFileForUserAsync(Windows::System::User const& user, param::hstring const& desiredName, Windows::Storage::CreationCollisionOption const& option)
{
    return impl::call_factory<DownloadsFolder, Windows::Storage::IDownloadsFolderStatics2>([&](auto&& f) { return f.CreateFileForUserAsync(user, desiredName, option); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFolder> DownloadsFolder::CreateFolderForUserAsync(Windows::System::User const& user, param::hstring const& desiredName, Windows::Storage::CreationCollisionOption const& option)
{
    return impl::call_factory<DownloadsFolder, Windows::Storage::IDownloadsFolderStatics2>([&](auto&& f) { return f.CreateFolderForUserAsync(user, desiredName, option); });
}

inline Windows::Foundation::IAsyncOperation<hstring> FileIO::ReadTextAsync(Windows::Storage::IStorageFile const& file)
{
    return impl::call_factory<FileIO, Windows::Storage::IFileIOStatics>([&](auto&& f) { return f.ReadTextAsync(file); });
}

inline Windows::Foundation::IAsyncOperation<hstring> FileIO::ReadTextAsync(Windows::Storage::IStorageFile const& file, Windows::Storage::Streams::UnicodeEncoding const& encoding)
{
    return impl::call_factory<FileIO, Windows::Storage::IFileIOStatics>([&](auto&& f) { return f.ReadTextAsync(file, encoding); });
}

inline Windows::Foundation::IAsyncAction FileIO::WriteTextAsync(Windows::Storage::IStorageFile const& file, param::hstring const& contents)
{
    return impl::call_factory<FileIO, Windows::Storage::IFileIOStatics>([&](auto&& f) { return f.WriteTextAsync(file, contents); });
}

inline Windows::Foundation::IAsyncAction FileIO::WriteTextAsync(Windows::Storage::IStorageFile const& file, param::hstring const& contents, Windows::Storage::Streams::UnicodeEncoding const& encoding)
{
    return impl::call_factory<FileIO, Windows::Storage::IFileIOStatics>([&](auto&& f) { return f.WriteTextAsync(file, contents, encoding); });
}

inline Windows::Foundation::IAsyncAction FileIO::AppendTextAsync(Windows::Storage::IStorageFile const& file, param::hstring const& contents)
{
    return impl::call_factory<FileIO, Windows::Storage::IFileIOStatics>([&](auto&& f) { return f.AppendTextAsync(file, contents); });
}

inline Windows::Foundation::IAsyncAction FileIO::AppendTextAsync(Windows::Storage::IStorageFile const& file, param::hstring const& contents, Windows::Storage::Streams::UnicodeEncoding const& encoding)
{
    return impl::call_factory<FileIO, Windows::Storage::IFileIOStatics>([&](auto&& f) { return f.AppendTextAsync(file, contents, encoding); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<hstring>> FileIO::ReadLinesAsync(Windows::Storage::IStorageFile const& file)
{
    return impl::call_factory<FileIO, Windows::Storage::IFileIOStatics>([&](auto&& f) { return f.ReadLinesAsync(file); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<hstring>> FileIO::ReadLinesAsync(Windows::Storage::IStorageFile const& file, Windows::Storage::Streams::UnicodeEncoding const& encoding)
{
    return impl::call_factory<FileIO, Windows::Storage::IFileIOStatics>([&](auto&& f) { return f.ReadLinesAsync(file, encoding); });
}

inline Windows::Foundation::IAsyncAction FileIO::WriteLinesAsync(Windows::Storage::IStorageFile const& file, param::async_iterable<hstring> const& lines)
{
    return impl::call_factory<FileIO, Windows::Storage::IFileIOStatics>([&](auto&& f) { return f.WriteLinesAsync(file, lines); });
}

inline Windows::Foundation::IAsyncAction FileIO::WriteLinesAsync(Windows::Storage::IStorageFile const& file, param::async_iterable<hstring> const& lines, Windows::Storage::Streams::UnicodeEncoding const& encoding)
{
    return impl::call_factory<FileIO, Windows::Storage::IFileIOStatics>([&](auto&& f) { return f.WriteLinesAsync(file, lines, encoding); });
}

inline Windows::Foundation::IAsyncAction FileIO::AppendLinesAsync(Windows::Storage::IStorageFile const& file, param::async_iterable<hstring> const& lines)
{
    return impl::call_factory<FileIO, Windows::Storage::IFileIOStatics>([&](auto&& f) { return f.AppendLinesAsync(file, lines); });
}

inline Windows::Foundation::IAsyncAction FileIO::AppendLinesAsync(Windows::Storage::IStorageFile const& file, param::async_iterable<hstring> const& lines, Windows::Storage::Streams::UnicodeEncoding const& encoding)
{
    return impl::call_factory<FileIO, Windows::Storage::IFileIOStatics>([&](auto&& f) { return f.AppendLinesAsync(file, lines, encoding); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer> FileIO::ReadBufferAsync(Windows::Storage::IStorageFile const& file)
{
    return impl::call_factory<FileIO, Windows::Storage::IFileIOStatics>([&](auto&& f) { return f.ReadBufferAsync(file); });
}

inline Windows::Foundation::IAsyncAction FileIO::WriteBufferAsync(Windows::Storage::IStorageFile const& file, Windows::Storage::Streams::IBuffer const& buffer)
{
    return impl::call_factory<FileIO, Windows::Storage::IFileIOStatics>([&](auto&& f) { return f.WriteBufferAsync(file, buffer); });
}

inline Windows::Foundation::IAsyncAction FileIO::WriteBytesAsync(Windows::Storage::IStorageFile const& file, array_view<uint8_t const> buffer)
{
    return impl::call_factory<FileIO, Windows::Storage::IFileIOStatics>([&](auto&& f) { return f.WriteBytesAsync(file, buffer); });
}

inline Windows::Storage::StorageFolder KnownFolders::CameraRoll()
{
    return impl::call_factory<KnownFolders, Windows::Storage::IKnownFoldersCameraRollStatics>([&](auto&& f) { return f.CameraRoll(); });
}

inline Windows::Storage::StorageFolder KnownFolders::Playlists()
{
    return impl::call_factory<KnownFolders, Windows::Storage::IKnownFoldersPlaylistsStatics>([&](auto&& f) { return f.Playlists(); });
}

inline Windows::Storage::StorageFolder KnownFolders::SavedPictures()
{
    return impl::call_factory<KnownFolders, Windows::Storage::IKnownFoldersSavedPicturesStatics>([&](auto&& f) { return f.SavedPictures(); });
}

inline Windows::Storage::StorageFolder KnownFolders::MusicLibrary()
{
    return impl::call_factory<KnownFolders, Windows::Storage::IKnownFoldersStatics>([&](auto&& f) { return f.MusicLibrary(); });
}

inline Windows::Storage::StorageFolder KnownFolders::PicturesLibrary()
{
    return impl::call_factory<KnownFolders, Windows::Storage::IKnownFoldersStatics>([&](auto&& f) { return f.PicturesLibrary(); });
}

inline Windows::Storage::StorageFolder KnownFolders::VideosLibrary()
{
    return impl::call_factory<KnownFolders, Windows::Storage::IKnownFoldersStatics>([&](auto&& f) { return f.VideosLibrary(); });
}

inline Windows::Storage::StorageFolder KnownFolders::DocumentsLibrary()
{
    return impl::call_factory<KnownFolders, Windows::Storage::IKnownFoldersStatics>([&](auto&& f) { return f.DocumentsLibrary(); });
}

inline Windows::Storage::StorageFolder KnownFolders::HomeGroup()
{
    return impl::call_factory<KnownFolders, Windows::Storage::IKnownFoldersStatics>([&](auto&& f) { return f.HomeGroup(); });
}

inline Windows::Storage::StorageFolder KnownFolders::RemovableDevices()
{
    return impl::call_factory<KnownFolders, Windows::Storage::IKnownFoldersStatics>([&](auto&& f) { return f.RemovableDevices(); });
}

inline Windows::Storage::StorageFolder KnownFolders::MediaServerDevices()
{
    return impl::call_factory<KnownFolders, Windows::Storage::IKnownFoldersStatics>([&](auto&& f) { return f.MediaServerDevices(); });
}

inline Windows::Storage::StorageFolder KnownFolders::Objects3D()
{
    return impl::call_factory<KnownFolders, Windows::Storage::IKnownFoldersStatics2>([&](auto&& f) { return f.Objects3D(); });
}

inline Windows::Storage::StorageFolder KnownFolders::AppCaptures()
{
    return impl::call_factory<KnownFolders, Windows::Storage::IKnownFoldersStatics2>([&](auto&& f) { return f.AppCaptures(); });
}

inline Windows::Storage::StorageFolder KnownFolders::RecordedCalls()
{
    return impl::call_factory<KnownFolders, Windows::Storage::IKnownFoldersStatics2>([&](auto&& f) { return f.RecordedCalls(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFolder> KnownFolders::GetFolderForUserAsync(Windows::System::User const& user, Windows::Storage::KnownFolderId const& folderId)
{
    return impl::call_factory<KnownFolders, Windows::Storage::IKnownFoldersStatics3>([&](auto&& f) { return f.GetFolderForUserAsync(user, folderId); });
}

inline Windows::Foundation::IAsyncOperation<hstring> PathIO::ReadTextAsync(param::hstring const& absolutePath)
{
    return impl::call_factory<PathIO, Windows::Storage::IPathIOStatics>([&](auto&& f) { return f.ReadTextAsync(absolutePath); });
}

inline Windows::Foundation::IAsyncOperation<hstring> PathIO::ReadTextAsync(param::hstring const& absolutePath, Windows::Storage::Streams::UnicodeEncoding const& encoding)
{
    return impl::call_factory<PathIO, Windows::Storage::IPathIOStatics>([&](auto&& f) { return f.ReadTextAsync(absolutePath, encoding); });
}

inline Windows::Foundation::IAsyncAction PathIO::WriteTextAsync(param::hstring const& absolutePath, param::hstring const& contents)
{
    return impl::call_factory<PathIO, Windows::Storage::IPathIOStatics>([&](auto&& f) { return f.WriteTextAsync(absolutePath, contents); });
}

inline Windows::Foundation::IAsyncAction PathIO::WriteTextAsync(param::hstring const& absolutePath, param::hstring const& contents, Windows::Storage::Streams::UnicodeEncoding const& encoding)
{
    return impl::call_factory<PathIO, Windows::Storage::IPathIOStatics>([&](auto&& f) { return f.WriteTextAsync(absolutePath, contents, encoding); });
}

inline Windows::Foundation::IAsyncAction PathIO::AppendTextAsync(param::hstring const& absolutePath, param::hstring const& contents)
{
    return impl::call_factory<PathIO, Windows::Storage::IPathIOStatics>([&](auto&& f) { return f.AppendTextAsync(absolutePath, contents); });
}

inline Windows::Foundation::IAsyncAction PathIO::AppendTextAsync(param::hstring const& absolutePath, param::hstring const& contents, Windows::Storage::Streams::UnicodeEncoding const& encoding)
{
    return impl::call_factory<PathIO, Windows::Storage::IPathIOStatics>([&](auto&& f) { return f.AppendTextAsync(absolutePath, contents, encoding); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<hstring>> PathIO::ReadLinesAsync(param::hstring const& absolutePath)
{
    return impl::call_factory<PathIO, Windows::Storage::IPathIOStatics>([&](auto&& f) { return f.ReadLinesAsync(absolutePath); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVector<hstring>> PathIO::ReadLinesAsync(param::hstring const& absolutePath, Windows::Storage::Streams::UnicodeEncoding const& encoding)
{
    return impl::call_factory<PathIO, Windows::Storage::IPathIOStatics>([&](auto&& f) { return f.ReadLinesAsync(absolutePath, encoding); });
}

inline Windows::Foundation::IAsyncAction PathIO::WriteLinesAsync(param::hstring const& absolutePath, param::async_iterable<hstring> const& lines)
{
    return impl::call_factory<PathIO, Windows::Storage::IPathIOStatics>([&](auto&& f) { return f.WriteLinesAsync(absolutePath, lines); });
}

inline Windows::Foundation::IAsyncAction PathIO::WriteLinesAsync(param::hstring const& absolutePath, param::async_iterable<hstring> const& lines, Windows::Storage::Streams::UnicodeEncoding const& encoding)
{
    return impl::call_factory<PathIO, Windows::Storage::IPathIOStatics>([&](auto&& f) { return f.WriteLinesAsync(absolutePath, lines, encoding); });
}

inline Windows::Foundation::IAsyncAction PathIO::AppendLinesAsync(param::hstring const& absolutePath, param::async_iterable<hstring> const& lines)
{
    return impl::call_factory<PathIO, Windows::Storage::IPathIOStatics>([&](auto&& f) { return f.AppendLinesAsync(absolutePath, lines); });
}

inline Windows::Foundation::IAsyncAction PathIO::AppendLinesAsync(param::hstring const& absolutePath, param::async_iterable<hstring> const& lines, Windows::Storage::Streams::UnicodeEncoding const& encoding)
{
    return impl::call_factory<PathIO, Windows::Storage::IPathIOStatics>([&](auto&& f) { return f.AppendLinesAsync(absolutePath, lines, encoding); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer> PathIO::ReadBufferAsync(param::hstring const& absolutePath)
{
    return impl::call_factory<PathIO, Windows::Storage::IPathIOStatics>([&](auto&& f) { return f.ReadBufferAsync(absolutePath); });
}

inline Windows::Foundation::IAsyncAction PathIO::WriteBufferAsync(param::hstring const& absolutePath, Windows::Storage::Streams::IBuffer const& buffer)
{
    return impl::call_factory<PathIO, Windows::Storage::IPathIOStatics>([&](auto&& f) { return f.WriteBufferAsync(absolutePath, buffer); });
}

inline Windows::Foundation::IAsyncAction PathIO::WriteBytesAsync(param::hstring const& absolutePath, array_view<uint8_t const> buffer)
{
    return impl::call_factory<PathIO, Windows::Storage::IPathIOStatics>([&](auto&& f) { return f.WriteBytesAsync(absolutePath, buffer); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile> StorageFile::GetFileFromPathAsync(param::hstring const& path)
{
    return impl::call_factory<StorageFile, Windows::Storage::IStorageFileStatics>([&](auto&& f) { return f.GetFileFromPathAsync(path); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile> StorageFile::GetFileFromApplicationUriAsync(Windows::Foundation::Uri const& uri)
{
    return impl::call_factory<StorageFile, Windows::Storage::IStorageFileStatics>([&](auto&& f) { return f.GetFileFromApplicationUriAsync(uri); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile> StorageFile::CreateStreamedFileAsync(param::hstring const& displayNameWithExtension, Windows::Storage::StreamedFileDataRequestedHandler const& dataRequested, Windows::Storage::Streams::IRandomAccessStreamReference const& thumbnail)
{
    return impl::call_factory<StorageFile, Windows::Storage::IStorageFileStatics>([&](auto&& f) { return f.CreateStreamedFileAsync(displayNameWithExtension, dataRequested, thumbnail); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile> StorageFile::ReplaceWithStreamedFileAsync(Windows::Storage::IStorageFile const& fileToReplace, Windows::Storage::StreamedFileDataRequestedHandler const& dataRequested, Windows::Storage::Streams::IRandomAccessStreamReference const& thumbnail)
{
    return impl::call_factory<StorageFile, Windows::Storage::IStorageFileStatics>([&](auto&& f) { return f.ReplaceWithStreamedFileAsync(fileToReplace, dataRequested, thumbnail); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile> StorageFile::CreateStreamedFileFromUriAsync(param::hstring const& displayNameWithExtension, Windows::Foundation::Uri const& uri, Windows::Storage::Streams::IRandomAccessStreamReference const& thumbnail)
{
    return impl::call_factory<StorageFile, Windows::Storage::IStorageFileStatics>([&](auto&& f) { return f.CreateStreamedFileFromUriAsync(displayNameWithExtension, uri, thumbnail); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile> StorageFile::ReplaceWithStreamedFileFromUriAsync(Windows::Storage::IStorageFile const& fileToReplace, Windows::Foundation::Uri const& uri, Windows::Storage::Streams::IRandomAccessStreamReference const& thumbnail)
{
    return impl::call_factory<StorageFile, Windows::Storage::IStorageFileStatics>([&](auto&& f) { return f.ReplaceWithStreamedFileFromUriAsync(fileToReplace, uri, thumbnail); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFolder> StorageFolder::GetFolderFromPathAsync(param::hstring const& path)
{
    return impl::call_factory<StorageFolder, Windows::Storage::IStorageFolderStatics>([&](auto&& f) { return f.GetFolderFromPathAsync(path); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Storage::StorageLibrary> StorageLibrary::GetLibraryAsync(Windows::Storage::KnownLibraryId const& libraryId)
{
    return impl::call_factory<StorageLibrary, Windows::Storage::IStorageLibraryStatics>([&](auto&& f) { return f.GetLibraryAsync(libraryId); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Storage::StorageLibrary> StorageLibrary::GetLibraryForUserAsync(Windows::System::User const& user, Windows::Storage::KnownLibraryId const& libraryId)
{
    return impl::call_factory<StorageLibrary, Windows::Storage::IStorageLibraryStatics2>([&](auto&& f) { return f.GetLibraryForUserAsync(user, libraryId); });
}

inline Windows::Storage::SystemDataPaths SystemDataPaths::GetDefault()
{
    return impl::call_factory<SystemDataPaths, Windows::Storage::ISystemDataPathsStatics>([&](auto&& f) { return f.GetDefault(); });
}

inline hstring SystemProperties::Author()
{
    return impl::call_factory<SystemProperties, Windows::Storage::ISystemProperties>([&](auto&& f) { return f.Author(); });
}

inline hstring SystemProperties::Comment()
{
    return impl::call_factory<SystemProperties, Windows::Storage::ISystemProperties>([&](auto&& f) { return f.Comment(); });
}

inline hstring SystemProperties::ItemNameDisplay()
{
    return impl::call_factory<SystemProperties, Windows::Storage::ISystemProperties>([&](auto&& f) { return f.ItemNameDisplay(); });
}

inline hstring SystemProperties::Keywords()
{
    return impl::call_factory<SystemProperties, Windows::Storage::ISystemProperties>([&](auto&& f) { return f.Keywords(); });
}

inline hstring SystemProperties::Rating()
{
    return impl::call_factory<SystemProperties, Windows::Storage::ISystemProperties>([&](auto&& f) { return f.Rating(); });
}

inline hstring SystemProperties::Title()
{
    return impl::call_factory<SystemProperties, Windows::Storage::ISystemProperties>([&](auto&& f) { return f.Title(); });
}

inline Windows::Storage::SystemAudioProperties SystemProperties::Audio()
{
    return impl::call_factory<SystemProperties, Windows::Storage::ISystemProperties>([&](auto&& f) { return f.Audio(); });
}

inline Windows::Storage::SystemGPSProperties SystemProperties::GPS()
{
    return impl::call_factory<SystemProperties, Windows::Storage::ISystemProperties>([&](auto&& f) { return f.GPS(); });
}

inline Windows::Storage::SystemMediaProperties SystemProperties::Media()
{
    return impl::call_factory<SystemProperties, Windows::Storage::ISystemProperties>([&](auto&& f) { return f.Media(); });
}

inline Windows::Storage::SystemMusicProperties SystemProperties::Music()
{
    return impl::call_factory<SystemProperties, Windows::Storage::ISystemProperties>([&](auto&& f) { return f.Music(); });
}

inline Windows::Storage::SystemPhotoProperties SystemProperties::Photo()
{
    return impl::call_factory<SystemProperties, Windows::Storage::ISystemProperties>([&](auto&& f) { return f.Photo(); });
}

inline Windows::Storage::SystemVideoProperties SystemProperties::Video()
{
    return impl::call_factory<SystemProperties, Windows::Storage::ISystemProperties>([&](auto&& f) { return f.Video(); });
}

inline Windows::Storage::SystemImageProperties SystemProperties::Image()
{
    return impl::call_factory<SystemProperties, Windows::Storage::ISystemProperties>([&](auto&& f) { return f.Image(); });
}

inline Windows::Storage::UserDataPaths UserDataPaths::GetForUser(Windows::System::User const& user)
{
    return impl::call_factory<UserDataPaths, Windows::Storage::IUserDataPathsStatics>([&](auto&& f) { return f.GetForUser(user); });
}

inline Windows::Storage::UserDataPaths UserDataPaths::GetDefault()
{
    return impl::call_factory<UserDataPaths, Windows::Storage::IUserDataPathsStatics>([&](auto&& f) { return f.GetDefault(); });
}

template <typename L> ApplicationDataSetVersionHandler::ApplicationDataSetVersionHandler(L handler) :
    ApplicationDataSetVersionHandler(impl::make_delegate<ApplicationDataSetVersionHandler>(std::forward<L>(handler)))
{}

template <typename F> ApplicationDataSetVersionHandler::ApplicationDataSetVersionHandler(F* handler) :
    ApplicationDataSetVersionHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> ApplicationDataSetVersionHandler::ApplicationDataSetVersionHandler(O* object, M method) :
    ApplicationDataSetVersionHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> ApplicationDataSetVersionHandler::ApplicationDataSetVersionHandler(com_ptr<O>&& object, M method) :
    ApplicationDataSetVersionHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> ApplicationDataSetVersionHandler::ApplicationDataSetVersionHandler(weak_ref<O>&& object, M method) :
    ApplicationDataSetVersionHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void ApplicationDataSetVersionHandler::operator()(Windows::Storage::SetVersionRequest const& setVersionRequest) const
{
    check_hresult((*(impl::abi_t<ApplicationDataSetVersionHandler>**)this)->Invoke(get_abi(setVersionRequest)));
}

template <typename L> StreamedFileDataRequestedHandler::StreamedFileDataRequestedHandler(L handler) :
    StreamedFileDataRequestedHandler(impl::make_delegate<StreamedFileDataRequestedHandler>(std::forward<L>(handler)))
{}

template <typename F> StreamedFileDataRequestedHandler::StreamedFileDataRequestedHandler(F* handler) :
    StreamedFileDataRequestedHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> StreamedFileDataRequestedHandler::StreamedFileDataRequestedHandler(O* object, M method) :
    StreamedFileDataRequestedHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> StreamedFileDataRequestedHandler::StreamedFileDataRequestedHandler(com_ptr<O>&& object, M method) :
    StreamedFileDataRequestedHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> StreamedFileDataRequestedHandler::StreamedFileDataRequestedHandler(weak_ref<O>&& object, M method) :
    StreamedFileDataRequestedHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void StreamedFileDataRequestedHandler::operator()(Windows::Storage::StreamedFileDataRequest const& stream) const
{
    check_hresult((*(impl::abi_t<StreamedFileDataRequestedHandler>**)this)->Invoke(get_abi(stream)));
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Storage::IAppDataPaths> : winrt::impl::hash_base<winrt::Windows::Storage::IAppDataPaths> {};
template<> struct hash<winrt::Windows::Storage::IAppDataPathsStatics> : winrt::impl::hash_base<winrt::Windows::Storage::IAppDataPathsStatics> {};
template<> struct hash<winrt::Windows::Storage::IApplicationData> : winrt::impl::hash_base<winrt::Windows::Storage::IApplicationData> {};
template<> struct hash<winrt::Windows::Storage::IApplicationData2> : winrt::impl::hash_base<winrt::Windows::Storage::IApplicationData2> {};
template<> struct hash<winrt::Windows::Storage::IApplicationData3> : winrt::impl::hash_base<winrt::Windows::Storage::IApplicationData3> {};
template<> struct hash<winrt::Windows::Storage::IApplicationDataContainer> : winrt::impl::hash_base<winrt::Windows::Storage::IApplicationDataContainer> {};
template<> struct hash<winrt::Windows::Storage::IApplicationDataStatics> : winrt::impl::hash_base<winrt::Windows::Storage::IApplicationDataStatics> {};
template<> struct hash<winrt::Windows::Storage::IApplicationDataStatics2> : winrt::impl::hash_base<winrt::Windows::Storage::IApplicationDataStatics2> {};
template<> struct hash<winrt::Windows::Storage::ICachedFileManagerStatics> : winrt::impl::hash_base<winrt::Windows::Storage::ICachedFileManagerStatics> {};
template<> struct hash<winrt::Windows::Storage::IDownloadsFolderStatics> : winrt::impl::hash_base<winrt::Windows::Storage::IDownloadsFolderStatics> {};
template<> struct hash<winrt::Windows::Storage::IDownloadsFolderStatics2> : winrt::impl::hash_base<winrt::Windows::Storage::IDownloadsFolderStatics2> {};
template<> struct hash<winrt::Windows::Storage::IFileIOStatics> : winrt::impl::hash_base<winrt::Windows::Storage::IFileIOStatics> {};
template<> struct hash<winrt::Windows::Storage::IKnownFoldersCameraRollStatics> : winrt::impl::hash_base<winrt::Windows::Storage::IKnownFoldersCameraRollStatics> {};
template<> struct hash<winrt::Windows::Storage::IKnownFoldersPlaylistsStatics> : winrt::impl::hash_base<winrt::Windows::Storage::IKnownFoldersPlaylistsStatics> {};
template<> struct hash<winrt::Windows::Storage::IKnownFoldersSavedPicturesStatics> : winrt::impl::hash_base<winrt::Windows::Storage::IKnownFoldersSavedPicturesStatics> {};
template<> struct hash<winrt::Windows::Storage::IKnownFoldersStatics> : winrt::impl::hash_base<winrt::Windows::Storage::IKnownFoldersStatics> {};
template<> struct hash<winrt::Windows::Storage::IKnownFoldersStatics2> : winrt::impl::hash_base<winrt::Windows::Storage::IKnownFoldersStatics2> {};
template<> struct hash<winrt::Windows::Storage::IKnownFoldersStatics3> : winrt::impl::hash_base<winrt::Windows::Storage::IKnownFoldersStatics3> {};
template<> struct hash<winrt::Windows::Storage::IPathIOStatics> : winrt::impl::hash_base<winrt::Windows::Storage::IPathIOStatics> {};
template<> struct hash<winrt::Windows::Storage::ISetVersionDeferral> : winrt::impl::hash_base<winrt::Windows::Storage::ISetVersionDeferral> {};
template<> struct hash<winrt::Windows::Storage::ISetVersionRequest> : winrt::impl::hash_base<winrt::Windows::Storage::ISetVersionRequest> {};
template<> struct hash<winrt::Windows::Storage::IStorageFile> : winrt::impl::hash_base<winrt::Windows::Storage::IStorageFile> {};
template<> struct hash<winrt::Windows::Storage::IStorageFile2> : winrt::impl::hash_base<winrt::Windows::Storage::IStorageFile2> {};
template<> struct hash<winrt::Windows::Storage::IStorageFilePropertiesWithAvailability> : winrt::impl::hash_base<winrt::Windows::Storage::IStorageFilePropertiesWithAvailability> {};
template<> struct hash<winrt::Windows::Storage::IStorageFileStatics> : winrt::impl::hash_base<winrt::Windows::Storage::IStorageFileStatics> {};
template<> struct hash<winrt::Windows::Storage::IStorageFolder> : winrt::impl::hash_base<winrt::Windows::Storage::IStorageFolder> {};
template<> struct hash<winrt::Windows::Storage::IStorageFolder2> : winrt::impl::hash_base<winrt::Windows::Storage::IStorageFolder2> {};
template<> struct hash<winrt::Windows::Storage::IStorageFolder3> : winrt::impl::hash_base<winrt::Windows::Storage::IStorageFolder3> {};
template<> struct hash<winrt::Windows::Storage::IStorageFolderStatics> : winrt::impl::hash_base<winrt::Windows::Storage::IStorageFolderStatics> {};
template<> struct hash<winrt::Windows::Storage::IStorageItem> : winrt::impl::hash_base<winrt::Windows::Storage::IStorageItem> {};
template<> struct hash<winrt::Windows::Storage::IStorageItem2> : winrt::impl::hash_base<winrt::Windows::Storage::IStorageItem2> {};
template<> struct hash<winrt::Windows::Storage::IStorageItemProperties> : winrt::impl::hash_base<winrt::Windows::Storage::IStorageItemProperties> {};
template<> struct hash<winrt::Windows::Storage::IStorageItemProperties2> : winrt::impl::hash_base<winrt::Windows::Storage::IStorageItemProperties2> {};
template<> struct hash<winrt::Windows::Storage::IStorageItemPropertiesWithProvider> : winrt::impl::hash_base<winrt::Windows::Storage::IStorageItemPropertiesWithProvider> {};
template<> struct hash<winrt::Windows::Storage::IStorageLibrary> : winrt::impl::hash_base<winrt::Windows::Storage::IStorageLibrary> {};
template<> struct hash<winrt::Windows::Storage::IStorageLibrary2> : winrt::impl::hash_base<winrt::Windows::Storage::IStorageLibrary2> {};
template<> struct hash<winrt::Windows::Storage::IStorageLibrary3> : winrt::impl::hash_base<winrt::Windows::Storage::IStorageLibrary3> {};
template<> struct hash<winrt::Windows::Storage::IStorageLibraryChange> : winrt::impl::hash_base<winrt::Windows::Storage::IStorageLibraryChange> {};
template<> struct hash<winrt::Windows::Storage::IStorageLibraryChangeReader> : winrt::impl::hash_base<winrt::Windows::Storage::IStorageLibraryChangeReader> {};
template<> struct hash<winrt::Windows::Storage::IStorageLibraryChangeTracker> : winrt::impl::hash_base<winrt::Windows::Storage::IStorageLibraryChangeTracker> {};
template<> struct hash<winrt::Windows::Storage::IStorageLibraryStatics> : winrt::impl::hash_base<winrt::Windows::Storage::IStorageLibraryStatics> {};
template<> struct hash<winrt::Windows::Storage::IStorageLibraryStatics2> : winrt::impl::hash_base<winrt::Windows::Storage::IStorageLibraryStatics2> {};
template<> struct hash<winrt::Windows::Storage::IStorageProvider> : winrt::impl::hash_base<winrt::Windows::Storage::IStorageProvider> {};
template<> struct hash<winrt::Windows::Storage::IStorageProvider2> : winrt::impl::hash_base<winrt::Windows::Storage::IStorageProvider2> {};
template<> struct hash<winrt::Windows::Storage::IStorageStreamTransaction> : winrt::impl::hash_base<winrt::Windows::Storage::IStorageStreamTransaction> {};
template<> struct hash<winrt::Windows::Storage::IStreamedFileDataRequest> : winrt::impl::hash_base<winrt::Windows::Storage::IStreamedFileDataRequest> {};
template<> struct hash<winrt::Windows::Storage::ISystemAudioProperties> : winrt::impl::hash_base<winrt::Windows::Storage::ISystemAudioProperties> {};
template<> struct hash<winrt::Windows::Storage::ISystemDataPaths> : winrt::impl::hash_base<winrt::Windows::Storage::ISystemDataPaths> {};
template<> struct hash<winrt::Windows::Storage::ISystemDataPathsStatics> : winrt::impl::hash_base<winrt::Windows::Storage::ISystemDataPathsStatics> {};
template<> struct hash<winrt::Windows::Storage::ISystemGPSProperties> : winrt::impl::hash_base<winrt::Windows::Storage::ISystemGPSProperties> {};
template<> struct hash<winrt::Windows::Storage::ISystemImageProperties> : winrt::impl::hash_base<winrt::Windows::Storage::ISystemImageProperties> {};
template<> struct hash<winrt::Windows::Storage::ISystemMediaProperties> : winrt::impl::hash_base<winrt::Windows::Storage::ISystemMediaProperties> {};
template<> struct hash<winrt::Windows::Storage::ISystemMusicProperties> : winrt::impl::hash_base<winrt::Windows::Storage::ISystemMusicProperties> {};
template<> struct hash<winrt::Windows::Storage::ISystemPhotoProperties> : winrt::impl::hash_base<winrt::Windows::Storage::ISystemPhotoProperties> {};
template<> struct hash<winrt::Windows::Storage::ISystemProperties> : winrt::impl::hash_base<winrt::Windows::Storage::ISystemProperties> {};
template<> struct hash<winrt::Windows::Storage::ISystemVideoProperties> : winrt::impl::hash_base<winrt::Windows::Storage::ISystemVideoProperties> {};
template<> struct hash<winrt::Windows::Storage::IUserDataPaths> : winrt::impl::hash_base<winrt::Windows::Storage::IUserDataPaths> {};
template<> struct hash<winrt::Windows::Storage::IUserDataPathsStatics> : winrt::impl::hash_base<winrt::Windows::Storage::IUserDataPathsStatics> {};
template<> struct hash<winrt::Windows::Storage::AppDataPaths> : winrt::impl::hash_base<winrt::Windows::Storage::AppDataPaths> {};
template<> struct hash<winrt::Windows::Storage::ApplicationData> : winrt::impl::hash_base<winrt::Windows::Storage::ApplicationData> {};
template<> struct hash<winrt::Windows::Storage::ApplicationDataCompositeValue> : winrt::impl::hash_base<winrt::Windows::Storage::ApplicationDataCompositeValue> {};
template<> struct hash<winrt::Windows::Storage::ApplicationDataContainer> : winrt::impl::hash_base<winrt::Windows::Storage::ApplicationDataContainer> {};
template<> struct hash<winrt::Windows::Storage::ApplicationDataContainerSettings> : winrt::impl::hash_base<winrt::Windows::Storage::ApplicationDataContainerSettings> {};
template<> struct hash<winrt::Windows::Storage::CachedFileManager> : winrt::impl::hash_base<winrt::Windows::Storage::CachedFileManager> {};
template<> struct hash<winrt::Windows::Storage::DownloadsFolder> : winrt::impl::hash_base<winrt::Windows::Storage::DownloadsFolder> {};
template<> struct hash<winrt::Windows::Storage::FileIO> : winrt::impl::hash_base<winrt::Windows::Storage::FileIO> {};
template<> struct hash<winrt::Windows::Storage::KnownFolders> : winrt::impl::hash_base<winrt::Windows::Storage::KnownFolders> {};
template<> struct hash<winrt::Windows::Storage::PathIO> : winrt::impl::hash_base<winrt::Windows::Storage::PathIO> {};
template<> struct hash<winrt::Windows::Storage::SetVersionDeferral> : winrt::impl::hash_base<winrt::Windows::Storage::SetVersionDeferral> {};
template<> struct hash<winrt::Windows::Storage::SetVersionRequest> : winrt::impl::hash_base<winrt::Windows::Storage::SetVersionRequest> {};
template<> struct hash<winrt::Windows::Storage::StorageFile> : winrt::impl::hash_base<winrt::Windows::Storage::StorageFile> {};
template<> struct hash<winrt::Windows::Storage::StorageFolder> : winrt::impl::hash_base<winrt::Windows::Storage::StorageFolder> {};
template<> struct hash<winrt::Windows::Storage::StorageLibrary> : winrt::impl::hash_base<winrt::Windows::Storage::StorageLibrary> {};
template<> struct hash<winrt::Windows::Storage::StorageLibraryChange> : winrt::impl::hash_base<winrt::Windows::Storage::StorageLibraryChange> {};
template<> struct hash<winrt::Windows::Storage::StorageLibraryChangeReader> : winrt::impl::hash_base<winrt::Windows::Storage::StorageLibraryChangeReader> {};
template<> struct hash<winrt::Windows::Storage::StorageLibraryChangeTracker> : winrt::impl::hash_base<winrt::Windows::Storage::StorageLibraryChangeTracker> {};
template<> struct hash<winrt::Windows::Storage::StorageProvider> : winrt::impl::hash_base<winrt::Windows::Storage::StorageProvider> {};
template<> struct hash<winrt::Windows::Storage::StorageStreamTransaction> : winrt::impl::hash_base<winrt::Windows::Storage::StorageStreamTransaction> {};
template<> struct hash<winrt::Windows::Storage::StreamedFileDataRequest> : winrt::impl::hash_base<winrt::Windows::Storage::StreamedFileDataRequest> {};
template<> struct hash<winrt::Windows::Storage::SystemAudioProperties> : winrt::impl::hash_base<winrt::Windows::Storage::SystemAudioProperties> {};
template<> struct hash<winrt::Windows::Storage::SystemDataPaths> : winrt::impl::hash_base<winrt::Windows::Storage::SystemDataPaths> {};
template<> struct hash<winrt::Windows::Storage::SystemGPSProperties> : winrt::impl::hash_base<winrt::Windows::Storage::SystemGPSProperties> {};
template<> struct hash<winrt::Windows::Storage::SystemImageProperties> : winrt::impl::hash_base<winrt::Windows::Storage::SystemImageProperties> {};
template<> struct hash<winrt::Windows::Storage::SystemMediaProperties> : winrt::impl::hash_base<winrt::Windows::Storage::SystemMediaProperties> {};
template<> struct hash<winrt::Windows::Storage::SystemMusicProperties> : winrt::impl::hash_base<winrt::Windows::Storage::SystemMusicProperties> {};
template<> struct hash<winrt::Windows::Storage::SystemPhotoProperties> : winrt::impl::hash_base<winrt::Windows::Storage::SystemPhotoProperties> {};
template<> struct hash<winrt::Windows::Storage::SystemProperties> : winrt::impl::hash_base<winrt::Windows::Storage::SystemProperties> {};
template<> struct hash<winrt::Windows::Storage::SystemVideoProperties> : winrt::impl::hash_base<winrt::Windows::Storage::SystemVideoProperties> {};
template<> struct hash<winrt::Windows::Storage::UserDataPaths> : winrt::impl::hash_base<winrt::Windows::Storage::UserDataPaths> {};

}
