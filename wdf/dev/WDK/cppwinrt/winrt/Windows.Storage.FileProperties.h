// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Devices.Geolocation.2.h"
#include "winrt/impl/Windows.Storage.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Storage.FileProperties.2.h"
#include "winrt/Windows.Storage.h"

namespace winrt::impl {

template <typename D> uint64_t consume_Windows_Storage_FileProperties_IBasicProperties<D>::Size() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IBasicProperties)->get_Size(&value));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_Storage_FileProperties_IBasicProperties<D>::DateModified() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IBasicProperties)->get_DateModified(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_Storage_FileProperties_IBasicProperties<D>::ItemDate() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IBasicProperties)->get_ItemDate(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<hstring> consume_Windows_Storage_FileProperties_IDocumentProperties<D>::Author() const
{
    Windows::Foundation::Collections::IVector<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IDocumentProperties)->get_Author(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_FileProperties_IDocumentProperties<D>::Title() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IDocumentProperties)->get_Title(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Storage_FileProperties_IDocumentProperties<D>::Title(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IDocumentProperties)->put_Title(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVector<hstring> consume_Windows_Storage_FileProperties_IDocumentProperties<D>::Keywords() const
{
    Windows::Foundation::Collections::IVector<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IDocumentProperties)->get_Keywords(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_FileProperties_IDocumentProperties<D>::Comment() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IDocumentProperties)->get_Comment(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Storage_FileProperties_IDocumentProperties<D>::Comment(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IDocumentProperties)->put_Comment(get_abi(value)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Geolocation::Geopoint> consume_Windows_Storage_FileProperties_IGeotagHelperStatics<D>::GetGeotagAsync(Windows::Storage::IStorageFile const& file) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Geolocation::Geopoint> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IGeotagHelperStatics)->GetGeotagAsync(get_abi(file), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Storage_FileProperties_IGeotagHelperStatics<D>::SetGeotagFromGeolocatorAsync(Windows::Storage::IStorageFile const& file, Windows::Devices::Geolocation::Geolocator const& geolocator) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IGeotagHelperStatics)->SetGeotagFromGeolocatorAsync(get_abi(file), get_abi(geolocator), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Storage_FileProperties_IGeotagHelperStatics<D>::SetGeotagAsync(Windows::Storage::IStorageFile const& file, Windows::Devices::Geolocation::Geopoint const& geopoint) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IGeotagHelperStatics)->SetGeotagAsync(get_abi(file), get_abi(geopoint), put_abi(operation)));
    return operation;
}

template <typename D> uint32_t consume_Windows_Storage_FileProperties_IImageProperties<D>::Rating() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IImageProperties)->get_Rating(&value));
    return value;
}

template <typename D> void consume_Windows_Storage_FileProperties_IImageProperties<D>::Rating(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IImageProperties)->put_Rating(value));
}

template <typename D> Windows::Foundation::Collections::IVector<hstring> consume_Windows_Storage_FileProperties_IImageProperties<D>::Keywords() const
{
    Windows::Foundation::Collections::IVector<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IImageProperties)->get_Keywords(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_Storage_FileProperties_IImageProperties<D>::DateTaken() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IImageProperties)->get_DateTaken(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Storage_FileProperties_IImageProperties<D>::DateTaken(Windows::Foundation::DateTime const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IImageProperties)->put_DateTaken(get_abi(value)));
}

template <typename D> uint32_t consume_Windows_Storage_FileProperties_IImageProperties<D>::Width() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IImageProperties)->get_Width(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Storage_FileProperties_IImageProperties<D>::Height() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IImageProperties)->get_Height(&value));
    return value;
}

template <typename D> hstring consume_Windows_Storage_FileProperties_IImageProperties<D>::Title() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IImageProperties)->get_Title(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Storage_FileProperties_IImageProperties<D>::Title(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IImageProperties)->put_Title(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<double> consume_Windows_Storage_FileProperties_IImageProperties<D>::Latitude() const
{
    Windows::Foundation::IReference<double> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IImageProperties)->get_Latitude(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<double> consume_Windows_Storage_FileProperties_IImageProperties<D>::Longitude() const
{
    Windows::Foundation::IReference<double> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IImageProperties)->get_Longitude(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_FileProperties_IImageProperties<D>::CameraManufacturer() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IImageProperties)->get_CameraManufacturer(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Storage_FileProperties_IImageProperties<D>::CameraManufacturer(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IImageProperties)->put_CameraManufacturer(get_abi(value)));
}

template <typename D> hstring consume_Windows_Storage_FileProperties_IImageProperties<D>::CameraModel() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IImageProperties)->get_CameraModel(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Storage_FileProperties_IImageProperties<D>::CameraModel(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IImageProperties)->put_CameraModel(get_abi(value)));
}

template <typename D> Windows::Storage::FileProperties::PhotoOrientation consume_Windows_Storage_FileProperties_IImageProperties<D>::Orientation() const
{
    Windows::Storage::FileProperties::PhotoOrientation value{};
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IImageProperties)->get_Orientation(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<hstring> consume_Windows_Storage_FileProperties_IImageProperties<D>::PeopleNames() const
{
    Windows::Foundation::Collections::IVectorView<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IImageProperties)->get_PeopleNames(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_FileProperties_IMusicProperties<D>::Album() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IMusicProperties)->get_Album(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Storage_FileProperties_IMusicProperties<D>::Album(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IMusicProperties)->put_Album(get_abi(value)));
}

template <typename D> hstring consume_Windows_Storage_FileProperties_IMusicProperties<D>::Artist() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IMusicProperties)->get_Artist(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Storage_FileProperties_IMusicProperties<D>::Artist(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IMusicProperties)->put_Artist(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVector<hstring> consume_Windows_Storage_FileProperties_IMusicProperties<D>::Genre() const
{
    Windows::Foundation::Collections::IVector<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IMusicProperties)->get_Genre(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Storage_FileProperties_IMusicProperties<D>::TrackNumber() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IMusicProperties)->get_TrackNumber(&value));
    return value;
}

template <typename D> void consume_Windows_Storage_FileProperties_IMusicProperties<D>::TrackNumber(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IMusicProperties)->put_TrackNumber(value));
}

template <typename D> hstring consume_Windows_Storage_FileProperties_IMusicProperties<D>::Title() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IMusicProperties)->get_Title(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Storage_FileProperties_IMusicProperties<D>::Title(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IMusicProperties)->put_Title(get_abi(value)));
}

template <typename D> uint32_t consume_Windows_Storage_FileProperties_IMusicProperties<D>::Rating() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IMusicProperties)->get_Rating(&value));
    return value;
}

template <typename D> void consume_Windows_Storage_FileProperties_IMusicProperties<D>::Rating(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IMusicProperties)->put_Rating(value));
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Storage_FileProperties_IMusicProperties<D>::Duration() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IMusicProperties)->get_Duration(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Storage_FileProperties_IMusicProperties<D>::Bitrate() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IMusicProperties)->get_Bitrate(&value));
    return value;
}

template <typename D> hstring consume_Windows_Storage_FileProperties_IMusicProperties<D>::AlbumArtist() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IMusicProperties)->get_AlbumArtist(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Storage_FileProperties_IMusicProperties<D>::AlbumArtist(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IMusicProperties)->put_AlbumArtist(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVector<hstring> consume_Windows_Storage_FileProperties_IMusicProperties<D>::Composers() const
{
    Windows::Foundation::Collections::IVector<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IMusicProperties)->get_Composers(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<hstring> consume_Windows_Storage_FileProperties_IMusicProperties<D>::Conductors() const
{
    Windows::Foundation::Collections::IVector<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IMusicProperties)->get_Conductors(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_FileProperties_IMusicProperties<D>::Subtitle() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IMusicProperties)->get_Subtitle(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Storage_FileProperties_IMusicProperties<D>::Subtitle(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IMusicProperties)->put_Subtitle(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVector<hstring> consume_Windows_Storage_FileProperties_IMusicProperties<D>::Producers() const
{
    Windows::Foundation::Collections::IVector<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IMusicProperties)->get_Producers(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_FileProperties_IMusicProperties<D>::Publisher() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IMusicProperties)->get_Publisher(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Storage_FileProperties_IMusicProperties<D>::Publisher(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IMusicProperties)->put_Publisher(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVector<hstring> consume_Windows_Storage_FileProperties_IMusicProperties<D>::Writers() const
{
    Windows::Foundation::Collections::IVector<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IMusicProperties)->get_Writers(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Storage_FileProperties_IMusicProperties<D>::Year() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IMusicProperties)->get_Year(&value));
    return value;
}

template <typename D> void consume_Windows_Storage_FileProperties_IMusicProperties<D>::Year(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IMusicProperties)->put_Year(value));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::FileProperties::MusicProperties> consume_Windows_Storage_FileProperties_IStorageItemContentProperties<D>::GetMusicPropertiesAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::FileProperties::MusicProperties> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IStorageItemContentProperties)->GetMusicPropertiesAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::FileProperties::VideoProperties> consume_Windows_Storage_FileProperties_IStorageItemContentProperties<D>::GetVideoPropertiesAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::FileProperties::VideoProperties> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IStorageItemContentProperties)->GetVideoPropertiesAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::FileProperties::ImageProperties> consume_Windows_Storage_FileProperties_IStorageItemContentProperties<D>::GetImagePropertiesAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::FileProperties::ImageProperties> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IStorageItemContentProperties)->GetImagePropertiesAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::FileProperties::DocumentProperties> consume_Windows_Storage_FileProperties_IStorageItemContentProperties<D>::GetDocumentPropertiesAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::FileProperties::DocumentProperties> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IStorageItemContentProperties)->GetDocumentPropertiesAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IMap<hstring, Windows::Foundation::IInspectable>> consume_Windows_Storage_FileProperties_IStorageItemExtraProperties<D>::RetrievePropertiesAsync(param::async_iterable<hstring> const& propertiesToRetrieve) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IMap<hstring, Windows::Foundation::IInspectable>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IStorageItemExtraProperties)->RetrievePropertiesAsync(get_abi(propertiesToRetrieve), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Storage_FileProperties_IStorageItemExtraProperties<D>::SavePropertiesAsync(param::async_iterable<Windows::Foundation::Collections::IKeyValuePair<hstring, Windows::Foundation::IInspectable>> const& propertiesToSave) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IStorageItemExtraProperties)->SavePropertiesAsync(get_abi(propertiesToSave), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Storage_FileProperties_IStorageItemExtraProperties<D>::SavePropertiesAsync() const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IStorageItemExtraProperties)->SavePropertiesAsyncOverloadDefault(put_abi(operation)));
    return operation;
}

template <typename D> uint32_t consume_Windows_Storage_FileProperties_IThumbnailProperties<D>::OriginalWidth() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IThumbnailProperties)->get_OriginalWidth(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Storage_FileProperties_IThumbnailProperties<D>::OriginalHeight() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IThumbnailProperties)->get_OriginalHeight(&value));
    return value;
}

template <typename D> bool consume_Windows_Storage_FileProperties_IThumbnailProperties<D>::ReturnedSmallerCachedSize() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IThumbnailProperties)->get_ReturnedSmallerCachedSize(&value));
    return value;
}

template <typename D> Windows::Storage::FileProperties::ThumbnailType consume_Windows_Storage_FileProperties_IThumbnailProperties<D>::Type() const
{
    Windows::Storage::FileProperties::ThumbnailType value{};
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IThumbnailProperties)->get_Type(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Storage_FileProperties_IVideoProperties<D>::Rating() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IVideoProperties)->get_Rating(&value));
    return value;
}

template <typename D> void consume_Windows_Storage_FileProperties_IVideoProperties<D>::Rating(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IVideoProperties)->put_Rating(value));
}

template <typename D> Windows::Foundation::Collections::IVector<hstring> consume_Windows_Storage_FileProperties_IVideoProperties<D>::Keywords() const
{
    Windows::Foundation::Collections::IVector<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IVideoProperties)->get_Keywords(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Storage_FileProperties_IVideoProperties<D>::Width() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IVideoProperties)->get_Width(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Storage_FileProperties_IVideoProperties<D>::Height() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IVideoProperties)->get_Height(&value));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Storage_FileProperties_IVideoProperties<D>::Duration() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IVideoProperties)->get_Duration(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<double> consume_Windows_Storage_FileProperties_IVideoProperties<D>::Latitude() const
{
    Windows::Foundation::IReference<double> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IVideoProperties)->get_Latitude(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<double> consume_Windows_Storage_FileProperties_IVideoProperties<D>::Longitude() const
{
    Windows::Foundation::IReference<double> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IVideoProperties)->get_Longitude(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_FileProperties_IVideoProperties<D>::Title() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IVideoProperties)->get_Title(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Storage_FileProperties_IVideoProperties<D>::Title(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IVideoProperties)->put_Title(get_abi(value)));
}

template <typename D> hstring consume_Windows_Storage_FileProperties_IVideoProperties<D>::Subtitle() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IVideoProperties)->get_Subtitle(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Storage_FileProperties_IVideoProperties<D>::Subtitle(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IVideoProperties)->put_Subtitle(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVector<hstring> consume_Windows_Storage_FileProperties_IVideoProperties<D>::Producers() const
{
    Windows::Foundation::Collections::IVector<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IVideoProperties)->get_Producers(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_FileProperties_IVideoProperties<D>::Publisher() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IVideoProperties)->get_Publisher(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Storage_FileProperties_IVideoProperties<D>::Publisher(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IVideoProperties)->put_Publisher(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVector<hstring> consume_Windows_Storage_FileProperties_IVideoProperties<D>::Writers() const
{
    Windows::Foundation::Collections::IVector<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IVideoProperties)->get_Writers(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Storage_FileProperties_IVideoProperties<D>::Year() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IVideoProperties)->get_Year(&value));
    return value;
}

template <typename D> void consume_Windows_Storage_FileProperties_IVideoProperties<D>::Year(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IVideoProperties)->put_Year(value));
}

template <typename D> uint32_t consume_Windows_Storage_FileProperties_IVideoProperties<D>::Bitrate() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IVideoProperties)->get_Bitrate(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<hstring> consume_Windows_Storage_FileProperties_IVideoProperties<D>::Directors() const
{
    Windows::Foundation::Collections::IVector<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IVideoProperties)->get_Directors(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::FileProperties::VideoOrientation consume_Windows_Storage_FileProperties_IVideoProperties<D>::Orientation() const
{
    Windows::Storage::FileProperties::VideoOrientation value{};
    check_hresult(WINRT_SHIM(Windows::Storage::FileProperties::IVideoProperties)->get_Orientation(put_abi(value)));
    return value;
}

template <typename D>
struct produce<D, Windows::Storage::FileProperties::IBasicProperties> : produce_base<D, Windows::Storage::FileProperties::IBasicProperties>
{
    int32_t WINRT_CALL get_Size(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Size, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().Size());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DateModified(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DateModified, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().DateModified());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ItemDate(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ItemDate, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().ItemDate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::FileProperties::IDocumentProperties> : produce_base<D, Windows::Storage::FileProperties::IDocumentProperties>
{
    int32_t WINRT_CALL get_Author(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Author, WINRT_WRAP(Windows::Foundation::Collections::IVector<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVector<hstring>>(this->shim().Author());
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

    int32_t WINRT_CALL put_Title(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Title, WINRT_WRAP(void), hstring const&);
            this->shim().Title(*reinterpret_cast<hstring const*>(&value));
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
            WINRT_ASSERT_DECLARATION(Keywords, WINRT_WRAP(Windows::Foundation::Collections::IVector<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVector<hstring>>(this->shim().Keywords());
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

    int32_t WINRT_CALL put_Comment(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Comment, WINRT_WRAP(void), hstring const&);
            this->shim().Comment(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::FileProperties::IGeotagHelperStatics> : produce_base<D, Windows::Storage::FileProperties::IGeotagHelperStatics>
{
    int32_t WINRT_CALL GetGeotagAsync(void* file, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetGeotagAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Geolocation::Geopoint>), Windows::Storage::IStorageFile const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Geolocation::Geopoint>>(this->shim().GetGeotagAsync(*reinterpret_cast<Windows::Storage::IStorageFile const*>(&file)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetGeotagFromGeolocatorAsync(void* file, void* geolocator, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetGeotagFromGeolocatorAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Storage::IStorageFile const, Windows::Devices::Geolocation::Geolocator const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SetGeotagFromGeolocatorAsync(*reinterpret_cast<Windows::Storage::IStorageFile const*>(&file), *reinterpret_cast<Windows::Devices::Geolocation::Geolocator const*>(&geolocator)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetGeotagAsync(void* file, void* geopoint, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetGeotagAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Storage::IStorageFile const, Windows::Devices::Geolocation::Geopoint const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SetGeotagAsync(*reinterpret_cast<Windows::Storage::IStorageFile const*>(&file), *reinterpret_cast<Windows::Devices::Geolocation::Geopoint const*>(&geopoint)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::FileProperties::IImageProperties> : produce_base<D, Windows::Storage::FileProperties::IImageProperties>
{
    int32_t WINRT_CALL get_Rating(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Rating, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Rating());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Rating(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Rating, WINRT_WRAP(void), uint32_t);
            this->shim().Rating(value);
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
            WINRT_ASSERT_DECLARATION(Keywords, WINRT_WRAP(Windows::Foundation::Collections::IVector<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVector<hstring>>(this->shim().Keywords());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DateTaken(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DateTaken, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().DateTaken());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DateTaken(Windows::Foundation::DateTime value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DateTaken, WINRT_WRAP(void), Windows::Foundation::DateTime const&);
            this->shim().DateTaken(*reinterpret_cast<Windows::Foundation::DateTime const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Width(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Width, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Width());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Height(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Height, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Height());
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

    int32_t WINRT_CALL put_Title(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Title, WINRT_WRAP(void), hstring const&);
            this->shim().Title(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Latitude(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Latitude, WINRT_WRAP(Windows::Foundation::IReference<double>));
            *value = detach_from<Windows::Foundation::IReference<double>>(this->shim().Latitude());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Longitude(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Longitude, WINRT_WRAP(Windows::Foundation::IReference<double>));
            *value = detach_from<Windows::Foundation::IReference<double>>(this->shim().Longitude());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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

    int32_t WINRT_CALL put_CameraManufacturer(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CameraManufacturer, WINRT_WRAP(void), hstring const&);
            this->shim().CameraManufacturer(*reinterpret_cast<hstring const*>(&value));
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

    int32_t WINRT_CALL put_CameraModel(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CameraModel, WINRT_WRAP(void), hstring const&);
            this->shim().CameraModel(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Orientation(Windows::Storage::FileProperties::PhotoOrientation* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Orientation, WINRT_WRAP(Windows::Storage::FileProperties::PhotoOrientation));
            *value = detach_from<Windows::Storage::FileProperties::PhotoOrientation>(this->shim().Orientation());
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
            WINRT_ASSERT_DECLARATION(PeopleNames, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().PeopleNames());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::FileProperties::IMusicProperties> : produce_base<D, Windows::Storage::FileProperties::IMusicProperties>
{
    int32_t WINRT_CALL get_Album(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Album, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Album());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Album(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Album, WINRT_WRAP(void), hstring const&);
            this->shim().Album(*reinterpret_cast<hstring const*>(&value));
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

    int32_t WINRT_CALL put_Artist(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Artist, WINRT_WRAP(void), hstring const&);
            this->shim().Artist(*reinterpret_cast<hstring const*>(&value));
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
            WINRT_ASSERT_DECLARATION(Genre, WINRT_WRAP(Windows::Foundation::Collections::IVector<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVector<hstring>>(this->shim().Genre());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TrackNumber(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrackNumber, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().TrackNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TrackNumber(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrackNumber, WINRT_WRAP(void), uint32_t);
            this->shim().TrackNumber(value);
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

    int32_t WINRT_CALL put_Title(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Title, WINRT_WRAP(void), hstring const&);
            this->shim().Title(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Rating(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Rating, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Rating());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Rating(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Rating, WINRT_WRAP(void), uint32_t);
            this->shim().Rating(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Duration(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Duration, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().Duration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Bitrate(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Bitrate, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Bitrate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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

    int32_t WINRT_CALL put_AlbumArtist(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AlbumArtist, WINRT_WRAP(void), hstring const&);
            this->shim().AlbumArtist(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Composers(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Composers, WINRT_WRAP(Windows::Foundation::Collections::IVector<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVector<hstring>>(this->shim().Composers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Conductors(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Conductors, WINRT_WRAP(Windows::Foundation::Collections::IVector<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVector<hstring>>(this->shim().Conductors());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Subtitle(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Subtitle, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Subtitle());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Subtitle(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Subtitle, WINRT_WRAP(void), hstring const&);
            this->shim().Subtitle(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Producers(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Producers, WINRT_WRAP(Windows::Foundation::Collections::IVector<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVector<hstring>>(this->shim().Producers());
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

    int32_t WINRT_CALL put_Publisher(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Publisher, WINRT_WRAP(void), hstring const&);
            this->shim().Publisher(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Writers(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Writers, WINRT_WRAP(Windows::Foundation::Collections::IVector<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVector<hstring>>(this->shim().Writers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Year(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Year, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Year());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Year(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Year, WINRT_WRAP(void), uint32_t);
            this->shim().Year(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::FileProperties::IStorageItemContentProperties> : produce_base<D, Windows::Storage::FileProperties::IStorageItemContentProperties>
{
    int32_t WINRT_CALL GetMusicPropertiesAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetMusicPropertiesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::FileProperties::MusicProperties>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::FileProperties::MusicProperties>>(this->shim().GetMusicPropertiesAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetVideoPropertiesAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetVideoPropertiesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::FileProperties::VideoProperties>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::FileProperties::VideoProperties>>(this->shim().GetVideoPropertiesAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetImagePropertiesAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetImagePropertiesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::FileProperties::ImageProperties>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::FileProperties::ImageProperties>>(this->shim().GetImagePropertiesAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDocumentPropertiesAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDocumentPropertiesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::FileProperties::DocumentProperties>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::FileProperties::DocumentProperties>>(this->shim().GetDocumentPropertiesAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::FileProperties::IStorageItemExtraProperties> : produce_base<D, Windows::Storage::FileProperties::IStorageItemExtraProperties>
{
    int32_t WINRT_CALL RetrievePropertiesAsync(void* propertiesToRetrieve, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RetrievePropertiesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IMap<hstring, Windows::Foundation::IInspectable>>), Windows::Foundation::Collections::IIterable<hstring> const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IMap<hstring, Windows::Foundation::IInspectable>>>(this->shim().RetrievePropertiesAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&propertiesToRetrieve)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SavePropertiesAsync(void* propertiesToSave, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SavePropertiesAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Foundation::Collections::IIterable<Windows::Foundation::Collections::IKeyValuePair<hstring, Windows::Foundation::IInspectable>> const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SavePropertiesAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Foundation::Collections::IKeyValuePair<hstring, Windows::Foundation::IInspectable>> const*>(&propertiesToSave)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SavePropertiesAsyncOverloadDefault(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SavePropertiesAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SavePropertiesAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::FileProperties::IThumbnailProperties> : produce_base<D, Windows::Storage::FileProperties::IThumbnailProperties>
{
    int32_t WINRT_CALL get_OriginalWidth(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OriginalWidth, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().OriginalWidth());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OriginalHeight(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OriginalHeight, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().OriginalHeight());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ReturnedSmallerCachedSize(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReturnedSmallerCachedSize, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().ReturnedSmallerCachedSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Type(Windows::Storage::FileProperties::ThumbnailType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Type, WINRT_WRAP(Windows::Storage::FileProperties::ThumbnailType));
            *value = detach_from<Windows::Storage::FileProperties::ThumbnailType>(this->shim().Type());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::FileProperties::IVideoProperties> : produce_base<D, Windows::Storage::FileProperties::IVideoProperties>
{
    int32_t WINRT_CALL get_Rating(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Rating, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Rating());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Rating(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Rating, WINRT_WRAP(void), uint32_t);
            this->shim().Rating(value);
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
            WINRT_ASSERT_DECLARATION(Keywords, WINRT_WRAP(Windows::Foundation::Collections::IVector<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVector<hstring>>(this->shim().Keywords());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Width(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Width, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Width());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Height(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Height, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Height());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Duration(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Duration, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().Duration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Latitude(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Latitude, WINRT_WRAP(Windows::Foundation::IReference<double>));
            *value = detach_from<Windows::Foundation::IReference<double>>(this->shim().Latitude());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Longitude(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Longitude, WINRT_WRAP(Windows::Foundation::IReference<double>));
            *value = detach_from<Windows::Foundation::IReference<double>>(this->shim().Longitude());
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

    int32_t WINRT_CALL put_Title(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Title, WINRT_WRAP(void), hstring const&);
            this->shim().Title(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Subtitle(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Subtitle, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Subtitle());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Subtitle(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Subtitle, WINRT_WRAP(void), hstring const&);
            this->shim().Subtitle(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Producers(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Producers, WINRT_WRAP(Windows::Foundation::Collections::IVector<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVector<hstring>>(this->shim().Producers());
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

    int32_t WINRT_CALL put_Publisher(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Publisher, WINRT_WRAP(void), hstring const&);
            this->shim().Publisher(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Writers(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Writers, WINRT_WRAP(Windows::Foundation::Collections::IVector<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVector<hstring>>(this->shim().Writers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Year(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Year, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Year());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Year(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Year, WINRT_WRAP(void), uint32_t);
            this->shim().Year(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Bitrate(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Bitrate, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Bitrate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Directors(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Directors, WINRT_WRAP(Windows::Foundation::Collections::IVector<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVector<hstring>>(this->shim().Directors());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Orientation(Windows::Storage::FileProperties::VideoOrientation* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Orientation, WINRT_WRAP(Windows::Storage::FileProperties::VideoOrientation));
            *value = detach_from<Windows::Storage::FileProperties::VideoOrientation>(this->shim().Orientation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Storage::FileProperties {

inline Windows::Foundation::IAsyncOperation<Windows::Devices::Geolocation::Geopoint> GeotagHelper::GetGeotagAsync(Windows::Storage::IStorageFile const& file)
{
    return impl::call_factory<GeotagHelper, Windows::Storage::FileProperties::IGeotagHelperStatics>([&](auto&& f) { return f.GetGeotagAsync(file); });
}

inline Windows::Foundation::IAsyncAction GeotagHelper::SetGeotagFromGeolocatorAsync(Windows::Storage::IStorageFile const& file, Windows::Devices::Geolocation::Geolocator const& geolocator)
{
    return impl::call_factory<GeotagHelper, Windows::Storage::FileProperties::IGeotagHelperStatics>([&](auto&& f) { return f.SetGeotagFromGeolocatorAsync(file, geolocator); });
}

inline Windows::Foundation::IAsyncAction GeotagHelper::SetGeotagAsync(Windows::Storage::IStorageFile const& file, Windows::Devices::Geolocation::Geopoint const& geopoint)
{
    return impl::call_factory<GeotagHelper, Windows::Storage::FileProperties::IGeotagHelperStatics>([&](auto&& f) { return f.SetGeotagAsync(file, geopoint); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Storage::FileProperties::IBasicProperties> : winrt::impl::hash_base<winrt::Windows::Storage::FileProperties::IBasicProperties> {};
template<> struct hash<winrt::Windows::Storage::FileProperties::IDocumentProperties> : winrt::impl::hash_base<winrt::Windows::Storage::FileProperties::IDocumentProperties> {};
template<> struct hash<winrt::Windows::Storage::FileProperties::IGeotagHelperStatics> : winrt::impl::hash_base<winrt::Windows::Storage::FileProperties::IGeotagHelperStatics> {};
template<> struct hash<winrt::Windows::Storage::FileProperties::IImageProperties> : winrt::impl::hash_base<winrt::Windows::Storage::FileProperties::IImageProperties> {};
template<> struct hash<winrt::Windows::Storage::FileProperties::IMusicProperties> : winrt::impl::hash_base<winrt::Windows::Storage::FileProperties::IMusicProperties> {};
template<> struct hash<winrt::Windows::Storage::FileProperties::IStorageItemContentProperties> : winrt::impl::hash_base<winrt::Windows::Storage::FileProperties::IStorageItemContentProperties> {};
template<> struct hash<winrt::Windows::Storage::FileProperties::IStorageItemExtraProperties> : winrt::impl::hash_base<winrt::Windows::Storage::FileProperties::IStorageItemExtraProperties> {};
template<> struct hash<winrt::Windows::Storage::FileProperties::IThumbnailProperties> : winrt::impl::hash_base<winrt::Windows::Storage::FileProperties::IThumbnailProperties> {};
template<> struct hash<winrt::Windows::Storage::FileProperties::IVideoProperties> : winrt::impl::hash_base<winrt::Windows::Storage::FileProperties::IVideoProperties> {};
template<> struct hash<winrt::Windows::Storage::FileProperties::BasicProperties> : winrt::impl::hash_base<winrt::Windows::Storage::FileProperties::BasicProperties> {};
template<> struct hash<winrt::Windows::Storage::FileProperties::DocumentProperties> : winrt::impl::hash_base<winrt::Windows::Storage::FileProperties::DocumentProperties> {};
template<> struct hash<winrt::Windows::Storage::FileProperties::GeotagHelper> : winrt::impl::hash_base<winrt::Windows::Storage::FileProperties::GeotagHelper> {};
template<> struct hash<winrt::Windows::Storage::FileProperties::ImageProperties> : winrt::impl::hash_base<winrt::Windows::Storage::FileProperties::ImageProperties> {};
template<> struct hash<winrt::Windows::Storage::FileProperties::MusicProperties> : winrt::impl::hash_base<winrt::Windows::Storage::FileProperties::MusicProperties> {};
template<> struct hash<winrt::Windows::Storage::FileProperties::StorageItemContentProperties> : winrt::impl::hash_base<winrt::Windows::Storage::FileProperties::StorageItemContentProperties> {};
template<> struct hash<winrt::Windows::Storage::FileProperties::StorageItemThumbnail> : winrt::impl::hash_base<winrt::Windows::Storage::FileProperties::StorageItemThumbnail> {};
template<> struct hash<winrt::Windows::Storage::FileProperties::VideoProperties> : winrt::impl::hash_base<winrt::Windows::Storage::FileProperties::VideoProperties> {};

}
