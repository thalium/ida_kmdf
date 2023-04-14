// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Devices::Geolocation {

struct Geolocator;
struct Geopoint;

}

WINRT_EXPORT namespace winrt::Windows::Storage {

struct IStorageFile;

}

WINRT_EXPORT namespace winrt::Windows::Storage::Streams {

enum class InputStreamOptions : unsigned;
struct IBuffer;
struct IInputStream;
struct IOutputStream;
struct IRandomAccessStream;

}

WINRT_EXPORT namespace winrt::Windows::Storage::Streams {

struct IRandomAccessStreamWithContentType;

}

WINRT_EXPORT namespace winrt::Windows::Storage::FileProperties {

enum class PhotoOrientation : int32_t
{
    Unspecified = 0,
    Normal = 1,
    FlipHorizontal = 2,
    Rotate180 = 3,
    FlipVertical = 4,
    Transpose = 5,
    Rotate270 = 6,
    Transverse = 7,
    Rotate90 = 8,
};

enum class PropertyPrefetchOptions : uint32_t
{
    None = 0x0,
    MusicProperties = 0x1,
    VideoProperties = 0x2,
    ImageProperties = 0x4,
    DocumentProperties = 0x8,
    BasicProperties = 0x10,
};

enum class ThumbnailMode : int32_t
{
    PicturesView = 0,
    VideosView = 1,
    MusicView = 2,
    DocumentsView = 3,
    ListView = 4,
    SingleItem = 5,
};

enum class ThumbnailOptions : uint32_t
{
    None = 0x0,
    ReturnOnlyIfCached = 0x1,
    ResizeThumbnail = 0x2,
    UseCurrentScale = 0x4,
};

enum class ThumbnailType : int32_t
{
    Image = 0,
    Icon = 1,
};

enum class VideoOrientation : int32_t
{
    Normal = 0,
    Rotate90 = 90,
    Rotate180 = 180,
    Rotate270 = 270,
};

struct IBasicProperties;
struct IDocumentProperties;
struct IGeotagHelperStatics;
struct IImageProperties;
struct IMusicProperties;
struct IStorageItemContentProperties;
struct IStorageItemExtraProperties;
struct IThumbnailProperties;
struct IVideoProperties;
struct BasicProperties;
struct DocumentProperties;
struct GeotagHelper;
struct ImageProperties;
struct MusicProperties;
struct StorageItemContentProperties;
struct StorageItemThumbnail;
struct VideoProperties;

}

namespace winrt::impl {

template<> struct is_enum_flag<Windows::Storage::FileProperties::PropertyPrefetchOptions> : std::true_type {};
template<> struct is_enum_flag<Windows::Storage::FileProperties::ThumbnailOptions> : std::true_type {};
template <> struct category<Windows::Storage::FileProperties::IBasicProperties>{ using type = interface_category; };
template <> struct category<Windows::Storage::FileProperties::IDocumentProperties>{ using type = interface_category; };
template <> struct category<Windows::Storage::FileProperties::IGeotagHelperStatics>{ using type = interface_category; };
template <> struct category<Windows::Storage::FileProperties::IImageProperties>{ using type = interface_category; };
template <> struct category<Windows::Storage::FileProperties::IMusicProperties>{ using type = interface_category; };
template <> struct category<Windows::Storage::FileProperties::IStorageItemContentProperties>{ using type = interface_category; };
template <> struct category<Windows::Storage::FileProperties::IStorageItemExtraProperties>{ using type = interface_category; };
template <> struct category<Windows::Storage::FileProperties::IThumbnailProperties>{ using type = interface_category; };
template <> struct category<Windows::Storage::FileProperties::IVideoProperties>{ using type = interface_category; };
template <> struct category<Windows::Storage::FileProperties::BasicProperties>{ using type = class_category; };
template <> struct category<Windows::Storage::FileProperties::DocumentProperties>{ using type = class_category; };
template <> struct category<Windows::Storage::FileProperties::GeotagHelper>{ using type = class_category; };
template <> struct category<Windows::Storage::FileProperties::ImageProperties>{ using type = class_category; };
template <> struct category<Windows::Storage::FileProperties::MusicProperties>{ using type = class_category; };
template <> struct category<Windows::Storage::FileProperties::StorageItemContentProperties>{ using type = class_category; };
template <> struct category<Windows::Storage::FileProperties::StorageItemThumbnail>{ using type = class_category; };
template <> struct category<Windows::Storage::FileProperties::VideoProperties>{ using type = class_category; };
template <> struct category<Windows::Storage::FileProperties::PhotoOrientation>{ using type = enum_category; };
template <> struct category<Windows::Storage::FileProperties::PropertyPrefetchOptions>{ using type = enum_category; };
template <> struct category<Windows::Storage::FileProperties::ThumbnailMode>{ using type = enum_category; };
template <> struct category<Windows::Storage::FileProperties::ThumbnailOptions>{ using type = enum_category; };
template <> struct category<Windows::Storage::FileProperties::ThumbnailType>{ using type = enum_category; };
template <> struct category<Windows::Storage::FileProperties::VideoOrientation>{ using type = enum_category; };
template <> struct name<Windows::Storage::FileProperties::IBasicProperties>{ static constexpr auto & value{ L"Windows.Storage.FileProperties.IBasicProperties" }; };
template <> struct name<Windows::Storage::FileProperties::IDocumentProperties>{ static constexpr auto & value{ L"Windows.Storage.FileProperties.IDocumentProperties" }; };
template <> struct name<Windows::Storage::FileProperties::IGeotagHelperStatics>{ static constexpr auto & value{ L"Windows.Storage.FileProperties.IGeotagHelperStatics" }; };
template <> struct name<Windows::Storage::FileProperties::IImageProperties>{ static constexpr auto & value{ L"Windows.Storage.FileProperties.IImageProperties" }; };
template <> struct name<Windows::Storage::FileProperties::IMusicProperties>{ static constexpr auto & value{ L"Windows.Storage.FileProperties.IMusicProperties" }; };
template <> struct name<Windows::Storage::FileProperties::IStorageItemContentProperties>{ static constexpr auto & value{ L"Windows.Storage.FileProperties.IStorageItemContentProperties" }; };
template <> struct name<Windows::Storage::FileProperties::IStorageItemExtraProperties>{ static constexpr auto & value{ L"Windows.Storage.FileProperties.IStorageItemExtraProperties" }; };
template <> struct name<Windows::Storage::FileProperties::IThumbnailProperties>{ static constexpr auto & value{ L"Windows.Storage.FileProperties.IThumbnailProperties" }; };
template <> struct name<Windows::Storage::FileProperties::IVideoProperties>{ static constexpr auto & value{ L"Windows.Storage.FileProperties.IVideoProperties" }; };
template <> struct name<Windows::Storage::FileProperties::BasicProperties>{ static constexpr auto & value{ L"Windows.Storage.FileProperties.BasicProperties" }; };
template <> struct name<Windows::Storage::FileProperties::DocumentProperties>{ static constexpr auto & value{ L"Windows.Storage.FileProperties.DocumentProperties" }; };
template <> struct name<Windows::Storage::FileProperties::GeotagHelper>{ static constexpr auto & value{ L"Windows.Storage.FileProperties.GeotagHelper" }; };
template <> struct name<Windows::Storage::FileProperties::ImageProperties>{ static constexpr auto & value{ L"Windows.Storage.FileProperties.ImageProperties" }; };
template <> struct name<Windows::Storage::FileProperties::MusicProperties>{ static constexpr auto & value{ L"Windows.Storage.FileProperties.MusicProperties" }; };
template <> struct name<Windows::Storage::FileProperties::StorageItemContentProperties>{ static constexpr auto & value{ L"Windows.Storage.FileProperties.StorageItemContentProperties" }; };
template <> struct name<Windows::Storage::FileProperties::StorageItemThumbnail>{ static constexpr auto & value{ L"Windows.Storage.FileProperties.StorageItemThumbnail" }; };
template <> struct name<Windows::Storage::FileProperties::VideoProperties>{ static constexpr auto & value{ L"Windows.Storage.FileProperties.VideoProperties" }; };
template <> struct name<Windows::Storage::FileProperties::PhotoOrientation>{ static constexpr auto & value{ L"Windows.Storage.FileProperties.PhotoOrientation" }; };
template <> struct name<Windows::Storage::FileProperties::PropertyPrefetchOptions>{ static constexpr auto & value{ L"Windows.Storage.FileProperties.PropertyPrefetchOptions" }; };
template <> struct name<Windows::Storage::FileProperties::ThumbnailMode>{ static constexpr auto & value{ L"Windows.Storage.FileProperties.ThumbnailMode" }; };
template <> struct name<Windows::Storage::FileProperties::ThumbnailOptions>{ static constexpr auto & value{ L"Windows.Storage.FileProperties.ThumbnailOptions" }; };
template <> struct name<Windows::Storage::FileProperties::ThumbnailType>{ static constexpr auto & value{ L"Windows.Storage.FileProperties.ThumbnailType" }; };
template <> struct name<Windows::Storage::FileProperties::VideoOrientation>{ static constexpr auto & value{ L"Windows.Storage.FileProperties.VideoOrientation" }; };
template <> struct guid_storage<Windows::Storage::FileProperties::IBasicProperties>{ static constexpr guid value{ 0xD05D55DB,0x785E,0x4A66,{ 0xBE,0x02,0x9B,0xEE,0xC5,0x8A,0xEA,0x81 } }; };
template <> struct guid_storage<Windows::Storage::FileProperties::IDocumentProperties>{ static constexpr guid value{ 0x7EAB19BC,0x1821,0x4923,{ 0xB4,0xA9,0x0A,0xEA,0x40,0x4D,0x00,0x70 } }; };
template <> struct guid_storage<Windows::Storage::FileProperties::IGeotagHelperStatics>{ static constexpr guid value{ 0x41493244,0x2524,0x4655,{ 0x86,0xA6,0xED,0x16,0xF5,0xFC,0x71,0x6B } }; };
template <> struct guid_storage<Windows::Storage::FileProperties::IImageProperties>{ static constexpr guid value{ 0x523C9424,0xFCFF,0x4275,{ 0xAF,0xEE,0xEC,0xDB,0x9A,0xB4,0x79,0x73 } }; };
template <> struct guid_storage<Windows::Storage::FileProperties::IMusicProperties>{ static constexpr guid value{ 0xBC8AAB62,0x66EC,0x419A,{ 0xBC,0x5D,0xCA,0x65,0xA4,0xCB,0x46,0xDA } }; };
template <> struct guid_storage<Windows::Storage::FileProperties::IStorageItemContentProperties>{ static constexpr guid value{ 0x05294BAD,0xBC38,0x48BF,{ 0x85,0xD7,0x77,0x0E,0x0E,0x2A,0xE0,0xBA } }; };
template <> struct guid_storage<Windows::Storage::FileProperties::IStorageItemExtraProperties>{ static constexpr guid value{ 0xC54361B2,0x54CD,0x432B,{ 0xBD,0xBC,0x4B,0x19,0xC4,0xB4,0x70,0xD7 } }; };
template <> struct guid_storage<Windows::Storage::FileProperties::IThumbnailProperties>{ static constexpr guid value{ 0x693DD42F,0xDBE7,0x49B5,{ 0xB3,0xB3,0x28,0x93,0xAC,0x5D,0x34,0x23 } }; };
template <> struct guid_storage<Windows::Storage::FileProperties::IVideoProperties>{ static constexpr guid value{ 0x719AE507,0x68DE,0x4DB8,{ 0x97,0xDE,0x49,0x99,0x8C,0x05,0x9F,0x2F } }; };
template <> struct default_interface<Windows::Storage::FileProperties::BasicProperties>{ using type = Windows::Storage::FileProperties::IBasicProperties; };
template <> struct default_interface<Windows::Storage::FileProperties::DocumentProperties>{ using type = Windows::Storage::FileProperties::IDocumentProperties; };
template <> struct default_interface<Windows::Storage::FileProperties::ImageProperties>{ using type = Windows::Storage::FileProperties::IImageProperties; };
template <> struct default_interface<Windows::Storage::FileProperties::MusicProperties>{ using type = Windows::Storage::FileProperties::IMusicProperties; };
template <> struct default_interface<Windows::Storage::FileProperties::StorageItemContentProperties>{ using type = Windows::Storage::FileProperties::IStorageItemContentProperties; };
template <> struct default_interface<Windows::Storage::FileProperties::StorageItemThumbnail>{ using type = Windows::Storage::Streams::IRandomAccessStreamWithContentType; };
template <> struct default_interface<Windows::Storage::FileProperties::VideoProperties>{ using type = Windows::Storage::FileProperties::IVideoProperties; };

template <> struct abi<Windows::Storage::FileProperties::IBasicProperties>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Size(uint64_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DateModified(Windows::Foundation::DateTime* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ItemDate(Windows::Foundation::DateTime* value) noexcept = 0;
};};

template <> struct abi<Windows::Storage::FileProperties::IDocumentProperties>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Author(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Title(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Title(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Keywords(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Comment(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Comment(void* value) noexcept = 0;
};};

template <> struct abi<Windows::Storage::FileProperties::IGeotagHelperStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetGeotagAsync(void* file, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL SetGeotagFromGeolocatorAsync(void* file, void* geolocator, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL SetGeotagAsync(void* file, void* geopoint, void** operation) noexcept = 0;
};};

template <> struct abi<Windows::Storage::FileProperties::IImageProperties>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Rating(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Rating(uint32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Keywords(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DateTaken(Windows::Foundation::DateTime* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_DateTaken(Windows::Foundation::DateTime value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Width(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Height(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Title(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Title(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Latitude(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Longitude(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CameraManufacturer(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_CameraManufacturer(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CameraModel(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_CameraModel(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Orientation(Windows::Storage::FileProperties::PhotoOrientation* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PeopleNames(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Storage::FileProperties::IMusicProperties>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Album(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Album(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Artist(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Artist(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Genre(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TrackNumber(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_TrackNumber(uint32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Title(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Title(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Rating(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Rating(uint32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Duration(Windows::Foundation::TimeSpan* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Bitrate(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AlbumArtist(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_AlbumArtist(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Composers(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Conductors(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Subtitle(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Subtitle(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Producers(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Publisher(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Publisher(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Writers(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Year(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Year(uint32_t value) noexcept = 0;
};};

template <> struct abi<Windows::Storage::FileProperties::IStorageItemContentProperties>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetMusicPropertiesAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetVideoPropertiesAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetImagePropertiesAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetDocumentPropertiesAsync(void** operation) noexcept = 0;
};};

template <> struct abi<Windows::Storage::FileProperties::IStorageItemExtraProperties>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL RetrievePropertiesAsync(void* propertiesToRetrieve, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL SavePropertiesAsync(void* propertiesToSave, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL SavePropertiesAsyncOverloadDefault(void** operation) noexcept = 0;
};};

template <> struct abi<Windows::Storage::FileProperties::IThumbnailProperties>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_OriginalWidth(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_OriginalHeight(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ReturnedSmallerCachedSize(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Type(Windows::Storage::FileProperties::ThumbnailType* value) noexcept = 0;
};};

template <> struct abi<Windows::Storage::FileProperties::IVideoProperties>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Rating(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Rating(uint32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Keywords(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Width(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Height(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Duration(Windows::Foundation::TimeSpan* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Latitude(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Longitude(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Title(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Title(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Subtitle(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Subtitle(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Producers(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Publisher(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Publisher(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Writers(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Year(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Year(uint32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Bitrate(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Directors(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Orientation(Windows::Storage::FileProperties::VideoOrientation* value) noexcept = 0;
};};

template <typename D>
struct consume_Windows_Storage_FileProperties_IBasicProperties
{
    uint64_t Size() const;
    Windows::Foundation::DateTime DateModified() const;
    Windows::Foundation::DateTime ItemDate() const;
};
template <> struct consume<Windows::Storage::FileProperties::IBasicProperties> { template <typename D> using type = consume_Windows_Storage_FileProperties_IBasicProperties<D>; };

template <typename D>
struct consume_Windows_Storage_FileProperties_IDocumentProperties
{
    Windows::Foundation::Collections::IVector<hstring> Author() const;
    hstring Title() const;
    void Title(param::hstring const& value) const;
    Windows::Foundation::Collections::IVector<hstring> Keywords() const;
    hstring Comment() const;
    void Comment(param::hstring const& value) const;
};
template <> struct consume<Windows::Storage::FileProperties::IDocumentProperties> { template <typename D> using type = consume_Windows_Storage_FileProperties_IDocumentProperties<D>; };

template <typename D>
struct consume_Windows_Storage_FileProperties_IGeotagHelperStatics
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Geolocation::Geopoint> GetGeotagAsync(Windows::Storage::IStorageFile const& file) const;
    Windows::Foundation::IAsyncAction SetGeotagFromGeolocatorAsync(Windows::Storage::IStorageFile const& file, Windows::Devices::Geolocation::Geolocator const& geolocator) const;
    Windows::Foundation::IAsyncAction SetGeotagAsync(Windows::Storage::IStorageFile const& file, Windows::Devices::Geolocation::Geopoint const& geopoint) const;
};
template <> struct consume<Windows::Storage::FileProperties::IGeotagHelperStatics> { template <typename D> using type = consume_Windows_Storage_FileProperties_IGeotagHelperStatics<D>; };

template <typename D>
struct consume_Windows_Storage_FileProperties_IImageProperties
{
    uint32_t Rating() const;
    void Rating(uint32_t value) const;
    Windows::Foundation::Collections::IVector<hstring> Keywords() const;
    Windows::Foundation::DateTime DateTaken() const;
    void DateTaken(Windows::Foundation::DateTime const& value) const;
    uint32_t Width() const;
    uint32_t Height() const;
    hstring Title() const;
    void Title(param::hstring const& value) const;
    Windows::Foundation::IReference<double> Latitude() const;
    Windows::Foundation::IReference<double> Longitude() const;
    hstring CameraManufacturer() const;
    void CameraManufacturer(param::hstring const& value) const;
    hstring CameraModel() const;
    void CameraModel(param::hstring const& value) const;
    Windows::Storage::FileProperties::PhotoOrientation Orientation() const;
    Windows::Foundation::Collections::IVectorView<hstring> PeopleNames() const;
};
template <> struct consume<Windows::Storage::FileProperties::IImageProperties> { template <typename D> using type = consume_Windows_Storage_FileProperties_IImageProperties<D>; };

template <typename D>
struct consume_Windows_Storage_FileProperties_IMusicProperties
{
    hstring Album() const;
    void Album(param::hstring const& value) const;
    hstring Artist() const;
    void Artist(param::hstring const& value) const;
    Windows::Foundation::Collections::IVector<hstring> Genre() const;
    uint32_t TrackNumber() const;
    void TrackNumber(uint32_t value) const;
    hstring Title() const;
    void Title(param::hstring const& value) const;
    uint32_t Rating() const;
    void Rating(uint32_t value) const;
    Windows::Foundation::TimeSpan Duration() const;
    uint32_t Bitrate() const;
    hstring AlbumArtist() const;
    void AlbumArtist(param::hstring const& value) const;
    Windows::Foundation::Collections::IVector<hstring> Composers() const;
    Windows::Foundation::Collections::IVector<hstring> Conductors() const;
    hstring Subtitle() const;
    void Subtitle(param::hstring const& value) const;
    Windows::Foundation::Collections::IVector<hstring> Producers() const;
    hstring Publisher() const;
    void Publisher(param::hstring const& value) const;
    Windows::Foundation::Collections::IVector<hstring> Writers() const;
    uint32_t Year() const;
    void Year(uint32_t value) const;
};
template <> struct consume<Windows::Storage::FileProperties::IMusicProperties> { template <typename D> using type = consume_Windows_Storage_FileProperties_IMusicProperties<D>; };

template <typename D>
struct consume_Windows_Storage_FileProperties_IStorageItemContentProperties
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::FileProperties::MusicProperties> GetMusicPropertiesAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::Storage::FileProperties::VideoProperties> GetVideoPropertiesAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::Storage::FileProperties::ImageProperties> GetImagePropertiesAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::Storage::FileProperties::DocumentProperties> GetDocumentPropertiesAsync() const;
};
template <> struct consume<Windows::Storage::FileProperties::IStorageItemContentProperties> { template <typename D> using type = consume_Windows_Storage_FileProperties_IStorageItemContentProperties<D>; };

template <typename D>
struct consume_Windows_Storage_FileProperties_IStorageItemExtraProperties
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IMap<hstring, Windows::Foundation::IInspectable>> RetrievePropertiesAsync(param::async_iterable<hstring> const& propertiesToRetrieve) const;
    Windows::Foundation::IAsyncAction SavePropertiesAsync(param::async_iterable<Windows::Foundation::Collections::IKeyValuePair<hstring, Windows::Foundation::IInspectable>> const& propertiesToSave) const;
    Windows::Foundation::IAsyncAction SavePropertiesAsync() const;
};
template <> struct consume<Windows::Storage::FileProperties::IStorageItemExtraProperties> { template <typename D> using type = consume_Windows_Storage_FileProperties_IStorageItemExtraProperties<D>; };

template <typename D>
struct consume_Windows_Storage_FileProperties_IThumbnailProperties
{
    uint32_t OriginalWidth() const;
    uint32_t OriginalHeight() const;
    bool ReturnedSmallerCachedSize() const;
    Windows::Storage::FileProperties::ThumbnailType Type() const;
};
template <> struct consume<Windows::Storage::FileProperties::IThumbnailProperties> { template <typename D> using type = consume_Windows_Storage_FileProperties_IThumbnailProperties<D>; };

template <typename D>
struct consume_Windows_Storage_FileProperties_IVideoProperties
{
    uint32_t Rating() const;
    void Rating(uint32_t value) const;
    Windows::Foundation::Collections::IVector<hstring> Keywords() const;
    uint32_t Width() const;
    uint32_t Height() const;
    Windows::Foundation::TimeSpan Duration() const;
    Windows::Foundation::IReference<double> Latitude() const;
    Windows::Foundation::IReference<double> Longitude() const;
    hstring Title() const;
    void Title(param::hstring const& value) const;
    hstring Subtitle() const;
    void Subtitle(param::hstring const& value) const;
    Windows::Foundation::Collections::IVector<hstring> Producers() const;
    hstring Publisher() const;
    void Publisher(param::hstring const& value) const;
    Windows::Foundation::Collections::IVector<hstring> Writers() const;
    uint32_t Year() const;
    void Year(uint32_t value) const;
    uint32_t Bitrate() const;
    Windows::Foundation::Collections::IVector<hstring> Directors() const;
    Windows::Storage::FileProperties::VideoOrientation Orientation() const;
};
template <> struct consume<Windows::Storage::FileProperties::IVideoProperties> { template <typename D> using type = consume_Windows_Storage_FileProperties_IVideoProperties<D>; };

}
