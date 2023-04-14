// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Storage {

struct IStorageFolder;

}

WINRT_EXPORT namespace winrt::Windows::Storage::Streams {

struct IRandomAccessStreamReference;

}

WINRT_EXPORT namespace winrt::Windows::Media::Import {

enum class PhotoImportAccessMode : int32_t
{
    ReadWrite = 0,
    ReadOnly = 1,
    ReadAndDelete = 2,
};

enum class PhotoImportConnectionTransport : int32_t
{
    Unknown = 0,
    Usb = 1,
    IP = 2,
    Bluetooth = 3,
};

enum class PhotoImportContentType : int32_t
{
    Unknown = 0,
    Image = 1,
    Video = 2,
};

enum class PhotoImportContentTypeFilter : int32_t
{
    OnlyImages = 0,
    OnlyVideos = 1,
    ImagesAndVideos = 2,
    ImagesAndVideosFromCameraRoll = 3,
};

enum class PhotoImportImportMode : int32_t
{
    ImportEverything = 0,
    IgnoreSidecars = 1,
    IgnoreSiblings = 2,
    IgnoreSidecarsAndSiblings = 3,
};

enum class PhotoImportItemSelectionMode : int32_t
{
    SelectAll = 0,
    SelectNone = 1,
    SelectNew = 2,
};

enum class PhotoImportPowerSource : int32_t
{
    Unknown = 0,
    Battery = 1,
    External = 2,
};

enum class PhotoImportSourceType : int32_t
{
    Generic = 0,
    Camera = 1,
    MediaPlayer = 2,
    Phone = 3,
    Video = 4,
    PersonalInfoManager = 5,
    AudioRecorder = 6,
};

enum class PhotoImportStage : int32_t
{
    NotStarted = 0,
    FindingItems = 1,
    ImportingItems = 2,
    DeletingImportedItemsFromSource = 3,
};

enum class PhotoImportStorageMediumType : int32_t
{
    Undefined = 0,
    Fixed = 1,
    Removable = 2,
};

enum class PhotoImportSubfolderCreationMode : int32_t
{
    DoNotCreateSubfolders = 0,
    CreateSubfoldersFromFileDate = 1,
    CreateSubfoldersFromExifDate = 2,
    KeepOriginalFolderStructure = 3,
};

enum class PhotoImportSubfolderDateFormat : int32_t
{
    Year = 0,
    YearMonth = 1,
    YearMonthDay = 2,
};

struct IPhotoImportDeleteImportedItemsFromSourceResult;
struct IPhotoImportFindItemsResult;
struct IPhotoImportFindItemsResult2;
struct IPhotoImportImportItemsResult;
struct IPhotoImportItem;
struct IPhotoImportItem2;
struct IPhotoImportItemImportedEventArgs;
struct IPhotoImportManagerStatics;
struct IPhotoImportOperation;
struct IPhotoImportSelectionChangedEventArgs;
struct IPhotoImportSession;
struct IPhotoImportSession2;
struct IPhotoImportSidecar;
struct IPhotoImportSource;
struct IPhotoImportSourceStatics;
struct IPhotoImportStorageMedium;
struct IPhotoImportVideoSegment;
struct PhotoImportDeleteImportedItemsFromSourceResult;
struct PhotoImportFindItemsResult;
struct PhotoImportImportItemsResult;
struct PhotoImportItem;
struct PhotoImportItemImportedEventArgs;
struct PhotoImportManager;
struct PhotoImportOperation;
struct PhotoImportSelectionChangedEventArgs;
struct PhotoImportSession;
struct PhotoImportSidecar;
struct PhotoImportSource;
struct PhotoImportStorageMedium;
struct PhotoImportVideoSegment;
struct PhotoImportProgress;

}

namespace winrt::impl {

template <> struct category<Windows::Media::Import::IPhotoImportDeleteImportedItemsFromSourceResult>{ using type = interface_category; };
template <> struct category<Windows::Media::Import::IPhotoImportFindItemsResult>{ using type = interface_category; };
template <> struct category<Windows::Media::Import::IPhotoImportFindItemsResult2>{ using type = interface_category; };
template <> struct category<Windows::Media::Import::IPhotoImportImportItemsResult>{ using type = interface_category; };
template <> struct category<Windows::Media::Import::IPhotoImportItem>{ using type = interface_category; };
template <> struct category<Windows::Media::Import::IPhotoImportItem2>{ using type = interface_category; };
template <> struct category<Windows::Media::Import::IPhotoImportItemImportedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Media::Import::IPhotoImportManagerStatics>{ using type = interface_category; };
template <> struct category<Windows::Media::Import::IPhotoImportOperation>{ using type = interface_category; };
template <> struct category<Windows::Media::Import::IPhotoImportSelectionChangedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Media::Import::IPhotoImportSession>{ using type = interface_category; };
template <> struct category<Windows::Media::Import::IPhotoImportSession2>{ using type = interface_category; };
template <> struct category<Windows::Media::Import::IPhotoImportSidecar>{ using type = interface_category; };
template <> struct category<Windows::Media::Import::IPhotoImportSource>{ using type = interface_category; };
template <> struct category<Windows::Media::Import::IPhotoImportSourceStatics>{ using type = interface_category; };
template <> struct category<Windows::Media::Import::IPhotoImportStorageMedium>{ using type = interface_category; };
template <> struct category<Windows::Media::Import::IPhotoImportVideoSegment>{ using type = interface_category; };
template <> struct category<Windows::Media::Import::PhotoImportDeleteImportedItemsFromSourceResult>{ using type = class_category; };
template <> struct category<Windows::Media::Import::PhotoImportFindItemsResult>{ using type = class_category; };
template <> struct category<Windows::Media::Import::PhotoImportImportItemsResult>{ using type = class_category; };
template <> struct category<Windows::Media::Import::PhotoImportItem>{ using type = class_category; };
template <> struct category<Windows::Media::Import::PhotoImportItemImportedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Media::Import::PhotoImportManager>{ using type = class_category; };
template <> struct category<Windows::Media::Import::PhotoImportOperation>{ using type = class_category; };
template <> struct category<Windows::Media::Import::PhotoImportSelectionChangedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Media::Import::PhotoImportSession>{ using type = class_category; };
template <> struct category<Windows::Media::Import::PhotoImportSidecar>{ using type = class_category; };
template <> struct category<Windows::Media::Import::PhotoImportSource>{ using type = class_category; };
template <> struct category<Windows::Media::Import::PhotoImportStorageMedium>{ using type = class_category; };
template <> struct category<Windows::Media::Import::PhotoImportVideoSegment>{ using type = class_category; };
template <> struct category<Windows::Media::Import::PhotoImportAccessMode>{ using type = enum_category; };
template <> struct category<Windows::Media::Import::PhotoImportConnectionTransport>{ using type = enum_category; };
template <> struct category<Windows::Media::Import::PhotoImportContentType>{ using type = enum_category; };
template <> struct category<Windows::Media::Import::PhotoImportContentTypeFilter>{ using type = enum_category; };
template <> struct category<Windows::Media::Import::PhotoImportImportMode>{ using type = enum_category; };
template <> struct category<Windows::Media::Import::PhotoImportItemSelectionMode>{ using type = enum_category; };
template <> struct category<Windows::Media::Import::PhotoImportPowerSource>{ using type = enum_category; };
template <> struct category<Windows::Media::Import::PhotoImportSourceType>{ using type = enum_category; };
template <> struct category<Windows::Media::Import::PhotoImportStage>{ using type = enum_category; };
template <> struct category<Windows::Media::Import::PhotoImportStorageMediumType>{ using type = enum_category; };
template <> struct category<Windows::Media::Import::PhotoImportSubfolderCreationMode>{ using type = enum_category; };
template <> struct category<Windows::Media::Import::PhotoImportSubfolderDateFormat>{ using type = enum_category; };
template <> struct category<Windows::Media::Import::PhotoImportProgress>{ using type = struct_category<uint32_t,uint32_t,uint64_t,uint64_t,double>; };
template <> struct name<Windows::Media::Import::IPhotoImportDeleteImportedItemsFromSourceResult>{ static constexpr auto & value{ L"Windows.Media.Import.IPhotoImportDeleteImportedItemsFromSourceResult" }; };
template <> struct name<Windows::Media::Import::IPhotoImportFindItemsResult>{ static constexpr auto & value{ L"Windows.Media.Import.IPhotoImportFindItemsResult" }; };
template <> struct name<Windows::Media::Import::IPhotoImportFindItemsResult2>{ static constexpr auto & value{ L"Windows.Media.Import.IPhotoImportFindItemsResult2" }; };
template <> struct name<Windows::Media::Import::IPhotoImportImportItemsResult>{ static constexpr auto & value{ L"Windows.Media.Import.IPhotoImportImportItemsResult" }; };
template <> struct name<Windows::Media::Import::IPhotoImportItem>{ static constexpr auto & value{ L"Windows.Media.Import.IPhotoImportItem" }; };
template <> struct name<Windows::Media::Import::IPhotoImportItem2>{ static constexpr auto & value{ L"Windows.Media.Import.IPhotoImportItem2" }; };
template <> struct name<Windows::Media::Import::IPhotoImportItemImportedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Import.IPhotoImportItemImportedEventArgs" }; };
template <> struct name<Windows::Media::Import::IPhotoImportManagerStatics>{ static constexpr auto & value{ L"Windows.Media.Import.IPhotoImportManagerStatics" }; };
template <> struct name<Windows::Media::Import::IPhotoImportOperation>{ static constexpr auto & value{ L"Windows.Media.Import.IPhotoImportOperation" }; };
template <> struct name<Windows::Media::Import::IPhotoImportSelectionChangedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Import.IPhotoImportSelectionChangedEventArgs" }; };
template <> struct name<Windows::Media::Import::IPhotoImportSession>{ static constexpr auto & value{ L"Windows.Media.Import.IPhotoImportSession" }; };
template <> struct name<Windows::Media::Import::IPhotoImportSession2>{ static constexpr auto & value{ L"Windows.Media.Import.IPhotoImportSession2" }; };
template <> struct name<Windows::Media::Import::IPhotoImportSidecar>{ static constexpr auto & value{ L"Windows.Media.Import.IPhotoImportSidecar" }; };
template <> struct name<Windows::Media::Import::IPhotoImportSource>{ static constexpr auto & value{ L"Windows.Media.Import.IPhotoImportSource" }; };
template <> struct name<Windows::Media::Import::IPhotoImportSourceStatics>{ static constexpr auto & value{ L"Windows.Media.Import.IPhotoImportSourceStatics" }; };
template <> struct name<Windows::Media::Import::IPhotoImportStorageMedium>{ static constexpr auto & value{ L"Windows.Media.Import.IPhotoImportStorageMedium" }; };
template <> struct name<Windows::Media::Import::IPhotoImportVideoSegment>{ static constexpr auto & value{ L"Windows.Media.Import.IPhotoImportVideoSegment" }; };
template <> struct name<Windows::Media::Import::PhotoImportDeleteImportedItemsFromSourceResult>{ static constexpr auto & value{ L"Windows.Media.Import.PhotoImportDeleteImportedItemsFromSourceResult" }; };
template <> struct name<Windows::Media::Import::PhotoImportFindItemsResult>{ static constexpr auto & value{ L"Windows.Media.Import.PhotoImportFindItemsResult" }; };
template <> struct name<Windows::Media::Import::PhotoImportImportItemsResult>{ static constexpr auto & value{ L"Windows.Media.Import.PhotoImportImportItemsResult" }; };
template <> struct name<Windows::Media::Import::PhotoImportItem>{ static constexpr auto & value{ L"Windows.Media.Import.PhotoImportItem" }; };
template <> struct name<Windows::Media::Import::PhotoImportItemImportedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Import.PhotoImportItemImportedEventArgs" }; };
template <> struct name<Windows::Media::Import::PhotoImportManager>{ static constexpr auto & value{ L"Windows.Media.Import.PhotoImportManager" }; };
template <> struct name<Windows::Media::Import::PhotoImportOperation>{ static constexpr auto & value{ L"Windows.Media.Import.PhotoImportOperation" }; };
template <> struct name<Windows::Media::Import::PhotoImportSelectionChangedEventArgs>{ static constexpr auto & value{ L"Windows.Media.Import.PhotoImportSelectionChangedEventArgs" }; };
template <> struct name<Windows::Media::Import::PhotoImportSession>{ static constexpr auto & value{ L"Windows.Media.Import.PhotoImportSession" }; };
template <> struct name<Windows::Media::Import::PhotoImportSidecar>{ static constexpr auto & value{ L"Windows.Media.Import.PhotoImportSidecar" }; };
template <> struct name<Windows::Media::Import::PhotoImportSource>{ static constexpr auto & value{ L"Windows.Media.Import.PhotoImportSource" }; };
template <> struct name<Windows::Media::Import::PhotoImportStorageMedium>{ static constexpr auto & value{ L"Windows.Media.Import.PhotoImportStorageMedium" }; };
template <> struct name<Windows::Media::Import::PhotoImportVideoSegment>{ static constexpr auto & value{ L"Windows.Media.Import.PhotoImportVideoSegment" }; };
template <> struct name<Windows::Media::Import::PhotoImportAccessMode>{ static constexpr auto & value{ L"Windows.Media.Import.PhotoImportAccessMode" }; };
template <> struct name<Windows::Media::Import::PhotoImportConnectionTransport>{ static constexpr auto & value{ L"Windows.Media.Import.PhotoImportConnectionTransport" }; };
template <> struct name<Windows::Media::Import::PhotoImportContentType>{ static constexpr auto & value{ L"Windows.Media.Import.PhotoImportContentType" }; };
template <> struct name<Windows::Media::Import::PhotoImportContentTypeFilter>{ static constexpr auto & value{ L"Windows.Media.Import.PhotoImportContentTypeFilter" }; };
template <> struct name<Windows::Media::Import::PhotoImportImportMode>{ static constexpr auto & value{ L"Windows.Media.Import.PhotoImportImportMode" }; };
template <> struct name<Windows::Media::Import::PhotoImportItemSelectionMode>{ static constexpr auto & value{ L"Windows.Media.Import.PhotoImportItemSelectionMode" }; };
template <> struct name<Windows::Media::Import::PhotoImportPowerSource>{ static constexpr auto & value{ L"Windows.Media.Import.PhotoImportPowerSource" }; };
template <> struct name<Windows::Media::Import::PhotoImportSourceType>{ static constexpr auto & value{ L"Windows.Media.Import.PhotoImportSourceType" }; };
template <> struct name<Windows::Media::Import::PhotoImportStage>{ static constexpr auto & value{ L"Windows.Media.Import.PhotoImportStage" }; };
template <> struct name<Windows::Media::Import::PhotoImportStorageMediumType>{ static constexpr auto & value{ L"Windows.Media.Import.PhotoImportStorageMediumType" }; };
template <> struct name<Windows::Media::Import::PhotoImportSubfolderCreationMode>{ static constexpr auto & value{ L"Windows.Media.Import.PhotoImportSubfolderCreationMode" }; };
template <> struct name<Windows::Media::Import::PhotoImportSubfolderDateFormat>{ static constexpr auto & value{ L"Windows.Media.Import.PhotoImportSubfolderDateFormat" }; };
template <> struct name<Windows::Media::Import::PhotoImportProgress>{ static constexpr auto & value{ L"Windows.Media.Import.PhotoImportProgress" }; };
template <> struct guid_storage<Windows::Media::Import::IPhotoImportDeleteImportedItemsFromSourceResult>{ static constexpr guid value{ 0xF4E112F8,0x843D,0x428A,{ 0xA1,0xA6,0x81,0x51,0x02,0x92,0xB0,0xAE } }; };
template <> struct guid_storage<Windows::Media::Import::IPhotoImportFindItemsResult>{ static constexpr guid value{ 0x3915E647,0x6C78,0x492B,{ 0x84,0x4E,0x8F,0xE5,0xE8,0xF6,0xBF,0xB9 } }; };
template <> struct guid_storage<Windows::Media::Import::IPhotoImportFindItemsResult2>{ static constexpr guid value{ 0xFBDD6A3B,0xECF9,0x406A,{ 0x81,0x5E,0x50,0x15,0x62,0x5B,0x0A,0x88 } }; };
template <> struct guid_storage<Windows::Media::Import::IPhotoImportImportItemsResult>{ static constexpr guid value{ 0xE4D4F478,0xD419,0x4443,{ 0xA8,0x4E,0xF0,0x6A,0x85,0x0C,0x0B,0x00 } }; };
template <> struct guid_storage<Windows::Media::Import::IPhotoImportItem>{ static constexpr guid value{ 0xA9D07E76,0x9BFC,0x43B8,{ 0xB3,0x56,0x63,0x3B,0x6A,0x98,0x8C,0x9E } }; };
template <> struct guid_storage<Windows::Media::Import::IPhotoImportItem2>{ static constexpr guid value{ 0xF1053505,0xF53B,0x46A3,{ 0x9E,0x30,0x36,0x10,0x79,0x1A,0x91,0x10 } }; };
template <> struct guid_storage<Windows::Media::Import::IPhotoImportItemImportedEventArgs>{ static constexpr guid value{ 0x42CB2FDD,0x7D68,0x47B5,{ 0xBC,0x7C,0xCE,0xB7,0x3E,0x0C,0x77,0xDC } }; };
template <> struct guid_storage<Windows::Media::Import::IPhotoImportManagerStatics>{ static constexpr guid value{ 0x2771903D,0xA046,0x4F06,{ 0x9B,0x9C,0xBF,0xD6,0x62,0xE8,0x32,0x87 } }; };
template <> struct guid_storage<Windows::Media::Import::IPhotoImportOperation>{ static constexpr guid value{ 0xD9F797E4,0xA09A,0x4EE4,{ 0xA4,0xB1,0x20,0x94,0x02,0x77,0xA5,0xBE } }; };
template <> struct guid_storage<Windows::Media::Import::IPhotoImportSelectionChangedEventArgs>{ static constexpr guid value{ 0x10461782,0xFA9D,0x4C30,{ 0x8B,0xC9,0x4D,0x64,0x91,0x15,0x72,0xD5 } }; };
template <> struct guid_storage<Windows::Media::Import::IPhotoImportSession>{ static constexpr guid value{ 0xAA63916E,0xECDB,0x4EFE,{ 0x94,0xC6,0x5F,0x5C,0xAF,0xE3,0x4C,0xFB } }; };
template <> struct guid_storage<Windows::Media::Import::IPhotoImportSession2>{ static constexpr guid value{ 0x2A526710,0x3EC6,0x469D,{ 0xA3,0x75,0x2B,0x9F,0x47,0x85,0x39,0x1E } }; };
template <> struct guid_storage<Windows::Media::Import::IPhotoImportSidecar>{ static constexpr guid value{ 0x46D7D757,0xF802,0x44C7,{ 0x9C,0x98,0x7A,0x71,0xF4,0xBC,0x14,0x86 } }; };
template <> struct guid_storage<Windows::Media::Import::IPhotoImportSource>{ static constexpr guid value{ 0x1F8EA35E,0x145B,0x4CD6,{ 0x87,0xF1,0x54,0x96,0x5A,0x98,0x2F,0xEF } }; };
template <> struct guid_storage<Windows::Media::Import::IPhotoImportSourceStatics>{ static constexpr guid value{ 0x0528E586,0x32D8,0x467C,{ 0x8C,0xEE,0x23,0xA1,0xB2,0xF4,0x3E,0x85 } }; };
template <> struct guid_storage<Windows::Media::Import::IPhotoImportStorageMedium>{ static constexpr guid value{ 0xF2B9B093,0xFC85,0x487F,{ 0x87,0xC2,0x58,0xD6,0x75,0xD0,0x5B,0x07 } }; };
template <> struct guid_storage<Windows::Media::Import::IPhotoImportVideoSegment>{ static constexpr guid value{ 0x623C0289,0x321A,0x41D8,{ 0x91,0x66,0x8C,0x62,0xA3,0x33,0x27,0x6C } }; };
template <> struct default_interface<Windows::Media::Import::PhotoImportDeleteImportedItemsFromSourceResult>{ using type = Windows::Media::Import::IPhotoImportDeleteImportedItemsFromSourceResult; };
template <> struct default_interface<Windows::Media::Import::PhotoImportFindItemsResult>{ using type = Windows::Media::Import::IPhotoImportFindItemsResult; };
template <> struct default_interface<Windows::Media::Import::PhotoImportImportItemsResult>{ using type = Windows::Media::Import::IPhotoImportImportItemsResult; };
template <> struct default_interface<Windows::Media::Import::PhotoImportItem>{ using type = Windows::Media::Import::IPhotoImportItem; };
template <> struct default_interface<Windows::Media::Import::PhotoImportItemImportedEventArgs>{ using type = Windows::Media::Import::IPhotoImportItemImportedEventArgs; };
template <> struct default_interface<Windows::Media::Import::PhotoImportOperation>{ using type = Windows::Media::Import::IPhotoImportOperation; };
template <> struct default_interface<Windows::Media::Import::PhotoImportSelectionChangedEventArgs>{ using type = Windows::Media::Import::IPhotoImportSelectionChangedEventArgs; };
template <> struct default_interface<Windows::Media::Import::PhotoImportSession>{ using type = Windows::Media::Import::IPhotoImportSession; };
template <> struct default_interface<Windows::Media::Import::PhotoImportSidecar>{ using type = Windows::Media::Import::IPhotoImportSidecar; };
template <> struct default_interface<Windows::Media::Import::PhotoImportSource>{ using type = Windows::Media::Import::IPhotoImportSource; };
template <> struct default_interface<Windows::Media::Import::PhotoImportStorageMedium>{ using type = Windows::Media::Import::IPhotoImportStorageMedium; };
template <> struct default_interface<Windows::Media::Import::PhotoImportVideoSegment>{ using type = Windows::Media::Import::IPhotoImportVideoSegment; };

template <> struct abi<Windows::Media::Import::IPhotoImportDeleteImportedItemsFromSourceResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Session(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HasSucceeded(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DeletedItems(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PhotosCount(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PhotosSizeInBytes(uint64_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_VideosCount(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_VideosSizeInBytes(uint64_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SidecarsCount(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SidecarsSizeInBytes(uint64_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SiblingsCount(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SiblingsSizeInBytes(uint64_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TotalCount(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TotalSizeInBytes(uint64_t* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Import::IPhotoImportFindItemsResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Session(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HasSucceeded(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_FoundItems(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PhotosCount(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PhotosSizeInBytes(uint64_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_VideosCount(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_VideosSizeInBytes(uint64_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SidecarsCount(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SidecarsSizeInBytes(uint64_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SiblingsCount(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SiblingsSizeInBytes(uint64_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TotalCount(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TotalSizeInBytes(uint64_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL SelectAll() noexcept = 0;
    virtual int32_t WINRT_CALL SelectNone() noexcept = 0;
    virtual int32_t WINRT_CALL SelectNewAsync(void** action) noexcept = 0;
    virtual int32_t WINRT_CALL SetImportMode(Windows::Media::Import::PhotoImportImportMode value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ImportMode(Windows::Media::Import::PhotoImportImportMode* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SelectedPhotosCount(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SelectedPhotosSizeInBytes(uint64_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SelectedVideosCount(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SelectedVideosSizeInBytes(uint64_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SelectedSidecarsCount(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SelectedSidecarsSizeInBytes(uint64_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SelectedSiblingsCount(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SelectedSiblingsSizeInBytes(uint64_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SelectedTotalCount(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SelectedTotalSizeInBytes(uint64_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL add_SelectionChanged(void* value, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_SelectionChanged(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL ImportItemsAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL add_ItemImported(void* value, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_ItemImported(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::Media::Import::IPhotoImportFindItemsResult2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL AddItemsInDateRangeToSelection(Windows::Foundation::DateTime rangeStart, Windows::Foundation::TimeSpan rangeLength) noexcept = 0;
};};

template <> struct abi<Windows::Media::Import::IPhotoImportImportItemsResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Session(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HasSucceeded(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ImportedItems(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PhotosCount(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PhotosSizeInBytes(uint64_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_VideosCount(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_VideosSizeInBytes(uint64_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SidecarsCount(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SidecarsSizeInBytes(uint64_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SiblingsCount(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SiblingsSizeInBytes(uint64_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TotalCount(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TotalSizeInBytes(uint64_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL DeleteImportedItemsFromSourceAsync(void** result) noexcept = 0;
};};

template <> struct abi<Windows::Media::Import::IPhotoImportItem>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Name(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ItemKey(uint64_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ContentType(Windows::Media::Import::PhotoImportContentType* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SizeInBytes(uint64_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Date(Windows::Foundation::DateTime* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Sibling(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Sidecars(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_VideoSegments(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsSelected(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IsSelected(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Thumbnail(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ImportedFileNames(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DeletedFileNames(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Import::IPhotoImportItem2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Path(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Import::IPhotoImportItemImportedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ImportedItem(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Import::IPhotoImportManagerStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL IsSupportedAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL FindAllSourcesAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetPendingOperations(void** result) noexcept = 0;
};};

template <> struct abi<Windows::Media::Import::IPhotoImportOperation>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Stage(Windows::Media::Import::PhotoImportStage* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Session(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ContinueFindingItemsAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL get_ContinueImportingItemsAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL get_ContinueDeletingImportedItemsFromSourceAsync(void** operation) noexcept = 0;
};};

template <> struct abi<Windows::Media::Import::IPhotoImportSelectionChangedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsSelectionEmpty(bool* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Import::IPhotoImportSession>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Source(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SessionId(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_DestinationFolder(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DestinationFolder(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_AppendSessionDateToDestinationFolder(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AppendSessionDateToDestinationFolder(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_SubfolderCreationMode(Windows::Media::Import::PhotoImportSubfolderCreationMode value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SubfolderCreationMode(Windows::Media::Import::PhotoImportSubfolderCreationMode* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_DestinationFileNamePrefix(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DestinationFileNamePrefix(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL FindItemsAsync(Windows::Media::Import::PhotoImportContentTypeFilter contentTypeFilter, Windows::Media::Import::PhotoImportItemSelectionMode itemSelectionMode, void** operation) noexcept = 0;
};};

template <> struct abi<Windows::Media::Import::IPhotoImportSession2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL put_SubfolderDateFormat(Windows::Media::Import::PhotoImportSubfolderDateFormat value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SubfolderDateFormat(Windows::Media::Import::PhotoImportSubfolderDateFormat* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_RememberDeselectedItems(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RememberDeselectedItems(bool* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Import::IPhotoImportSidecar>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Name(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SizeInBytes(uint64_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Date(Windows::Foundation::DateTime* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::Import::IPhotoImportSource>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Id(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DisplayName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Description(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Manufacturer(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Model(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SerialNumber(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ConnectionProtocol(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ConnectionTransport(Windows::Media::Import::PhotoImportConnectionTransport* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Type(Windows::Media::Import::PhotoImportSourceType* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PowerSource(Windows::Media::Import::PhotoImportPowerSource* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BatteryLevelPercent(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DateTime(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_StorageMedia(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsLocked(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsMassStorage(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Thumbnail(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateImportSession(void** result) noexcept = 0;
};};

template <> struct abi<Windows::Media::Import::IPhotoImportSourceStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL FromIdAsync(void* sourceId, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL FromFolderAsync(void* sourceRootFolder, void** operation) noexcept = 0;
};};

template <> struct abi<Windows::Media::Import::IPhotoImportStorageMedium>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Name(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Description(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SerialNumber(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_StorageMediumType(Windows::Media::Import::PhotoImportStorageMediumType* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SupportedAccessMode(Windows::Media::Import::PhotoImportAccessMode* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CapacityInBytes(uint64_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AvailableSpaceInBytes(uint64_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL Refresh() noexcept = 0;
};};

template <> struct abi<Windows::Media::Import::IPhotoImportVideoSegment>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Name(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SizeInBytes(uint64_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Date(Windows::Foundation::DateTime* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Sibling(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Sidecars(void** value) noexcept = 0;
};};

template <typename D>
struct consume_Windows_Media_Import_IPhotoImportDeleteImportedItemsFromSourceResult
{
    Windows::Media::Import::PhotoImportSession Session() const;
    bool HasSucceeded() const;
    Windows::Foundation::Collections::IVectorView<Windows::Media::Import::PhotoImportItem> DeletedItems() const;
    uint32_t PhotosCount() const;
    uint64_t PhotosSizeInBytes() const;
    uint32_t VideosCount() const;
    uint64_t VideosSizeInBytes() const;
    uint32_t SidecarsCount() const;
    uint64_t SidecarsSizeInBytes() const;
    uint32_t SiblingsCount() const;
    uint64_t SiblingsSizeInBytes() const;
    uint32_t TotalCount() const;
    uint64_t TotalSizeInBytes() const;
};
template <> struct consume<Windows::Media::Import::IPhotoImportDeleteImportedItemsFromSourceResult> { template <typename D> using type = consume_Windows_Media_Import_IPhotoImportDeleteImportedItemsFromSourceResult<D>; };

template <typename D>
struct consume_Windows_Media_Import_IPhotoImportFindItemsResult
{
    Windows::Media::Import::PhotoImportSession Session() const;
    bool HasSucceeded() const;
    Windows::Foundation::Collections::IVectorView<Windows::Media::Import::PhotoImportItem> FoundItems() const;
    uint32_t PhotosCount() const;
    uint64_t PhotosSizeInBytes() const;
    uint32_t VideosCount() const;
    uint64_t VideosSizeInBytes() const;
    uint32_t SidecarsCount() const;
    uint64_t SidecarsSizeInBytes() const;
    uint32_t SiblingsCount() const;
    uint64_t SiblingsSizeInBytes() const;
    uint32_t TotalCount() const;
    uint64_t TotalSizeInBytes() const;
    void SelectAll() const;
    void SelectNone() const;
    Windows::Foundation::IAsyncAction SelectNewAsync() const;
    void SetImportMode(Windows::Media::Import::PhotoImportImportMode const& value) const;
    Windows::Media::Import::PhotoImportImportMode ImportMode() const;
    uint32_t SelectedPhotosCount() const;
    uint64_t SelectedPhotosSizeInBytes() const;
    uint32_t SelectedVideosCount() const;
    uint64_t SelectedVideosSizeInBytes() const;
    uint32_t SelectedSidecarsCount() const;
    uint64_t SelectedSidecarsSizeInBytes() const;
    uint32_t SelectedSiblingsCount() const;
    uint64_t SelectedSiblingsSizeInBytes() const;
    uint32_t SelectedTotalCount() const;
    uint64_t SelectedTotalSizeInBytes() const;
    winrt::event_token SelectionChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Import::PhotoImportFindItemsResult, Windows::Media::Import::PhotoImportSelectionChangedEventArgs> const& value) const;
    using SelectionChanged_revoker = impl::event_revoker<Windows::Media::Import::IPhotoImportFindItemsResult, &impl::abi_t<Windows::Media::Import::IPhotoImportFindItemsResult>::remove_SelectionChanged>;
    SelectionChanged_revoker SelectionChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Import::PhotoImportFindItemsResult, Windows::Media::Import::PhotoImportSelectionChangedEventArgs> const& value) const;
    void SelectionChanged(winrt::event_token const& token) const noexcept;
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Media::Import::PhotoImportImportItemsResult, Windows::Media::Import::PhotoImportProgress> ImportItemsAsync() const;
    winrt::event_token ItemImported(Windows::Foundation::TypedEventHandler<Windows::Media::Import::PhotoImportFindItemsResult, Windows::Media::Import::PhotoImportItemImportedEventArgs> const& value) const;
    using ItemImported_revoker = impl::event_revoker<Windows::Media::Import::IPhotoImportFindItemsResult, &impl::abi_t<Windows::Media::Import::IPhotoImportFindItemsResult>::remove_ItemImported>;
    ItemImported_revoker ItemImported(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Import::PhotoImportFindItemsResult, Windows::Media::Import::PhotoImportItemImportedEventArgs> const& value) const;
    void ItemImported(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::Media::Import::IPhotoImportFindItemsResult> { template <typename D> using type = consume_Windows_Media_Import_IPhotoImportFindItemsResult<D>; };

template <typename D>
struct consume_Windows_Media_Import_IPhotoImportFindItemsResult2
{
    void AddItemsInDateRangeToSelection(Windows::Foundation::DateTime const& rangeStart, Windows::Foundation::TimeSpan const& rangeLength) const;
};
template <> struct consume<Windows::Media::Import::IPhotoImportFindItemsResult2> { template <typename D> using type = consume_Windows_Media_Import_IPhotoImportFindItemsResult2<D>; };

template <typename D>
struct consume_Windows_Media_Import_IPhotoImportImportItemsResult
{
    Windows::Media::Import::PhotoImportSession Session() const;
    bool HasSucceeded() const;
    Windows::Foundation::Collections::IVectorView<Windows::Media::Import::PhotoImportItem> ImportedItems() const;
    uint32_t PhotosCount() const;
    uint64_t PhotosSizeInBytes() const;
    uint32_t VideosCount() const;
    uint64_t VideosSizeInBytes() const;
    uint32_t SidecarsCount() const;
    uint64_t SidecarsSizeInBytes() const;
    uint32_t SiblingsCount() const;
    uint64_t SiblingsSizeInBytes() const;
    uint32_t TotalCount() const;
    uint64_t TotalSizeInBytes() const;
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Media::Import::PhotoImportDeleteImportedItemsFromSourceResult, double> DeleteImportedItemsFromSourceAsync() const;
};
template <> struct consume<Windows::Media::Import::IPhotoImportImportItemsResult> { template <typename D> using type = consume_Windows_Media_Import_IPhotoImportImportItemsResult<D>; };

template <typename D>
struct consume_Windows_Media_Import_IPhotoImportItem
{
    hstring Name() const;
    uint64_t ItemKey() const;
    Windows::Media::Import::PhotoImportContentType ContentType() const;
    uint64_t SizeInBytes() const;
    Windows::Foundation::DateTime Date() const;
    Windows::Media::Import::PhotoImportSidecar Sibling() const;
    Windows::Foundation::Collections::IVectorView<Windows::Media::Import::PhotoImportSidecar> Sidecars() const;
    Windows::Foundation::Collections::IVectorView<Windows::Media::Import::PhotoImportVideoSegment> VideoSegments() const;
    bool IsSelected() const;
    void IsSelected(bool value) const;
    Windows::Storage::Streams::IRandomAccessStreamReference Thumbnail() const;
    Windows::Foundation::Collections::IVectorView<hstring> ImportedFileNames() const;
    Windows::Foundation::Collections::IVectorView<hstring> DeletedFileNames() const;
};
template <> struct consume<Windows::Media::Import::IPhotoImportItem> { template <typename D> using type = consume_Windows_Media_Import_IPhotoImportItem<D>; };

template <typename D>
struct consume_Windows_Media_Import_IPhotoImportItem2
{
    hstring Path() const;
};
template <> struct consume<Windows::Media::Import::IPhotoImportItem2> { template <typename D> using type = consume_Windows_Media_Import_IPhotoImportItem2<D>; };

template <typename D>
struct consume_Windows_Media_Import_IPhotoImportItemImportedEventArgs
{
    Windows::Media::Import::PhotoImportItem ImportedItem() const;
};
template <> struct consume<Windows::Media::Import::IPhotoImportItemImportedEventArgs> { template <typename D> using type = consume_Windows_Media_Import_IPhotoImportItemImportedEventArgs<D>; };

template <typename D>
struct consume_Windows_Media_Import_IPhotoImportManagerStatics
{
    Windows::Foundation::IAsyncOperation<bool> IsSupportedAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Media::Import::PhotoImportSource>> FindAllSourcesAsync() const;
    Windows::Foundation::Collections::IVectorView<Windows::Media::Import::PhotoImportOperation> GetPendingOperations() const;
};
template <> struct consume<Windows::Media::Import::IPhotoImportManagerStatics> { template <typename D> using type = consume_Windows_Media_Import_IPhotoImportManagerStatics<D>; };

template <typename D>
struct consume_Windows_Media_Import_IPhotoImportOperation
{
    Windows::Media::Import::PhotoImportStage Stage() const;
    Windows::Media::Import::PhotoImportSession Session() const;
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Media::Import::PhotoImportFindItemsResult, uint32_t> ContinueFindingItemsAsync() const;
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Media::Import::PhotoImportImportItemsResult, Windows::Media::Import::PhotoImportProgress> ContinueImportingItemsAsync() const;
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Media::Import::PhotoImportDeleteImportedItemsFromSourceResult, double> ContinueDeletingImportedItemsFromSourceAsync() const;
};
template <> struct consume<Windows::Media::Import::IPhotoImportOperation> { template <typename D> using type = consume_Windows_Media_Import_IPhotoImportOperation<D>; };

template <typename D>
struct consume_Windows_Media_Import_IPhotoImportSelectionChangedEventArgs
{
    bool IsSelectionEmpty() const;
};
template <> struct consume<Windows::Media::Import::IPhotoImportSelectionChangedEventArgs> { template <typename D> using type = consume_Windows_Media_Import_IPhotoImportSelectionChangedEventArgs<D>; };

template <typename D>
struct consume_Windows_Media_Import_IPhotoImportSession
{
    Windows::Media::Import::PhotoImportSource Source() const;
    winrt::guid SessionId() const;
    void DestinationFolder(Windows::Storage::IStorageFolder const& value) const;
    Windows::Storage::IStorageFolder DestinationFolder() const;
    void AppendSessionDateToDestinationFolder(bool value) const;
    bool AppendSessionDateToDestinationFolder() const;
    void SubfolderCreationMode(Windows::Media::Import::PhotoImportSubfolderCreationMode const& value) const;
    Windows::Media::Import::PhotoImportSubfolderCreationMode SubfolderCreationMode() const;
    void DestinationFileNamePrefix(param::hstring const& value) const;
    hstring DestinationFileNamePrefix() const;
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Media::Import::PhotoImportFindItemsResult, uint32_t> FindItemsAsync(Windows::Media::Import::PhotoImportContentTypeFilter const& contentTypeFilter, Windows::Media::Import::PhotoImportItemSelectionMode const& itemSelectionMode) const;
};
template <> struct consume<Windows::Media::Import::IPhotoImportSession> { template <typename D> using type = consume_Windows_Media_Import_IPhotoImportSession<D>; };

template <typename D>
struct consume_Windows_Media_Import_IPhotoImportSession2
{
    void SubfolderDateFormat(Windows::Media::Import::PhotoImportSubfolderDateFormat const& value) const;
    Windows::Media::Import::PhotoImportSubfolderDateFormat SubfolderDateFormat() const;
    void RememberDeselectedItems(bool value) const;
    bool RememberDeselectedItems() const;
};
template <> struct consume<Windows::Media::Import::IPhotoImportSession2> { template <typename D> using type = consume_Windows_Media_Import_IPhotoImportSession2<D>; };

template <typename D>
struct consume_Windows_Media_Import_IPhotoImportSidecar
{
    hstring Name() const;
    uint64_t SizeInBytes() const;
    Windows::Foundation::DateTime Date() const;
};
template <> struct consume<Windows::Media::Import::IPhotoImportSidecar> { template <typename D> using type = consume_Windows_Media_Import_IPhotoImportSidecar<D>; };

template <typename D>
struct consume_Windows_Media_Import_IPhotoImportSource
{
    hstring Id() const;
    hstring DisplayName() const;
    hstring Description() const;
    hstring Manufacturer() const;
    hstring Model() const;
    hstring SerialNumber() const;
    hstring ConnectionProtocol() const;
    Windows::Media::Import::PhotoImportConnectionTransport ConnectionTransport() const;
    Windows::Media::Import::PhotoImportSourceType Type() const;
    Windows::Media::Import::PhotoImportPowerSource PowerSource() const;
    Windows::Foundation::IReference<uint32_t> BatteryLevelPercent() const;
    Windows::Foundation::IReference<Windows::Foundation::DateTime> DateTime() const;
    Windows::Foundation::Collections::IVectorView<Windows::Media::Import::PhotoImportStorageMedium> StorageMedia() const;
    Windows::Foundation::IReference<bool> IsLocked() const;
    bool IsMassStorage() const;
    Windows::Storage::Streams::IRandomAccessStreamReference Thumbnail() const;
    Windows::Media::Import::PhotoImportSession CreateImportSession() const;
};
template <> struct consume<Windows::Media::Import::IPhotoImportSource> { template <typename D> using type = consume_Windows_Media_Import_IPhotoImportSource<D>; };

template <typename D>
struct consume_Windows_Media_Import_IPhotoImportSourceStatics
{
    Windows::Foundation::IAsyncOperation<Windows::Media::Import::PhotoImportSource> FromIdAsync(param::hstring const& sourceId) const;
    Windows::Foundation::IAsyncOperation<Windows::Media::Import::PhotoImportSource> FromFolderAsync(Windows::Storage::IStorageFolder const& sourceRootFolder) const;
};
template <> struct consume<Windows::Media::Import::IPhotoImportSourceStatics> { template <typename D> using type = consume_Windows_Media_Import_IPhotoImportSourceStatics<D>; };

template <typename D>
struct consume_Windows_Media_Import_IPhotoImportStorageMedium
{
    hstring Name() const;
    hstring Description() const;
    hstring SerialNumber() const;
    Windows::Media::Import::PhotoImportStorageMediumType StorageMediumType() const;
    Windows::Media::Import::PhotoImportAccessMode SupportedAccessMode() const;
    uint64_t CapacityInBytes() const;
    uint64_t AvailableSpaceInBytes() const;
    void Refresh() const;
};
template <> struct consume<Windows::Media::Import::IPhotoImportStorageMedium> { template <typename D> using type = consume_Windows_Media_Import_IPhotoImportStorageMedium<D>; };

template <typename D>
struct consume_Windows_Media_Import_IPhotoImportVideoSegment
{
    hstring Name() const;
    uint64_t SizeInBytes() const;
    Windows::Foundation::DateTime Date() const;
    Windows::Media::Import::PhotoImportSidecar Sibling() const;
    Windows::Foundation::Collections::IVectorView<Windows::Media::Import::PhotoImportSidecar> Sidecars() const;
};
template <> struct consume<Windows::Media::Import::IPhotoImportVideoSegment> { template <typename D> using type = consume_Windows_Media_Import_IPhotoImportVideoSegment<D>; };

struct struct_Windows_Media_Import_PhotoImportProgress
{
    uint32_t ItemsImported;
    uint32_t TotalItemsToImport;
    uint64_t BytesImported;
    uint64_t TotalBytesToImport;
    double ImportProgress;
};
template <> struct abi<Windows::Media::Import::PhotoImportProgress>{ using type = struct_Windows_Media_Import_PhotoImportProgress; };


}
