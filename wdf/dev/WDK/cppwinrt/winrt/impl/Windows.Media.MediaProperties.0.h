// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Media::Core {

struct AudioStreamDescriptor;
struct TimedMetadataStreamDescriptor;
struct VideoStreamDescriptor;

}

WINRT_EXPORT namespace winrt::Windows::Storage {

struct IStorageFile;

}

WINRT_EXPORT namespace winrt::Windows::Storage::Streams {

struct IRandomAccessStream;

}

WINRT_EXPORT namespace winrt::Windows::Media::MediaProperties {

enum class AudioEncodingQuality : int32_t
{
    Auto = 0,
    High = 1,
    Medium = 2,
    Low = 3,
};

enum class MediaMirroringOptions : uint32_t
{
    None = 0x0,
    Horizontal = 0x1,
    Vertical = 0x2,
};

enum class MediaPixelFormat : int32_t
{
    Nv12 = 0,
    Bgra8 = 1,
    P010 = 2,
};

enum class MediaRotation : int32_t
{
    None = 0,
    Clockwise90Degrees = 1,
    Clockwise180Degrees = 2,
    Clockwise270Degrees = 3,
};

enum class MediaThumbnailFormat : int32_t
{
    Bmp = 0,
    Bgra8 = 1,
};

enum class SphericalVideoFrameFormat : int32_t
{
    None = 0,
    Unsupported = 1,
    Equirectangular = 2,
};

enum class StereoscopicVideoPackingMode : int32_t
{
    None = 0,
    SideBySide = 1,
    TopBottom = 2,
};

enum class VideoEncodingQuality : int32_t
{
    Auto = 0,
    HD1080p = 1,
    HD720p = 2,
    Wvga = 3,
    Ntsc = 4,
    Pal = 5,
    Vga = 6,
    Qvga = 7,
    Uhd2160p = 8,
    Uhd4320p = 9,
};

struct IAudioEncodingProperties;
struct IAudioEncodingProperties2;
struct IAudioEncodingProperties3;
struct IAudioEncodingPropertiesStatics;
struct IAudioEncodingPropertiesStatics2;
struct IAudioEncodingPropertiesWithFormatUserData;
struct IContainerEncodingProperties;
struct IContainerEncodingProperties2;
struct IH264ProfileIdsStatics;
struct IImageEncodingProperties;
struct IImageEncodingProperties2;
struct IImageEncodingPropertiesStatics;
struct IImageEncodingPropertiesStatics2;
struct IImageEncodingPropertiesStatics3;
struct IMediaEncodingProfile;
struct IMediaEncodingProfile2;
struct IMediaEncodingProfile3;
struct IMediaEncodingProfileStatics;
struct IMediaEncodingProfileStatics2;
struct IMediaEncodingProfileStatics3;
struct IMediaEncodingProperties;
struct IMediaEncodingSubtypesStatics;
struct IMediaEncodingSubtypesStatics2;
struct IMediaEncodingSubtypesStatics3;
struct IMediaEncodingSubtypesStatics4;
struct IMediaEncodingSubtypesStatics5;
struct IMediaRatio;
struct IMpeg2ProfileIdsStatics;
struct ITimedMetadataEncodingProperties;
struct IVideoEncodingProperties;
struct IVideoEncodingProperties2;
struct IVideoEncodingProperties3;
struct IVideoEncodingProperties4;
struct IVideoEncodingProperties5;
struct IVideoEncodingPropertiesStatics;
struct IVideoEncodingPropertiesStatics2;
struct AudioEncodingProperties;
struct ContainerEncodingProperties;
struct H264ProfileIds;
struct ImageEncodingProperties;
struct MediaEncodingProfile;
struct MediaEncodingSubtypes;
struct MediaPropertySet;
struct MediaRatio;
struct Mpeg2ProfileIds;
struct TimedMetadataEncodingProperties;
struct VideoEncodingProperties;

}

namespace winrt::impl {

template<> struct is_enum_flag<Windows::Media::MediaProperties::MediaMirroringOptions> : std::true_type {};
template <> struct category<Windows::Media::MediaProperties::IAudioEncodingProperties>{ using type = interface_category; };
template <> struct category<Windows::Media::MediaProperties::IAudioEncodingProperties2>{ using type = interface_category; };
template <> struct category<Windows::Media::MediaProperties::IAudioEncodingProperties3>{ using type = interface_category; };
template <> struct category<Windows::Media::MediaProperties::IAudioEncodingPropertiesStatics>{ using type = interface_category; };
template <> struct category<Windows::Media::MediaProperties::IAudioEncodingPropertiesStatics2>{ using type = interface_category; };
template <> struct category<Windows::Media::MediaProperties::IAudioEncodingPropertiesWithFormatUserData>{ using type = interface_category; };
template <> struct category<Windows::Media::MediaProperties::IContainerEncodingProperties>{ using type = interface_category; };
template <> struct category<Windows::Media::MediaProperties::IContainerEncodingProperties2>{ using type = interface_category; };
template <> struct category<Windows::Media::MediaProperties::IH264ProfileIdsStatics>{ using type = interface_category; };
template <> struct category<Windows::Media::MediaProperties::IImageEncodingProperties>{ using type = interface_category; };
template <> struct category<Windows::Media::MediaProperties::IImageEncodingProperties2>{ using type = interface_category; };
template <> struct category<Windows::Media::MediaProperties::IImageEncodingPropertiesStatics>{ using type = interface_category; };
template <> struct category<Windows::Media::MediaProperties::IImageEncodingPropertiesStatics2>{ using type = interface_category; };
template <> struct category<Windows::Media::MediaProperties::IImageEncodingPropertiesStatics3>{ using type = interface_category; };
template <> struct category<Windows::Media::MediaProperties::IMediaEncodingProfile>{ using type = interface_category; };
template <> struct category<Windows::Media::MediaProperties::IMediaEncodingProfile2>{ using type = interface_category; };
template <> struct category<Windows::Media::MediaProperties::IMediaEncodingProfile3>{ using type = interface_category; };
template <> struct category<Windows::Media::MediaProperties::IMediaEncodingProfileStatics>{ using type = interface_category; };
template <> struct category<Windows::Media::MediaProperties::IMediaEncodingProfileStatics2>{ using type = interface_category; };
template <> struct category<Windows::Media::MediaProperties::IMediaEncodingProfileStatics3>{ using type = interface_category; };
template <> struct category<Windows::Media::MediaProperties::IMediaEncodingProperties>{ using type = interface_category; };
template <> struct category<Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics>{ using type = interface_category; };
template <> struct category<Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics2>{ using type = interface_category; };
template <> struct category<Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics3>{ using type = interface_category; };
template <> struct category<Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics4>{ using type = interface_category; };
template <> struct category<Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics5>{ using type = interface_category; };
template <> struct category<Windows::Media::MediaProperties::IMediaRatio>{ using type = interface_category; };
template <> struct category<Windows::Media::MediaProperties::IMpeg2ProfileIdsStatics>{ using type = interface_category; };
template <> struct category<Windows::Media::MediaProperties::ITimedMetadataEncodingProperties>{ using type = interface_category; };
template <> struct category<Windows::Media::MediaProperties::IVideoEncodingProperties>{ using type = interface_category; };
template <> struct category<Windows::Media::MediaProperties::IVideoEncodingProperties2>{ using type = interface_category; };
template <> struct category<Windows::Media::MediaProperties::IVideoEncodingProperties3>{ using type = interface_category; };
template <> struct category<Windows::Media::MediaProperties::IVideoEncodingProperties4>{ using type = interface_category; };
template <> struct category<Windows::Media::MediaProperties::IVideoEncodingProperties5>{ using type = interface_category; };
template <> struct category<Windows::Media::MediaProperties::IVideoEncodingPropertiesStatics>{ using type = interface_category; };
template <> struct category<Windows::Media::MediaProperties::IVideoEncodingPropertiesStatics2>{ using type = interface_category; };
template <> struct category<Windows::Media::MediaProperties::AudioEncodingProperties>{ using type = class_category; };
template <> struct category<Windows::Media::MediaProperties::ContainerEncodingProperties>{ using type = class_category; };
template <> struct category<Windows::Media::MediaProperties::H264ProfileIds>{ using type = class_category; };
template <> struct category<Windows::Media::MediaProperties::ImageEncodingProperties>{ using type = class_category; };
template <> struct category<Windows::Media::MediaProperties::MediaEncodingProfile>{ using type = class_category; };
template <> struct category<Windows::Media::MediaProperties::MediaEncodingSubtypes>{ using type = class_category; };
template <> struct category<Windows::Media::MediaProperties::MediaPropertySet>{ using type = class_category; };
template <> struct category<Windows::Media::MediaProperties::MediaRatio>{ using type = class_category; };
template <> struct category<Windows::Media::MediaProperties::Mpeg2ProfileIds>{ using type = class_category; };
template <> struct category<Windows::Media::MediaProperties::TimedMetadataEncodingProperties>{ using type = class_category; };
template <> struct category<Windows::Media::MediaProperties::VideoEncodingProperties>{ using type = class_category; };
template <> struct category<Windows::Media::MediaProperties::AudioEncodingQuality>{ using type = enum_category; };
template <> struct category<Windows::Media::MediaProperties::MediaMirroringOptions>{ using type = enum_category; };
template <> struct category<Windows::Media::MediaProperties::MediaPixelFormat>{ using type = enum_category; };
template <> struct category<Windows::Media::MediaProperties::MediaRotation>{ using type = enum_category; };
template <> struct category<Windows::Media::MediaProperties::MediaThumbnailFormat>{ using type = enum_category; };
template <> struct category<Windows::Media::MediaProperties::SphericalVideoFrameFormat>{ using type = enum_category; };
template <> struct category<Windows::Media::MediaProperties::StereoscopicVideoPackingMode>{ using type = enum_category; };
template <> struct category<Windows::Media::MediaProperties::VideoEncodingQuality>{ using type = enum_category; };
template <> struct name<Windows::Media::MediaProperties::IAudioEncodingProperties>{ static constexpr auto & value{ L"Windows.Media.MediaProperties.IAudioEncodingProperties" }; };
template <> struct name<Windows::Media::MediaProperties::IAudioEncodingProperties2>{ static constexpr auto & value{ L"Windows.Media.MediaProperties.IAudioEncodingProperties2" }; };
template <> struct name<Windows::Media::MediaProperties::IAudioEncodingProperties3>{ static constexpr auto & value{ L"Windows.Media.MediaProperties.IAudioEncodingProperties3" }; };
template <> struct name<Windows::Media::MediaProperties::IAudioEncodingPropertiesStatics>{ static constexpr auto & value{ L"Windows.Media.MediaProperties.IAudioEncodingPropertiesStatics" }; };
template <> struct name<Windows::Media::MediaProperties::IAudioEncodingPropertiesStatics2>{ static constexpr auto & value{ L"Windows.Media.MediaProperties.IAudioEncodingPropertiesStatics2" }; };
template <> struct name<Windows::Media::MediaProperties::IAudioEncodingPropertiesWithFormatUserData>{ static constexpr auto & value{ L"Windows.Media.MediaProperties.IAudioEncodingPropertiesWithFormatUserData" }; };
template <> struct name<Windows::Media::MediaProperties::IContainerEncodingProperties>{ static constexpr auto & value{ L"Windows.Media.MediaProperties.IContainerEncodingProperties" }; };
template <> struct name<Windows::Media::MediaProperties::IContainerEncodingProperties2>{ static constexpr auto & value{ L"Windows.Media.MediaProperties.IContainerEncodingProperties2" }; };
template <> struct name<Windows::Media::MediaProperties::IH264ProfileIdsStatics>{ static constexpr auto & value{ L"Windows.Media.MediaProperties.IH264ProfileIdsStatics" }; };
template <> struct name<Windows::Media::MediaProperties::IImageEncodingProperties>{ static constexpr auto & value{ L"Windows.Media.MediaProperties.IImageEncodingProperties" }; };
template <> struct name<Windows::Media::MediaProperties::IImageEncodingProperties2>{ static constexpr auto & value{ L"Windows.Media.MediaProperties.IImageEncodingProperties2" }; };
template <> struct name<Windows::Media::MediaProperties::IImageEncodingPropertiesStatics>{ static constexpr auto & value{ L"Windows.Media.MediaProperties.IImageEncodingPropertiesStatics" }; };
template <> struct name<Windows::Media::MediaProperties::IImageEncodingPropertiesStatics2>{ static constexpr auto & value{ L"Windows.Media.MediaProperties.IImageEncodingPropertiesStatics2" }; };
template <> struct name<Windows::Media::MediaProperties::IImageEncodingPropertiesStatics3>{ static constexpr auto & value{ L"Windows.Media.MediaProperties.IImageEncodingPropertiesStatics3" }; };
template <> struct name<Windows::Media::MediaProperties::IMediaEncodingProfile>{ static constexpr auto & value{ L"Windows.Media.MediaProperties.IMediaEncodingProfile" }; };
template <> struct name<Windows::Media::MediaProperties::IMediaEncodingProfile2>{ static constexpr auto & value{ L"Windows.Media.MediaProperties.IMediaEncodingProfile2" }; };
template <> struct name<Windows::Media::MediaProperties::IMediaEncodingProfile3>{ static constexpr auto & value{ L"Windows.Media.MediaProperties.IMediaEncodingProfile3" }; };
template <> struct name<Windows::Media::MediaProperties::IMediaEncodingProfileStatics>{ static constexpr auto & value{ L"Windows.Media.MediaProperties.IMediaEncodingProfileStatics" }; };
template <> struct name<Windows::Media::MediaProperties::IMediaEncodingProfileStatics2>{ static constexpr auto & value{ L"Windows.Media.MediaProperties.IMediaEncodingProfileStatics2" }; };
template <> struct name<Windows::Media::MediaProperties::IMediaEncodingProfileStatics3>{ static constexpr auto & value{ L"Windows.Media.MediaProperties.IMediaEncodingProfileStatics3" }; };
template <> struct name<Windows::Media::MediaProperties::IMediaEncodingProperties>{ static constexpr auto & value{ L"Windows.Media.MediaProperties.IMediaEncodingProperties" }; };
template <> struct name<Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics>{ static constexpr auto & value{ L"Windows.Media.MediaProperties.IMediaEncodingSubtypesStatics" }; };
template <> struct name<Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics2>{ static constexpr auto & value{ L"Windows.Media.MediaProperties.IMediaEncodingSubtypesStatics2" }; };
template <> struct name<Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics3>{ static constexpr auto & value{ L"Windows.Media.MediaProperties.IMediaEncodingSubtypesStatics3" }; };
template <> struct name<Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics4>{ static constexpr auto & value{ L"Windows.Media.MediaProperties.IMediaEncodingSubtypesStatics4" }; };
template <> struct name<Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics5>{ static constexpr auto & value{ L"Windows.Media.MediaProperties.IMediaEncodingSubtypesStatics5" }; };
template <> struct name<Windows::Media::MediaProperties::IMediaRatio>{ static constexpr auto & value{ L"Windows.Media.MediaProperties.IMediaRatio" }; };
template <> struct name<Windows::Media::MediaProperties::IMpeg2ProfileIdsStatics>{ static constexpr auto & value{ L"Windows.Media.MediaProperties.IMpeg2ProfileIdsStatics" }; };
template <> struct name<Windows::Media::MediaProperties::ITimedMetadataEncodingProperties>{ static constexpr auto & value{ L"Windows.Media.MediaProperties.ITimedMetadataEncodingProperties" }; };
template <> struct name<Windows::Media::MediaProperties::IVideoEncodingProperties>{ static constexpr auto & value{ L"Windows.Media.MediaProperties.IVideoEncodingProperties" }; };
template <> struct name<Windows::Media::MediaProperties::IVideoEncodingProperties2>{ static constexpr auto & value{ L"Windows.Media.MediaProperties.IVideoEncodingProperties2" }; };
template <> struct name<Windows::Media::MediaProperties::IVideoEncodingProperties3>{ static constexpr auto & value{ L"Windows.Media.MediaProperties.IVideoEncodingProperties3" }; };
template <> struct name<Windows::Media::MediaProperties::IVideoEncodingProperties4>{ static constexpr auto & value{ L"Windows.Media.MediaProperties.IVideoEncodingProperties4" }; };
template <> struct name<Windows::Media::MediaProperties::IVideoEncodingProperties5>{ static constexpr auto & value{ L"Windows.Media.MediaProperties.IVideoEncodingProperties5" }; };
template <> struct name<Windows::Media::MediaProperties::IVideoEncodingPropertiesStatics>{ static constexpr auto & value{ L"Windows.Media.MediaProperties.IVideoEncodingPropertiesStatics" }; };
template <> struct name<Windows::Media::MediaProperties::IVideoEncodingPropertiesStatics2>{ static constexpr auto & value{ L"Windows.Media.MediaProperties.IVideoEncodingPropertiesStatics2" }; };
template <> struct name<Windows::Media::MediaProperties::AudioEncodingProperties>{ static constexpr auto & value{ L"Windows.Media.MediaProperties.AudioEncodingProperties" }; };
template <> struct name<Windows::Media::MediaProperties::ContainerEncodingProperties>{ static constexpr auto & value{ L"Windows.Media.MediaProperties.ContainerEncodingProperties" }; };
template <> struct name<Windows::Media::MediaProperties::H264ProfileIds>{ static constexpr auto & value{ L"Windows.Media.MediaProperties.H264ProfileIds" }; };
template <> struct name<Windows::Media::MediaProperties::ImageEncodingProperties>{ static constexpr auto & value{ L"Windows.Media.MediaProperties.ImageEncodingProperties" }; };
template <> struct name<Windows::Media::MediaProperties::MediaEncodingProfile>{ static constexpr auto & value{ L"Windows.Media.MediaProperties.MediaEncodingProfile" }; };
template <> struct name<Windows::Media::MediaProperties::MediaEncodingSubtypes>{ static constexpr auto & value{ L"Windows.Media.MediaProperties.MediaEncodingSubtypes" }; };
template <> struct name<Windows::Media::MediaProperties::MediaPropertySet>{ static constexpr auto & value{ L"Windows.Media.MediaProperties.MediaPropertySet" }; };
template <> struct name<Windows::Media::MediaProperties::MediaRatio>{ static constexpr auto & value{ L"Windows.Media.MediaProperties.MediaRatio" }; };
template <> struct name<Windows::Media::MediaProperties::Mpeg2ProfileIds>{ static constexpr auto & value{ L"Windows.Media.MediaProperties.Mpeg2ProfileIds" }; };
template <> struct name<Windows::Media::MediaProperties::TimedMetadataEncodingProperties>{ static constexpr auto & value{ L"Windows.Media.MediaProperties.TimedMetadataEncodingProperties" }; };
template <> struct name<Windows::Media::MediaProperties::VideoEncodingProperties>{ static constexpr auto & value{ L"Windows.Media.MediaProperties.VideoEncodingProperties" }; };
template <> struct name<Windows::Media::MediaProperties::AudioEncodingQuality>{ static constexpr auto & value{ L"Windows.Media.MediaProperties.AudioEncodingQuality" }; };
template <> struct name<Windows::Media::MediaProperties::MediaMirroringOptions>{ static constexpr auto & value{ L"Windows.Media.MediaProperties.MediaMirroringOptions" }; };
template <> struct name<Windows::Media::MediaProperties::MediaPixelFormat>{ static constexpr auto & value{ L"Windows.Media.MediaProperties.MediaPixelFormat" }; };
template <> struct name<Windows::Media::MediaProperties::MediaRotation>{ static constexpr auto & value{ L"Windows.Media.MediaProperties.MediaRotation" }; };
template <> struct name<Windows::Media::MediaProperties::MediaThumbnailFormat>{ static constexpr auto & value{ L"Windows.Media.MediaProperties.MediaThumbnailFormat" }; };
template <> struct name<Windows::Media::MediaProperties::SphericalVideoFrameFormat>{ static constexpr auto & value{ L"Windows.Media.MediaProperties.SphericalVideoFrameFormat" }; };
template <> struct name<Windows::Media::MediaProperties::StereoscopicVideoPackingMode>{ static constexpr auto & value{ L"Windows.Media.MediaProperties.StereoscopicVideoPackingMode" }; };
template <> struct name<Windows::Media::MediaProperties::VideoEncodingQuality>{ static constexpr auto & value{ L"Windows.Media.MediaProperties.VideoEncodingQuality" }; };
template <> struct guid_storage<Windows::Media::MediaProperties::IAudioEncodingProperties>{ static constexpr guid value{ 0x62BC7A16,0x005C,0x4B3B,{ 0x8A,0x0B,0x0A,0x09,0x0E,0x96,0x87,0xF3 } }; };
template <> struct guid_storage<Windows::Media::MediaProperties::IAudioEncodingProperties2>{ static constexpr guid value{ 0xC45D54DA,0x80BD,0x4C23,{ 0x80,0xD5,0x72,0xD4,0xA1,0x81,0xE8,0x94 } }; };
template <> struct guid_storage<Windows::Media::MediaProperties::IAudioEncodingProperties3>{ static constexpr guid value{ 0x87600341,0x748C,0x4F8D,{ 0xB0,0xFD,0x10,0xCA,0xF0,0x8F,0xF0,0x87 } }; };
template <> struct guid_storage<Windows::Media::MediaProperties::IAudioEncodingPropertiesStatics>{ static constexpr guid value{ 0x0CAD332C,0xEBE9,0x4527,{ 0xB3,0x6D,0xE4,0x2A,0x13,0xCF,0x38,0xDB } }; };
template <> struct guid_storage<Windows::Media::MediaProperties::IAudioEncodingPropertiesStatics2>{ static constexpr guid value{ 0x7489316F,0x77A0,0x433D,{ 0x8E,0xD5,0x40,0x40,0x28,0x0E,0x86,0x65 } }; };
template <> struct guid_storage<Windows::Media::MediaProperties::IAudioEncodingPropertiesWithFormatUserData>{ static constexpr guid value{ 0x98F10D79,0x13EA,0x49FF,{ 0xBE,0x70,0x26,0x73,0xDB,0x69,0x70,0x2C } }; };
template <> struct guid_storage<Windows::Media::MediaProperties::IContainerEncodingProperties>{ static constexpr guid value{ 0x59AC2A57,0xB32A,0x479E,{ 0x8A,0x61,0x4B,0x7F,0x2E,0x9E,0x7E,0xA0 } }; };
template <> struct guid_storage<Windows::Media::MediaProperties::IContainerEncodingProperties2>{ static constexpr guid value{ 0xB272C029,0xAE26,0x4819,{ 0xBA,0xAD,0xAD,0x7A,0x49,0xB0,0xA8,0x76 } }; };
template <> struct guid_storage<Windows::Media::MediaProperties::IH264ProfileIdsStatics>{ static constexpr guid value{ 0x38654CA7,0x846A,0x4F97,{ 0xA2,0xE5,0xC3,0xA1,0x5B,0xBF,0x70,0xFD } }; };
template <> struct guid_storage<Windows::Media::MediaProperties::IImageEncodingProperties>{ static constexpr guid value{ 0x78625635,0xF331,0x4189,{ 0xB1,0xC3,0xB4,0x8D,0x5A,0xE0,0x34,0xF1 } }; };
template <> struct guid_storage<Windows::Media::MediaProperties::IImageEncodingProperties2>{ static constexpr guid value{ 0xC854A2DF,0xC923,0x469B,{ 0xAC,0x8E,0x6A,0x9F,0x3C,0x1C,0xD9,0xE3 } }; };
template <> struct guid_storage<Windows::Media::MediaProperties::IImageEncodingPropertiesStatics>{ static constexpr guid value{ 0x257C68DC,0x8B99,0x439E,{ 0xAA,0x59,0x91,0x3A,0x36,0x16,0x12,0x97 } }; };
template <> struct guid_storage<Windows::Media::MediaProperties::IImageEncodingPropertiesStatics2>{ static constexpr guid value{ 0xF6C25B29,0x3824,0x46B0,{ 0x95,0x6E,0x50,0x13,0x29,0xE1,0xBE,0x3C } }; };
template <> struct guid_storage<Windows::Media::MediaProperties::IImageEncodingPropertiesStatics3>{ static constexpr guid value{ 0x48F4814D,0xA2FF,0x48DC,{ 0x8E,0xA0,0xE9,0x06,0x80,0x66,0x36,0x56 } }; };
template <> struct guid_storage<Windows::Media::MediaProperties::IMediaEncodingProfile>{ static constexpr guid value{ 0xE7DBF5A8,0x1DB9,0x4783,{ 0x87,0x6B,0x3D,0xFE,0x12,0xAC,0xFD,0xB3 } }; };
template <> struct guid_storage<Windows::Media::MediaProperties::IMediaEncodingProfile2>{ static constexpr guid value{ 0x349B3E0A,0x4035,0x488E,{ 0x98,0x77,0x85,0x63,0x28,0x65,0xED,0x10 } }; };
template <> struct guid_storage<Windows::Media::MediaProperties::IMediaEncodingProfile3>{ static constexpr guid value{ 0xBA6EBE88,0x7570,0x4E69,{ 0xAC,0xCF,0x56,0x11,0xAD,0x01,0x5F,0x88 } }; };
template <> struct guid_storage<Windows::Media::MediaProperties::IMediaEncodingProfileStatics>{ static constexpr guid value{ 0x197F352C,0x2EDE,0x4A45,{ 0xA8,0x96,0x81,0x7A,0x48,0x54,0xF8,0xFE } }; };
template <> struct guid_storage<Windows::Media::MediaProperties::IMediaEncodingProfileStatics2>{ static constexpr guid value{ 0xCE8DE74F,0x6AF4,0x4288,{ 0x8F,0xE2,0x79,0xAD,0xF1,0xF7,0x9A,0x43 } }; };
template <> struct guid_storage<Windows::Media::MediaProperties::IMediaEncodingProfileStatics3>{ static constexpr guid value{ 0x90DAC5AA,0xCF76,0x4294,{ 0xA9,0xED,0x1A,0x14,0x20,0xF5,0x1F,0x6B } }; };
template <> struct guid_storage<Windows::Media::MediaProperties::IMediaEncodingProperties>{ static constexpr guid value{ 0xB4002AF6,0xACD4,0x4E5A,{ 0xA2,0x4B,0x5D,0x74,0x98,0xA8,0xB8,0xC4 } }; };
template <> struct guid_storage<Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics>{ static constexpr guid value{ 0x37B6580E,0xA171,0x4464,{ 0xBA,0x5A,0x53,0x18,0x9E,0x48,0xC1,0xC8 } }; };
template <> struct guid_storage<Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics2>{ static constexpr guid value{ 0x4B7CD23D,0x42FF,0x4D33,{ 0x85,0x31,0x06,0x26,0xBE,0xE4,0xB5,0x2D } }; };
template <> struct guid_storage<Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics3>{ static constexpr guid value{ 0xBA2414E4,0x883D,0x464E,{ 0xA4,0x4F,0x09,0x7D,0xA0,0x8E,0xF7,0xFF } }; };
template <> struct guid_storage<Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics4>{ static constexpr guid value{ 0xDDECE58A,0x3949,0x4644,{ 0x8A,0x2C,0x59,0xEF,0x02,0xC6,0x42,0xFA } }; };
template <> struct guid_storage<Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics5>{ static constexpr guid value{ 0x5AD4A007,0xFFCE,0x4760,{ 0x98,0x28,0x5D,0x0C,0x99,0x63,0x7E,0x6A } }; };
template <> struct guid_storage<Windows::Media::MediaProperties::IMediaRatio>{ static constexpr guid value{ 0xD2D0FEE5,0x8929,0x401D,{ 0xAC,0x78,0x7D,0x35,0x7E,0x37,0x81,0x63 } }; };
template <> struct guid_storage<Windows::Media::MediaProperties::IMpeg2ProfileIdsStatics>{ static constexpr guid value{ 0xA461FF85,0xE57A,0x4128,{ 0x9B,0x21,0xD5,0x33,0x1B,0x04,0x23,0x5C } }; };
template <> struct guid_storage<Windows::Media::MediaProperties::ITimedMetadataEncodingProperties>{ static constexpr guid value{ 0x51CD30D3,0xD690,0x4CFA,{ 0x97,0xF4,0x4A,0x39,0x8E,0x9D,0xB4,0x20 } }; };
template <> struct guid_storage<Windows::Media::MediaProperties::IVideoEncodingProperties>{ static constexpr guid value{ 0x76EE6C9A,0x37C2,0x4F2A,{ 0x88,0x0A,0x12,0x82,0xBB,0xB4,0x37,0x3D } }; };
template <> struct guid_storage<Windows::Media::MediaProperties::IVideoEncodingProperties2>{ static constexpr guid value{ 0xF743A1EF,0xD465,0x4290,{ 0xA9,0x4B,0xEF,0x0F,0x15,0x28,0xF8,0xE3 } }; };
template <> struct guid_storage<Windows::Media::MediaProperties::IVideoEncodingProperties3>{ static constexpr guid value{ 0x386BCDC4,0x873A,0x479F,{ 0xB3,0xEB,0x56,0xC1,0xFC,0xBE,0xC6,0xD7 } }; };
template <> struct guid_storage<Windows::Media::MediaProperties::IVideoEncodingProperties4>{ static constexpr guid value{ 0x724EF014,0xC10C,0x40F2,{ 0x9D,0x72,0x3E,0xE1,0x3B,0x45,0xFA,0x8E } }; };
template <> struct guid_storage<Windows::Media::MediaProperties::IVideoEncodingProperties5>{ static constexpr guid value{ 0x4959080F,0x272F,0x4ECE,{ 0xA4,0xDF,0xC0,0xCC,0xDB,0x33,0xD8,0x40 } }; };
template <> struct guid_storage<Windows::Media::MediaProperties::IVideoEncodingPropertiesStatics>{ static constexpr guid value{ 0x3CE14D44,0x1DC5,0x43DB,{ 0x9F,0x38,0xEB,0xEB,0xF9,0x01,0x52,0xCB } }; };
template <> struct guid_storage<Windows::Media::MediaProperties::IVideoEncodingPropertiesStatics2>{ static constexpr guid value{ 0xCF1EBD5D,0x49FE,0x4D00,{ 0xB5,0x9A,0xCF,0xA4,0xDF,0xC5,0x19,0x44 } }; };
template <> struct default_interface<Windows::Media::MediaProperties::AudioEncodingProperties>{ using type = Windows::Media::MediaProperties::IAudioEncodingProperties; };
template <> struct default_interface<Windows::Media::MediaProperties::ContainerEncodingProperties>{ using type = Windows::Media::MediaProperties::IContainerEncodingProperties; };
template <> struct default_interface<Windows::Media::MediaProperties::ImageEncodingProperties>{ using type = Windows::Media::MediaProperties::IImageEncodingProperties; };
template <> struct default_interface<Windows::Media::MediaProperties::MediaEncodingProfile>{ using type = Windows::Media::MediaProperties::IMediaEncodingProfile; };
template <> struct default_interface<Windows::Media::MediaProperties::MediaPropertySet>{ using type = Windows::Foundation::Collections::IMap<winrt::guid, Windows::Foundation::IInspectable>; };
template <> struct default_interface<Windows::Media::MediaProperties::MediaRatio>{ using type = Windows::Media::MediaProperties::IMediaRatio; };
template <> struct default_interface<Windows::Media::MediaProperties::TimedMetadataEncodingProperties>{ using type = Windows::Media::MediaProperties::IMediaEncodingProperties; };
template <> struct default_interface<Windows::Media::MediaProperties::VideoEncodingProperties>{ using type = Windows::Media::MediaProperties::IVideoEncodingProperties; };

template <> struct abi<Windows::Media::MediaProperties::IAudioEncodingProperties>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL put_Bitrate(uint32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Bitrate(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ChannelCount(uint32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ChannelCount(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_SampleRate(uint32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SampleRate(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_BitsPerSample(uint32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BitsPerSample(uint32_t* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::MediaProperties::IAudioEncodingProperties2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsSpatial(bool* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::MediaProperties::IAudioEncodingProperties3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Copy(void** result) noexcept = 0;
};};

template <> struct abi<Windows::Media::MediaProperties::IAudioEncodingPropertiesStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateAac(uint32_t sampleRate, uint32_t channelCount, uint32_t bitrate, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateAacAdts(uint32_t sampleRate, uint32_t channelCount, uint32_t bitrate, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateMp3(uint32_t sampleRate, uint32_t channelCount, uint32_t bitrate, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CreatePcm(uint32_t sampleRate, uint32_t channelCount, uint32_t bitsPerSample, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateWma(uint32_t sampleRate, uint32_t channelCount, uint32_t bitrate, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::MediaProperties::IAudioEncodingPropertiesStatics2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateAlac(uint32_t sampleRate, uint32_t channelCount, uint32_t bitsPerSample, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateFlac(uint32_t sampleRate, uint32_t channelCount, uint32_t bitsPerSample, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::MediaProperties::IAudioEncodingPropertiesWithFormatUserData>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL SetFormatUserData(uint32_t __valueSize, uint8_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL GetFormatUserData(uint32_t* __valueSize, uint8_t** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::MediaProperties::IContainerEncodingProperties>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::Media::MediaProperties::IContainerEncodingProperties2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Copy(void** result) noexcept = 0;
};};

template <> struct abi<Windows::Media::MediaProperties::IH264ProfileIdsStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ConstrainedBaseline(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Baseline(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Extended(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Main(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_High(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_High10(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_High422(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_High444(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_StereoHigh(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MultiviewHigh(int32_t* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::MediaProperties::IImageEncodingProperties>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL put_Width(uint32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Width(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Height(uint32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Height(uint32_t* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::MediaProperties::IImageEncodingProperties2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Copy(void** result) noexcept = 0;
};};

template <> struct abi<Windows::Media::MediaProperties::IImageEncodingPropertiesStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateJpeg(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CreatePng(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateJpegXR(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::MediaProperties::IImageEncodingPropertiesStatics2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateUncompressed(Windows::Media::MediaProperties::MediaPixelFormat format, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateBmp(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::MediaProperties::IImageEncodingPropertiesStatics3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateHeif(void** result) noexcept = 0;
};};

template <> struct abi<Windows::Media::MediaProperties::IMediaEncodingProfile>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL put_Audio(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Audio(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Video(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Video(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Container(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Container(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::MediaProperties::IMediaEncodingProfile2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL SetAudioTracks(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL GetAudioTracks(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL SetVideoTracks(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL GetVideoTracks(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::MediaProperties::IMediaEncodingProfile3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL SetTimedMetadataTracks(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL GetTimedMetadataTracks(void** result) noexcept = 0;
};};

template <> struct abi<Windows::Media::MediaProperties::IMediaEncodingProfileStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateM4a(Windows::Media::MediaProperties::AudioEncodingQuality quality, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateMp3(Windows::Media::MediaProperties::AudioEncodingQuality quality, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateWma(Windows::Media::MediaProperties::AudioEncodingQuality quality, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateMp4(Windows::Media::MediaProperties::VideoEncodingQuality quality, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateWmv(Windows::Media::MediaProperties::VideoEncodingQuality quality, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateFromFileAsync(void* file, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL CreateFromStreamAsync(void* stream, void** operation) noexcept = 0;
};};

template <> struct abi<Windows::Media::MediaProperties::IMediaEncodingProfileStatics2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateWav(Windows::Media::MediaProperties::AudioEncodingQuality quality, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateAvi(Windows::Media::MediaProperties::VideoEncodingQuality quality, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::MediaProperties::IMediaEncodingProfileStatics3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateAlac(Windows::Media::MediaProperties::AudioEncodingQuality quality, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateFlac(Windows::Media::MediaProperties::AudioEncodingQuality quality, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateHevc(Windows::Media::MediaProperties::VideoEncodingQuality quality, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::MediaProperties::IMediaEncodingProperties>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Properties(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Type(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Subtype(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Subtype(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Aac(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AacAdts(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Ac3(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AmrNb(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AmrWb(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Argb32(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Asf(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Avi(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Bgra8(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Bmp(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Eac3(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Float(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Gif(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_H263(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_H264(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_H264Es(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Hevc(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HevcEs(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Iyuv(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Jpeg(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_JpegXr(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Mjpg(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Mpeg(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Mpeg1(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Mpeg2(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Mp3(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Mpeg4(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Nv12(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Pcm(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Png(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Rgb24(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Rgb32(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Tiff(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Wave(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Wma8(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Wma9(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Wmv3(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Wvc1(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Yuy2(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Yv12(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Vp9(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_L8(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_L16(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_D16(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Alac(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Flac(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics4>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_P010(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics5>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Heif(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::MediaProperties::IMediaRatio>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL put_Numerator(uint32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Numerator(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Denominator(uint32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Denominator(uint32_t* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::MediaProperties::IMpeg2ProfileIdsStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Simple(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Main(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SignalNoiseRatioScalable(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SpatiallyScalable(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_High(int32_t* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::MediaProperties::ITimedMetadataEncodingProperties>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL SetFormatUserData(uint32_t __valueSize, uint8_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL GetFormatUserData(uint32_t* __valueSize, uint8_t** value) noexcept = 0;
    virtual int32_t WINRT_CALL Copy(void** result) noexcept = 0;
};};

template <> struct abi<Windows::Media::MediaProperties::IVideoEncodingProperties>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL put_Bitrate(uint32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Bitrate(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Width(uint32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Width(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Height(uint32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Height(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_FrameRate(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PixelAspectRatio(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::MediaProperties::IVideoEncodingProperties2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL SetFormatUserData(uint32_t __valueSize, uint8_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL GetFormatUserData(uint32_t* __valueSize, uint8_t** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ProfileId(int32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ProfileId(int32_t* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::MediaProperties::IVideoEncodingProperties3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_StereoscopicVideoPackingMode(Windows::Media::MediaProperties::StereoscopicVideoPackingMode* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::MediaProperties::IVideoEncodingProperties4>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_SphericalVideoFrameFormat(Windows::Media::MediaProperties::SphericalVideoFrameFormat* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::MediaProperties::IVideoEncodingProperties5>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Copy(void** result) noexcept = 0;
};};

template <> struct abi<Windows::Media::MediaProperties::IVideoEncodingPropertiesStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateH264(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateMpeg2(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateUncompressed(void* subtype, uint32_t width, uint32_t height, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::MediaProperties::IVideoEncodingPropertiesStatics2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateHevc(void** value) noexcept = 0;
};};

template <typename D>
struct consume_Windows_Media_MediaProperties_IAudioEncodingProperties
{
    void Bitrate(uint32_t value) const;
    uint32_t Bitrate() const;
    void ChannelCount(uint32_t value) const;
    uint32_t ChannelCount() const;
    void SampleRate(uint32_t value) const;
    uint32_t SampleRate() const;
    void BitsPerSample(uint32_t value) const;
    uint32_t BitsPerSample() const;
};
template <> struct consume<Windows::Media::MediaProperties::IAudioEncodingProperties> { template <typename D> using type = consume_Windows_Media_MediaProperties_IAudioEncodingProperties<D>; };

template <typename D>
struct consume_Windows_Media_MediaProperties_IAudioEncodingProperties2
{
    bool IsSpatial() const;
};
template <> struct consume<Windows::Media::MediaProperties::IAudioEncodingProperties2> { template <typename D> using type = consume_Windows_Media_MediaProperties_IAudioEncodingProperties2<D>; };

template <typename D>
struct consume_Windows_Media_MediaProperties_IAudioEncodingProperties3
{
    Windows::Media::MediaProperties::AudioEncodingProperties Copy() const;
};
template <> struct consume<Windows::Media::MediaProperties::IAudioEncodingProperties3> { template <typename D> using type = consume_Windows_Media_MediaProperties_IAudioEncodingProperties3<D>; };

template <typename D>
struct consume_Windows_Media_MediaProperties_IAudioEncodingPropertiesStatics
{
    Windows::Media::MediaProperties::AudioEncodingProperties CreateAac(uint32_t sampleRate, uint32_t channelCount, uint32_t bitrate) const;
    Windows::Media::MediaProperties::AudioEncodingProperties CreateAacAdts(uint32_t sampleRate, uint32_t channelCount, uint32_t bitrate) const;
    Windows::Media::MediaProperties::AudioEncodingProperties CreateMp3(uint32_t sampleRate, uint32_t channelCount, uint32_t bitrate) const;
    Windows::Media::MediaProperties::AudioEncodingProperties CreatePcm(uint32_t sampleRate, uint32_t channelCount, uint32_t bitsPerSample) const;
    Windows::Media::MediaProperties::AudioEncodingProperties CreateWma(uint32_t sampleRate, uint32_t channelCount, uint32_t bitrate) const;
};
template <> struct consume<Windows::Media::MediaProperties::IAudioEncodingPropertiesStatics> { template <typename D> using type = consume_Windows_Media_MediaProperties_IAudioEncodingPropertiesStatics<D>; };

template <typename D>
struct consume_Windows_Media_MediaProperties_IAudioEncodingPropertiesStatics2
{
    Windows::Media::MediaProperties::AudioEncodingProperties CreateAlac(uint32_t sampleRate, uint32_t channelCount, uint32_t bitsPerSample) const;
    Windows::Media::MediaProperties::AudioEncodingProperties CreateFlac(uint32_t sampleRate, uint32_t channelCount, uint32_t bitsPerSample) const;
};
template <> struct consume<Windows::Media::MediaProperties::IAudioEncodingPropertiesStatics2> { template <typename D> using type = consume_Windows_Media_MediaProperties_IAudioEncodingPropertiesStatics2<D>; };

template <typename D>
struct consume_Windows_Media_MediaProperties_IAudioEncodingPropertiesWithFormatUserData
{
    void SetFormatUserData(array_view<uint8_t const> value) const;
    void GetFormatUserData(com_array<uint8_t>& value) const;
};
template <> struct consume<Windows::Media::MediaProperties::IAudioEncodingPropertiesWithFormatUserData> { template <typename D> using type = consume_Windows_Media_MediaProperties_IAudioEncodingPropertiesWithFormatUserData<D>; };

template <typename D>
struct consume_Windows_Media_MediaProperties_IContainerEncodingProperties
{
};
template <> struct consume<Windows::Media::MediaProperties::IContainerEncodingProperties> { template <typename D> using type = consume_Windows_Media_MediaProperties_IContainerEncodingProperties<D>; };

template <typename D>
struct consume_Windows_Media_MediaProperties_IContainerEncodingProperties2
{
    Windows::Media::MediaProperties::ContainerEncodingProperties Copy() const;
};
template <> struct consume<Windows::Media::MediaProperties::IContainerEncodingProperties2> { template <typename D> using type = consume_Windows_Media_MediaProperties_IContainerEncodingProperties2<D>; };

template <typename D>
struct consume_Windows_Media_MediaProperties_IH264ProfileIdsStatics
{
    int32_t ConstrainedBaseline() const;
    int32_t Baseline() const;
    int32_t Extended() const;
    int32_t Main() const;
    int32_t High() const;
    int32_t High10() const;
    int32_t High422() const;
    int32_t High444() const;
    int32_t StereoHigh() const;
    int32_t MultiviewHigh() const;
};
template <> struct consume<Windows::Media::MediaProperties::IH264ProfileIdsStatics> { template <typename D> using type = consume_Windows_Media_MediaProperties_IH264ProfileIdsStatics<D>; };

template <typename D>
struct consume_Windows_Media_MediaProperties_IImageEncodingProperties
{
    void Width(uint32_t value) const;
    uint32_t Width() const;
    void Height(uint32_t value) const;
    uint32_t Height() const;
};
template <> struct consume<Windows::Media::MediaProperties::IImageEncodingProperties> { template <typename D> using type = consume_Windows_Media_MediaProperties_IImageEncodingProperties<D>; };

template <typename D>
struct consume_Windows_Media_MediaProperties_IImageEncodingProperties2
{
    Windows::Media::MediaProperties::ImageEncodingProperties Copy() const;
};
template <> struct consume<Windows::Media::MediaProperties::IImageEncodingProperties2> { template <typename D> using type = consume_Windows_Media_MediaProperties_IImageEncodingProperties2<D>; };

template <typename D>
struct consume_Windows_Media_MediaProperties_IImageEncodingPropertiesStatics
{
    Windows::Media::MediaProperties::ImageEncodingProperties CreateJpeg() const;
    Windows::Media::MediaProperties::ImageEncodingProperties CreatePng() const;
    Windows::Media::MediaProperties::ImageEncodingProperties CreateJpegXR() const;
};
template <> struct consume<Windows::Media::MediaProperties::IImageEncodingPropertiesStatics> { template <typename D> using type = consume_Windows_Media_MediaProperties_IImageEncodingPropertiesStatics<D>; };

template <typename D>
struct consume_Windows_Media_MediaProperties_IImageEncodingPropertiesStatics2
{
    Windows::Media::MediaProperties::ImageEncodingProperties CreateUncompressed(Windows::Media::MediaProperties::MediaPixelFormat const& format) const;
    Windows::Media::MediaProperties::ImageEncodingProperties CreateBmp() const;
};
template <> struct consume<Windows::Media::MediaProperties::IImageEncodingPropertiesStatics2> { template <typename D> using type = consume_Windows_Media_MediaProperties_IImageEncodingPropertiesStatics2<D>; };

template <typename D>
struct consume_Windows_Media_MediaProperties_IImageEncodingPropertiesStatics3
{
    Windows::Media::MediaProperties::ImageEncodingProperties CreateHeif() const;
};
template <> struct consume<Windows::Media::MediaProperties::IImageEncodingPropertiesStatics3> { template <typename D> using type = consume_Windows_Media_MediaProperties_IImageEncodingPropertiesStatics3<D>; };

template <typename D>
struct consume_Windows_Media_MediaProperties_IMediaEncodingProfile
{
    void Audio(Windows::Media::MediaProperties::AudioEncodingProperties const& value) const;
    Windows::Media::MediaProperties::AudioEncodingProperties Audio() const;
    void Video(Windows::Media::MediaProperties::VideoEncodingProperties const& value) const;
    Windows::Media::MediaProperties::VideoEncodingProperties Video() const;
    void Container(Windows::Media::MediaProperties::ContainerEncodingProperties const& value) const;
    Windows::Media::MediaProperties::ContainerEncodingProperties Container() const;
};
template <> struct consume<Windows::Media::MediaProperties::IMediaEncodingProfile> { template <typename D> using type = consume_Windows_Media_MediaProperties_IMediaEncodingProfile<D>; };

template <typename D>
struct consume_Windows_Media_MediaProperties_IMediaEncodingProfile2
{
    void SetAudioTracks(param::iterable<Windows::Media::Core::AudioStreamDescriptor> const& value) const;
    Windows::Foundation::Collections::IVector<Windows::Media::Core::AudioStreamDescriptor> GetAudioTracks() const;
    void SetVideoTracks(param::iterable<Windows::Media::Core::VideoStreamDescriptor> const& value) const;
    Windows::Foundation::Collections::IVector<Windows::Media::Core::VideoStreamDescriptor> GetVideoTracks() const;
};
template <> struct consume<Windows::Media::MediaProperties::IMediaEncodingProfile2> { template <typename D> using type = consume_Windows_Media_MediaProperties_IMediaEncodingProfile2<D>; };

template <typename D>
struct consume_Windows_Media_MediaProperties_IMediaEncodingProfile3
{
    void SetTimedMetadataTracks(param::iterable<Windows::Media::Core::TimedMetadataStreamDescriptor> const& value) const;
    Windows::Foundation::Collections::IVector<Windows::Media::Core::TimedMetadataStreamDescriptor> GetTimedMetadataTracks() const;
};
template <> struct consume<Windows::Media::MediaProperties::IMediaEncodingProfile3> { template <typename D> using type = consume_Windows_Media_MediaProperties_IMediaEncodingProfile3<D>; };

template <typename D>
struct consume_Windows_Media_MediaProperties_IMediaEncodingProfileStatics
{
    Windows::Media::MediaProperties::MediaEncodingProfile CreateM4a(Windows::Media::MediaProperties::AudioEncodingQuality const& quality) const;
    Windows::Media::MediaProperties::MediaEncodingProfile CreateMp3(Windows::Media::MediaProperties::AudioEncodingQuality const& quality) const;
    Windows::Media::MediaProperties::MediaEncodingProfile CreateWma(Windows::Media::MediaProperties::AudioEncodingQuality const& quality) const;
    Windows::Media::MediaProperties::MediaEncodingProfile CreateMp4(Windows::Media::MediaProperties::VideoEncodingQuality const& quality) const;
    Windows::Media::MediaProperties::MediaEncodingProfile CreateWmv(Windows::Media::MediaProperties::VideoEncodingQuality const& quality) const;
    Windows::Foundation::IAsyncOperation<Windows::Media::MediaProperties::MediaEncodingProfile> CreateFromFileAsync(Windows::Storage::IStorageFile const& file) const;
    Windows::Foundation::IAsyncOperation<Windows::Media::MediaProperties::MediaEncodingProfile> CreateFromStreamAsync(Windows::Storage::Streams::IRandomAccessStream const& stream) const;
};
template <> struct consume<Windows::Media::MediaProperties::IMediaEncodingProfileStatics> { template <typename D> using type = consume_Windows_Media_MediaProperties_IMediaEncodingProfileStatics<D>; };

template <typename D>
struct consume_Windows_Media_MediaProperties_IMediaEncodingProfileStatics2
{
    Windows::Media::MediaProperties::MediaEncodingProfile CreateWav(Windows::Media::MediaProperties::AudioEncodingQuality const& quality) const;
    Windows::Media::MediaProperties::MediaEncodingProfile CreateAvi(Windows::Media::MediaProperties::VideoEncodingQuality const& quality) const;
};
template <> struct consume<Windows::Media::MediaProperties::IMediaEncodingProfileStatics2> { template <typename D> using type = consume_Windows_Media_MediaProperties_IMediaEncodingProfileStatics2<D>; };

template <typename D>
struct consume_Windows_Media_MediaProperties_IMediaEncodingProfileStatics3
{
    Windows::Media::MediaProperties::MediaEncodingProfile CreateAlac(Windows::Media::MediaProperties::AudioEncodingQuality const& quality) const;
    Windows::Media::MediaProperties::MediaEncodingProfile CreateFlac(Windows::Media::MediaProperties::AudioEncodingQuality const& quality) const;
    Windows::Media::MediaProperties::MediaEncodingProfile CreateHevc(Windows::Media::MediaProperties::VideoEncodingQuality const& quality) const;
};
template <> struct consume<Windows::Media::MediaProperties::IMediaEncodingProfileStatics3> { template <typename D> using type = consume_Windows_Media_MediaProperties_IMediaEncodingProfileStatics3<D>; };

template <typename D>
struct consume_Windows_Media_MediaProperties_IMediaEncodingProperties
{
    Windows::Media::MediaProperties::MediaPropertySet Properties() const;
    hstring Type() const;
    void Subtype(param::hstring const& value) const;
    hstring Subtype() const;
};
template <> struct consume<Windows::Media::MediaProperties::IMediaEncodingProperties> { template <typename D> using type = consume_Windows_Media_MediaProperties_IMediaEncodingProperties<D>; };

template <typename D>
struct consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics
{
    hstring Aac() const;
    hstring AacAdts() const;
    hstring Ac3() const;
    hstring AmrNb() const;
    hstring AmrWb() const;
    hstring Argb32() const;
    hstring Asf() const;
    hstring Avi() const;
    hstring Bgra8() const;
    hstring Bmp() const;
    hstring Eac3() const;
    hstring Float() const;
    hstring Gif() const;
    hstring H263() const;
    hstring H264() const;
    hstring H264Es() const;
    hstring Hevc() const;
    hstring HevcEs() const;
    hstring Iyuv() const;
    hstring Jpeg() const;
    hstring JpegXr() const;
    hstring Mjpg() const;
    hstring Mpeg() const;
    hstring Mpeg1() const;
    hstring Mpeg2() const;
    hstring Mp3() const;
    hstring Mpeg4() const;
    hstring Nv12() const;
    hstring Pcm() const;
    hstring Png() const;
    hstring Rgb24() const;
    hstring Rgb32() const;
    hstring Tiff() const;
    hstring Wave() const;
    hstring Wma8() const;
    hstring Wma9() const;
    hstring Wmv3() const;
    hstring Wvc1() const;
    hstring Yuy2() const;
    hstring Yv12() const;
};
template <> struct consume<Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics> { template <typename D> using type = consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>; };

template <typename D>
struct consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics2
{
    hstring Vp9() const;
    hstring L8() const;
    hstring L16() const;
    hstring D16() const;
};
template <> struct consume<Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics2> { template <typename D> using type = consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics2<D>; };

template <typename D>
struct consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics3
{
    hstring Alac() const;
    hstring Flac() const;
};
template <> struct consume<Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics3> { template <typename D> using type = consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics3<D>; };

template <typename D>
struct consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics4
{
    hstring P010() const;
};
template <> struct consume<Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics4> { template <typename D> using type = consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics4<D>; };

template <typename D>
struct consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics5
{
    hstring Heif() const;
};
template <> struct consume<Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics5> { template <typename D> using type = consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics5<D>; };

template <typename D>
struct consume_Windows_Media_MediaProperties_IMediaRatio
{
    void Numerator(uint32_t value) const;
    uint32_t Numerator() const;
    void Denominator(uint32_t value) const;
    uint32_t Denominator() const;
};
template <> struct consume<Windows::Media::MediaProperties::IMediaRatio> { template <typename D> using type = consume_Windows_Media_MediaProperties_IMediaRatio<D>; };

template <typename D>
struct consume_Windows_Media_MediaProperties_IMpeg2ProfileIdsStatics
{
    int32_t Simple() const;
    int32_t Main() const;
    int32_t SignalNoiseRatioScalable() const;
    int32_t SpatiallyScalable() const;
    int32_t High() const;
};
template <> struct consume<Windows::Media::MediaProperties::IMpeg2ProfileIdsStatics> { template <typename D> using type = consume_Windows_Media_MediaProperties_IMpeg2ProfileIdsStatics<D>; };

template <typename D>
struct consume_Windows_Media_MediaProperties_ITimedMetadataEncodingProperties
{
    void SetFormatUserData(array_view<uint8_t const> value) const;
    void GetFormatUserData(com_array<uint8_t>& value) const;
    Windows::Media::MediaProperties::TimedMetadataEncodingProperties Copy() const;
};
template <> struct consume<Windows::Media::MediaProperties::ITimedMetadataEncodingProperties> { template <typename D> using type = consume_Windows_Media_MediaProperties_ITimedMetadataEncodingProperties<D>; };

template <typename D>
struct consume_Windows_Media_MediaProperties_IVideoEncodingProperties
{
    void Bitrate(uint32_t value) const;
    uint32_t Bitrate() const;
    void Width(uint32_t value) const;
    uint32_t Width() const;
    void Height(uint32_t value) const;
    uint32_t Height() const;
    Windows::Media::MediaProperties::MediaRatio FrameRate() const;
    Windows::Media::MediaProperties::MediaRatio PixelAspectRatio() const;
};
template <> struct consume<Windows::Media::MediaProperties::IVideoEncodingProperties> { template <typename D> using type = consume_Windows_Media_MediaProperties_IVideoEncodingProperties<D>; };

template <typename D>
struct consume_Windows_Media_MediaProperties_IVideoEncodingProperties2
{
    void SetFormatUserData(array_view<uint8_t const> value) const;
    void GetFormatUserData(com_array<uint8_t>& value) const;
    void ProfileId(int32_t value) const;
    int32_t ProfileId() const;
};
template <> struct consume<Windows::Media::MediaProperties::IVideoEncodingProperties2> { template <typename D> using type = consume_Windows_Media_MediaProperties_IVideoEncodingProperties2<D>; };

template <typename D>
struct consume_Windows_Media_MediaProperties_IVideoEncodingProperties3
{
    Windows::Media::MediaProperties::StereoscopicVideoPackingMode StereoscopicVideoPackingMode() const;
};
template <> struct consume<Windows::Media::MediaProperties::IVideoEncodingProperties3> { template <typename D> using type = consume_Windows_Media_MediaProperties_IVideoEncodingProperties3<D>; };

template <typename D>
struct consume_Windows_Media_MediaProperties_IVideoEncodingProperties4
{
    Windows::Media::MediaProperties::SphericalVideoFrameFormat SphericalVideoFrameFormat() const;
};
template <> struct consume<Windows::Media::MediaProperties::IVideoEncodingProperties4> { template <typename D> using type = consume_Windows_Media_MediaProperties_IVideoEncodingProperties4<D>; };

template <typename D>
struct consume_Windows_Media_MediaProperties_IVideoEncodingProperties5
{
    Windows::Media::MediaProperties::VideoEncodingProperties Copy() const;
};
template <> struct consume<Windows::Media::MediaProperties::IVideoEncodingProperties5> { template <typename D> using type = consume_Windows_Media_MediaProperties_IVideoEncodingProperties5<D>; };

template <typename D>
struct consume_Windows_Media_MediaProperties_IVideoEncodingPropertiesStatics
{
    Windows::Media::MediaProperties::VideoEncodingProperties CreateH264() const;
    Windows::Media::MediaProperties::VideoEncodingProperties CreateMpeg2() const;
    Windows::Media::MediaProperties::VideoEncodingProperties CreateUncompressed(param::hstring const& subtype, uint32_t width, uint32_t height) const;
};
template <> struct consume<Windows::Media::MediaProperties::IVideoEncodingPropertiesStatics> { template <typename D> using type = consume_Windows_Media_MediaProperties_IVideoEncodingPropertiesStatics<D>; };

template <typename D>
struct consume_Windows_Media_MediaProperties_IVideoEncodingPropertiesStatics2
{
    Windows::Media::MediaProperties::VideoEncodingProperties CreateHevc() const;
};
template <> struct consume<Windows::Media::MediaProperties::IVideoEncodingPropertiesStatics2> { template <typename D> using type = consume_Windows_Media_MediaProperties_IVideoEncodingPropertiesStatics2<D>; };

}
