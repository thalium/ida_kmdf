// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Foundation {

enum class PropertyType;
struct IMemoryBufferReference;

}

WINRT_EXPORT namespace winrt::Windows::Graphics::DirectX::Direct3D11 {

struct IDirect3DSurface;

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

WINRT_EXPORT namespace winrt::Windows::Graphics::Imaging {

enum class BitmapAlphaMode : int32_t
{
    Premultiplied = 0,
    Straight = 1,
    Ignore = 2,
};

enum class BitmapBufferAccessMode : int32_t
{
    Read = 0,
    ReadWrite = 1,
    Write = 2,
};

enum class BitmapFlip : int32_t
{
    None = 0,
    Horizontal = 1,
    Vertical = 2,
};

enum class BitmapInterpolationMode : int32_t
{
    NearestNeighbor = 0,
    Linear = 1,
    Cubic = 2,
    Fant = 3,
};

enum class BitmapPixelFormat : int32_t
{
    Unknown = 0,
    Rgba16 = 12,
    Rgba8 = 30,
    Gray16 = 57,
    Gray8 = 62,
    Bgra8 = 87,
    Nv12 = 103,
    P010 = 104,
    Yuy2 = 107,
};

enum class BitmapRotation : int32_t
{
    None = 0,
    Clockwise90Degrees = 1,
    Clockwise180Degrees = 2,
    Clockwise270Degrees = 3,
};

enum class ColorManagementMode : int32_t
{
    DoNotColorManage = 0,
    ColorManageToSRgb = 1,
};

enum class ExifOrientationMode : int32_t
{
    IgnoreExifOrientation = 0,
    RespectExifOrientation = 1,
};

enum class JpegSubsamplingMode : int32_t
{
    Default = 0,
    Y4Cb2Cr0 = 1,
    Y4Cb2Cr2 = 2,
    Y4Cb4Cr4 = 3,
};

enum class PngFilterMode : int32_t
{
    Automatic = 0,
    None = 1,
    Sub = 2,
    Up = 3,
    Average = 4,
    Paeth = 5,
    Adaptive = 6,
};

enum class TiffCompressionMode : int32_t
{
    Automatic = 0,
    None = 1,
    Ccitt3 = 2,
    Ccitt4 = 3,
    Lzw = 4,
    Rle = 5,
    Zip = 6,
    LzwhDifferencing = 7,
};

struct IBitmapBuffer;
struct IBitmapCodecInformation;
struct IBitmapDecoder;
struct IBitmapDecoderStatics;
struct IBitmapDecoderStatics2;
struct IBitmapEncoder;
struct IBitmapEncoderStatics;
struct IBitmapEncoderStatics2;
struct IBitmapEncoderWithSoftwareBitmap;
struct IBitmapFrame;
struct IBitmapFrameWithSoftwareBitmap;
struct IBitmapProperties;
struct IBitmapPropertiesView;
struct IBitmapTransform;
struct IBitmapTypedValue;
struct IBitmapTypedValueFactory;
struct IPixelDataProvider;
struct ISoftwareBitmap;
struct ISoftwareBitmapFactory;
struct ISoftwareBitmapStatics;
struct BitmapBuffer;
struct BitmapCodecInformation;
struct BitmapDecoder;
struct BitmapEncoder;
struct BitmapFrame;
struct BitmapProperties;
struct BitmapPropertiesView;
struct BitmapPropertySet;
struct BitmapTransform;
struct BitmapTypedValue;
struct ImageStream;
struct PixelDataProvider;
struct SoftwareBitmap;
struct BitmapBounds;
struct BitmapPlaneDescription;
struct BitmapSize;

}

namespace winrt::impl {

template <> struct category<Windows::Graphics::Imaging::IBitmapBuffer>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Imaging::IBitmapCodecInformation>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Imaging::IBitmapDecoder>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Imaging::IBitmapDecoderStatics>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Imaging::IBitmapDecoderStatics2>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Imaging::IBitmapEncoder>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Imaging::IBitmapEncoderStatics>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Imaging::IBitmapEncoderStatics2>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Imaging::IBitmapEncoderWithSoftwareBitmap>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Imaging::IBitmapFrame>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Imaging::IBitmapFrameWithSoftwareBitmap>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Imaging::IBitmapProperties>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Imaging::IBitmapPropertiesView>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Imaging::IBitmapTransform>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Imaging::IBitmapTypedValue>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Imaging::IBitmapTypedValueFactory>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Imaging::IPixelDataProvider>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Imaging::ISoftwareBitmap>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Imaging::ISoftwareBitmapFactory>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Imaging::ISoftwareBitmapStatics>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Imaging::BitmapBuffer>{ using type = class_category; };
template <> struct category<Windows::Graphics::Imaging::BitmapCodecInformation>{ using type = class_category; };
template <> struct category<Windows::Graphics::Imaging::BitmapDecoder>{ using type = class_category; };
template <> struct category<Windows::Graphics::Imaging::BitmapEncoder>{ using type = class_category; };
template <> struct category<Windows::Graphics::Imaging::BitmapFrame>{ using type = class_category; };
template <> struct category<Windows::Graphics::Imaging::BitmapProperties>{ using type = class_category; };
template <> struct category<Windows::Graphics::Imaging::BitmapPropertiesView>{ using type = class_category; };
template <> struct category<Windows::Graphics::Imaging::BitmapPropertySet>{ using type = class_category; };
template <> struct category<Windows::Graphics::Imaging::BitmapTransform>{ using type = class_category; };
template <> struct category<Windows::Graphics::Imaging::BitmapTypedValue>{ using type = class_category; };
template <> struct category<Windows::Graphics::Imaging::ImageStream>{ using type = class_category; };
template <> struct category<Windows::Graphics::Imaging::PixelDataProvider>{ using type = class_category; };
template <> struct category<Windows::Graphics::Imaging::SoftwareBitmap>{ using type = class_category; };
template <> struct category<Windows::Graphics::Imaging::BitmapAlphaMode>{ using type = enum_category; };
template <> struct category<Windows::Graphics::Imaging::BitmapBufferAccessMode>{ using type = enum_category; };
template <> struct category<Windows::Graphics::Imaging::BitmapFlip>{ using type = enum_category; };
template <> struct category<Windows::Graphics::Imaging::BitmapInterpolationMode>{ using type = enum_category; };
template <> struct category<Windows::Graphics::Imaging::BitmapPixelFormat>{ using type = enum_category; };
template <> struct category<Windows::Graphics::Imaging::BitmapRotation>{ using type = enum_category; };
template <> struct category<Windows::Graphics::Imaging::ColorManagementMode>{ using type = enum_category; };
template <> struct category<Windows::Graphics::Imaging::ExifOrientationMode>{ using type = enum_category; };
template <> struct category<Windows::Graphics::Imaging::JpegSubsamplingMode>{ using type = enum_category; };
template <> struct category<Windows::Graphics::Imaging::PngFilterMode>{ using type = enum_category; };
template <> struct category<Windows::Graphics::Imaging::TiffCompressionMode>{ using type = enum_category; };
template <> struct category<Windows::Graphics::Imaging::BitmapBounds>{ using type = struct_category<uint32_t,uint32_t,uint32_t,uint32_t>; };
template <> struct category<Windows::Graphics::Imaging::BitmapPlaneDescription>{ using type = struct_category<int32_t,int32_t,int32_t,int32_t>; };
template <> struct category<Windows::Graphics::Imaging::BitmapSize>{ using type = struct_category<uint32_t,uint32_t>; };
template <> struct name<Windows::Graphics::Imaging::IBitmapBuffer>{ static constexpr auto & value{ L"Windows.Graphics.Imaging.IBitmapBuffer" }; };
template <> struct name<Windows::Graphics::Imaging::IBitmapCodecInformation>{ static constexpr auto & value{ L"Windows.Graphics.Imaging.IBitmapCodecInformation" }; };
template <> struct name<Windows::Graphics::Imaging::IBitmapDecoder>{ static constexpr auto & value{ L"Windows.Graphics.Imaging.IBitmapDecoder" }; };
template <> struct name<Windows::Graphics::Imaging::IBitmapDecoderStatics>{ static constexpr auto & value{ L"Windows.Graphics.Imaging.IBitmapDecoderStatics" }; };
template <> struct name<Windows::Graphics::Imaging::IBitmapDecoderStatics2>{ static constexpr auto & value{ L"Windows.Graphics.Imaging.IBitmapDecoderStatics2" }; };
template <> struct name<Windows::Graphics::Imaging::IBitmapEncoder>{ static constexpr auto & value{ L"Windows.Graphics.Imaging.IBitmapEncoder" }; };
template <> struct name<Windows::Graphics::Imaging::IBitmapEncoderStatics>{ static constexpr auto & value{ L"Windows.Graphics.Imaging.IBitmapEncoderStatics" }; };
template <> struct name<Windows::Graphics::Imaging::IBitmapEncoderStatics2>{ static constexpr auto & value{ L"Windows.Graphics.Imaging.IBitmapEncoderStatics2" }; };
template <> struct name<Windows::Graphics::Imaging::IBitmapEncoderWithSoftwareBitmap>{ static constexpr auto & value{ L"Windows.Graphics.Imaging.IBitmapEncoderWithSoftwareBitmap" }; };
template <> struct name<Windows::Graphics::Imaging::IBitmapFrame>{ static constexpr auto & value{ L"Windows.Graphics.Imaging.IBitmapFrame" }; };
template <> struct name<Windows::Graphics::Imaging::IBitmapFrameWithSoftwareBitmap>{ static constexpr auto & value{ L"Windows.Graphics.Imaging.IBitmapFrameWithSoftwareBitmap" }; };
template <> struct name<Windows::Graphics::Imaging::IBitmapProperties>{ static constexpr auto & value{ L"Windows.Graphics.Imaging.IBitmapProperties" }; };
template <> struct name<Windows::Graphics::Imaging::IBitmapPropertiesView>{ static constexpr auto & value{ L"Windows.Graphics.Imaging.IBitmapPropertiesView" }; };
template <> struct name<Windows::Graphics::Imaging::IBitmapTransform>{ static constexpr auto & value{ L"Windows.Graphics.Imaging.IBitmapTransform" }; };
template <> struct name<Windows::Graphics::Imaging::IBitmapTypedValue>{ static constexpr auto & value{ L"Windows.Graphics.Imaging.IBitmapTypedValue" }; };
template <> struct name<Windows::Graphics::Imaging::IBitmapTypedValueFactory>{ static constexpr auto & value{ L"Windows.Graphics.Imaging.IBitmapTypedValueFactory" }; };
template <> struct name<Windows::Graphics::Imaging::IPixelDataProvider>{ static constexpr auto & value{ L"Windows.Graphics.Imaging.IPixelDataProvider" }; };
template <> struct name<Windows::Graphics::Imaging::ISoftwareBitmap>{ static constexpr auto & value{ L"Windows.Graphics.Imaging.ISoftwareBitmap" }; };
template <> struct name<Windows::Graphics::Imaging::ISoftwareBitmapFactory>{ static constexpr auto & value{ L"Windows.Graphics.Imaging.ISoftwareBitmapFactory" }; };
template <> struct name<Windows::Graphics::Imaging::ISoftwareBitmapStatics>{ static constexpr auto & value{ L"Windows.Graphics.Imaging.ISoftwareBitmapStatics" }; };
template <> struct name<Windows::Graphics::Imaging::BitmapBuffer>{ static constexpr auto & value{ L"Windows.Graphics.Imaging.BitmapBuffer" }; };
template <> struct name<Windows::Graphics::Imaging::BitmapCodecInformation>{ static constexpr auto & value{ L"Windows.Graphics.Imaging.BitmapCodecInformation" }; };
template <> struct name<Windows::Graphics::Imaging::BitmapDecoder>{ static constexpr auto & value{ L"Windows.Graphics.Imaging.BitmapDecoder" }; };
template <> struct name<Windows::Graphics::Imaging::BitmapEncoder>{ static constexpr auto & value{ L"Windows.Graphics.Imaging.BitmapEncoder" }; };
template <> struct name<Windows::Graphics::Imaging::BitmapFrame>{ static constexpr auto & value{ L"Windows.Graphics.Imaging.BitmapFrame" }; };
template <> struct name<Windows::Graphics::Imaging::BitmapProperties>{ static constexpr auto & value{ L"Windows.Graphics.Imaging.BitmapProperties" }; };
template <> struct name<Windows::Graphics::Imaging::BitmapPropertiesView>{ static constexpr auto & value{ L"Windows.Graphics.Imaging.BitmapPropertiesView" }; };
template <> struct name<Windows::Graphics::Imaging::BitmapPropertySet>{ static constexpr auto & value{ L"Windows.Graphics.Imaging.BitmapPropertySet" }; };
template <> struct name<Windows::Graphics::Imaging::BitmapTransform>{ static constexpr auto & value{ L"Windows.Graphics.Imaging.BitmapTransform" }; };
template <> struct name<Windows::Graphics::Imaging::BitmapTypedValue>{ static constexpr auto & value{ L"Windows.Graphics.Imaging.BitmapTypedValue" }; };
template <> struct name<Windows::Graphics::Imaging::ImageStream>{ static constexpr auto & value{ L"Windows.Graphics.Imaging.ImageStream" }; };
template <> struct name<Windows::Graphics::Imaging::PixelDataProvider>{ static constexpr auto & value{ L"Windows.Graphics.Imaging.PixelDataProvider" }; };
template <> struct name<Windows::Graphics::Imaging::SoftwareBitmap>{ static constexpr auto & value{ L"Windows.Graphics.Imaging.SoftwareBitmap" }; };
template <> struct name<Windows::Graphics::Imaging::BitmapAlphaMode>{ static constexpr auto & value{ L"Windows.Graphics.Imaging.BitmapAlphaMode" }; };
template <> struct name<Windows::Graphics::Imaging::BitmapBufferAccessMode>{ static constexpr auto & value{ L"Windows.Graphics.Imaging.BitmapBufferAccessMode" }; };
template <> struct name<Windows::Graphics::Imaging::BitmapFlip>{ static constexpr auto & value{ L"Windows.Graphics.Imaging.BitmapFlip" }; };
template <> struct name<Windows::Graphics::Imaging::BitmapInterpolationMode>{ static constexpr auto & value{ L"Windows.Graphics.Imaging.BitmapInterpolationMode" }; };
template <> struct name<Windows::Graphics::Imaging::BitmapPixelFormat>{ static constexpr auto & value{ L"Windows.Graphics.Imaging.BitmapPixelFormat" }; };
template <> struct name<Windows::Graphics::Imaging::BitmapRotation>{ static constexpr auto & value{ L"Windows.Graphics.Imaging.BitmapRotation" }; };
template <> struct name<Windows::Graphics::Imaging::ColorManagementMode>{ static constexpr auto & value{ L"Windows.Graphics.Imaging.ColorManagementMode" }; };
template <> struct name<Windows::Graphics::Imaging::ExifOrientationMode>{ static constexpr auto & value{ L"Windows.Graphics.Imaging.ExifOrientationMode" }; };
template <> struct name<Windows::Graphics::Imaging::JpegSubsamplingMode>{ static constexpr auto & value{ L"Windows.Graphics.Imaging.JpegSubsamplingMode" }; };
template <> struct name<Windows::Graphics::Imaging::PngFilterMode>{ static constexpr auto & value{ L"Windows.Graphics.Imaging.PngFilterMode" }; };
template <> struct name<Windows::Graphics::Imaging::TiffCompressionMode>{ static constexpr auto & value{ L"Windows.Graphics.Imaging.TiffCompressionMode" }; };
template <> struct name<Windows::Graphics::Imaging::BitmapBounds>{ static constexpr auto & value{ L"Windows.Graphics.Imaging.BitmapBounds" }; };
template <> struct name<Windows::Graphics::Imaging::BitmapPlaneDescription>{ static constexpr auto & value{ L"Windows.Graphics.Imaging.BitmapPlaneDescription" }; };
template <> struct name<Windows::Graphics::Imaging::BitmapSize>{ static constexpr auto & value{ L"Windows.Graphics.Imaging.BitmapSize" }; };
template <> struct guid_storage<Windows::Graphics::Imaging::IBitmapBuffer>{ static constexpr guid value{ 0xA53E04C4,0x399C,0x438C,{ 0xB2,0x8F,0xA6,0x3A,0x6B,0x83,0xD1,0xA1 } }; };
template <> struct guid_storage<Windows::Graphics::Imaging::IBitmapCodecInformation>{ static constexpr guid value{ 0x400CAAF2,0xC4B0,0x4392,{ 0xA3,0xB0,0x6F,0x6F,0x9B,0xA9,0x5C,0xB4 } }; };
template <> struct guid_storage<Windows::Graphics::Imaging::IBitmapDecoder>{ static constexpr guid value{ 0xACEF22BA,0x1D74,0x4C91,{ 0x9D,0xFC,0x96,0x20,0x74,0x52,0x33,0xE6 } }; };
template <> struct guid_storage<Windows::Graphics::Imaging::IBitmapDecoderStatics>{ static constexpr guid value{ 0x438CCB26,0xBCEF,0x4E95,{ 0xBA,0xD6,0x23,0xA8,0x22,0xE5,0x8D,0x01 } }; };
template <> struct guid_storage<Windows::Graphics::Imaging::IBitmapDecoderStatics2>{ static constexpr guid value{ 0x50BA68EA,0x99A1,0x40C4,{ 0x80,0xD9,0xAE,0xF0,0xDA,0xFA,0x6C,0x3F } }; };
template <> struct guid_storage<Windows::Graphics::Imaging::IBitmapEncoder>{ static constexpr guid value{ 0x2BC468E3,0xE1F8,0x4B54,{ 0x95,0xE8,0x32,0x91,0x95,0x51,0xCE,0x62 } }; };
template <> struct guid_storage<Windows::Graphics::Imaging::IBitmapEncoderStatics>{ static constexpr guid value{ 0xA74356A7,0xA4E4,0x4EB9,{ 0x8E,0x40,0x56,0x4D,0xE7,0xE1,0xCC,0xB2 } }; };
template <> struct guid_storage<Windows::Graphics::Imaging::IBitmapEncoderStatics2>{ static constexpr guid value{ 0x33CBC259,0xFE31,0x41B1,{ 0xB8,0x12,0x08,0x6D,0x21,0xE8,0x7E,0x16 } }; };
template <> struct guid_storage<Windows::Graphics::Imaging::IBitmapEncoderWithSoftwareBitmap>{ static constexpr guid value{ 0x686CD241,0x4330,0x4C77,{ 0xAC,0xE4,0x03,0x34,0x96,0x8B,0x17,0x68 } }; };
template <> struct guid_storage<Windows::Graphics::Imaging::IBitmapFrame>{ static constexpr guid value{ 0x72A49A1C,0x8081,0x438D,{ 0x91,0xBC,0x94,0xEC,0xFC,0x81,0x85,0xC6 } }; };
template <> struct guid_storage<Windows::Graphics::Imaging::IBitmapFrameWithSoftwareBitmap>{ static constexpr guid value{ 0xFE287C9A,0x420C,0x4963,{ 0x87,0xAD,0x69,0x14,0x36,0xE0,0x83,0x83 } }; };
template <> struct guid_storage<Windows::Graphics::Imaging::IBitmapProperties>{ static constexpr guid value{ 0xEA9F4F1B,0xB505,0x4450,{ 0xA4,0xD1,0xE8,0xCA,0x94,0x52,0x9D,0x8D } }; };
template <> struct guid_storage<Windows::Graphics::Imaging::IBitmapPropertiesView>{ static constexpr guid value{ 0x7E0FE87A,0x3A70,0x48F8,{ 0x9C,0x55,0x19,0x6C,0xF5,0xA5,0x45,0xF5 } }; };
template <> struct guid_storage<Windows::Graphics::Imaging::IBitmapTransform>{ static constexpr guid value{ 0xAE755344,0xE268,0x4D35,{ 0xAD,0xCF,0xE9,0x95,0xD3,0x1A,0x8D,0x34 } }; };
template <> struct guid_storage<Windows::Graphics::Imaging::IBitmapTypedValue>{ static constexpr guid value{ 0xCD8044A9,0x2443,0x4000,{ 0xB0,0xCD,0x79,0x31,0x6C,0x56,0xF5,0x89 } }; };
template <> struct guid_storage<Windows::Graphics::Imaging::IBitmapTypedValueFactory>{ static constexpr guid value{ 0x92DBB599,0xCE13,0x46BB,{ 0x95,0x45,0xCB,0x3A,0x3F,0x63,0xEB,0x8B } }; };
template <> struct guid_storage<Windows::Graphics::Imaging::IPixelDataProvider>{ static constexpr guid value{ 0xDD831F25,0x185C,0x4595,{ 0x9F,0xB9,0xCC,0xBE,0x6E,0xC1,0x8A,0x6F } }; };
template <> struct guid_storage<Windows::Graphics::Imaging::ISoftwareBitmap>{ static constexpr guid value{ 0x689E0708,0x7EEF,0x483F,{ 0x96,0x3F,0xDA,0x93,0x88,0x18,0xE0,0x73 } }; };
template <> struct guid_storage<Windows::Graphics::Imaging::ISoftwareBitmapFactory>{ static constexpr guid value{ 0xC99FEB69,0x2D62,0x4D47,{ 0xA6,0xB3,0x4F,0xDB,0x6A,0x07,0xFD,0xF8 } }; };
template <> struct guid_storage<Windows::Graphics::Imaging::ISoftwareBitmapStatics>{ static constexpr guid value{ 0xDF0385DB,0x672F,0x4A9D,{ 0x80,0x6E,0xC2,0x44,0x2F,0x34,0x3E,0x86 } }; };
template <> struct default_interface<Windows::Graphics::Imaging::BitmapBuffer>{ using type = Windows::Graphics::Imaging::IBitmapBuffer; };
template <> struct default_interface<Windows::Graphics::Imaging::BitmapCodecInformation>{ using type = Windows::Graphics::Imaging::IBitmapCodecInformation; };
template <> struct default_interface<Windows::Graphics::Imaging::BitmapDecoder>{ using type = Windows::Graphics::Imaging::IBitmapDecoder; };
template <> struct default_interface<Windows::Graphics::Imaging::BitmapEncoder>{ using type = Windows::Graphics::Imaging::IBitmapEncoder; };
template <> struct default_interface<Windows::Graphics::Imaging::BitmapFrame>{ using type = Windows::Graphics::Imaging::IBitmapFrame; };
template <> struct default_interface<Windows::Graphics::Imaging::BitmapProperties>{ using type = Windows::Graphics::Imaging::IBitmapProperties; };
template <> struct default_interface<Windows::Graphics::Imaging::BitmapPropertiesView>{ using type = Windows::Graphics::Imaging::IBitmapPropertiesView; };
template <> struct default_interface<Windows::Graphics::Imaging::BitmapPropertySet>{ using type = Windows::Foundation::Collections::IMap<hstring, Windows::Graphics::Imaging::BitmapTypedValue>; };
template <> struct default_interface<Windows::Graphics::Imaging::BitmapTransform>{ using type = Windows::Graphics::Imaging::IBitmapTransform; };
template <> struct default_interface<Windows::Graphics::Imaging::BitmapTypedValue>{ using type = Windows::Graphics::Imaging::IBitmapTypedValue; };
template <> struct default_interface<Windows::Graphics::Imaging::ImageStream>{ using type = Windows::Storage::Streams::IRandomAccessStreamWithContentType; };
template <> struct default_interface<Windows::Graphics::Imaging::PixelDataProvider>{ using type = Windows::Graphics::Imaging::IPixelDataProvider; };
template <> struct default_interface<Windows::Graphics::Imaging::SoftwareBitmap>{ using type = Windows::Graphics::Imaging::ISoftwareBitmap; };

template <> struct abi<Windows::Graphics::Imaging::IBitmapBuffer>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetPlaneCount(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL GetPlaneDescription(int32_t index, struct struct_Windows_Graphics_Imaging_BitmapPlaneDescription* value) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Imaging::IBitmapCodecInformation>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_CodecId(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_FileExtensions(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_FriendlyName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MimeTypes(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Imaging::IBitmapDecoder>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_BitmapContainerProperties(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DecoderInformation(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_FrameCount(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL GetPreviewAsync(void** asyncInfo) noexcept = 0;
    virtual int32_t WINRT_CALL GetFrameAsync(uint32_t frameIndex, void** asyncInfo) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Imaging::IBitmapDecoderStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_BmpDecoderId(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_JpegDecoderId(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PngDecoderId(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TiffDecoderId(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_GifDecoderId(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_JpegXRDecoderId(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IcoDecoderId(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL GetDecoderInformationEnumerator(void** decoderInformationEnumerator) noexcept = 0;
    virtual int32_t WINRT_CALL CreateAsync(void* stream, void** asyncInfo) noexcept = 0;
    virtual int32_t WINRT_CALL CreateWithIdAsync(winrt::guid decoderId, void* stream, void** asyncInfo) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Imaging::IBitmapDecoderStatics2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_HeifDecoderId(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_WebpDecoderId(winrt::guid* value) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Imaging::IBitmapEncoder>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_EncoderInformation(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BitmapProperties(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BitmapContainerProperties(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsThumbnailGenerated(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IsThumbnailGenerated(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_GeneratedThumbnailWidth(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_GeneratedThumbnailWidth(uint32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_GeneratedThumbnailHeight(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_GeneratedThumbnailHeight(uint32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BitmapTransform(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL SetPixelData(Windows::Graphics::Imaging::BitmapPixelFormat pixelFormat, Windows::Graphics::Imaging::BitmapAlphaMode alphaMode, uint32_t width, uint32_t height, double dpiX, double dpiY, uint32_t __pixelsSize, uint8_t* pixels) noexcept = 0;
    virtual int32_t WINRT_CALL GoToNextFrameAsync(void** asyncInfo) noexcept = 0;
    virtual int32_t WINRT_CALL GoToNextFrameWithEncodingOptionsAsync(void* encodingOptions, void** asyncInfo) noexcept = 0;
    virtual int32_t WINRT_CALL FlushAsync(void** asyncInfo) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Imaging::IBitmapEncoderStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_BmpEncoderId(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_JpegEncoderId(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PngEncoderId(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TiffEncoderId(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_GifEncoderId(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_JpegXREncoderId(winrt::guid* value) noexcept = 0;
    virtual int32_t WINRT_CALL GetEncoderInformationEnumerator(void** encoderInformationEnumerator) noexcept = 0;
    virtual int32_t WINRT_CALL CreateAsync(winrt::guid encoderId, void* stream, void** asyncInfo) noexcept = 0;
    virtual int32_t WINRT_CALL CreateWithEncodingOptionsAsync(winrt::guid encoderId, void* stream, void* encodingOptions, void** asyncInfo) noexcept = 0;
    virtual int32_t WINRT_CALL CreateForTranscodingAsync(void* stream, void* bitmapDecoder, void** asyncInfo) noexcept = 0;
    virtual int32_t WINRT_CALL CreateForInPlacePropertyEncodingAsync(void* bitmapDecoder, void** asyncInfo) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Imaging::IBitmapEncoderStatics2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_HeifEncoderId(winrt::guid* value) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Imaging::IBitmapEncoderWithSoftwareBitmap>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL SetSoftwareBitmap(void* bitmap) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Imaging::IBitmapFrame>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetThumbnailAsync(void** asyncInfo) noexcept = 0;
    virtual int32_t WINRT_CALL get_BitmapProperties(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BitmapPixelFormat(Windows::Graphics::Imaging::BitmapPixelFormat* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BitmapAlphaMode(Windows::Graphics::Imaging::BitmapAlphaMode* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DpiX(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DpiY(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PixelWidth(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PixelHeight(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_OrientedPixelWidth(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_OrientedPixelHeight(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL GetPixelDataAsync(void** asyncInfo) noexcept = 0;
    virtual int32_t WINRT_CALL GetPixelDataTransformedAsync(Windows::Graphics::Imaging::BitmapPixelFormat pixelFormat, Windows::Graphics::Imaging::BitmapAlphaMode alphaMode, void* transform, Windows::Graphics::Imaging::ExifOrientationMode exifOrientationMode, Windows::Graphics::Imaging::ColorManagementMode colorManagementMode, void** asyncInfo) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Imaging::IBitmapFrameWithSoftwareBitmap>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetSoftwareBitmapAsync(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetSoftwareBitmapConvertedAsync(Windows::Graphics::Imaging::BitmapPixelFormat pixelFormat, Windows::Graphics::Imaging::BitmapAlphaMode alphaMode, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetSoftwareBitmapTransformedAsync(Windows::Graphics::Imaging::BitmapPixelFormat pixelFormat, Windows::Graphics::Imaging::BitmapAlphaMode alphaMode, void* transform, Windows::Graphics::Imaging::ExifOrientationMode exifOrientationMode, Windows::Graphics::Imaging::ColorManagementMode colorManagementMode, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Imaging::IBitmapProperties>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL SetPropertiesAsync(void* propertiesToSet, void** asyncInfo) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Imaging::IBitmapPropertiesView>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetPropertiesAsync(void* propertiesToRetrieve, void** asyncInfo) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Imaging::IBitmapTransform>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ScaledWidth(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ScaledWidth(uint32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ScaledHeight(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ScaledHeight(uint32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_InterpolationMode(Windows::Graphics::Imaging::BitmapInterpolationMode* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_InterpolationMode(Windows::Graphics::Imaging::BitmapInterpolationMode value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Flip(Windows::Graphics::Imaging::BitmapFlip* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Flip(Windows::Graphics::Imaging::BitmapFlip value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Rotation(Windows::Graphics::Imaging::BitmapRotation* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Rotation(Windows::Graphics::Imaging::BitmapRotation value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Bounds(struct struct_Windows_Graphics_Imaging_BitmapBounds* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Bounds(struct struct_Windows_Graphics_Imaging_BitmapBounds value) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Imaging::IBitmapTypedValue>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Value(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Type(Windows::Foundation::PropertyType* value) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Imaging::IBitmapTypedValueFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Create(void* value, Windows::Foundation::PropertyType type, void** bitmapTypedValue) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Imaging::IPixelDataProvider>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL DetachPixelData(uint32_t* __pixelDataSize, uint8_t** pixelData) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Imaging::ISoftwareBitmap>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_BitmapPixelFormat(Windows::Graphics::Imaging::BitmapPixelFormat* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BitmapAlphaMode(Windows::Graphics::Imaging::BitmapAlphaMode* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PixelWidth(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PixelHeight(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsReadOnly(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_DpiX(double value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DpiX(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_DpiY(double value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DpiY(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL LockBuffer(Windows::Graphics::Imaging::BitmapBufferAccessMode mode, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CopyTo(void* bitmap) noexcept = 0;
    virtual int32_t WINRT_CALL CopyFromBuffer(void* buffer) noexcept = 0;
    virtual int32_t WINRT_CALL CopyToBuffer(void* buffer) noexcept = 0;
    virtual int32_t WINRT_CALL GetReadOnlyView(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Imaging::ISoftwareBitmapFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Create(Windows::Graphics::Imaging::BitmapPixelFormat format, int32_t width, int32_t height, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateWithAlpha(Windows::Graphics::Imaging::BitmapPixelFormat format, int32_t width, int32_t height, Windows::Graphics::Imaging::BitmapAlphaMode alpha, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Imaging::ISoftwareBitmapStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Copy(void* source, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL Convert(void* source, Windows::Graphics::Imaging::BitmapPixelFormat format, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL ConvertWithAlpha(void* source, Windows::Graphics::Imaging::BitmapPixelFormat format, Windows::Graphics::Imaging::BitmapAlphaMode alpha, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateCopyFromBuffer(void* source, Windows::Graphics::Imaging::BitmapPixelFormat format, int32_t width, int32_t height, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateCopyWithAlphaFromBuffer(void* source, Windows::Graphics::Imaging::BitmapPixelFormat format, int32_t width, int32_t height, Windows::Graphics::Imaging::BitmapAlphaMode alpha, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateCopyFromSurfaceAsync(void* surface, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateCopyWithAlphaFromSurfaceAsync(void* surface, Windows::Graphics::Imaging::BitmapAlphaMode alpha, void** value) noexcept = 0;
};};

template <typename D>
struct consume_Windows_Graphics_Imaging_IBitmapBuffer
{
    int32_t GetPlaneCount() const;
    Windows::Graphics::Imaging::BitmapPlaneDescription GetPlaneDescription(int32_t index) const;
};
template <> struct consume<Windows::Graphics::Imaging::IBitmapBuffer> { template <typename D> using type = consume_Windows_Graphics_Imaging_IBitmapBuffer<D>; };

template <typename D>
struct consume_Windows_Graphics_Imaging_IBitmapCodecInformation
{
    winrt::guid CodecId() const;
    Windows::Foundation::Collections::IVectorView<hstring> FileExtensions() const;
    hstring FriendlyName() const;
    Windows::Foundation::Collections::IVectorView<hstring> MimeTypes() const;
};
template <> struct consume<Windows::Graphics::Imaging::IBitmapCodecInformation> { template <typename D> using type = consume_Windows_Graphics_Imaging_IBitmapCodecInformation<D>; };

template <typename D>
struct consume_Windows_Graphics_Imaging_IBitmapDecoder
{
    Windows::Graphics::Imaging::BitmapPropertiesView BitmapContainerProperties() const;
    Windows::Graphics::Imaging::BitmapCodecInformation DecoderInformation() const;
    uint32_t FrameCount() const;
    Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::ImageStream> GetPreviewAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::BitmapFrame> GetFrameAsync(uint32_t frameIndex) const;
};
template <> struct consume<Windows::Graphics::Imaging::IBitmapDecoder> { template <typename D> using type = consume_Windows_Graphics_Imaging_IBitmapDecoder<D>; };

template <typename D>
struct consume_Windows_Graphics_Imaging_IBitmapDecoderStatics
{
    winrt::guid BmpDecoderId() const;
    winrt::guid JpegDecoderId() const;
    winrt::guid PngDecoderId() const;
    winrt::guid TiffDecoderId() const;
    winrt::guid GifDecoderId() const;
    winrt::guid JpegXRDecoderId() const;
    winrt::guid IcoDecoderId() const;
    Windows::Foundation::Collections::IVectorView<Windows::Graphics::Imaging::BitmapCodecInformation> GetDecoderInformationEnumerator() const;
    Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::BitmapDecoder> CreateAsync(Windows::Storage::Streams::IRandomAccessStream const& stream) const;
    Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::BitmapDecoder> CreateAsync(winrt::guid const& decoderId, Windows::Storage::Streams::IRandomAccessStream const& stream) const;
};
template <> struct consume<Windows::Graphics::Imaging::IBitmapDecoderStatics> { template <typename D> using type = consume_Windows_Graphics_Imaging_IBitmapDecoderStatics<D>; };

template <typename D>
struct consume_Windows_Graphics_Imaging_IBitmapDecoderStatics2
{
    winrt::guid HeifDecoderId() const;
    winrt::guid WebpDecoderId() const;
};
template <> struct consume<Windows::Graphics::Imaging::IBitmapDecoderStatics2> { template <typename D> using type = consume_Windows_Graphics_Imaging_IBitmapDecoderStatics2<D>; };

template <typename D>
struct consume_Windows_Graphics_Imaging_IBitmapEncoder
{
    Windows::Graphics::Imaging::BitmapCodecInformation EncoderInformation() const;
    Windows::Graphics::Imaging::BitmapProperties BitmapProperties() const;
    Windows::Graphics::Imaging::BitmapProperties BitmapContainerProperties() const;
    bool IsThumbnailGenerated() const;
    void IsThumbnailGenerated(bool value) const;
    uint32_t GeneratedThumbnailWidth() const;
    void GeneratedThumbnailWidth(uint32_t value) const;
    uint32_t GeneratedThumbnailHeight() const;
    void GeneratedThumbnailHeight(uint32_t value) const;
    Windows::Graphics::Imaging::BitmapTransform BitmapTransform() const;
    void SetPixelData(Windows::Graphics::Imaging::BitmapPixelFormat const& pixelFormat, Windows::Graphics::Imaging::BitmapAlphaMode const& alphaMode, uint32_t width, uint32_t height, double dpiX, double dpiY, array_view<uint8_t const> pixels) const;
    Windows::Foundation::IAsyncAction GoToNextFrameAsync() const;
    Windows::Foundation::IAsyncAction GoToNextFrameAsync(param::async_iterable<Windows::Foundation::Collections::IKeyValuePair<hstring, Windows::Graphics::Imaging::BitmapTypedValue>> const& encodingOptions) const;
    Windows::Foundation::IAsyncAction FlushAsync() const;
};
template <> struct consume<Windows::Graphics::Imaging::IBitmapEncoder> { template <typename D> using type = consume_Windows_Graphics_Imaging_IBitmapEncoder<D>; };

template <typename D>
struct consume_Windows_Graphics_Imaging_IBitmapEncoderStatics
{
    winrt::guid BmpEncoderId() const;
    winrt::guid JpegEncoderId() const;
    winrt::guid PngEncoderId() const;
    winrt::guid TiffEncoderId() const;
    winrt::guid GifEncoderId() const;
    winrt::guid JpegXREncoderId() const;
    Windows::Foundation::Collections::IVectorView<Windows::Graphics::Imaging::BitmapCodecInformation> GetEncoderInformationEnumerator() const;
    Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::BitmapEncoder> CreateAsync(winrt::guid const& encoderId, Windows::Storage::Streams::IRandomAccessStream const& stream) const;
    Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::BitmapEncoder> CreateAsync(winrt::guid const& encoderId, Windows::Storage::Streams::IRandomAccessStream const& stream, param::async_iterable<Windows::Foundation::Collections::IKeyValuePair<hstring, Windows::Graphics::Imaging::BitmapTypedValue>> const& encodingOptions) const;
    Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::BitmapEncoder> CreateForTranscodingAsync(Windows::Storage::Streams::IRandomAccessStream const& stream, Windows::Graphics::Imaging::BitmapDecoder const& bitmapDecoder) const;
    Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::BitmapEncoder> CreateForInPlacePropertyEncodingAsync(Windows::Graphics::Imaging::BitmapDecoder const& bitmapDecoder) const;
};
template <> struct consume<Windows::Graphics::Imaging::IBitmapEncoderStatics> { template <typename D> using type = consume_Windows_Graphics_Imaging_IBitmapEncoderStatics<D>; };

template <typename D>
struct consume_Windows_Graphics_Imaging_IBitmapEncoderStatics2
{
    winrt::guid HeifEncoderId() const;
};
template <> struct consume<Windows::Graphics::Imaging::IBitmapEncoderStatics2> { template <typename D> using type = consume_Windows_Graphics_Imaging_IBitmapEncoderStatics2<D>; };

template <typename D>
struct consume_Windows_Graphics_Imaging_IBitmapEncoderWithSoftwareBitmap
{
    void SetSoftwareBitmap(Windows::Graphics::Imaging::SoftwareBitmap const& bitmap) const;
};
template <> struct consume<Windows::Graphics::Imaging::IBitmapEncoderWithSoftwareBitmap> { template <typename D> using type = consume_Windows_Graphics_Imaging_IBitmapEncoderWithSoftwareBitmap<D>; };

template <typename D>
struct consume_Windows_Graphics_Imaging_IBitmapFrame
{
    Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::ImageStream> GetThumbnailAsync() const;
    Windows::Graphics::Imaging::BitmapPropertiesView BitmapProperties() const;
    Windows::Graphics::Imaging::BitmapPixelFormat BitmapPixelFormat() const;
    Windows::Graphics::Imaging::BitmapAlphaMode BitmapAlphaMode() const;
    double DpiX() const;
    double DpiY() const;
    uint32_t PixelWidth() const;
    uint32_t PixelHeight() const;
    uint32_t OrientedPixelWidth() const;
    uint32_t OrientedPixelHeight() const;
    Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::PixelDataProvider> GetPixelDataAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::PixelDataProvider> GetPixelDataAsync(Windows::Graphics::Imaging::BitmapPixelFormat const& pixelFormat, Windows::Graphics::Imaging::BitmapAlphaMode const& alphaMode, Windows::Graphics::Imaging::BitmapTransform const& transform, Windows::Graphics::Imaging::ExifOrientationMode const& exifOrientationMode, Windows::Graphics::Imaging::ColorManagementMode const& colorManagementMode) const;
};
template <> struct consume<Windows::Graphics::Imaging::IBitmapFrame> { template <typename D> using type = consume_Windows_Graphics_Imaging_IBitmapFrame<D>; };

template <typename D>
struct consume_Windows_Graphics_Imaging_IBitmapFrameWithSoftwareBitmap
{
    Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::SoftwareBitmap> GetSoftwareBitmapAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::SoftwareBitmap> GetSoftwareBitmapAsync(Windows::Graphics::Imaging::BitmapPixelFormat const& pixelFormat, Windows::Graphics::Imaging::BitmapAlphaMode const& alphaMode) const;
    Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::SoftwareBitmap> GetSoftwareBitmapAsync(Windows::Graphics::Imaging::BitmapPixelFormat const& pixelFormat, Windows::Graphics::Imaging::BitmapAlphaMode const& alphaMode, Windows::Graphics::Imaging::BitmapTransform const& transform, Windows::Graphics::Imaging::ExifOrientationMode const& exifOrientationMode, Windows::Graphics::Imaging::ColorManagementMode const& colorManagementMode) const;
};
template <> struct consume<Windows::Graphics::Imaging::IBitmapFrameWithSoftwareBitmap> { template <typename D> using type = consume_Windows_Graphics_Imaging_IBitmapFrameWithSoftwareBitmap<D>; };

template <typename D>
struct consume_Windows_Graphics_Imaging_IBitmapProperties
{
    Windows::Foundation::IAsyncAction SetPropertiesAsync(param::async_iterable<Windows::Foundation::Collections::IKeyValuePair<hstring, Windows::Graphics::Imaging::BitmapTypedValue>> const& propertiesToSet) const;
};
template <> struct consume<Windows::Graphics::Imaging::IBitmapProperties> { template <typename D> using type = consume_Windows_Graphics_Imaging_IBitmapProperties<D>; };

template <typename D>
struct consume_Windows_Graphics_Imaging_IBitmapPropertiesView
{
    Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::BitmapPropertySet> GetPropertiesAsync(param::async_iterable<hstring> const& propertiesToRetrieve) const;
};
template <> struct consume<Windows::Graphics::Imaging::IBitmapPropertiesView> { template <typename D> using type = consume_Windows_Graphics_Imaging_IBitmapPropertiesView<D>; };

template <typename D>
struct consume_Windows_Graphics_Imaging_IBitmapTransform
{
    uint32_t ScaledWidth() const;
    void ScaledWidth(uint32_t value) const;
    uint32_t ScaledHeight() const;
    void ScaledHeight(uint32_t value) const;
    Windows::Graphics::Imaging::BitmapInterpolationMode InterpolationMode() const;
    void InterpolationMode(Windows::Graphics::Imaging::BitmapInterpolationMode const& value) const;
    Windows::Graphics::Imaging::BitmapFlip Flip() const;
    void Flip(Windows::Graphics::Imaging::BitmapFlip const& value) const;
    Windows::Graphics::Imaging::BitmapRotation Rotation() const;
    void Rotation(Windows::Graphics::Imaging::BitmapRotation const& value) const;
    Windows::Graphics::Imaging::BitmapBounds Bounds() const;
    void Bounds(Windows::Graphics::Imaging::BitmapBounds const& value) const;
};
template <> struct consume<Windows::Graphics::Imaging::IBitmapTransform> { template <typename D> using type = consume_Windows_Graphics_Imaging_IBitmapTransform<D>; };

template <typename D>
struct consume_Windows_Graphics_Imaging_IBitmapTypedValue
{
    Windows::Foundation::IInspectable Value() const;
    Windows::Foundation::PropertyType Type() const;
};
template <> struct consume<Windows::Graphics::Imaging::IBitmapTypedValue> { template <typename D> using type = consume_Windows_Graphics_Imaging_IBitmapTypedValue<D>; };

template <typename D>
struct consume_Windows_Graphics_Imaging_IBitmapTypedValueFactory
{
    Windows::Graphics::Imaging::BitmapTypedValue Create(Windows::Foundation::IInspectable const& value, Windows::Foundation::PropertyType const& type) const;
};
template <> struct consume<Windows::Graphics::Imaging::IBitmapTypedValueFactory> { template <typename D> using type = consume_Windows_Graphics_Imaging_IBitmapTypedValueFactory<D>; };

template <typename D>
struct consume_Windows_Graphics_Imaging_IPixelDataProvider
{
    com_array<uint8_t> DetachPixelData() const;
};
template <> struct consume<Windows::Graphics::Imaging::IPixelDataProvider> { template <typename D> using type = consume_Windows_Graphics_Imaging_IPixelDataProvider<D>; };

template <typename D>
struct consume_Windows_Graphics_Imaging_ISoftwareBitmap
{
    Windows::Graphics::Imaging::BitmapPixelFormat BitmapPixelFormat() const;
    Windows::Graphics::Imaging::BitmapAlphaMode BitmapAlphaMode() const;
    int32_t PixelWidth() const;
    int32_t PixelHeight() const;
    bool IsReadOnly() const;
    void DpiX(double value) const;
    double DpiX() const;
    void DpiY(double value) const;
    double DpiY() const;
    Windows::Graphics::Imaging::BitmapBuffer LockBuffer(Windows::Graphics::Imaging::BitmapBufferAccessMode const& mode) const;
    void CopyTo(Windows::Graphics::Imaging::SoftwareBitmap const& bitmap) const;
    void CopyFromBuffer(Windows::Storage::Streams::IBuffer const& buffer) const;
    void CopyToBuffer(Windows::Storage::Streams::IBuffer const& buffer) const;
    Windows::Graphics::Imaging::SoftwareBitmap GetReadOnlyView() const;
};
template <> struct consume<Windows::Graphics::Imaging::ISoftwareBitmap> { template <typename D> using type = consume_Windows_Graphics_Imaging_ISoftwareBitmap<D>; };

template <typename D>
struct consume_Windows_Graphics_Imaging_ISoftwareBitmapFactory
{
    Windows::Graphics::Imaging::SoftwareBitmap Create(Windows::Graphics::Imaging::BitmapPixelFormat const& format, int32_t width, int32_t height) const;
    Windows::Graphics::Imaging::SoftwareBitmap CreateWithAlpha(Windows::Graphics::Imaging::BitmapPixelFormat const& format, int32_t width, int32_t height, Windows::Graphics::Imaging::BitmapAlphaMode const& alpha) const;
};
template <> struct consume<Windows::Graphics::Imaging::ISoftwareBitmapFactory> { template <typename D> using type = consume_Windows_Graphics_Imaging_ISoftwareBitmapFactory<D>; };

template <typename D>
struct consume_Windows_Graphics_Imaging_ISoftwareBitmapStatics
{
    Windows::Graphics::Imaging::SoftwareBitmap Copy(Windows::Graphics::Imaging::SoftwareBitmap const& source) const;
    Windows::Graphics::Imaging::SoftwareBitmap Convert(Windows::Graphics::Imaging::SoftwareBitmap const& source, Windows::Graphics::Imaging::BitmapPixelFormat const& format) const;
    Windows::Graphics::Imaging::SoftwareBitmap Convert(Windows::Graphics::Imaging::SoftwareBitmap const& source, Windows::Graphics::Imaging::BitmapPixelFormat const& format, Windows::Graphics::Imaging::BitmapAlphaMode const& alpha) const;
    Windows::Graphics::Imaging::SoftwareBitmap CreateCopyFromBuffer(Windows::Storage::Streams::IBuffer const& source, Windows::Graphics::Imaging::BitmapPixelFormat const& format, int32_t width, int32_t height) const;
    Windows::Graphics::Imaging::SoftwareBitmap CreateCopyFromBuffer(Windows::Storage::Streams::IBuffer const& source, Windows::Graphics::Imaging::BitmapPixelFormat const& format, int32_t width, int32_t height, Windows::Graphics::Imaging::BitmapAlphaMode const& alpha) const;
    Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::SoftwareBitmap> CreateCopyFromSurfaceAsync(Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const& surface) const;
    Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::SoftwareBitmap> CreateCopyFromSurfaceAsync(Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const& surface, Windows::Graphics::Imaging::BitmapAlphaMode const& alpha) const;
};
template <> struct consume<Windows::Graphics::Imaging::ISoftwareBitmapStatics> { template <typename D> using type = consume_Windows_Graphics_Imaging_ISoftwareBitmapStatics<D>; };

struct struct_Windows_Graphics_Imaging_BitmapBounds
{
    uint32_t X;
    uint32_t Y;
    uint32_t Width;
    uint32_t Height;
};
template <> struct abi<Windows::Graphics::Imaging::BitmapBounds>{ using type = struct_Windows_Graphics_Imaging_BitmapBounds; };


struct struct_Windows_Graphics_Imaging_BitmapPlaneDescription
{
    int32_t StartIndex;
    int32_t Width;
    int32_t Height;
    int32_t Stride;
};
template <> struct abi<Windows::Graphics::Imaging::BitmapPlaneDescription>{ using type = struct_Windows_Graphics_Imaging_BitmapPlaneDescription; };


struct struct_Windows_Graphics_Imaging_BitmapSize
{
    uint32_t Width;
    uint32_t Height;
};
template <> struct abi<Windows::Graphics::Imaging::BitmapSize>{ using type = struct_Windows_Graphics_Imaging_BitmapSize; };


}
