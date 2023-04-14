// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.Graphics.DirectX.Direct3D11.1.h"
#include "winrt/impl/Windows.Storage.Streams.1.h"
#include "winrt/impl/Windows.Graphics.Imaging.1.h"

WINRT_EXPORT namespace winrt::Windows::Graphics::Imaging {

struct BitmapBounds
{
    uint32_t X;
    uint32_t Y;
    uint32_t Width;
    uint32_t Height;
};

inline bool operator==(BitmapBounds const& left, BitmapBounds const& right) noexcept
{
    return left.X == right.X && left.Y == right.Y && left.Width == right.Width && left.Height == right.Height;
}

inline bool operator!=(BitmapBounds const& left, BitmapBounds const& right) noexcept
{
    return !(left == right);
}

struct BitmapPlaneDescription
{
    int32_t StartIndex;
    int32_t Width;
    int32_t Height;
    int32_t Stride;
};

inline bool operator==(BitmapPlaneDescription const& left, BitmapPlaneDescription const& right) noexcept
{
    return left.StartIndex == right.StartIndex && left.Width == right.Width && left.Height == right.Height && left.Stride == right.Stride;
}

inline bool operator!=(BitmapPlaneDescription const& left, BitmapPlaneDescription const& right) noexcept
{
    return !(left == right);
}

struct BitmapSize
{
    uint32_t Width;
    uint32_t Height;
};

inline bool operator==(BitmapSize const& left, BitmapSize const& right) noexcept
{
    return left.Width == right.Width && left.Height == right.Height;
}

inline bool operator!=(BitmapSize const& left, BitmapSize const& right) noexcept
{
    return !(left == right);
}

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::Graphics::Imaging {

struct WINRT_EBO BitmapBuffer :
    Windows::Graphics::Imaging::IBitmapBuffer
{
    BitmapBuffer(std::nullptr_t) noexcept {}
};

struct WINRT_EBO BitmapCodecInformation :
    Windows::Graphics::Imaging::IBitmapCodecInformation
{
    BitmapCodecInformation(std::nullptr_t) noexcept {}
};

struct WINRT_EBO BitmapDecoder :
    Windows::Graphics::Imaging::IBitmapDecoder,
    impl::require<BitmapDecoder, Windows::Graphics::Imaging::IBitmapFrame, Windows::Graphics::Imaging::IBitmapFrameWithSoftwareBitmap>
{
    BitmapDecoder(std::nullptr_t) noexcept {}
    static winrt::guid BmpDecoderId();
    static winrt::guid JpegDecoderId();
    static winrt::guid PngDecoderId();
    static winrt::guid TiffDecoderId();
    static winrt::guid GifDecoderId();
    static winrt::guid JpegXRDecoderId();
    static winrt::guid IcoDecoderId();
    static Windows::Foundation::Collections::IVectorView<Windows::Graphics::Imaging::BitmapCodecInformation> GetDecoderInformationEnumerator();
    static Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::BitmapDecoder> CreateAsync(Windows::Storage::Streams::IRandomAccessStream const& stream);
    static Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::BitmapDecoder> CreateAsync(winrt::guid const& decoderId, Windows::Storage::Streams::IRandomAccessStream const& stream);
    static winrt::guid HeifDecoderId();
    static winrt::guid WebpDecoderId();
};

struct WINRT_EBO BitmapEncoder :
    Windows::Graphics::Imaging::IBitmapEncoder,
    impl::require<BitmapEncoder, Windows::Graphics::Imaging::IBitmapEncoderWithSoftwareBitmap>
{
    BitmapEncoder(std::nullptr_t) noexcept {}
    static winrt::guid BmpEncoderId();
    static winrt::guid JpegEncoderId();
    static winrt::guid PngEncoderId();
    static winrt::guid TiffEncoderId();
    static winrt::guid GifEncoderId();
    static winrt::guid JpegXREncoderId();
    static Windows::Foundation::Collections::IVectorView<Windows::Graphics::Imaging::BitmapCodecInformation> GetEncoderInformationEnumerator();
    static Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::BitmapEncoder> CreateAsync(winrt::guid const& encoderId, Windows::Storage::Streams::IRandomAccessStream const& stream);
    static Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::BitmapEncoder> CreateAsync(winrt::guid const& encoderId, Windows::Storage::Streams::IRandomAccessStream const& stream, param::async_iterable<Windows::Foundation::Collections::IKeyValuePair<hstring, Windows::Graphics::Imaging::BitmapTypedValue>> const& encodingOptions);
    static Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::BitmapEncoder> CreateForTranscodingAsync(Windows::Storage::Streams::IRandomAccessStream const& stream, Windows::Graphics::Imaging::BitmapDecoder const& bitmapDecoder);
    static Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::BitmapEncoder> CreateForInPlacePropertyEncodingAsync(Windows::Graphics::Imaging::BitmapDecoder const& bitmapDecoder);
    static winrt::guid HeifEncoderId();
};

struct WINRT_EBO BitmapFrame :
    Windows::Graphics::Imaging::IBitmapFrame,
    impl::require<BitmapFrame, Windows::Graphics::Imaging::IBitmapFrameWithSoftwareBitmap>
{
    BitmapFrame(std::nullptr_t) noexcept {}
};

struct WINRT_EBO BitmapProperties :
    Windows::Graphics::Imaging::IBitmapProperties
{
    BitmapProperties(std::nullptr_t) noexcept {}
};

struct WINRT_EBO BitmapPropertiesView :
    Windows::Graphics::Imaging::IBitmapPropertiesView
{
    BitmapPropertiesView(std::nullptr_t) noexcept {}
};

struct WINRT_EBO BitmapPropertySet :
    Windows::Foundation::Collections::IMap<hstring, Windows::Graphics::Imaging::BitmapTypedValue>
{
    BitmapPropertySet(std::nullptr_t) noexcept {}
    BitmapPropertySet();
};

struct WINRT_EBO BitmapTransform :
    Windows::Graphics::Imaging::IBitmapTransform
{
    BitmapTransform(std::nullptr_t) noexcept {}
    BitmapTransform();
};

struct WINRT_EBO BitmapTypedValue :
    Windows::Graphics::Imaging::IBitmapTypedValue
{
    BitmapTypedValue(std::nullptr_t) noexcept {}
    BitmapTypedValue(Windows::Foundation::IInspectable const& value, Windows::Foundation::PropertyType const& type);
};

struct WINRT_EBO ImageStream :
    Windows::Storage::Streams::IRandomAccessStreamWithContentType
{
    ImageStream(std::nullptr_t) noexcept {}
};

struct WINRT_EBO PixelDataProvider :
    Windows::Graphics::Imaging::IPixelDataProvider
{
    PixelDataProvider(std::nullptr_t) noexcept {}
};

struct WINRT_EBO SoftwareBitmap :
    Windows::Graphics::Imaging::ISoftwareBitmap
{
    SoftwareBitmap(std::nullptr_t) noexcept {}
    SoftwareBitmap(Windows::Graphics::Imaging::BitmapPixelFormat const& format, int32_t width, int32_t height);
    SoftwareBitmap(Windows::Graphics::Imaging::BitmapPixelFormat const& format, int32_t width, int32_t height, Windows::Graphics::Imaging::BitmapAlphaMode const& alpha);
    static Windows::Graphics::Imaging::SoftwareBitmap Copy(Windows::Graphics::Imaging::SoftwareBitmap const& source);
    static Windows::Graphics::Imaging::SoftwareBitmap Convert(Windows::Graphics::Imaging::SoftwareBitmap const& source, Windows::Graphics::Imaging::BitmapPixelFormat const& format);
    static Windows::Graphics::Imaging::SoftwareBitmap Convert(Windows::Graphics::Imaging::SoftwareBitmap const& source, Windows::Graphics::Imaging::BitmapPixelFormat const& format, Windows::Graphics::Imaging::BitmapAlphaMode const& alpha);
    static Windows::Graphics::Imaging::SoftwareBitmap CreateCopyFromBuffer(Windows::Storage::Streams::IBuffer const& source, Windows::Graphics::Imaging::BitmapPixelFormat const& format, int32_t width, int32_t height);
    static Windows::Graphics::Imaging::SoftwareBitmap CreateCopyFromBuffer(Windows::Storage::Streams::IBuffer const& source, Windows::Graphics::Imaging::BitmapPixelFormat const& format, int32_t width, int32_t height, Windows::Graphics::Imaging::BitmapAlphaMode const& alpha);
    static Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::SoftwareBitmap> CreateCopyFromSurfaceAsync(Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const& surface);
    static Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::SoftwareBitmap> CreateCopyFromSurfaceAsync(Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const& surface, Windows::Graphics::Imaging::BitmapAlphaMode const& alpha);
};

}
