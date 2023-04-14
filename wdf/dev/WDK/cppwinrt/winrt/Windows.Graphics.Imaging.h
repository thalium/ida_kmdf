// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Graphics.DirectX.Direct3D11.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Graphics.Imaging.2.h"
#include "winrt/Windows.Graphics.h"

namespace winrt::impl {

template <typename D> int32_t consume_Windows_Graphics_Imaging_IBitmapBuffer<D>::GetPlaneCount() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapBuffer)->GetPlaneCount(&value));
    return value;
}

template <typename D> Windows::Graphics::Imaging::BitmapPlaneDescription consume_Windows_Graphics_Imaging_IBitmapBuffer<D>::GetPlaneDescription(int32_t index) const
{
    Windows::Graphics::Imaging::BitmapPlaneDescription value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapBuffer)->GetPlaneDescription(index, put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Graphics_Imaging_IBitmapCodecInformation<D>::CodecId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapCodecInformation)->get_CodecId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<hstring> consume_Windows_Graphics_Imaging_IBitmapCodecInformation<D>::FileExtensions() const
{
    Windows::Foundation::Collections::IVectorView<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapCodecInformation)->get_FileExtensions(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Graphics_Imaging_IBitmapCodecInformation<D>::FriendlyName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapCodecInformation)->get_FriendlyName(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<hstring> consume_Windows_Graphics_Imaging_IBitmapCodecInformation<D>::MimeTypes() const
{
    Windows::Foundation::Collections::IVectorView<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapCodecInformation)->get_MimeTypes(put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::Imaging::BitmapPropertiesView consume_Windows_Graphics_Imaging_IBitmapDecoder<D>::BitmapContainerProperties() const
{
    Windows::Graphics::Imaging::BitmapPropertiesView value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapDecoder)->get_BitmapContainerProperties(put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::Imaging::BitmapCodecInformation consume_Windows_Graphics_Imaging_IBitmapDecoder<D>::DecoderInformation() const
{
    Windows::Graphics::Imaging::BitmapCodecInformation value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapDecoder)->get_DecoderInformation(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Graphics_Imaging_IBitmapDecoder<D>::FrameCount() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapDecoder)->get_FrameCount(&value));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::ImageStream> consume_Windows_Graphics_Imaging_IBitmapDecoder<D>::GetPreviewAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::ImageStream> asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapDecoder)->GetPreviewAsync(put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::BitmapFrame> consume_Windows_Graphics_Imaging_IBitmapDecoder<D>::GetFrameAsync(uint32_t frameIndex) const
{
    Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::BitmapFrame> asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapDecoder)->GetFrameAsync(frameIndex, put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> winrt::guid consume_Windows_Graphics_Imaging_IBitmapDecoderStatics<D>::BmpDecoderId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapDecoderStatics)->get_BmpDecoderId(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Graphics_Imaging_IBitmapDecoderStatics<D>::JpegDecoderId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapDecoderStatics)->get_JpegDecoderId(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Graphics_Imaging_IBitmapDecoderStatics<D>::PngDecoderId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapDecoderStatics)->get_PngDecoderId(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Graphics_Imaging_IBitmapDecoderStatics<D>::TiffDecoderId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapDecoderStatics)->get_TiffDecoderId(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Graphics_Imaging_IBitmapDecoderStatics<D>::GifDecoderId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapDecoderStatics)->get_GifDecoderId(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Graphics_Imaging_IBitmapDecoderStatics<D>::JpegXRDecoderId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapDecoderStatics)->get_JpegXRDecoderId(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Graphics_Imaging_IBitmapDecoderStatics<D>::IcoDecoderId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapDecoderStatics)->get_IcoDecoderId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Graphics::Imaging::BitmapCodecInformation> consume_Windows_Graphics_Imaging_IBitmapDecoderStatics<D>::GetDecoderInformationEnumerator() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Graphics::Imaging::BitmapCodecInformation> decoderInformationEnumerator{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapDecoderStatics)->GetDecoderInformationEnumerator(put_abi(decoderInformationEnumerator)));
    return decoderInformationEnumerator;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::BitmapDecoder> consume_Windows_Graphics_Imaging_IBitmapDecoderStatics<D>::CreateAsync(Windows::Storage::Streams::IRandomAccessStream const& stream) const
{
    Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::BitmapDecoder> asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapDecoderStatics)->CreateAsync(get_abi(stream), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::BitmapDecoder> consume_Windows_Graphics_Imaging_IBitmapDecoderStatics<D>::CreateAsync(winrt::guid const& decoderId, Windows::Storage::Streams::IRandomAccessStream const& stream) const
{
    Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::BitmapDecoder> asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapDecoderStatics)->CreateWithIdAsync(get_abi(decoderId), get_abi(stream), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> winrt::guid consume_Windows_Graphics_Imaging_IBitmapDecoderStatics2<D>::HeifDecoderId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapDecoderStatics2)->get_HeifDecoderId(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Graphics_Imaging_IBitmapDecoderStatics2<D>::WebpDecoderId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapDecoderStatics2)->get_WebpDecoderId(put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::Imaging::BitmapCodecInformation consume_Windows_Graphics_Imaging_IBitmapEncoder<D>::EncoderInformation() const
{
    Windows::Graphics::Imaging::BitmapCodecInformation value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapEncoder)->get_EncoderInformation(put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::Imaging::BitmapProperties consume_Windows_Graphics_Imaging_IBitmapEncoder<D>::BitmapProperties() const
{
    Windows::Graphics::Imaging::BitmapProperties value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapEncoder)->get_BitmapProperties(put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::Imaging::BitmapProperties consume_Windows_Graphics_Imaging_IBitmapEncoder<D>::BitmapContainerProperties() const
{
    Windows::Graphics::Imaging::BitmapProperties value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapEncoder)->get_BitmapContainerProperties(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Graphics_Imaging_IBitmapEncoder<D>::IsThumbnailGenerated() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapEncoder)->get_IsThumbnailGenerated(&value));
    return value;
}

template <typename D> void consume_Windows_Graphics_Imaging_IBitmapEncoder<D>::IsThumbnailGenerated(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapEncoder)->put_IsThumbnailGenerated(value));
}

template <typename D> uint32_t consume_Windows_Graphics_Imaging_IBitmapEncoder<D>::GeneratedThumbnailWidth() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapEncoder)->get_GeneratedThumbnailWidth(&value));
    return value;
}

template <typename D> void consume_Windows_Graphics_Imaging_IBitmapEncoder<D>::GeneratedThumbnailWidth(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapEncoder)->put_GeneratedThumbnailWidth(value));
}

template <typename D> uint32_t consume_Windows_Graphics_Imaging_IBitmapEncoder<D>::GeneratedThumbnailHeight() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapEncoder)->get_GeneratedThumbnailHeight(&value));
    return value;
}

template <typename D> void consume_Windows_Graphics_Imaging_IBitmapEncoder<D>::GeneratedThumbnailHeight(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapEncoder)->put_GeneratedThumbnailHeight(value));
}

template <typename D> Windows::Graphics::Imaging::BitmapTransform consume_Windows_Graphics_Imaging_IBitmapEncoder<D>::BitmapTransform() const
{
    Windows::Graphics::Imaging::BitmapTransform value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapEncoder)->get_BitmapTransform(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Imaging_IBitmapEncoder<D>::SetPixelData(Windows::Graphics::Imaging::BitmapPixelFormat const& pixelFormat, Windows::Graphics::Imaging::BitmapAlphaMode const& alphaMode, uint32_t width, uint32_t height, double dpiX, double dpiY, array_view<uint8_t const> pixels) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapEncoder)->SetPixelData(get_abi(pixelFormat), get_abi(alphaMode), width, height, dpiX, dpiY, pixels.size(), get_abi(pixels)));
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Graphics_Imaging_IBitmapEncoder<D>::GoToNextFrameAsync() const
{
    Windows::Foundation::IAsyncAction asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapEncoder)->GoToNextFrameAsync(put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Graphics_Imaging_IBitmapEncoder<D>::GoToNextFrameAsync(param::async_iterable<Windows::Foundation::Collections::IKeyValuePair<hstring, Windows::Graphics::Imaging::BitmapTypedValue>> const& encodingOptions) const
{
    Windows::Foundation::IAsyncAction asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapEncoder)->GoToNextFrameWithEncodingOptionsAsync(get_abi(encodingOptions), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Graphics_Imaging_IBitmapEncoder<D>::FlushAsync() const
{
    Windows::Foundation::IAsyncAction asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapEncoder)->FlushAsync(put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> winrt::guid consume_Windows_Graphics_Imaging_IBitmapEncoderStatics<D>::BmpEncoderId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapEncoderStatics)->get_BmpEncoderId(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Graphics_Imaging_IBitmapEncoderStatics<D>::JpegEncoderId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapEncoderStatics)->get_JpegEncoderId(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Graphics_Imaging_IBitmapEncoderStatics<D>::PngEncoderId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapEncoderStatics)->get_PngEncoderId(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Graphics_Imaging_IBitmapEncoderStatics<D>::TiffEncoderId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapEncoderStatics)->get_TiffEncoderId(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Graphics_Imaging_IBitmapEncoderStatics<D>::GifEncoderId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapEncoderStatics)->get_GifEncoderId(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Graphics_Imaging_IBitmapEncoderStatics<D>::JpegXREncoderId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapEncoderStatics)->get_JpegXREncoderId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Graphics::Imaging::BitmapCodecInformation> consume_Windows_Graphics_Imaging_IBitmapEncoderStatics<D>::GetEncoderInformationEnumerator() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Graphics::Imaging::BitmapCodecInformation> encoderInformationEnumerator{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapEncoderStatics)->GetEncoderInformationEnumerator(put_abi(encoderInformationEnumerator)));
    return encoderInformationEnumerator;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::BitmapEncoder> consume_Windows_Graphics_Imaging_IBitmapEncoderStatics<D>::CreateAsync(winrt::guid const& encoderId, Windows::Storage::Streams::IRandomAccessStream const& stream) const
{
    Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::BitmapEncoder> asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapEncoderStatics)->CreateAsync(get_abi(encoderId), get_abi(stream), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::BitmapEncoder> consume_Windows_Graphics_Imaging_IBitmapEncoderStatics<D>::CreateAsync(winrt::guid const& encoderId, Windows::Storage::Streams::IRandomAccessStream const& stream, param::async_iterable<Windows::Foundation::Collections::IKeyValuePair<hstring, Windows::Graphics::Imaging::BitmapTypedValue>> const& encodingOptions) const
{
    Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::BitmapEncoder> asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapEncoderStatics)->CreateWithEncodingOptionsAsync(get_abi(encoderId), get_abi(stream), get_abi(encodingOptions), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::BitmapEncoder> consume_Windows_Graphics_Imaging_IBitmapEncoderStatics<D>::CreateForTranscodingAsync(Windows::Storage::Streams::IRandomAccessStream const& stream, Windows::Graphics::Imaging::BitmapDecoder const& bitmapDecoder) const
{
    Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::BitmapEncoder> asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapEncoderStatics)->CreateForTranscodingAsync(get_abi(stream), get_abi(bitmapDecoder), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::BitmapEncoder> consume_Windows_Graphics_Imaging_IBitmapEncoderStatics<D>::CreateForInPlacePropertyEncodingAsync(Windows::Graphics::Imaging::BitmapDecoder const& bitmapDecoder) const
{
    Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::BitmapEncoder> asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapEncoderStatics)->CreateForInPlacePropertyEncodingAsync(get_abi(bitmapDecoder), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> winrt::guid consume_Windows_Graphics_Imaging_IBitmapEncoderStatics2<D>::HeifEncoderId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapEncoderStatics2)->get_HeifEncoderId(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Imaging_IBitmapEncoderWithSoftwareBitmap<D>::SetSoftwareBitmap(Windows::Graphics::Imaging::SoftwareBitmap const& bitmap) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapEncoderWithSoftwareBitmap)->SetSoftwareBitmap(get_abi(bitmap)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::ImageStream> consume_Windows_Graphics_Imaging_IBitmapFrame<D>::GetThumbnailAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::ImageStream> asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapFrame)->GetThumbnailAsync(put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Graphics::Imaging::BitmapPropertiesView consume_Windows_Graphics_Imaging_IBitmapFrame<D>::BitmapProperties() const
{
    Windows::Graphics::Imaging::BitmapPropertiesView value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapFrame)->get_BitmapProperties(put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::Imaging::BitmapPixelFormat consume_Windows_Graphics_Imaging_IBitmapFrame<D>::BitmapPixelFormat() const
{
    Windows::Graphics::Imaging::BitmapPixelFormat value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapFrame)->get_BitmapPixelFormat(put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::Imaging::BitmapAlphaMode consume_Windows_Graphics_Imaging_IBitmapFrame<D>::BitmapAlphaMode() const
{
    Windows::Graphics::Imaging::BitmapAlphaMode value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapFrame)->get_BitmapAlphaMode(put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_Graphics_Imaging_IBitmapFrame<D>::DpiX() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapFrame)->get_DpiX(&value));
    return value;
}

template <typename D> double consume_Windows_Graphics_Imaging_IBitmapFrame<D>::DpiY() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapFrame)->get_DpiY(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Graphics_Imaging_IBitmapFrame<D>::PixelWidth() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapFrame)->get_PixelWidth(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Graphics_Imaging_IBitmapFrame<D>::PixelHeight() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapFrame)->get_PixelHeight(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Graphics_Imaging_IBitmapFrame<D>::OrientedPixelWidth() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapFrame)->get_OrientedPixelWidth(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Graphics_Imaging_IBitmapFrame<D>::OrientedPixelHeight() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapFrame)->get_OrientedPixelHeight(&value));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::PixelDataProvider> consume_Windows_Graphics_Imaging_IBitmapFrame<D>::GetPixelDataAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::PixelDataProvider> asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapFrame)->GetPixelDataAsync(put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::PixelDataProvider> consume_Windows_Graphics_Imaging_IBitmapFrame<D>::GetPixelDataAsync(Windows::Graphics::Imaging::BitmapPixelFormat const& pixelFormat, Windows::Graphics::Imaging::BitmapAlphaMode const& alphaMode, Windows::Graphics::Imaging::BitmapTransform const& transform, Windows::Graphics::Imaging::ExifOrientationMode const& exifOrientationMode, Windows::Graphics::Imaging::ColorManagementMode const& colorManagementMode) const
{
    Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::PixelDataProvider> asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapFrame)->GetPixelDataTransformedAsync(get_abi(pixelFormat), get_abi(alphaMode), get_abi(transform), get_abi(exifOrientationMode), get_abi(colorManagementMode), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::SoftwareBitmap> consume_Windows_Graphics_Imaging_IBitmapFrameWithSoftwareBitmap<D>::GetSoftwareBitmapAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::SoftwareBitmap> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapFrameWithSoftwareBitmap)->GetSoftwareBitmapAsync(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::SoftwareBitmap> consume_Windows_Graphics_Imaging_IBitmapFrameWithSoftwareBitmap<D>::GetSoftwareBitmapAsync(Windows::Graphics::Imaging::BitmapPixelFormat const& pixelFormat, Windows::Graphics::Imaging::BitmapAlphaMode const& alphaMode) const
{
    Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::SoftwareBitmap> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapFrameWithSoftwareBitmap)->GetSoftwareBitmapConvertedAsync(get_abi(pixelFormat), get_abi(alphaMode), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::SoftwareBitmap> consume_Windows_Graphics_Imaging_IBitmapFrameWithSoftwareBitmap<D>::GetSoftwareBitmapAsync(Windows::Graphics::Imaging::BitmapPixelFormat const& pixelFormat, Windows::Graphics::Imaging::BitmapAlphaMode const& alphaMode, Windows::Graphics::Imaging::BitmapTransform const& transform, Windows::Graphics::Imaging::ExifOrientationMode const& exifOrientationMode, Windows::Graphics::Imaging::ColorManagementMode const& colorManagementMode) const
{
    Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::SoftwareBitmap> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapFrameWithSoftwareBitmap)->GetSoftwareBitmapTransformedAsync(get_abi(pixelFormat), get_abi(alphaMode), get_abi(transform), get_abi(exifOrientationMode), get_abi(colorManagementMode), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Graphics_Imaging_IBitmapProperties<D>::SetPropertiesAsync(param::async_iterable<Windows::Foundation::Collections::IKeyValuePair<hstring, Windows::Graphics::Imaging::BitmapTypedValue>> const& propertiesToSet) const
{
    Windows::Foundation::IAsyncAction asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapProperties)->SetPropertiesAsync(get_abi(propertiesToSet), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::BitmapPropertySet> consume_Windows_Graphics_Imaging_IBitmapPropertiesView<D>::GetPropertiesAsync(param::async_iterable<hstring> const& propertiesToRetrieve) const
{
    Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::BitmapPropertySet> asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapPropertiesView)->GetPropertiesAsync(get_abi(propertiesToRetrieve), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> uint32_t consume_Windows_Graphics_Imaging_IBitmapTransform<D>::ScaledWidth() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapTransform)->get_ScaledWidth(&value));
    return value;
}

template <typename D> void consume_Windows_Graphics_Imaging_IBitmapTransform<D>::ScaledWidth(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapTransform)->put_ScaledWidth(value));
}

template <typename D> uint32_t consume_Windows_Graphics_Imaging_IBitmapTransform<D>::ScaledHeight() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapTransform)->get_ScaledHeight(&value));
    return value;
}

template <typename D> void consume_Windows_Graphics_Imaging_IBitmapTransform<D>::ScaledHeight(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapTransform)->put_ScaledHeight(value));
}

template <typename D> Windows::Graphics::Imaging::BitmapInterpolationMode consume_Windows_Graphics_Imaging_IBitmapTransform<D>::InterpolationMode() const
{
    Windows::Graphics::Imaging::BitmapInterpolationMode value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapTransform)->get_InterpolationMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Imaging_IBitmapTransform<D>::InterpolationMode(Windows::Graphics::Imaging::BitmapInterpolationMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapTransform)->put_InterpolationMode(get_abi(value)));
}

template <typename D> Windows::Graphics::Imaging::BitmapFlip consume_Windows_Graphics_Imaging_IBitmapTransform<D>::Flip() const
{
    Windows::Graphics::Imaging::BitmapFlip value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapTransform)->get_Flip(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Imaging_IBitmapTransform<D>::Flip(Windows::Graphics::Imaging::BitmapFlip const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapTransform)->put_Flip(get_abi(value)));
}

template <typename D> Windows::Graphics::Imaging::BitmapRotation consume_Windows_Graphics_Imaging_IBitmapTransform<D>::Rotation() const
{
    Windows::Graphics::Imaging::BitmapRotation value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapTransform)->get_Rotation(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Imaging_IBitmapTransform<D>::Rotation(Windows::Graphics::Imaging::BitmapRotation const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapTransform)->put_Rotation(get_abi(value)));
}

template <typename D> Windows::Graphics::Imaging::BitmapBounds consume_Windows_Graphics_Imaging_IBitmapTransform<D>::Bounds() const
{
    Windows::Graphics::Imaging::BitmapBounds value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapTransform)->get_Bounds(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Imaging_IBitmapTransform<D>::Bounds(Windows::Graphics::Imaging::BitmapBounds const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapTransform)->put_Bounds(get_abi(value)));
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_Graphics_Imaging_IBitmapTypedValue<D>::Value() const
{
    Windows::Foundation::IInspectable value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapTypedValue)->get_Value(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::PropertyType consume_Windows_Graphics_Imaging_IBitmapTypedValue<D>::Type() const
{
    Windows::Foundation::PropertyType value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapTypedValue)->get_Type(put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::Imaging::BitmapTypedValue consume_Windows_Graphics_Imaging_IBitmapTypedValueFactory<D>::Create(Windows::Foundation::IInspectable const& value, Windows::Foundation::PropertyType const& type) const
{
    Windows::Graphics::Imaging::BitmapTypedValue bitmapTypedValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IBitmapTypedValueFactory)->Create(get_abi(value), get_abi(type), put_abi(bitmapTypedValue)));
    return bitmapTypedValue;
}

template <typename D> com_array<uint8_t> consume_Windows_Graphics_Imaging_IPixelDataProvider<D>::DetachPixelData() const
{
    com_array<uint8_t> pixelData;
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::IPixelDataProvider)->DetachPixelData(impl::put_size_abi(pixelData), put_abi(pixelData)));
    return pixelData;
}

template <typename D> Windows::Graphics::Imaging::BitmapPixelFormat consume_Windows_Graphics_Imaging_ISoftwareBitmap<D>::BitmapPixelFormat() const
{
    Windows::Graphics::Imaging::BitmapPixelFormat value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::ISoftwareBitmap)->get_BitmapPixelFormat(put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::Imaging::BitmapAlphaMode consume_Windows_Graphics_Imaging_ISoftwareBitmap<D>::BitmapAlphaMode() const
{
    Windows::Graphics::Imaging::BitmapAlphaMode value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::ISoftwareBitmap)->get_BitmapAlphaMode(put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_Graphics_Imaging_ISoftwareBitmap<D>::PixelWidth() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::ISoftwareBitmap)->get_PixelWidth(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Graphics_Imaging_ISoftwareBitmap<D>::PixelHeight() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::ISoftwareBitmap)->get_PixelHeight(&value));
    return value;
}

template <typename D> bool consume_Windows_Graphics_Imaging_ISoftwareBitmap<D>::IsReadOnly() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::ISoftwareBitmap)->get_IsReadOnly(&value));
    return value;
}

template <typename D> void consume_Windows_Graphics_Imaging_ISoftwareBitmap<D>::DpiX(double value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::ISoftwareBitmap)->put_DpiX(value));
}

template <typename D> double consume_Windows_Graphics_Imaging_ISoftwareBitmap<D>::DpiX() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::ISoftwareBitmap)->get_DpiX(&value));
    return value;
}

template <typename D> void consume_Windows_Graphics_Imaging_ISoftwareBitmap<D>::DpiY(double value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::ISoftwareBitmap)->put_DpiY(value));
}

template <typename D> double consume_Windows_Graphics_Imaging_ISoftwareBitmap<D>::DpiY() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::ISoftwareBitmap)->get_DpiY(&value));
    return value;
}

template <typename D> Windows::Graphics::Imaging::BitmapBuffer consume_Windows_Graphics_Imaging_ISoftwareBitmap<D>::LockBuffer(Windows::Graphics::Imaging::BitmapBufferAccessMode const& mode) const
{
    Windows::Graphics::Imaging::BitmapBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::ISoftwareBitmap)->LockBuffer(get_abi(mode), put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Imaging_ISoftwareBitmap<D>::CopyTo(Windows::Graphics::Imaging::SoftwareBitmap const& bitmap) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::ISoftwareBitmap)->CopyTo(get_abi(bitmap)));
}

template <typename D> void consume_Windows_Graphics_Imaging_ISoftwareBitmap<D>::CopyFromBuffer(Windows::Storage::Streams::IBuffer const& buffer) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::ISoftwareBitmap)->CopyFromBuffer(get_abi(buffer)));
}

template <typename D> void consume_Windows_Graphics_Imaging_ISoftwareBitmap<D>::CopyToBuffer(Windows::Storage::Streams::IBuffer const& buffer) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::ISoftwareBitmap)->CopyToBuffer(get_abi(buffer)));
}

template <typename D> Windows::Graphics::Imaging::SoftwareBitmap consume_Windows_Graphics_Imaging_ISoftwareBitmap<D>::GetReadOnlyView() const
{
    Windows::Graphics::Imaging::SoftwareBitmap value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::ISoftwareBitmap)->GetReadOnlyView(put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::Imaging::SoftwareBitmap consume_Windows_Graphics_Imaging_ISoftwareBitmapFactory<D>::Create(Windows::Graphics::Imaging::BitmapPixelFormat const& format, int32_t width, int32_t height) const
{
    Windows::Graphics::Imaging::SoftwareBitmap value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::ISoftwareBitmapFactory)->Create(get_abi(format), width, height, put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::Imaging::SoftwareBitmap consume_Windows_Graphics_Imaging_ISoftwareBitmapFactory<D>::CreateWithAlpha(Windows::Graphics::Imaging::BitmapPixelFormat const& format, int32_t width, int32_t height, Windows::Graphics::Imaging::BitmapAlphaMode const& alpha) const
{
    Windows::Graphics::Imaging::SoftwareBitmap value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::ISoftwareBitmapFactory)->CreateWithAlpha(get_abi(format), width, height, get_abi(alpha), put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::Imaging::SoftwareBitmap consume_Windows_Graphics_Imaging_ISoftwareBitmapStatics<D>::Copy(Windows::Graphics::Imaging::SoftwareBitmap const& source) const
{
    Windows::Graphics::Imaging::SoftwareBitmap value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::ISoftwareBitmapStatics)->Copy(get_abi(source), put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::Imaging::SoftwareBitmap consume_Windows_Graphics_Imaging_ISoftwareBitmapStatics<D>::Convert(Windows::Graphics::Imaging::SoftwareBitmap const& source, Windows::Graphics::Imaging::BitmapPixelFormat const& format) const
{
    Windows::Graphics::Imaging::SoftwareBitmap value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::ISoftwareBitmapStatics)->Convert(get_abi(source), get_abi(format), put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::Imaging::SoftwareBitmap consume_Windows_Graphics_Imaging_ISoftwareBitmapStatics<D>::Convert(Windows::Graphics::Imaging::SoftwareBitmap const& source, Windows::Graphics::Imaging::BitmapPixelFormat const& format, Windows::Graphics::Imaging::BitmapAlphaMode const& alpha) const
{
    Windows::Graphics::Imaging::SoftwareBitmap value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::ISoftwareBitmapStatics)->ConvertWithAlpha(get_abi(source), get_abi(format), get_abi(alpha), put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::Imaging::SoftwareBitmap consume_Windows_Graphics_Imaging_ISoftwareBitmapStatics<D>::CreateCopyFromBuffer(Windows::Storage::Streams::IBuffer const& source, Windows::Graphics::Imaging::BitmapPixelFormat const& format, int32_t width, int32_t height) const
{
    Windows::Graphics::Imaging::SoftwareBitmap value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::ISoftwareBitmapStatics)->CreateCopyFromBuffer(get_abi(source), get_abi(format), width, height, put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::Imaging::SoftwareBitmap consume_Windows_Graphics_Imaging_ISoftwareBitmapStatics<D>::CreateCopyFromBuffer(Windows::Storage::Streams::IBuffer const& source, Windows::Graphics::Imaging::BitmapPixelFormat const& format, int32_t width, int32_t height, Windows::Graphics::Imaging::BitmapAlphaMode const& alpha) const
{
    Windows::Graphics::Imaging::SoftwareBitmap value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::ISoftwareBitmapStatics)->CreateCopyWithAlphaFromBuffer(get_abi(source), get_abi(format), width, height, get_abi(alpha), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::SoftwareBitmap> consume_Windows_Graphics_Imaging_ISoftwareBitmapStatics<D>::CreateCopyFromSurfaceAsync(Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const& surface) const
{
    Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::SoftwareBitmap> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::ISoftwareBitmapStatics)->CreateCopyFromSurfaceAsync(get_abi(surface), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::SoftwareBitmap> consume_Windows_Graphics_Imaging_ISoftwareBitmapStatics<D>::CreateCopyFromSurfaceAsync(Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const& surface, Windows::Graphics::Imaging::BitmapAlphaMode const& alpha) const
{
    Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::SoftwareBitmap> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Imaging::ISoftwareBitmapStatics)->CreateCopyWithAlphaFromSurfaceAsync(get_abi(surface), get_abi(alpha), put_abi(value)));
    return value;
}

template <typename D>
struct produce<D, Windows::Graphics::Imaging::IBitmapBuffer> : produce_base<D, Windows::Graphics::Imaging::IBitmapBuffer>
{
    int32_t WINRT_CALL GetPlaneCount(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetPlaneCount, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().GetPlaneCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetPlaneDescription(int32_t index, struct struct_Windows_Graphics_Imaging_BitmapPlaneDescription* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetPlaneDescription, WINRT_WRAP(Windows::Graphics::Imaging::BitmapPlaneDescription), int32_t);
            *value = detach_from<Windows::Graphics::Imaging::BitmapPlaneDescription>(this->shim().GetPlaneDescription(index));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Imaging::IBitmapCodecInformation> : produce_base<D, Windows::Graphics::Imaging::IBitmapCodecInformation>
{
    int32_t WINRT_CALL get_CodecId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CodecId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().CodecId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FileExtensions(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FileExtensions, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().FileExtensions());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FriendlyName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FriendlyName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().FriendlyName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MimeTypes(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MimeTypes, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().MimeTypes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Imaging::IBitmapDecoder> : produce_base<D, Windows::Graphics::Imaging::IBitmapDecoder>
{
    int32_t WINRT_CALL get_BitmapContainerProperties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BitmapContainerProperties, WINRT_WRAP(Windows::Graphics::Imaging::BitmapPropertiesView));
            *value = detach_from<Windows::Graphics::Imaging::BitmapPropertiesView>(this->shim().BitmapContainerProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DecoderInformation(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DecoderInformation, WINRT_WRAP(Windows::Graphics::Imaging::BitmapCodecInformation));
            *value = detach_from<Windows::Graphics::Imaging::BitmapCodecInformation>(this->shim().DecoderInformation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FrameCount(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FrameCount, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().FrameCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetPreviewAsync(void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetPreviewAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::ImageStream>));
            *asyncInfo = detach_from<Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::ImageStream>>(this->shim().GetPreviewAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetFrameAsync(uint32_t frameIndex, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetFrameAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::BitmapFrame>), uint32_t);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::BitmapFrame>>(this->shim().GetFrameAsync(frameIndex));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Imaging::IBitmapDecoderStatics> : produce_base<D, Windows::Graphics::Imaging::IBitmapDecoderStatics>
{
    int32_t WINRT_CALL get_BmpDecoderId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BmpDecoderId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().BmpDecoderId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_JpegDecoderId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(JpegDecoderId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().JpegDecoderId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PngDecoderId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PngDecoderId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().PngDecoderId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TiffDecoderId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TiffDecoderId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().TiffDecoderId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_GifDecoderId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GifDecoderId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().GifDecoderId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_JpegXRDecoderId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(JpegXRDecoderId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().JpegXRDecoderId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IcoDecoderId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IcoDecoderId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().IcoDecoderId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDecoderInformationEnumerator(void** decoderInformationEnumerator) noexcept final
    {
        try
        {
            *decoderInformationEnumerator = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDecoderInformationEnumerator, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Graphics::Imaging::BitmapCodecInformation>));
            *decoderInformationEnumerator = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Graphics::Imaging::BitmapCodecInformation>>(this->shim().GetDecoderInformationEnumerator());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateAsync(void* stream, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::BitmapDecoder>), Windows::Storage::Streams::IRandomAccessStream const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::BitmapDecoder>>(this->shim().CreateAsync(*reinterpret_cast<Windows::Storage::Streams::IRandomAccessStream const*>(&stream)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithIdAsync(winrt::guid decoderId, void* stream, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::BitmapDecoder>), winrt::guid const, Windows::Storage::Streams::IRandomAccessStream const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::BitmapDecoder>>(this->shim().CreateAsync(*reinterpret_cast<winrt::guid const*>(&decoderId), *reinterpret_cast<Windows::Storage::Streams::IRandomAccessStream const*>(&stream)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Imaging::IBitmapDecoderStatics2> : produce_base<D, Windows::Graphics::Imaging::IBitmapDecoderStatics2>
{
    int32_t WINRT_CALL get_HeifDecoderId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HeifDecoderId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().HeifDecoderId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WebpDecoderId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WebpDecoderId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().WebpDecoderId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Imaging::IBitmapEncoder> : produce_base<D, Windows::Graphics::Imaging::IBitmapEncoder>
{
    int32_t WINRT_CALL get_EncoderInformation(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EncoderInformation, WINRT_WRAP(Windows::Graphics::Imaging::BitmapCodecInformation));
            *value = detach_from<Windows::Graphics::Imaging::BitmapCodecInformation>(this->shim().EncoderInformation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BitmapProperties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BitmapProperties, WINRT_WRAP(Windows::Graphics::Imaging::BitmapProperties));
            *value = detach_from<Windows::Graphics::Imaging::BitmapProperties>(this->shim().BitmapProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BitmapContainerProperties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BitmapContainerProperties, WINRT_WRAP(Windows::Graphics::Imaging::BitmapProperties));
            *value = detach_from<Windows::Graphics::Imaging::BitmapProperties>(this->shim().BitmapContainerProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsThumbnailGenerated(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsThumbnailGenerated, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsThumbnailGenerated());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsThumbnailGenerated(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsThumbnailGenerated, WINRT_WRAP(void), bool);
            this->shim().IsThumbnailGenerated(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_GeneratedThumbnailWidth(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GeneratedThumbnailWidth, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().GeneratedThumbnailWidth());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_GeneratedThumbnailWidth(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GeneratedThumbnailWidth, WINRT_WRAP(void), uint32_t);
            this->shim().GeneratedThumbnailWidth(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_GeneratedThumbnailHeight(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GeneratedThumbnailHeight, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().GeneratedThumbnailHeight());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_GeneratedThumbnailHeight(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GeneratedThumbnailHeight, WINRT_WRAP(void), uint32_t);
            this->shim().GeneratedThumbnailHeight(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BitmapTransform(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BitmapTransform, WINRT_WRAP(Windows::Graphics::Imaging::BitmapTransform));
            *value = detach_from<Windows::Graphics::Imaging::BitmapTransform>(this->shim().BitmapTransform());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetPixelData(Windows::Graphics::Imaging::BitmapPixelFormat pixelFormat, Windows::Graphics::Imaging::BitmapAlphaMode alphaMode, uint32_t width, uint32_t height, double dpiX, double dpiY, uint32_t __pixelsSize, uint8_t* pixels) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetPixelData, WINRT_WRAP(void), Windows::Graphics::Imaging::BitmapPixelFormat const&, Windows::Graphics::Imaging::BitmapAlphaMode const&, uint32_t, uint32_t, double, double, array_view<uint8_t const>);
            this->shim().SetPixelData(*reinterpret_cast<Windows::Graphics::Imaging::BitmapPixelFormat const*>(&pixelFormat), *reinterpret_cast<Windows::Graphics::Imaging::BitmapAlphaMode const*>(&alphaMode), width, height, dpiX, dpiY, array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(pixels), reinterpret_cast<uint8_t const *>(pixels) + __pixelsSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GoToNextFrameAsync(void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GoToNextFrameAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *asyncInfo = detach_from<Windows::Foundation::IAsyncAction>(this->shim().GoToNextFrameAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GoToNextFrameWithEncodingOptionsAsync(void* encodingOptions, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GoToNextFrameAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Foundation::Collections::IIterable<Windows::Foundation::Collections::IKeyValuePair<hstring, Windows::Graphics::Imaging::BitmapTypedValue>> const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncAction>(this->shim().GoToNextFrameAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Foundation::Collections::IKeyValuePair<hstring, Windows::Graphics::Imaging::BitmapTypedValue>> const*>(&encodingOptions)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FlushAsync(void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FlushAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *asyncInfo = detach_from<Windows::Foundation::IAsyncAction>(this->shim().FlushAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Imaging::IBitmapEncoderStatics> : produce_base<D, Windows::Graphics::Imaging::IBitmapEncoderStatics>
{
    int32_t WINRT_CALL get_BmpEncoderId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BmpEncoderId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().BmpEncoderId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_JpegEncoderId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(JpegEncoderId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().JpegEncoderId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PngEncoderId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PngEncoderId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().PngEncoderId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TiffEncoderId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TiffEncoderId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().TiffEncoderId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_GifEncoderId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GifEncoderId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().GifEncoderId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_JpegXREncoderId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(JpegXREncoderId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().JpegXREncoderId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetEncoderInformationEnumerator(void** encoderInformationEnumerator) noexcept final
    {
        try
        {
            *encoderInformationEnumerator = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetEncoderInformationEnumerator, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Graphics::Imaging::BitmapCodecInformation>));
            *encoderInformationEnumerator = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Graphics::Imaging::BitmapCodecInformation>>(this->shim().GetEncoderInformationEnumerator());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateAsync(winrt::guid encoderId, void* stream, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::BitmapEncoder>), winrt::guid const, Windows::Storage::Streams::IRandomAccessStream const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::BitmapEncoder>>(this->shim().CreateAsync(*reinterpret_cast<winrt::guid const*>(&encoderId), *reinterpret_cast<Windows::Storage::Streams::IRandomAccessStream const*>(&stream)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithEncodingOptionsAsync(winrt::guid encoderId, void* stream, void* encodingOptions, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::BitmapEncoder>), winrt::guid const, Windows::Storage::Streams::IRandomAccessStream const, Windows::Foundation::Collections::IIterable<Windows::Foundation::Collections::IKeyValuePair<hstring, Windows::Graphics::Imaging::BitmapTypedValue>> const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::BitmapEncoder>>(this->shim().CreateAsync(*reinterpret_cast<winrt::guid const*>(&encoderId), *reinterpret_cast<Windows::Storage::Streams::IRandomAccessStream const*>(&stream), *reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Foundation::Collections::IKeyValuePair<hstring, Windows::Graphics::Imaging::BitmapTypedValue>> const*>(&encodingOptions)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateForTranscodingAsync(void* stream, void* bitmapDecoder, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateForTranscodingAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::BitmapEncoder>), Windows::Storage::Streams::IRandomAccessStream const, Windows::Graphics::Imaging::BitmapDecoder const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::BitmapEncoder>>(this->shim().CreateForTranscodingAsync(*reinterpret_cast<Windows::Storage::Streams::IRandomAccessStream const*>(&stream), *reinterpret_cast<Windows::Graphics::Imaging::BitmapDecoder const*>(&bitmapDecoder)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateForInPlacePropertyEncodingAsync(void* bitmapDecoder, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateForInPlacePropertyEncodingAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::BitmapEncoder>), Windows::Graphics::Imaging::BitmapDecoder const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::BitmapEncoder>>(this->shim().CreateForInPlacePropertyEncodingAsync(*reinterpret_cast<Windows::Graphics::Imaging::BitmapDecoder const*>(&bitmapDecoder)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Imaging::IBitmapEncoderStatics2> : produce_base<D, Windows::Graphics::Imaging::IBitmapEncoderStatics2>
{
    int32_t WINRT_CALL get_HeifEncoderId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HeifEncoderId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().HeifEncoderId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Imaging::IBitmapEncoderWithSoftwareBitmap> : produce_base<D, Windows::Graphics::Imaging::IBitmapEncoderWithSoftwareBitmap>
{
    int32_t WINRT_CALL SetSoftwareBitmap(void* bitmap) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetSoftwareBitmap, WINRT_WRAP(void), Windows::Graphics::Imaging::SoftwareBitmap const&);
            this->shim().SetSoftwareBitmap(*reinterpret_cast<Windows::Graphics::Imaging::SoftwareBitmap const*>(&bitmap));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Imaging::IBitmapFrame> : produce_base<D, Windows::Graphics::Imaging::IBitmapFrame>
{
    int32_t WINRT_CALL GetThumbnailAsync(void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetThumbnailAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::ImageStream>));
            *asyncInfo = detach_from<Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::ImageStream>>(this->shim().GetThumbnailAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BitmapProperties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BitmapProperties, WINRT_WRAP(Windows::Graphics::Imaging::BitmapPropertiesView));
            *value = detach_from<Windows::Graphics::Imaging::BitmapPropertiesView>(this->shim().BitmapProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BitmapPixelFormat(Windows::Graphics::Imaging::BitmapPixelFormat* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BitmapPixelFormat, WINRT_WRAP(Windows::Graphics::Imaging::BitmapPixelFormat));
            *value = detach_from<Windows::Graphics::Imaging::BitmapPixelFormat>(this->shim().BitmapPixelFormat());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BitmapAlphaMode(Windows::Graphics::Imaging::BitmapAlphaMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BitmapAlphaMode, WINRT_WRAP(Windows::Graphics::Imaging::BitmapAlphaMode));
            *value = detach_from<Windows::Graphics::Imaging::BitmapAlphaMode>(this->shim().BitmapAlphaMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DpiX(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DpiX, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().DpiX());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DpiY(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DpiY, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().DpiY());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PixelWidth(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PixelWidth, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().PixelWidth());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PixelHeight(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PixelHeight, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().PixelHeight());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OrientedPixelWidth(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OrientedPixelWidth, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().OrientedPixelWidth());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OrientedPixelHeight(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OrientedPixelHeight, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().OrientedPixelHeight());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetPixelDataAsync(void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetPixelDataAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::PixelDataProvider>));
            *asyncInfo = detach_from<Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::PixelDataProvider>>(this->shim().GetPixelDataAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetPixelDataTransformedAsync(Windows::Graphics::Imaging::BitmapPixelFormat pixelFormat, Windows::Graphics::Imaging::BitmapAlphaMode alphaMode, void* transform, Windows::Graphics::Imaging::ExifOrientationMode exifOrientationMode, Windows::Graphics::Imaging::ColorManagementMode colorManagementMode, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetPixelDataAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::PixelDataProvider>), Windows::Graphics::Imaging::BitmapPixelFormat const, Windows::Graphics::Imaging::BitmapAlphaMode const, Windows::Graphics::Imaging::BitmapTransform const, Windows::Graphics::Imaging::ExifOrientationMode const, Windows::Graphics::Imaging::ColorManagementMode const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::PixelDataProvider>>(this->shim().GetPixelDataAsync(*reinterpret_cast<Windows::Graphics::Imaging::BitmapPixelFormat const*>(&pixelFormat), *reinterpret_cast<Windows::Graphics::Imaging::BitmapAlphaMode const*>(&alphaMode), *reinterpret_cast<Windows::Graphics::Imaging::BitmapTransform const*>(&transform), *reinterpret_cast<Windows::Graphics::Imaging::ExifOrientationMode const*>(&exifOrientationMode), *reinterpret_cast<Windows::Graphics::Imaging::ColorManagementMode const*>(&colorManagementMode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Imaging::IBitmapFrameWithSoftwareBitmap> : produce_base<D, Windows::Graphics::Imaging::IBitmapFrameWithSoftwareBitmap>
{
    int32_t WINRT_CALL GetSoftwareBitmapAsync(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetSoftwareBitmapAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::SoftwareBitmap>));
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::SoftwareBitmap>>(this->shim().GetSoftwareBitmapAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetSoftwareBitmapConvertedAsync(Windows::Graphics::Imaging::BitmapPixelFormat pixelFormat, Windows::Graphics::Imaging::BitmapAlphaMode alphaMode, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetSoftwareBitmapAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::SoftwareBitmap>), Windows::Graphics::Imaging::BitmapPixelFormat const, Windows::Graphics::Imaging::BitmapAlphaMode const);
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::SoftwareBitmap>>(this->shim().GetSoftwareBitmapAsync(*reinterpret_cast<Windows::Graphics::Imaging::BitmapPixelFormat const*>(&pixelFormat), *reinterpret_cast<Windows::Graphics::Imaging::BitmapAlphaMode const*>(&alphaMode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetSoftwareBitmapTransformedAsync(Windows::Graphics::Imaging::BitmapPixelFormat pixelFormat, Windows::Graphics::Imaging::BitmapAlphaMode alphaMode, void* transform, Windows::Graphics::Imaging::ExifOrientationMode exifOrientationMode, Windows::Graphics::Imaging::ColorManagementMode colorManagementMode, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetSoftwareBitmapAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::SoftwareBitmap>), Windows::Graphics::Imaging::BitmapPixelFormat const, Windows::Graphics::Imaging::BitmapAlphaMode const, Windows::Graphics::Imaging::BitmapTransform const, Windows::Graphics::Imaging::ExifOrientationMode const, Windows::Graphics::Imaging::ColorManagementMode const);
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::SoftwareBitmap>>(this->shim().GetSoftwareBitmapAsync(*reinterpret_cast<Windows::Graphics::Imaging::BitmapPixelFormat const*>(&pixelFormat), *reinterpret_cast<Windows::Graphics::Imaging::BitmapAlphaMode const*>(&alphaMode), *reinterpret_cast<Windows::Graphics::Imaging::BitmapTransform const*>(&transform), *reinterpret_cast<Windows::Graphics::Imaging::ExifOrientationMode const*>(&exifOrientationMode), *reinterpret_cast<Windows::Graphics::Imaging::ColorManagementMode const*>(&colorManagementMode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Imaging::IBitmapProperties> : produce_base<D, Windows::Graphics::Imaging::IBitmapProperties>
{
    int32_t WINRT_CALL SetPropertiesAsync(void* propertiesToSet, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetPropertiesAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Foundation::Collections::IIterable<Windows::Foundation::Collections::IKeyValuePair<hstring, Windows::Graphics::Imaging::BitmapTypedValue>> const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SetPropertiesAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Foundation::Collections::IKeyValuePair<hstring, Windows::Graphics::Imaging::BitmapTypedValue>> const*>(&propertiesToSet)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Imaging::IBitmapPropertiesView> : produce_base<D, Windows::Graphics::Imaging::IBitmapPropertiesView>
{
    int32_t WINRT_CALL GetPropertiesAsync(void* propertiesToRetrieve, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetPropertiesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::BitmapPropertySet>), Windows::Foundation::Collections::IIterable<hstring> const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::BitmapPropertySet>>(this->shim().GetPropertiesAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&propertiesToRetrieve)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Imaging::IBitmapTransform> : produce_base<D, Windows::Graphics::Imaging::IBitmapTransform>
{
    int32_t WINRT_CALL get_ScaledWidth(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScaledWidth, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().ScaledWidth());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ScaledWidth(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScaledWidth, WINRT_WRAP(void), uint32_t);
            this->shim().ScaledWidth(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ScaledHeight(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScaledHeight, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().ScaledHeight());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ScaledHeight(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScaledHeight, WINRT_WRAP(void), uint32_t);
            this->shim().ScaledHeight(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InterpolationMode(Windows::Graphics::Imaging::BitmapInterpolationMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InterpolationMode, WINRT_WRAP(Windows::Graphics::Imaging::BitmapInterpolationMode));
            *value = detach_from<Windows::Graphics::Imaging::BitmapInterpolationMode>(this->shim().InterpolationMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_InterpolationMode(Windows::Graphics::Imaging::BitmapInterpolationMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InterpolationMode, WINRT_WRAP(void), Windows::Graphics::Imaging::BitmapInterpolationMode const&);
            this->shim().InterpolationMode(*reinterpret_cast<Windows::Graphics::Imaging::BitmapInterpolationMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Flip(Windows::Graphics::Imaging::BitmapFlip* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Flip, WINRT_WRAP(Windows::Graphics::Imaging::BitmapFlip));
            *value = detach_from<Windows::Graphics::Imaging::BitmapFlip>(this->shim().Flip());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Flip(Windows::Graphics::Imaging::BitmapFlip value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Flip, WINRT_WRAP(void), Windows::Graphics::Imaging::BitmapFlip const&);
            this->shim().Flip(*reinterpret_cast<Windows::Graphics::Imaging::BitmapFlip const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Rotation(Windows::Graphics::Imaging::BitmapRotation* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Rotation, WINRT_WRAP(Windows::Graphics::Imaging::BitmapRotation));
            *value = detach_from<Windows::Graphics::Imaging::BitmapRotation>(this->shim().Rotation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Rotation(Windows::Graphics::Imaging::BitmapRotation value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Rotation, WINRT_WRAP(void), Windows::Graphics::Imaging::BitmapRotation const&);
            this->shim().Rotation(*reinterpret_cast<Windows::Graphics::Imaging::BitmapRotation const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Bounds(struct struct_Windows_Graphics_Imaging_BitmapBounds* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Bounds, WINRT_WRAP(Windows::Graphics::Imaging::BitmapBounds));
            *value = detach_from<Windows::Graphics::Imaging::BitmapBounds>(this->shim().Bounds());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Bounds(struct struct_Windows_Graphics_Imaging_BitmapBounds value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Bounds, WINRT_WRAP(void), Windows::Graphics::Imaging::BitmapBounds const&);
            this->shim().Bounds(*reinterpret_cast<Windows::Graphics::Imaging::BitmapBounds const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Imaging::IBitmapTypedValue> : produce_base<D, Windows::Graphics::Imaging::IBitmapTypedValue>
{
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

    int32_t WINRT_CALL get_Type(Windows::Foundation::PropertyType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Type, WINRT_WRAP(Windows::Foundation::PropertyType));
            *value = detach_from<Windows::Foundation::PropertyType>(this->shim().Type());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Imaging::IBitmapTypedValueFactory> : produce_base<D, Windows::Graphics::Imaging::IBitmapTypedValueFactory>
{
    int32_t WINRT_CALL Create(void* value, Windows::Foundation::PropertyType type, void** bitmapTypedValue) noexcept final
    {
        try
        {
            *bitmapTypedValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Graphics::Imaging::BitmapTypedValue), Windows::Foundation::IInspectable const&, Windows::Foundation::PropertyType const&);
            *bitmapTypedValue = detach_from<Windows::Graphics::Imaging::BitmapTypedValue>(this->shim().Create(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&value), *reinterpret_cast<Windows::Foundation::PropertyType const*>(&type)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Imaging::IPixelDataProvider> : produce_base<D, Windows::Graphics::Imaging::IPixelDataProvider>
{
    int32_t WINRT_CALL DetachPixelData(uint32_t* __pixelDataSize, uint8_t** pixelData) noexcept final
    {
        try
        {
            *__pixelDataSize = 0;
            *pixelData = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DetachPixelData, WINRT_WRAP(com_array<uint8_t>));
            std::tie(*__pixelDataSize, *pixelData) = detach_abi(this->shim().DetachPixelData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Imaging::ISoftwareBitmap> : produce_base<D, Windows::Graphics::Imaging::ISoftwareBitmap>
{
    int32_t WINRT_CALL get_BitmapPixelFormat(Windows::Graphics::Imaging::BitmapPixelFormat* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BitmapPixelFormat, WINRT_WRAP(Windows::Graphics::Imaging::BitmapPixelFormat));
            *value = detach_from<Windows::Graphics::Imaging::BitmapPixelFormat>(this->shim().BitmapPixelFormat());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BitmapAlphaMode(Windows::Graphics::Imaging::BitmapAlphaMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BitmapAlphaMode, WINRT_WRAP(Windows::Graphics::Imaging::BitmapAlphaMode));
            *value = detach_from<Windows::Graphics::Imaging::BitmapAlphaMode>(this->shim().BitmapAlphaMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PixelWidth(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PixelWidth, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().PixelWidth());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PixelHeight(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PixelHeight, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().PixelHeight());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsReadOnly(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsReadOnly, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsReadOnly());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DpiX(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DpiX, WINRT_WRAP(void), double);
            this->shim().DpiX(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DpiX(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DpiX, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().DpiX());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DpiY(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DpiY, WINRT_WRAP(void), double);
            this->shim().DpiY(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DpiY(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DpiY, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().DpiY());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL LockBuffer(Windows::Graphics::Imaging::BitmapBufferAccessMode mode, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LockBuffer, WINRT_WRAP(Windows::Graphics::Imaging::BitmapBuffer), Windows::Graphics::Imaging::BitmapBufferAccessMode const&);
            *value = detach_from<Windows::Graphics::Imaging::BitmapBuffer>(this->shim().LockBuffer(*reinterpret_cast<Windows::Graphics::Imaging::BitmapBufferAccessMode const*>(&mode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CopyTo(void* bitmap) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CopyTo, WINRT_WRAP(void), Windows::Graphics::Imaging::SoftwareBitmap const&);
            this->shim().CopyTo(*reinterpret_cast<Windows::Graphics::Imaging::SoftwareBitmap const*>(&bitmap));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CopyFromBuffer(void* buffer) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CopyFromBuffer, WINRT_WRAP(void), Windows::Storage::Streams::IBuffer const&);
            this->shim().CopyFromBuffer(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&buffer));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CopyToBuffer(void* buffer) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CopyToBuffer, WINRT_WRAP(void), Windows::Storage::Streams::IBuffer const&);
            this->shim().CopyToBuffer(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&buffer));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetReadOnlyView(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetReadOnlyView, WINRT_WRAP(Windows::Graphics::Imaging::SoftwareBitmap));
            *value = detach_from<Windows::Graphics::Imaging::SoftwareBitmap>(this->shim().GetReadOnlyView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Imaging::ISoftwareBitmapFactory> : produce_base<D, Windows::Graphics::Imaging::ISoftwareBitmapFactory>
{
    int32_t WINRT_CALL Create(Windows::Graphics::Imaging::BitmapPixelFormat format, int32_t width, int32_t height, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Graphics::Imaging::SoftwareBitmap), Windows::Graphics::Imaging::BitmapPixelFormat const&, int32_t, int32_t);
            *value = detach_from<Windows::Graphics::Imaging::SoftwareBitmap>(this->shim().Create(*reinterpret_cast<Windows::Graphics::Imaging::BitmapPixelFormat const*>(&format), width, height));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithAlpha(Windows::Graphics::Imaging::BitmapPixelFormat format, int32_t width, int32_t height, Windows::Graphics::Imaging::BitmapAlphaMode alpha, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithAlpha, WINRT_WRAP(Windows::Graphics::Imaging::SoftwareBitmap), Windows::Graphics::Imaging::BitmapPixelFormat const&, int32_t, int32_t, Windows::Graphics::Imaging::BitmapAlphaMode const&);
            *value = detach_from<Windows::Graphics::Imaging::SoftwareBitmap>(this->shim().CreateWithAlpha(*reinterpret_cast<Windows::Graphics::Imaging::BitmapPixelFormat const*>(&format), width, height, *reinterpret_cast<Windows::Graphics::Imaging::BitmapAlphaMode const*>(&alpha)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Imaging::ISoftwareBitmapStatics> : produce_base<D, Windows::Graphics::Imaging::ISoftwareBitmapStatics>
{
    int32_t WINRT_CALL Copy(void* source, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Copy, WINRT_WRAP(Windows::Graphics::Imaging::SoftwareBitmap), Windows::Graphics::Imaging::SoftwareBitmap const&);
            *value = detach_from<Windows::Graphics::Imaging::SoftwareBitmap>(this->shim().Copy(*reinterpret_cast<Windows::Graphics::Imaging::SoftwareBitmap const*>(&source)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Convert(void* source, Windows::Graphics::Imaging::BitmapPixelFormat format, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Convert, WINRT_WRAP(Windows::Graphics::Imaging::SoftwareBitmap), Windows::Graphics::Imaging::SoftwareBitmap const&, Windows::Graphics::Imaging::BitmapPixelFormat const&);
            *value = detach_from<Windows::Graphics::Imaging::SoftwareBitmap>(this->shim().Convert(*reinterpret_cast<Windows::Graphics::Imaging::SoftwareBitmap const*>(&source), *reinterpret_cast<Windows::Graphics::Imaging::BitmapPixelFormat const*>(&format)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ConvertWithAlpha(void* source, Windows::Graphics::Imaging::BitmapPixelFormat format, Windows::Graphics::Imaging::BitmapAlphaMode alpha, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Convert, WINRT_WRAP(Windows::Graphics::Imaging::SoftwareBitmap), Windows::Graphics::Imaging::SoftwareBitmap const&, Windows::Graphics::Imaging::BitmapPixelFormat const&, Windows::Graphics::Imaging::BitmapAlphaMode const&);
            *value = detach_from<Windows::Graphics::Imaging::SoftwareBitmap>(this->shim().Convert(*reinterpret_cast<Windows::Graphics::Imaging::SoftwareBitmap const*>(&source), *reinterpret_cast<Windows::Graphics::Imaging::BitmapPixelFormat const*>(&format), *reinterpret_cast<Windows::Graphics::Imaging::BitmapAlphaMode const*>(&alpha)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateCopyFromBuffer(void* source, Windows::Graphics::Imaging::BitmapPixelFormat format, int32_t width, int32_t height, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateCopyFromBuffer, WINRT_WRAP(Windows::Graphics::Imaging::SoftwareBitmap), Windows::Storage::Streams::IBuffer const&, Windows::Graphics::Imaging::BitmapPixelFormat const&, int32_t, int32_t);
            *value = detach_from<Windows::Graphics::Imaging::SoftwareBitmap>(this->shim().CreateCopyFromBuffer(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&source), *reinterpret_cast<Windows::Graphics::Imaging::BitmapPixelFormat const*>(&format), width, height));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateCopyWithAlphaFromBuffer(void* source, Windows::Graphics::Imaging::BitmapPixelFormat format, int32_t width, int32_t height, Windows::Graphics::Imaging::BitmapAlphaMode alpha, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateCopyFromBuffer, WINRT_WRAP(Windows::Graphics::Imaging::SoftwareBitmap), Windows::Storage::Streams::IBuffer const&, Windows::Graphics::Imaging::BitmapPixelFormat const&, int32_t, int32_t, Windows::Graphics::Imaging::BitmapAlphaMode const&);
            *value = detach_from<Windows::Graphics::Imaging::SoftwareBitmap>(this->shim().CreateCopyFromBuffer(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&source), *reinterpret_cast<Windows::Graphics::Imaging::BitmapPixelFormat const*>(&format), width, height, *reinterpret_cast<Windows::Graphics::Imaging::BitmapAlphaMode const*>(&alpha)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateCopyFromSurfaceAsync(void* surface, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateCopyFromSurfaceAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::SoftwareBitmap>), Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const);
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::SoftwareBitmap>>(this->shim().CreateCopyFromSurfaceAsync(*reinterpret_cast<Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const*>(&surface)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateCopyWithAlphaFromSurfaceAsync(void* surface, Windows::Graphics::Imaging::BitmapAlphaMode alpha, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateCopyFromSurfaceAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::SoftwareBitmap>), Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const, Windows::Graphics::Imaging::BitmapAlphaMode const);
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::SoftwareBitmap>>(this->shim().CreateCopyFromSurfaceAsync(*reinterpret_cast<Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const*>(&surface), *reinterpret_cast<Windows::Graphics::Imaging::BitmapAlphaMode const*>(&alpha)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Graphics::Imaging {

inline winrt::guid BitmapDecoder::BmpDecoderId()
{
    return impl::call_factory<BitmapDecoder, Windows::Graphics::Imaging::IBitmapDecoderStatics>([&](auto&& f) { return f.BmpDecoderId(); });
}

inline winrt::guid BitmapDecoder::JpegDecoderId()
{
    return impl::call_factory<BitmapDecoder, Windows::Graphics::Imaging::IBitmapDecoderStatics>([&](auto&& f) { return f.JpegDecoderId(); });
}

inline winrt::guid BitmapDecoder::PngDecoderId()
{
    return impl::call_factory<BitmapDecoder, Windows::Graphics::Imaging::IBitmapDecoderStatics>([&](auto&& f) { return f.PngDecoderId(); });
}

inline winrt::guid BitmapDecoder::TiffDecoderId()
{
    return impl::call_factory<BitmapDecoder, Windows::Graphics::Imaging::IBitmapDecoderStatics>([&](auto&& f) { return f.TiffDecoderId(); });
}

inline winrt::guid BitmapDecoder::GifDecoderId()
{
    return impl::call_factory<BitmapDecoder, Windows::Graphics::Imaging::IBitmapDecoderStatics>([&](auto&& f) { return f.GifDecoderId(); });
}

inline winrt::guid BitmapDecoder::JpegXRDecoderId()
{
    return impl::call_factory<BitmapDecoder, Windows::Graphics::Imaging::IBitmapDecoderStatics>([&](auto&& f) { return f.JpegXRDecoderId(); });
}

inline winrt::guid BitmapDecoder::IcoDecoderId()
{
    return impl::call_factory<BitmapDecoder, Windows::Graphics::Imaging::IBitmapDecoderStatics>([&](auto&& f) { return f.IcoDecoderId(); });
}

inline Windows::Foundation::Collections::IVectorView<Windows::Graphics::Imaging::BitmapCodecInformation> BitmapDecoder::GetDecoderInformationEnumerator()
{
    return impl::call_factory<BitmapDecoder, Windows::Graphics::Imaging::IBitmapDecoderStatics>([&](auto&& f) { return f.GetDecoderInformationEnumerator(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::BitmapDecoder> BitmapDecoder::CreateAsync(Windows::Storage::Streams::IRandomAccessStream const& stream)
{
    return impl::call_factory<BitmapDecoder, Windows::Graphics::Imaging::IBitmapDecoderStatics>([&](auto&& f) { return f.CreateAsync(stream); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::BitmapDecoder> BitmapDecoder::CreateAsync(winrt::guid const& decoderId, Windows::Storage::Streams::IRandomAccessStream const& stream)
{
    return impl::call_factory<BitmapDecoder, Windows::Graphics::Imaging::IBitmapDecoderStatics>([&](auto&& f) { return f.CreateAsync(decoderId, stream); });
}

inline winrt::guid BitmapDecoder::HeifDecoderId()
{
    return impl::call_factory<BitmapDecoder, Windows::Graphics::Imaging::IBitmapDecoderStatics2>([&](auto&& f) { return f.HeifDecoderId(); });
}

inline winrt::guid BitmapDecoder::WebpDecoderId()
{
    return impl::call_factory<BitmapDecoder, Windows::Graphics::Imaging::IBitmapDecoderStatics2>([&](auto&& f) { return f.WebpDecoderId(); });
}

inline winrt::guid BitmapEncoder::BmpEncoderId()
{
    return impl::call_factory<BitmapEncoder, Windows::Graphics::Imaging::IBitmapEncoderStatics>([&](auto&& f) { return f.BmpEncoderId(); });
}

inline winrt::guid BitmapEncoder::JpegEncoderId()
{
    return impl::call_factory<BitmapEncoder, Windows::Graphics::Imaging::IBitmapEncoderStatics>([&](auto&& f) { return f.JpegEncoderId(); });
}

inline winrt::guid BitmapEncoder::PngEncoderId()
{
    return impl::call_factory<BitmapEncoder, Windows::Graphics::Imaging::IBitmapEncoderStatics>([&](auto&& f) { return f.PngEncoderId(); });
}

inline winrt::guid BitmapEncoder::TiffEncoderId()
{
    return impl::call_factory<BitmapEncoder, Windows::Graphics::Imaging::IBitmapEncoderStatics>([&](auto&& f) { return f.TiffEncoderId(); });
}

inline winrt::guid BitmapEncoder::GifEncoderId()
{
    return impl::call_factory<BitmapEncoder, Windows::Graphics::Imaging::IBitmapEncoderStatics>([&](auto&& f) { return f.GifEncoderId(); });
}

inline winrt::guid BitmapEncoder::JpegXREncoderId()
{
    return impl::call_factory<BitmapEncoder, Windows::Graphics::Imaging::IBitmapEncoderStatics>([&](auto&& f) { return f.JpegXREncoderId(); });
}

inline Windows::Foundation::Collections::IVectorView<Windows::Graphics::Imaging::BitmapCodecInformation> BitmapEncoder::GetEncoderInformationEnumerator()
{
    return impl::call_factory<BitmapEncoder, Windows::Graphics::Imaging::IBitmapEncoderStatics>([&](auto&& f) { return f.GetEncoderInformationEnumerator(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::BitmapEncoder> BitmapEncoder::CreateAsync(winrt::guid const& encoderId, Windows::Storage::Streams::IRandomAccessStream const& stream)
{
    return impl::call_factory<BitmapEncoder, Windows::Graphics::Imaging::IBitmapEncoderStatics>([&](auto&& f) { return f.CreateAsync(encoderId, stream); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::BitmapEncoder> BitmapEncoder::CreateAsync(winrt::guid const& encoderId, Windows::Storage::Streams::IRandomAccessStream const& stream, param::async_iterable<Windows::Foundation::Collections::IKeyValuePair<hstring, Windows::Graphics::Imaging::BitmapTypedValue>> const& encodingOptions)
{
    return impl::call_factory<BitmapEncoder, Windows::Graphics::Imaging::IBitmapEncoderStatics>([&](auto&& f) { return f.CreateAsync(encoderId, stream, encodingOptions); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::BitmapEncoder> BitmapEncoder::CreateForTranscodingAsync(Windows::Storage::Streams::IRandomAccessStream const& stream, Windows::Graphics::Imaging::BitmapDecoder const& bitmapDecoder)
{
    return impl::call_factory<BitmapEncoder, Windows::Graphics::Imaging::IBitmapEncoderStatics>([&](auto&& f) { return f.CreateForTranscodingAsync(stream, bitmapDecoder); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::BitmapEncoder> BitmapEncoder::CreateForInPlacePropertyEncodingAsync(Windows::Graphics::Imaging::BitmapDecoder const& bitmapDecoder)
{
    return impl::call_factory<BitmapEncoder, Windows::Graphics::Imaging::IBitmapEncoderStatics>([&](auto&& f) { return f.CreateForInPlacePropertyEncodingAsync(bitmapDecoder); });
}

inline winrt::guid BitmapEncoder::HeifEncoderId()
{
    return impl::call_factory<BitmapEncoder, Windows::Graphics::Imaging::IBitmapEncoderStatics2>([&](auto&& f) { return f.HeifEncoderId(); });
}

inline BitmapPropertySet::BitmapPropertySet() :
    BitmapPropertySet(impl::call_factory<BitmapPropertySet>([](auto&& f) { return f.template ActivateInstance<BitmapPropertySet>(); }))
{}

inline BitmapTransform::BitmapTransform() :
    BitmapTransform(impl::call_factory<BitmapTransform>([](auto&& f) { return f.template ActivateInstance<BitmapTransform>(); }))
{}

inline BitmapTypedValue::BitmapTypedValue(Windows::Foundation::IInspectable const& value, Windows::Foundation::PropertyType const& type) :
    BitmapTypedValue(impl::call_factory<BitmapTypedValue, Windows::Graphics::Imaging::IBitmapTypedValueFactory>([&](auto&& f) { return f.Create(value, type); }))
{}

inline SoftwareBitmap::SoftwareBitmap(Windows::Graphics::Imaging::BitmapPixelFormat const& format, int32_t width, int32_t height) :
    SoftwareBitmap(impl::call_factory<SoftwareBitmap, Windows::Graphics::Imaging::ISoftwareBitmapFactory>([&](auto&& f) { return f.Create(format, width, height); }))
{}

inline SoftwareBitmap::SoftwareBitmap(Windows::Graphics::Imaging::BitmapPixelFormat const& format, int32_t width, int32_t height, Windows::Graphics::Imaging::BitmapAlphaMode const& alpha) :
    SoftwareBitmap(impl::call_factory<SoftwareBitmap, Windows::Graphics::Imaging::ISoftwareBitmapFactory>([&](auto&& f) { return f.CreateWithAlpha(format, width, height, alpha); }))
{}

inline Windows::Graphics::Imaging::SoftwareBitmap SoftwareBitmap::Copy(Windows::Graphics::Imaging::SoftwareBitmap const& source)
{
    return impl::call_factory<SoftwareBitmap, Windows::Graphics::Imaging::ISoftwareBitmapStatics>([&](auto&& f) { return f.Copy(source); });
}

inline Windows::Graphics::Imaging::SoftwareBitmap SoftwareBitmap::Convert(Windows::Graphics::Imaging::SoftwareBitmap const& source, Windows::Graphics::Imaging::BitmapPixelFormat const& format)
{
    return impl::call_factory<SoftwareBitmap, Windows::Graphics::Imaging::ISoftwareBitmapStatics>([&](auto&& f) { return f.Convert(source, format); });
}

inline Windows::Graphics::Imaging::SoftwareBitmap SoftwareBitmap::Convert(Windows::Graphics::Imaging::SoftwareBitmap const& source, Windows::Graphics::Imaging::BitmapPixelFormat const& format, Windows::Graphics::Imaging::BitmapAlphaMode const& alpha)
{
    return impl::call_factory<SoftwareBitmap, Windows::Graphics::Imaging::ISoftwareBitmapStatics>([&](auto&& f) { return f.Convert(source, format, alpha); });
}

inline Windows::Graphics::Imaging::SoftwareBitmap SoftwareBitmap::CreateCopyFromBuffer(Windows::Storage::Streams::IBuffer const& source, Windows::Graphics::Imaging::BitmapPixelFormat const& format, int32_t width, int32_t height)
{
    return impl::call_factory<SoftwareBitmap, Windows::Graphics::Imaging::ISoftwareBitmapStatics>([&](auto&& f) { return f.CreateCopyFromBuffer(source, format, width, height); });
}

inline Windows::Graphics::Imaging::SoftwareBitmap SoftwareBitmap::CreateCopyFromBuffer(Windows::Storage::Streams::IBuffer const& source, Windows::Graphics::Imaging::BitmapPixelFormat const& format, int32_t width, int32_t height, Windows::Graphics::Imaging::BitmapAlphaMode const& alpha)
{
    return impl::call_factory<SoftwareBitmap, Windows::Graphics::Imaging::ISoftwareBitmapStatics>([&](auto&& f) { return f.CreateCopyFromBuffer(source, format, width, height, alpha); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::SoftwareBitmap> SoftwareBitmap::CreateCopyFromSurfaceAsync(Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const& surface)
{
    return impl::call_factory<SoftwareBitmap, Windows::Graphics::Imaging::ISoftwareBitmapStatics>([&](auto&& f) { return f.CreateCopyFromSurfaceAsync(surface); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Graphics::Imaging::SoftwareBitmap> SoftwareBitmap::CreateCopyFromSurfaceAsync(Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const& surface, Windows::Graphics::Imaging::BitmapAlphaMode const& alpha)
{
    return impl::call_factory<SoftwareBitmap, Windows::Graphics::Imaging::ISoftwareBitmapStatics>([&](auto&& f) { return f.CreateCopyFromSurfaceAsync(surface, alpha); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Graphics::Imaging::IBitmapBuffer> : winrt::impl::hash_base<winrt::Windows::Graphics::Imaging::IBitmapBuffer> {};
template<> struct hash<winrt::Windows::Graphics::Imaging::IBitmapCodecInformation> : winrt::impl::hash_base<winrt::Windows::Graphics::Imaging::IBitmapCodecInformation> {};
template<> struct hash<winrt::Windows::Graphics::Imaging::IBitmapDecoder> : winrt::impl::hash_base<winrt::Windows::Graphics::Imaging::IBitmapDecoder> {};
template<> struct hash<winrt::Windows::Graphics::Imaging::IBitmapDecoderStatics> : winrt::impl::hash_base<winrt::Windows::Graphics::Imaging::IBitmapDecoderStatics> {};
template<> struct hash<winrt::Windows::Graphics::Imaging::IBitmapDecoderStatics2> : winrt::impl::hash_base<winrt::Windows::Graphics::Imaging::IBitmapDecoderStatics2> {};
template<> struct hash<winrt::Windows::Graphics::Imaging::IBitmapEncoder> : winrt::impl::hash_base<winrt::Windows::Graphics::Imaging::IBitmapEncoder> {};
template<> struct hash<winrt::Windows::Graphics::Imaging::IBitmapEncoderStatics> : winrt::impl::hash_base<winrt::Windows::Graphics::Imaging::IBitmapEncoderStatics> {};
template<> struct hash<winrt::Windows::Graphics::Imaging::IBitmapEncoderStatics2> : winrt::impl::hash_base<winrt::Windows::Graphics::Imaging::IBitmapEncoderStatics2> {};
template<> struct hash<winrt::Windows::Graphics::Imaging::IBitmapEncoderWithSoftwareBitmap> : winrt::impl::hash_base<winrt::Windows::Graphics::Imaging::IBitmapEncoderWithSoftwareBitmap> {};
template<> struct hash<winrt::Windows::Graphics::Imaging::IBitmapFrame> : winrt::impl::hash_base<winrt::Windows::Graphics::Imaging::IBitmapFrame> {};
template<> struct hash<winrt::Windows::Graphics::Imaging::IBitmapFrameWithSoftwareBitmap> : winrt::impl::hash_base<winrt::Windows::Graphics::Imaging::IBitmapFrameWithSoftwareBitmap> {};
template<> struct hash<winrt::Windows::Graphics::Imaging::IBitmapProperties> : winrt::impl::hash_base<winrt::Windows::Graphics::Imaging::IBitmapProperties> {};
template<> struct hash<winrt::Windows::Graphics::Imaging::IBitmapPropertiesView> : winrt::impl::hash_base<winrt::Windows::Graphics::Imaging::IBitmapPropertiesView> {};
template<> struct hash<winrt::Windows::Graphics::Imaging::IBitmapTransform> : winrt::impl::hash_base<winrt::Windows::Graphics::Imaging::IBitmapTransform> {};
template<> struct hash<winrt::Windows::Graphics::Imaging::IBitmapTypedValue> : winrt::impl::hash_base<winrt::Windows::Graphics::Imaging::IBitmapTypedValue> {};
template<> struct hash<winrt::Windows::Graphics::Imaging::IBitmapTypedValueFactory> : winrt::impl::hash_base<winrt::Windows::Graphics::Imaging::IBitmapTypedValueFactory> {};
template<> struct hash<winrt::Windows::Graphics::Imaging::IPixelDataProvider> : winrt::impl::hash_base<winrt::Windows::Graphics::Imaging::IPixelDataProvider> {};
template<> struct hash<winrt::Windows::Graphics::Imaging::ISoftwareBitmap> : winrt::impl::hash_base<winrt::Windows::Graphics::Imaging::ISoftwareBitmap> {};
template<> struct hash<winrt::Windows::Graphics::Imaging::ISoftwareBitmapFactory> : winrt::impl::hash_base<winrt::Windows::Graphics::Imaging::ISoftwareBitmapFactory> {};
template<> struct hash<winrt::Windows::Graphics::Imaging::ISoftwareBitmapStatics> : winrt::impl::hash_base<winrt::Windows::Graphics::Imaging::ISoftwareBitmapStatics> {};
template<> struct hash<winrt::Windows::Graphics::Imaging::BitmapBuffer> : winrt::impl::hash_base<winrt::Windows::Graphics::Imaging::BitmapBuffer> {};
template<> struct hash<winrt::Windows::Graphics::Imaging::BitmapCodecInformation> : winrt::impl::hash_base<winrt::Windows::Graphics::Imaging::BitmapCodecInformation> {};
template<> struct hash<winrt::Windows::Graphics::Imaging::BitmapDecoder> : winrt::impl::hash_base<winrt::Windows::Graphics::Imaging::BitmapDecoder> {};
template<> struct hash<winrt::Windows::Graphics::Imaging::BitmapEncoder> : winrt::impl::hash_base<winrt::Windows::Graphics::Imaging::BitmapEncoder> {};
template<> struct hash<winrt::Windows::Graphics::Imaging::BitmapFrame> : winrt::impl::hash_base<winrt::Windows::Graphics::Imaging::BitmapFrame> {};
template<> struct hash<winrt::Windows::Graphics::Imaging::BitmapProperties> : winrt::impl::hash_base<winrt::Windows::Graphics::Imaging::BitmapProperties> {};
template<> struct hash<winrt::Windows::Graphics::Imaging::BitmapPropertiesView> : winrt::impl::hash_base<winrt::Windows::Graphics::Imaging::BitmapPropertiesView> {};
template<> struct hash<winrt::Windows::Graphics::Imaging::BitmapPropertySet> : winrt::impl::hash_base<winrt::Windows::Graphics::Imaging::BitmapPropertySet> {};
template<> struct hash<winrt::Windows::Graphics::Imaging::BitmapTransform> : winrt::impl::hash_base<winrt::Windows::Graphics::Imaging::BitmapTransform> {};
template<> struct hash<winrt::Windows::Graphics::Imaging::BitmapTypedValue> : winrt::impl::hash_base<winrt::Windows::Graphics::Imaging::BitmapTypedValue> {};
template<> struct hash<winrt::Windows::Graphics::Imaging::ImageStream> : winrt::impl::hash_base<winrt::Windows::Graphics::Imaging::ImageStream> {};
template<> struct hash<winrt::Windows::Graphics::Imaging::PixelDataProvider> : winrt::impl::hash_base<winrt::Windows::Graphics::Imaging::PixelDataProvider> {};
template<> struct hash<winrt::Windows::Graphics::Imaging::SoftwareBitmap> : winrt::impl::hash_base<winrt::Windows::Graphics::Imaging::SoftwareBitmap> {};

}
