// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.ApplicationModel.Background.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Graphics.Imaging.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.UI.Xaml.2.h"
#include "winrt/impl/Windows.UI.Xaml.Media.2.h"
#include "winrt/impl/Windows.UI.Xaml.Media.Imaging.2.h"
#include "winrt/Windows.UI.Xaml.Media.h"

namespace winrt::impl {

template <typename D> Windows::UI::Xaml::Media::Imaging::BitmapCreateOptions consume_Windows_UI_Xaml_Media_Imaging_IBitmapImage<D>::CreateOptions() const
{
    Windows::UI::Xaml::Media::Imaging::BitmapCreateOptions value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::IBitmapImage)->get_CreateOptions(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Imaging_IBitmapImage<D>::CreateOptions(Windows::UI::Xaml::Media::Imaging::BitmapCreateOptions const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::IBitmapImage)->put_CreateOptions(get_abi(value)));
}

template <typename D> Windows::Foundation::Uri consume_Windows_UI_Xaml_Media_Imaging_IBitmapImage<D>::UriSource() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::IBitmapImage)->get_UriSource(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Imaging_IBitmapImage<D>::UriSource(Windows::Foundation::Uri const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::IBitmapImage)->put_UriSource(get_abi(value)));
}

template <typename D> int32_t consume_Windows_UI_Xaml_Media_Imaging_IBitmapImage<D>::DecodePixelWidth() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::IBitmapImage)->get_DecodePixelWidth(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Imaging_IBitmapImage<D>::DecodePixelWidth(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::IBitmapImage)->put_DecodePixelWidth(value));
}

template <typename D> int32_t consume_Windows_UI_Xaml_Media_Imaging_IBitmapImage<D>::DecodePixelHeight() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::IBitmapImage)->get_DecodePixelHeight(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Imaging_IBitmapImage<D>::DecodePixelHeight(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::IBitmapImage)->put_DecodePixelHeight(value));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Media_Imaging_IBitmapImage<D>::DownloadProgress(Windows::UI::Xaml::Media::Imaging::DownloadProgressEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::IBitmapImage)->add_DownloadProgress(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Media_Imaging_IBitmapImage<D>::DownloadProgress_revoker consume_Windows_UI_Xaml_Media_Imaging_IBitmapImage<D>::DownloadProgress(auto_revoke_t, Windows::UI::Xaml::Media::Imaging::DownloadProgressEventHandler const& handler) const
{
    return impl::make_event_revoker<D, DownloadProgress_revoker>(this, DownloadProgress(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Media_Imaging_IBitmapImage<D>::DownloadProgress(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::IBitmapImage)->remove_DownloadProgress(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Media_Imaging_IBitmapImage<D>::ImageOpened(Windows::UI::Xaml::RoutedEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::IBitmapImage)->add_ImageOpened(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Media_Imaging_IBitmapImage<D>::ImageOpened_revoker consume_Windows_UI_Xaml_Media_Imaging_IBitmapImage<D>::ImageOpened(auto_revoke_t, Windows::UI::Xaml::RoutedEventHandler const& handler) const
{
    return impl::make_event_revoker<D, ImageOpened_revoker>(this, ImageOpened(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Media_Imaging_IBitmapImage<D>::ImageOpened(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::IBitmapImage)->remove_ImageOpened(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Media_Imaging_IBitmapImage<D>::ImageFailed(Windows::UI::Xaml::ExceptionRoutedEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::IBitmapImage)->add_ImageFailed(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Media_Imaging_IBitmapImage<D>::ImageFailed_revoker consume_Windows_UI_Xaml_Media_Imaging_IBitmapImage<D>::ImageFailed(auto_revoke_t, Windows::UI::Xaml::ExceptionRoutedEventHandler const& handler) const
{
    return impl::make_event_revoker<D, ImageFailed_revoker>(this, ImageFailed(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Media_Imaging_IBitmapImage<D>::ImageFailed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::IBitmapImage)->remove_ImageFailed(get_abi(token)));
}

template <typename D> Windows::UI::Xaml::Media::Imaging::DecodePixelType consume_Windows_UI_Xaml_Media_Imaging_IBitmapImage2<D>::DecodePixelType() const
{
    Windows::UI::Xaml::Media::Imaging::DecodePixelType value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::IBitmapImage2)->get_DecodePixelType(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Imaging_IBitmapImage2<D>::DecodePixelType(Windows::UI::Xaml::Media::Imaging::DecodePixelType const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::IBitmapImage2)->put_DecodePixelType(get_abi(value)));
}

template <typename D> bool consume_Windows_UI_Xaml_Media_Imaging_IBitmapImage3<D>::IsAnimatedBitmap() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::IBitmapImage3)->get_IsAnimatedBitmap(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Media_Imaging_IBitmapImage3<D>::IsPlaying() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::IBitmapImage3)->get_IsPlaying(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Media_Imaging_IBitmapImage3<D>::AutoPlay() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::IBitmapImage3)->get_AutoPlay(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Imaging_IBitmapImage3<D>::AutoPlay(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::IBitmapImage3)->put_AutoPlay(value));
}

template <typename D> void consume_Windows_UI_Xaml_Media_Imaging_IBitmapImage3<D>::Play() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::IBitmapImage3)->Play());
}

template <typename D> void consume_Windows_UI_Xaml_Media_Imaging_IBitmapImage3<D>::Stop() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::IBitmapImage3)->Stop());
}

template <typename D> Windows::UI::Xaml::Media::Imaging::BitmapImage consume_Windows_UI_Xaml_Media_Imaging_IBitmapImageFactory<D>::CreateInstanceWithUriSource(Windows::Foundation::Uri const& uriSource) const
{
    Windows::UI::Xaml::Media::Imaging::BitmapImage value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::IBitmapImageFactory)->CreateInstanceWithUriSource(get_abi(uriSource), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Imaging_IBitmapImageStatics<D>::CreateOptionsProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::IBitmapImageStatics)->get_CreateOptionsProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Imaging_IBitmapImageStatics<D>::UriSourceProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::IBitmapImageStatics)->get_UriSourceProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Imaging_IBitmapImageStatics<D>::DecodePixelWidthProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::IBitmapImageStatics)->get_DecodePixelWidthProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Imaging_IBitmapImageStatics<D>::DecodePixelHeightProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::IBitmapImageStatics)->get_DecodePixelHeightProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Imaging_IBitmapImageStatics2<D>::DecodePixelTypeProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::IBitmapImageStatics2)->get_DecodePixelTypeProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Imaging_IBitmapImageStatics3<D>::IsAnimatedBitmapProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::IBitmapImageStatics3)->get_IsAnimatedBitmapProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Imaging_IBitmapImageStatics3<D>::IsPlayingProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::IBitmapImageStatics3)->get_IsPlayingProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Imaging_IBitmapImageStatics3<D>::AutoPlayProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::IBitmapImageStatics3)->get_AutoPlayProperty(put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_UI_Xaml_Media_Imaging_IBitmapSource<D>::PixelWidth() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::IBitmapSource)->get_PixelWidth(&value));
    return value;
}

template <typename D> int32_t consume_Windows_UI_Xaml_Media_Imaging_IBitmapSource<D>::PixelHeight() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::IBitmapSource)->get_PixelHeight(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Imaging_IBitmapSource<D>::SetSource(Windows::Storage::Streams::IRandomAccessStream const& streamSource) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::IBitmapSource)->SetSource(get_abi(streamSource)));
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_UI_Xaml_Media_Imaging_IBitmapSource<D>::SetSourceAsync(Windows::Storage::Streams::IRandomAccessStream const& streamSource) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::IBitmapSource)->SetSourceAsync(get_abi(streamSource), put_abi(operation)));
    return operation;
}

template <typename D> Windows::UI::Xaml::Media::Imaging::BitmapSource consume_Windows_UI_Xaml_Media_Imaging_IBitmapSourceFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Media::Imaging::BitmapSource value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::IBitmapSourceFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Imaging_IBitmapSourceStatics<D>::PixelWidthProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::IBitmapSourceStatics)->get_PixelWidthProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Imaging_IBitmapSourceStatics<D>::PixelHeightProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::IBitmapSourceStatics)->get_PixelHeightProperty(put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_UI_Xaml_Media_Imaging_IDownloadProgressEventArgs<D>::Progress() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::IDownloadProgressEventArgs)->get_Progress(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Imaging_IDownloadProgressEventArgs<D>::Progress(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::IDownloadProgressEventArgs)->put_Progress(value));
}

template <typename D> int32_t consume_Windows_UI_Xaml_Media_Imaging_IRenderTargetBitmap<D>::PixelWidth() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::IRenderTargetBitmap)->get_PixelWidth(&value));
    return value;
}

template <typename D> int32_t consume_Windows_UI_Xaml_Media_Imaging_IRenderTargetBitmap<D>::PixelHeight() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::IRenderTargetBitmap)->get_PixelHeight(&value));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_UI_Xaml_Media_Imaging_IRenderTargetBitmap<D>::RenderAsync(Windows::UI::Xaml::UIElement const& element) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::IRenderTargetBitmap)->RenderAsync(get_abi(element), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_UI_Xaml_Media_Imaging_IRenderTargetBitmap<D>::RenderAsync(Windows::UI::Xaml::UIElement const& element, int32_t scaledWidth, int32_t scaledHeight) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::IRenderTargetBitmap)->RenderToSizeAsync(get_abi(element), scaledWidth, scaledHeight, put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer> consume_Windows_UI_Xaml_Media_Imaging_IRenderTargetBitmap<D>::GetPixelsAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::IRenderTargetBitmap)->GetPixelsAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Imaging_IRenderTargetBitmapStatics<D>::PixelWidthProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::IRenderTargetBitmapStatics)->get_PixelWidthProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Imaging_IRenderTargetBitmapStatics<D>::PixelHeightProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::IRenderTargetBitmapStatics)->get_PixelHeightProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_UI_Xaml_Media_Imaging_ISoftwareBitmapSource<D>::SetBitmapAsync(Windows::Graphics::Imaging::SoftwareBitmap const& softwareBitmap) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::ISoftwareBitmapSource)->SetBitmapAsync(get_abi(softwareBitmap), put_abi(operation)));
    return operation;
}

template <typename D> Windows::UI::Xaml::Media::Imaging::SurfaceImageSource consume_Windows_UI_Xaml_Media_Imaging_ISurfaceImageSourceFactory<D>::CreateInstanceWithDimensions(int32_t pixelWidth, int32_t pixelHeight, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Media::Imaging::SurfaceImageSource value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::ISurfaceImageSourceFactory)->CreateInstanceWithDimensions(pixelWidth, pixelHeight, get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Media::Imaging::SurfaceImageSource consume_Windows_UI_Xaml_Media_Imaging_ISurfaceImageSourceFactory<D>::CreateInstanceWithDimensionsAndOpacity(int32_t pixelWidth, int32_t pixelHeight, bool isOpaque, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Media::Imaging::SurfaceImageSource value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::ISurfaceImageSourceFactory)->CreateInstanceWithDimensionsAndOpacity(pixelWidth, pixelHeight, isOpaque, get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Uri consume_Windows_UI_Xaml_Media_Imaging_ISvgImageSource<D>::UriSource() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::ISvgImageSource)->get_UriSource(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Imaging_ISvgImageSource<D>::UriSource(Windows::Foundation::Uri const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::ISvgImageSource)->put_UriSource(get_abi(value)));
}

template <typename D> double consume_Windows_UI_Xaml_Media_Imaging_ISvgImageSource<D>::RasterizePixelWidth() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::ISvgImageSource)->get_RasterizePixelWidth(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Imaging_ISvgImageSource<D>::RasterizePixelWidth(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::ISvgImageSource)->put_RasterizePixelWidth(value));
}

template <typename D> double consume_Windows_UI_Xaml_Media_Imaging_ISvgImageSource<D>::RasterizePixelHeight() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::ISvgImageSource)->get_RasterizePixelHeight(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Imaging_ISvgImageSource<D>::RasterizePixelHeight(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::ISvgImageSource)->put_RasterizePixelHeight(value));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Media_Imaging_ISvgImageSource<D>::Opened(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Media::Imaging::SvgImageSource, Windows::UI::Xaml::Media::Imaging::SvgImageSourceOpenedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::ISvgImageSource)->add_Opened(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Media_Imaging_ISvgImageSource<D>::Opened_revoker consume_Windows_UI_Xaml_Media_Imaging_ISvgImageSource<D>::Opened(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Media::Imaging::SvgImageSource, Windows::UI::Xaml::Media::Imaging::SvgImageSourceOpenedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Opened_revoker>(this, Opened(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Media_Imaging_ISvgImageSource<D>::Opened(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::ISvgImageSource)->remove_Opened(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Media_Imaging_ISvgImageSource<D>::OpenFailed(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Media::Imaging::SvgImageSource, Windows::UI::Xaml::Media::Imaging::SvgImageSourceFailedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::ISvgImageSource)->add_OpenFailed(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Media_Imaging_ISvgImageSource<D>::OpenFailed_revoker consume_Windows_UI_Xaml_Media_Imaging_ISvgImageSource<D>::OpenFailed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Media::Imaging::SvgImageSource, Windows::UI::Xaml::Media::Imaging::SvgImageSourceFailedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, OpenFailed_revoker>(this, OpenFailed(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Media_Imaging_ISvgImageSource<D>::OpenFailed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::ISvgImageSource)->remove_OpenFailed(get_abi(token)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::UI::Xaml::Media::Imaging::SvgImageSourceLoadStatus> consume_Windows_UI_Xaml_Media_Imaging_ISvgImageSource<D>::SetSourceAsync(Windows::Storage::Streams::IRandomAccessStream const& streamSource) const
{
    Windows::Foundation::IAsyncOperation<Windows::UI::Xaml::Media::Imaging::SvgImageSourceLoadStatus> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::ISvgImageSource)->SetSourceAsync(get_abi(streamSource), put_abi(operation)));
    return operation;
}

template <typename D> Windows::UI::Xaml::Media::Imaging::SvgImageSource consume_Windows_UI_Xaml_Media_Imaging_ISvgImageSourceFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Media::Imaging::SvgImageSource value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::ISvgImageSourceFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Media::Imaging::SvgImageSource consume_Windows_UI_Xaml_Media_Imaging_ISvgImageSourceFactory<D>::CreateInstanceWithUriSource(Windows::Foundation::Uri const& uriSource, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Media::Imaging::SvgImageSource value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::ISvgImageSourceFactory)->CreateInstanceWithUriSource(get_abi(uriSource), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Media::Imaging::SvgImageSourceLoadStatus consume_Windows_UI_Xaml_Media_Imaging_ISvgImageSourceFailedEventArgs<D>::Status() const
{
    Windows::UI::Xaml::Media::Imaging::SvgImageSourceLoadStatus value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::ISvgImageSourceFailedEventArgs)->get_Status(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Imaging_ISvgImageSourceStatics<D>::UriSourceProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::ISvgImageSourceStatics)->get_UriSourceProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Imaging_ISvgImageSourceStatics<D>::RasterizePixelWidthProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::ISvgImageSourceStatics)->get_RasterizePixelWidthProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Media_Imaging_ISvgImageSourceStatics<D>::RasterizePixelHeightProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::ISvgImageSourceStatics)->get_RasterizePixelHeightProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Media::Imaging::VirtualSurfaceImageSource consume_Windows_UI_Xaml_Media_Imaging_IVirtualSurfaceImageSourceFactory<D>::CreateInstanceWithDimensions(int32_t pixelWidth, int32_t pixelHeight) const
{
    Windows::UI::Xaml::Media::Imaging::VirtualSurfaceImageSource value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::IVirtualSurfaceImageSourceFactory)->CreateInstanceWithDimensions(pixelWidth, pixelHeight, put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Media::Imaging::VirtualSurfaceImageSource consume_Windows_UI_Xaml_Media_Imaging_IVirtualSurfaceImageSourceFactory<D>::CreateInstanceWithDimensionsAndOpacity(int32_t pixelWidth, int32_t pixelHeight, bool isOpaque) const
{
    Windows::UI::Xaml::Media::Imaging::VirtualSurfaceImageSource value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::IVirtualSurfaceImageSourceFactory)->CreateInstanceWithDimensionsAndOpacity(pixelWidth, pixelHeight, isOpaque, put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_UI_Xaml_Media_Imaging_IWriteableBitmap<D>::PixelBuffer() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::IWriteableBitmap)->get_PixelBuffer(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Imaging_IWriteableBitmap<D>::Invalidate() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::IWriteableBitmap)->Invalidate());
}

template <typename D> Windows::UI::Xaml::Media::Imaging::WriteableBitmap consume_Windows_UI_Xaml_Media_Imaging_IWriteableBitmapFactory<D>::CreateInstanceWithDimensions(int32_t pixelWidth, int32_t pixelHeight) const
{
    Windows::UI::Xaml::Media::Imaging::WriteableBitmap value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::IWriteableBitmapFactory)->CreateInstanceWithDimensions(pixelWidth, pixelHeight, put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Media::Imaging::XamlRenderingBackgroundTask consume_Windows_UI_Xaml_Media_Imaging_IXamlRenderingBackgroundTaskFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Media::Imaging::XamlRenderingBackgroundTask value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::IXamlRenderingBackgroundTaskFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Media_Imaging_IXamlRenderingBackgroundTaskOverrides<D>::OnRun(Windows::ApplicationModel::Background::IBackgroundTaskInstance const& taskInstance) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Media::Imaging::IXamlRenderingBackgroundTaskOverrides)->OnRun(get_abi(taskInstance)));
}

template <> struct delegate<Windows::UI::Xaml::Media::Imaging::DownloadProgressEventHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::UI::Xaml::Media::Imaging::DownloadProgressEventHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::UI::Xaml::Media::Imaging::DownloadProgressEventHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* sender, void* e) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<Windows::UI::Xaml::Media::Imaging::DownloadProgressEventArgs const*>(&e));
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
struct produce<D, Windows::UI::Xaml::Media::Imaging::IBitmapImage> : produce_base<D, Windows::UI::Xaml::Media::Imaging::IBitmapImage>
{
    int32_t WINRT_CALL get_CreateOptions(Windows::UI::Xaml::Media::Imaging::BitmapCreateOptions* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateOptions, WINRT_WRAP(Windows::UI::Xaml::Media::Imaging::BitmapCreateOptions));
            *value = detach_from<Windows::UI::Xaml::Media::Imaging::BitmapCreateOptions>(this->shim().CreateOptions());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CreateOptions(Windows::UI::Xaml::Media::Imaging::BitmapCreateOptions value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateOptions, WINRT_WRAP(void), Windows::UI::Xaml::Media::Imaging::BitmapCreateOptions const&);
            this->shim().CreateOptions(*reinterpret_cast<Windows::UI::Xaml::Media::Imaging::BitmapCreateOptions const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UriSource(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UriSource, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().UriSource());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_UriSource(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UriSource, WINRT_WRAP(void), Windows::Foundation::Uri const&);
            this->shim().UriSource(*reinterpret_cast<Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DecodePixelWidth(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DecodePixelWidth, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().DecodePixelWidth());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DecodePixelWidth(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DecodePixelWidth, WINRT_WRAP(void), int32_t);
            this->shim().DecodePixelWidth(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DecodePixelHeight(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DecodePixelHeight, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().DecodePixelHeight());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DecodePixelHeight(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DecodePixelHeight, WINRT_WRAP(void), int32_t);
            this->shim().DecodePixelHeight(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_DownloadProgress(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DownloadProgress, WINRT_WRAP(winrt::event_token), Windows::UI::Xaml::Media::Imaging::DownloadProgressEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().DownloadProgress(*reinterpret_cast<Windows::UI::Xaml::Media::Imaging::DownloadProgressEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_DownloadProgress(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(DownloadProgress, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().DownloadProgress(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_ImageOpened(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ImageOpened, WINRT_WRAP(winrt::event_token), Windows::UI::Xaml::RoutedEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().ImageOpened(*reinterpret_cast<Windows::UI::Xaml::RoutedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ImageOpened(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ImageOpened, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ImageOpened(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_ImageFailed(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ImageFailed, WINRT_WRAP(winrt::event_token), Windows::UI::Xaml::ExceptionRoutedEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().ImageFailed(*reinterpret_cast<Windows::UI::Xaml::ExceptionRoutedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ImageFailed(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ImageFailed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ImageFailed(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Imaging::IBitmapImage2> : produce_base<D, Windows::UI::Xaml::Media::Imaging::IBitmapImage2>
{
    int32_t WINRT_CALL get_DecodePixelType(Windows::UI::Xaml::Media::Imaging::DecodePixelType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DecodePixelType, WINRT_WRAP(Windows::UI::Xaml::Media::Imaging::DecodePixelType));
            *value = detach_from<Windows::UI::Xaml::Media::Imaging::DecodePixelType>(this->shim().DecodePixelType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DecodePixelType(Windows::UI::Xaml::Media::Imaging::DecodePixelType value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DecodePixelType, WINRT_WRAP(void), Windows::UI::Xaml::Media::Imaging::DecodePixelType const&);
            this->shim().DecodePixelType(*reinterpret_cast<Windows::UI::Xaml::Media::Imaging::DecodePixelType const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Imaging::IBitmapImage3> : produce_base<D, Windows::UI::Xaml::Media::Imaging::IBitmapImage3>
{
    int32_t WINRT_CALL get_IsAnimatedBitmap(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsAnimatedBitmap, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsAnimatedBitmap());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsPlaying(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsPlaying, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsPlaying());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AutoPlay(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AutoPlay, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AutoPlay());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AutoPlay(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AutoPlay, WINRT_WRAP(void), bool);
            this->shim().AutoPlay(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Play() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Play, WINRT_WRAP(void));
            this->shim().Play();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Stop() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Stop, WINRT_WRAP(void));
            this->shim().Stop();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Imaging::IBitmapImageFactory> : produce_base<D, Windows::UI::Xaml::Media::Imaging::IBitmapImageFactory>
{
    int32_t WINRT_CALL CreateInstanceWithUriSource(void* uriSource, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInstanceWithUriSource, WINRT_WRAP(Windows::UI::Xaml::Media::Imaging::BitmapImage), Windows::Foundation::Uri const&);
            *value = detach_from<Windows::UI::Xaml::Media::Imaging::BitmapImage>(this->shim().CreateInstanceWithUriSource(*reinterpret_cast<Windows::Foundation::Uri const*>(&uriSource)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Imaging::IBitmapImageStatics> : produce_base<D, Windows::UI::Xaml::Media::Imaging::IBitmapImageStatics>
{
    int32_t WINRT_CALL get_CreateOptionsProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateOptionsProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().CreateOptionsProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UriSourceProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UriSourceProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().UriSourceProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DecodePixelWidthProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DecodePixelWidthProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().DecodePixelWidthProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DecodePixelHeightProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DecodePixelHeightProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().DecodePixelHeightProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Imaging::IBitmapImageStatics2> : produce_base<D, Windows::UI::Xaml::Media::Imaging::IBitmapImageStatics2>
{
    int32_t WINRT_CALL get_DecodePixelTypeProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DecodePixelTypeProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().DecodePixelTypeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Imaging::IBitmapImageStatics3> : produce_base<D, Windows::UI::Xaml::Media::Imaging::IBitmapImageStatics3>
{
    int32_t WINRT_CALL get_IsAnimatedBitmapProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsAnimatedBitmapProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().IsAnimatedBitmapProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsPlayingProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsPlayingProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().IsPlayingProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AutoPlayProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AutoPlayProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().AutoPlayProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Imaging::IBitmapSource> : produce_base<D, Windows::UI::Xaml::Media::Imaging::IBitmapSource>
{
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

    int32_t WINRT_CALL SetSource(void* streamSource) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetSource, WINRT_WRAP(void), Windows::Storage::Streams::IRandomAccessStream const&);
            this->shim().SetSource(*reinterpret_cast<Windows::Storage::Streams::IRandomAccessStream const*>(&streamSource));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetSourceAsync(void* streamSource, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetSourceAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Storage::Streams::IRandomAccessStream const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SetSourceAsync(*reinterpret_cast<Windows::Storage::Streams::IRandomAccessStream const*>(&streamSource)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Imaging::IBitmapSourceFactory> : produce_base<D, Windows::UI::Xaml::Media::Imaging::IBitmapSourceFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Media::Imaging::BitmapSource), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Media::Imaging::BitmapSource>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Imaging::IBitmapSourceStatics> : produce_base<D, Windows::UI::Xaml::Media::Imaging::IBitmapSourceStatics>
{
    int32_t WINRT_CALL get_PixelWidthProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PixelWidthProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().PixelWidthProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PixelHeightProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PixelHeightProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().PixelHeightProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Imaging::IDownloadProgressEventArgs> : produce_base<D, Windows::UI::Xaml::Media::Imaging::IDownloadProgressEventArgs>
{
    int32_t WINRT_CALL get_Progress(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Progress, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().Progress());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Progress(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Progress, WINRT_WRAP(void), int32_t);
            this->shim().Progress(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Imaging::IRenderTargetBitmap> : produce_base<D, Windows::UI::Xaml::Media::Imaging::IRenderTargetBitmap>
{
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

    int32_t WINRT_CALL RenderAsync(void* element, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RenderAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::UI::Xaml::UIElement const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().RenderAsync(*reinterpret_cast<Windows::UI::Xaml::UIElement const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RenderToSizeAsync(void* element, int32_t scaledWidth, int32_t scaledHeight, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RenderAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::UI::Xaml::UIElement const, int32_t, int32_t);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().RenderAsync(*reinterpret_cast<Windows::UI::Xaml::UIElement const*>(&element), scaledWidth, scaledHeight));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetPixelsAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetPixelsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer>>(this->shim().GetPixelsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Imaging::IRenderTargetBitmapStatics> : produce_base<D, Windows::UI::Xaml::Media::Imaging::IRenderTargetBitmapStatics>
{
    int32_t WINRT_CALL get_PixelWidthProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PixelWidthProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().PixelWidthProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PixelHeightProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PixelHeightProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().PixelHeightProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Imaging::ISoftwareBitmapSource> : produce_base<D, Windows::UI::Xaml::Media::Imaging::ISoftwareBitmapSource>
{
    int32_t WINRT_CALL SetBitmapAsync(void* softwareBitmap, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetBitmapAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Graphics::Imaging::SoftwareBitmap const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SetBitmapAsync(*reinterpret_cast<Windows::Graphics::Imaging::SoftwareBitmap const*>(&softwareBitmap)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Imaging::ISurfaceImageSource> : produce_base<D, Windows::UI::Xaml::Media::Imaging::ISurfaceImageSource>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Imaging::ISurfaceImageSourceFactory> : produce_base<D, Windows::UI::Xaml::Media::Imaging::ISurfaceImageSourceFactory>
{
    int32_t WINRT_CALL CreateInstanceWithDimensions(int32_t pixelWidth, int32_t pixelHeight, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithDimensions, WINRT_WRAP(Windows::UI::Xaml::Media::Imaging::SurfaceImageSource), int32_t, int32_t, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Media::Imaging::SurfaceImageSource>(this->shim().CreateInstanceWithDimensions(pixelWidth, pixelHeight, *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateInstanceWithDimensionsAndOpacity(int32_t pixelWidth, int32_t pixelHeight, bool isOpaque, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithDimensionsAndOpacity, WINRT_WRAP(Windows::UI::Xaml::Media::Imaging::SurfaceImageSource), int32_t, int32_t, bool, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Media::Imaging::SurfaceImageSource>(this->shim().CreateInstanceWithDimensionsAndOpacity(pixelWidth, pixelHeight, isOpaque, *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Imaging::ISvgImageSource> : produce_base<D, Windows::UI::Xaml::Media::Imaging::ISvgImageSource>
{
    int32_t WINRT_CALL get_UriSource(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UriSource, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().UriSource());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_UriSource(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UriSource, WINRT_WRAP(void), Windows::Foundation::Uri const&);
            this->shim().UriSource(*reinterpret_cast<Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RasterizePixelWidth(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RasterizePixelWidth, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().RasterizePixelWidth());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RasterizePixelWidth(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RasterizePixelWidth, WINRT_WRAP(void), double);
            this->shim().RasterizePixelWidth(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RasterizePixelHeight(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RasterizePixelHeight, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().RasterizePixelHeight());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RasterizePixelHeight(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RasterizePixelHeight, WINRT_WRAP(void), double);
            this->shim().RasterizePixelHeight(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_Opened(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Opened, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Media::Imaging::SvgImageSource, Windows::UI::Xaml::Media::Imaging::SvgImageSourceOpenedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Opened(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Media::Imaging::SvgImageSource, Windows::UI::Xaml::Media::Imaging::SvgImageSourceOpenedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Opened(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Opened, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Opened(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_OpenFailed(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OpenFailed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Media::Imaging::SvgImageSource, Windows::UI::Xaml::Media::Imaging::SvgImageSourceFailedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().OpenFailed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Media::Imaging::SvgImageSource, Windows::UI::Xaml::Media::Imaging::SvgImageSourceFailedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_OpenFailed(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(OpenFailed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().OpenFailed(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL SetSourceAsync(void* streamSource, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetSourceAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::UI::Xaml::Media::Imaging::SvgImageSourceLoadStatus>), Windows::Storage::Streams::IRandomAccessStream const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::UI::Xaml::Media::Imaging::SvgImageSourceLoadStatus>>(this->shim().SetSourceAsync(*reinterpret_cast<Windows::Storage::Streams::IRandomAccessStream const*>(&streamSource)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Imaging::ISvgImageSourceFactory> : produce_base<D, Windows::UI::Xaml::Media::Imaging::ISvgImageSourceFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Media::Imaging::SvgImageSource), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Media::Imaging::SvgImageSource>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateInstanceWithUriSource(void* uriSource, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithUriSource, WINRT_WRAP(Windows::UI::Xaml::Media::Imaging::SvgImageSource), Windows::Foundation::Uri const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Media::Imaging::SvgImageSource>(this->shim().CreateInstanceWithUriSource(*reinterpret_cast<Windows::Foundation::Uri const*>(&uriSource), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Imaging::ISvgImageSourceFailedEventArgs> : produce_base<D, Windows::UI::Xaml::Media::Imaging::ISvgImageSourceFailedEventArgs>
{
    int32_t WINRT_CALL get_Status(Windows::UI::Xaml::Media::Imaging::SvgImageSourceLoadStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::UI::Xaml::Media::Imaging::SvgImageSourceLoadStatus));
            *value = detach_from<Windows::UI::Xaml::Media::Imaging::SvgImageSourceLoadStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Imaging::ISvgImageSourceOpenedEventArgs> : produce_base<D, Windows::UI::Xaml::Media::Imaging::ISvgImageSourceOpenedEventArgs>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Imaging::ISvgImageSourceStatics> : produce_base<D, Windows::UI::Xaml::Media::Imaging::ISvgImageSourceStatics>
{
    int32_t WINRT_CALL get_UriSourceProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UriSourceProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().UriSourceProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RasterizePixelWidthProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RasterizePixelWidthProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().RasterizePixelWidthProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RasterizePixelHeightProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RasterizePixelHeightProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().RasterizePixelHeightProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Imaging::IVirtualSurfaceImageSource> : produce_base<D, Windows::UI::Xaml::Media::Imaging::IVirtualSurfaceImageSource>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Imaging::IVirtualSurfaceImageSourceFactory> : produce_base<D, Windows::UI::Xaml::Media::Imaging::IVirtualSurfaceImageSourceFactory>
{
    int32_t WINRT_CALL CreateInstanceWithDimensions(int32_t pixelWidth, int32_t pixelHeight, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInstanceWithDimensions, WINRT_WRAP(Windows::UI::Xaml::Media::Imaging::VirtualSurfaceImageSource), int32_t, int32_t);
            *value = detach_from<Windows::UI::Xaml::Media::Imaging::VirtualSurfaceImageSource>(this->shim().CreateInstanceWithDimensions(pixelWidth, pixelHeight));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateInstanceWithDimensionsAndOpacity(int32_t pixelWidth, int32_t pixelHeight, bool isOpaque, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInstanceWithDimensionsAndOpacity, WINRT_WRAP(Windows::UI::Xaml::Media::Imaging::VirtualSurfaceImageSource), int32_t, int32_t, bool);
            *value = detach_from<Windows::UI::Xaml::Media::Imaging::VirtualSurfaceImageSource>(this->shim().CreateInstanceWithDimensionsAndOpacity(pixelWidth, pixelHeight, isOpaque));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Imaging::IWriteableBitmap> : produce_base<D, Windows::UI::Xaml::Media::Imaging::IWriteableBitmap>
{
    int32_t WINRT_CALL get_PixelBuffer(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PixelBuffer, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().PixelBuffer());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Invalidate() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Invalidate, WINRT_WRAP(void));
            this->shim().Invalidate();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Imaging::IWriteableBitmapFactory> : produce_base<D, Windows::UI::Xaml::Media::Imaging::IWriteableBitmapFactory>
{
    int32_t WINRT_CALL CreateInstanceWithDimensions(int32_t pixelWidth, int32_t pixelHeight, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInstanceWithDimensions, WINRT_WRAP(Windows::UI::Xaml::Media::Imaging::WriteableBitmap), int32_t, int32_t);
            *value = detach_from<Windows::UI::Xaml::Media::Imaging::WriteableBitmap>(this->shim().CreateInstanceWithDimensions(pixelWidth, pixelHeight));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Imaging::IXamlRenderingBackgroundTask> : produce_base<D, Windows::UI::Xaml::Media::Imaging::IXamlRenderingBackgroundTask>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Imaging::IXamlRenderingBackgroundTaskFactory> : produce_base<D, Windows::UI::Xaml::Media::Imaging::IXamlRenderingBackgroundTaskFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Media::Imaging::XamlRenderingBackgroundTask), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Media::Imaging::XamlRenderingBackgroundTask>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Media::Imaging::IXamlRenderingBackgroundTaskOverrides> : produce_base<D, Windows::UI::Xaml::Media::Imaging::IXamlRenderingBackgroundTaskOverrides>
{
    int32_t WINRT_CALL OnRun(void* taskInstance) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OnRun, WINRT_WRAP(void), Windows::ApplicationModel::Background::IBackgroundTaskInstance const&);
            this->shim().OnRun(*reinterpret_cast<Windows::ApplicationModel::Background::IBackgroundTaskInstance const*>(&taskInstance));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename T, typename D>
struct WINRT_EBO produce_dispatch_to_overridable<T, D, Windows::UI::Xaml::Media::Imaging::IXamlRenderingBackgroundTaskOverrides>
    : produce_dispatch_to_overridable_base<T, D, Windows::UI::Xaml::Media::Imaging::IXamlRenderingBackgroundTaskOverrides>
{
    void OnRun(Windows::ApplicationModel::Background::IBackgroundTaskInstance const& taskInstance)
    {
        Windows::UI::Xaml::Media::Imaging::IXamlRenderingBackgroundTaskOverrides overridable = this->shim_overridable();
        if (overridable)
        {
            return overridable.OnRun(taskInstance);
        }
        return this->shim().OnRun(taskInstance);
    }
};
}

WINRT_EXPORT namespace winrt::Windows::UI::Xaml::Media::Imaging {

inline BitmapImage::BitmapImage() :
    BitmapImage(impl::call_factory<BitmapImage>([](auto&& f) { return f.template ActivateInstance<BitmapImage>(); }))
{}

inline BitmapImage::BitmapImage(Windows::Foundation::Uri const& uriSource) :
    BitmapImage(impl::call_factory<BitmapImage, Windows::UI::Xaml::Media::Imaging::IBitmapImageFactory>([&](auto&& f) { return f.CreateInstanceWithUriSource(uriSource); }))
{}

inline Windows::UI::Xaml::DependencyProperty BitmapImage::CreateOptionsProperty()
{
    return impl::call_factory<BitmapImage, Windows::UI::Xaml::Media::Imaging::IBitmapImageStatics>([&](auto&& f) { return f.CreateOptionsProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty BitmapImage::UriSourceProperty()
{
    return impl::call_factory<BitmapImage, Windows::UI::Xaml::Media::Imaging::IBitmapImageStatics>([&](auto&& f) { return f.UriSourceProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty BitmapImage::DecodePixelWidthProperty()
{
    return impl::call_factory<BitmapImage, Windows::UI::Xaml::Media::Imaging::IBitmapImageStatics>([&](auto&& f) { return f.DecodePixelWidthProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty BitmapImage::DecodePixelHeightProperty()
{
    return impl::call_factory<BitmapImage, Windows::UI::Xaml::Media::Imaging::IBitmapImageStatics>([&](auto&& f) { return f.DecodePixelHeightProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty BitmapImage::DecodePixelTypeProperty()
{
    return impl::call_factory<BitmapImage, Windows::UI::Xaml::Media::Imaging::IBitmapImageStatics2>([&](auto&& f) { return f.DecodePixelTypeProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty BitmapImage::IsAnimatedBitmapProperty()
{
    return impl::call_factory<BitmapImage, Windows::UI::Xaml::Media::Imaging::IBitmapImageStatics3>([&](auto&& f) { return f.IsAnimatedBitmapProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty BitmapImage::IsPlayingProperty()
{
    return impl::call_factory<BitmapImage, Windows::UI::Xaml::Media::Imaging::IBitmapImageStatics3>([&](auto&& f) { return f.IsPlayingProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty BitmapImage::AutoPlayProperty()
{
    return impl::call_factory<BitmapImage, Windows::UI::Xaml::Media::Imaging::IBitmapImageStatics3>([&](auto&& f) { return f.AutoPlayProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty BitmapSource::PixelWidthProperty()
{
    return impl::call_factory<BitmapSource, Windows::UI::Xaml::Media::Imaging::IBitmapSourceStatics>([&](auto&& f) { return f.PixelWidthProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty BitmapSource::PixelHeightProperty()
{
    return impl::call_factory<BitmapSource, Windows::UI::Xaml::Media::Imaging::IBitmapSourceStatics>([&](auto&& f) { return f.PixelHeightProperty(); });
}

inline RenderTargetBitmap::RenderTargetBitmap() :
    RenderTargetBitmap(impl::call_factory<RenderTargetBitmap>([](auto&& f) { return f.template ActivateInstance<RenderTargetBitmap>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty RenderTargetBitmap::PixelWidthProperty()
{
    return impl::call_factory<RenderTargetBitmap, Windows::UI::Xaml::Media::Imaging::IRenderTargetBitmapStatics>([&](auto&& f) { return f.PixelWidthProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty RenderTargetBitmap::PixelHeightProperty()
{
    return impl::call_factory<RenderTargetBitmap, Windows::UI::Xaml::Media::Imaging::IRenderTargetBitmapStatics>([&](auto&& f) { return f.PixelHeightProperty(); });
}

inline SoftwareBitmapSource::SoftwareBitmapSource() :
    SoftwareBitmapSource(impl::call_factory<SoftwareBitmapSource>([](auto&& f) { return f.template ActivateInstance<SoftwareBitmapSource>(); }))
{}

inline SurfaceImageSource::SurfaceImageSource(int32_t pixelWidth, int32_t pixelHeight)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<SurfaceImageSource, Windows::UI::Xaml::Media::Imaging::ISurfaceImageSourceFactory>([&](auto&& f) { return f.CreateInstanceWithDimensions(pixelWidth, pixelHeight, baseInterface, innerInterface); });
}

inline SurfaceImageSource::SurfaceImageSource(int32_t pixelWidth, int32_t pixelHeight, bool isOpaque)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<SurfaceImageSource, Windows::UI::Xaml::Media::Imaging::ISurfaceImageSourceFactory>([&](auto&& f) { return f.CreateInstanceWithDimensionsAndOpacity(pixelWidth, pixelHeight, isOpaque, baseInterface, innerInterface); });
}

inline SvgImageSource::SvgImageSource()
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<SvgImageSource, Windows::UI::Xaml::Media::Imaging::ISvgImageSourceFactory>([&](auto&& f) { return f.CreateInstance(baseInterface, innerInterface); });
}

inline SvgImageSource::SvgImageSource(Windows::Foundation::Uri const& uriSource)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<SvgImageSource, Windows::UI::Xaml::Media::Imaging::ISvgImageSourceFactory>([&](auto&& f) { return f.CreateInstanceWithUriSource(uriSource, baseInterface, innerInterface); });
}

inline Windows::UI::Xaml::DependencyProperty SvgImageSource::UriSourceProperty()
{
    return impl::call_factory<SvgImageSource, Windows::UI::Xaml::Media::Imaging::ISvgImageSourceStatics>([&](auto&& f) { return f.UriSourceProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty SvgImageSource::RasterizePixelWidthProperty()
{
    return impl::call_factory<SvgImageSource, Windows::UI::Xaml::Media::Imaging::ISvgImageSourceStatics>([&](auto&& f) { return f.RasterizePixelWidthProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty SvgImageSource::RasterizePixelHeightProperty()
{
    return impl::call_factory<SvgImageSource, Windows::UI::Xaml::Media::Imaging::ISvgImageSourceStatics>([&](auto&& f) { return f.RasterizePixelHeightProperty(); });
}

inline VirtualSurfaceImageSource::VirtualSurfaceImageSource(int32_t pixelWidth, int32_t pixelHeight) :
    VirtualSurfaceImageSource(impl::call_factory<VirtualSurfaceImageSource, Windows::UI::Xaml::Media::Imaging::IVirtualSurfaceImageSourceFactory>([&](auto&& f) { return f.CreateInstanceWithDimensions(pixelWidth, pixelHeight); }))
{}

inline VirtualSurfaceImageSource::VirtualSurfaceImageSource(int32_t pixelWidth, int32_t pixelHeight, bool isOpaque) :
    VirtualSurfaceImageSource(impl::call_factory<VirtualSurfaceImageSource, Windows::UI::Xaml::Media::Imaging::IVirtualSurfaceImageSourceFactory>([&](auto&& f) { return f.CreateInstanceWithDimensionsAndOpacity(pixelWidth, pixelHeight, isOpaque); }))
{}

inline WriteableBitmap::WriteableBitmap(int32_t pixelWidth, int32_t pixelHeight) :
    WriteableBitmap(impl::call_factory<WriteableBitmap, Windows::UI::Xaml::Media::Imaging::IWriteableBitmapFactory>([&](auto&& f) { return f.CreateInstanceWithDimensions(pixelWidth, pixelHeight); }))
{}

template <typename L> DownloadProgressEventHandler::DownloadProgressEventHandler(L handler) :
    DownloadProgressEventHandler(impl::make_delegate<DownloadProgressEventHandler>(std::forward<L>(handler)))
{}

template <typename F> DownloadProgressEventHandler::DownloadProgressEventHandler(F* handler) :
    DownloadProgressEventHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> DownloadProgressEventHandler::DownloadProgressEventHandler(O* object, M method) :
    DownloadProgressEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> DownloadProgressEventHandler::DownloadProgressEventHandler(com_ptr<O>&& object, M method) :
    DownloadProgressEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> DownloadProgressEventHandler::DownloadProgressEventHandler(weak_ref<O>&& object, M method) :
    DownloadProgressEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void DownloadProgressEventHandler::operator()(Windows::Foundation::IInspectable const& sender, Windows::UI::Xaml::Media::Imaging::DownloadProgressEventArgs const& e) const
{
    check_hresult((*(impl::abi_t<DownloadProgressEventHandler>**)this)->Invoke(get_abi(sender), get_abi(e)));
}

template <typename D> void IXamlRenderingBackgroundTaskOverridesT<D>::OnRun(Windows::ApplicationModel::Background::IBackgroundTaskInstance const& taskInstance) const
{
    return shim().template try_as<IXamlRenderingBackgroundTaskOverrides>().OnRun(taskInstance);
}

template <typename D, typename... Interfaces>
struct BitmapSourceT :
    implements<D, Windows::Foundation::IInspectable, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Media::Imaging::IBitmapSource, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2, Windows::UI::Xaml::Media::IImageSource>,
    impl::base<D, Windows::UI::Xaml::Media::Imaging::BitmapSource, Windows::UI::Xaml::Media::ImageSource, Windows::UI::Xaml::DependencyObject>
{
    using composable = BitmapSource;

protected:
    BitmapSourceT()
    {
        impl::call_factory<Windows::UI::Xaml::Media::Imaging::BitmapSource, Windows::UI::Xaml::Media::Imaging::IBitmapSourceFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct SurfaceImageSourceT :
    implements<D, Windows::Foundation::IInspectable, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Media::Imaging::ISurfaceImageSource, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2, Windows::UI::Xaml::Media::IImageSource>,
    impl::base<D, Windows::UI::Xaml::Media::Imaging::SurfaceImageSource, Windows::UI::Xaml::Media::ImageSource, Windows::UI::Xaml::DependencyObject>
{
    using composable = SurfaceImageSource;

protected:
    SurfaceImageSourceT(int32_t pixelWidth, int32_t pixelHeight)
    {
        impl::call_factory<Windows::UI::Xaml::Media::Imaging::SurfaceImageSource, Windows::UI::Xaml::Media::Imaging::ISurfaceImageSourceFactory>([&](auto&& f) { f.CreateInstanceWithDimensions(pixelWidth, pixelHeight, *this, this->m_inner); });
    }
    SurfaceImageSourceT(int32_t pixelWidth, int32_t pixelHeight, bool isOpaque)
    {
        impl::call_factory<Windows::UI::Xaml::Media::Imaging::SurfaceImageSource, Windows::UI::Xaml::Media::Imaging::ISurfaceImageSourceFactory>([&](auto&& f) { f.CreateInstanceWithDimensionsAndOpacity(pixelWidth, pixelHeight, isOpaque, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct SvgImageSourceT :
    implements<D, Windows::Foundation::IInspectable, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Media::Imaging::ISvgImageSource, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2, Windows::UI::Xaml::Media::IImageSource>,
    impl::base<D, Windows::UI::Xaml::Media::Imaging::SvgImageSource, Windows::UI::Xaml::Media::ImageSource, Windows::UI::Xaml::DependencyObject>
{
    using composable = SvgImageSource;

protected:
    SvgImageSourceT()
    {
        impl::call_factory<Windows::UI::Xaml::Media::Imaging::SvgImageSource, Windows::UI::Xaml::Media::Imaging::ISvgImageSourceFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
    SvgImageSourceT(Windows::Foundation::Uri const& uriSource)
    {
        impl::call_factory<Windows::UI::Xaml::Media::Imaging::SvgImageSource, Windows::UI::Xaml::Media::Imaging::ISvgImageSourceFactory>([&](auto&& f) { f.CreateInstanceWithUriSource(uriSource, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct XamlRenderingBackgroundTaskT :
    implements<D, Windows::UI::Xaml::Media::Imaging::IXamlRenderingBackgroundTaskOverrides, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Media::Imaging::IXamlRenderingBackgroundTask>,
    impl::base<D, Windows::UI::Xaml::Media::Imaging::XamlRenderingBackgroundTask>,
    Windows::UI::Xaml::Media::Imaging::IXamlRenderingBackgroundTaskOverridesT<D>
{
    using composable = XamlRenderingBackgroundTask;

protected:
    XamlRenderingBackgroundTaskT()
    {
        impl::call_factory<Windows::UI::Xaml::Media::Imaging::XamlRenderingBackgroundTask, Windows::UI::Xaml::Media::Imaging::IXamlRenderingBackgroundTaskFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::IBitmapImage> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Imaging::IBitmapImage> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::IBitmapImage2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Imaging::IBitmapImage2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::IBitmapImage3> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Imaging::IBitmapImage3> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::IBitmapImageFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Imaging::IBitmapImageFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::IBitmapImageStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Imaging::IBitmapImageStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::IBitmapImageStatics2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Imaging::IBitmapImageStatics2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::IBitmapImageStatics3> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Imaging::IBitmapImageStatics3> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::IBitmapSource> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Imaging::IBitmapSource> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::IBitmapSourceFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Imaging::IBitmapSourceFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::IBitmapSourceStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Imaging::IBitmapSourceStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::IDownloadProgressEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Imaging::IDownloadProgressEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::IRenderTargetBitmap> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Imaging::IRenderTargetBitmap> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::IRenderTargetBitmapStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Imaging::IRenderTargetBitmapStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::ISoftwareBitmapSource> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Imaging::ISoftwareBitmapSource> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::ISurfaceImageSource> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Imaging::ISurfaceImageSource> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::ISurfaceImageSourceFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Imaging::ISurfaceImageSourceFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::ISvgImageSource> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Imaging::ISvgImageSource> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::ISvgImageSourceFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Imaging::ISvgImageSourceFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::ISvgImageSourceFailedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Imaging::ISvgImageSourceFailedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::ISvgImageSourceOpenedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Imaging::ISvgImageSourceOpenedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::ISvgImageSourceStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Imaging::ISvgImageSourceStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::IVirtualSurfaceImageSource> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Imaging::IVirtualSurfaceImageSource> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::IVirtualSurfaceImageSourceFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Imaging::IVirtualSurfaceImageSourceFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::IWriteableBitmap> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Imaging::IWriteableBitmap> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::IWriteableBitmapFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Imaging::IWriteableBitmapFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::IXamlRenderingBackgroundTask> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Imaging::IXamlRenderingBackgroundTask> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::IXamlRenderingBackgroundTaskFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Imaging::IXamlRenderingBackgroundTaskFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::IXamlRenderingBackgroundTaskOverrides> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Imaging::IXamlRenderingBackgroundTaskOverrides> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::BitmapImage> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Imaging::BitmapImage> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::BitmapSource> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Imaging::BitmapSource> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::DownloadProgressEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Imaging::DownloadProgressEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::RenderTargetBitmap> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Imaging::RenderTargetBitmap> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::SoftwareBitmapSource> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Imaging::SoftwareBitmapSource> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::SurfaceImageSource> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Imaging::SurfaceImageSource> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::SvgImageSource> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Imaging::SvgImageSource> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::SvgImageSourceFailedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Imaging::SvgImageSourceFailedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::SvgImageSourceOpenedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Imaging::SvgImageSourceOpenedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::VirtualSurfaceImageSource> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Imaging::VirtualSurfaceImageSource> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::WriteableBitmap> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Imaging::WriteableBitmap> {};
template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::XamlRenderingBackgroundTask> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Media::Imaging::XamlRenderingBackgroundTask> {};

}
