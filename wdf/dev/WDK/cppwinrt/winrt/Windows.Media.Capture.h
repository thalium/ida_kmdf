// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Graphics.DirectX.Direct3D11.2.h"
#include "winrt/impl/Windows.Graphics.Imaging.2.h"
#include "winrt/impl/Windows.Media.2.h"
#include "winrt/impl/Windows.Media.Capture.Core.2.h"
#include "winrt/impl/Windows.Media.Capture.Frames.2.h"
#include "winrt/impl/Windows.Media.Core.2.h"
#include "winrt/impl/Windows.Media.Devices.2.h"
#include "winrt/impl/Windows.Media.Effects.2.h"
#include "winrt/impl/Windows.Media.MediaProperties.2.h"
#include "winrt/impl/Windows.Security.Authentication.Web.2.h"
#include "winrt/impl/Windows.Storage.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.Media.Capture.2.h"
#include "winrt/Windows.Media.h"

namespace winrt::impl {

template <typename D> Windows::Media::Capture::CapturedFrame consume_Windows_Media_Capture_IAdvancedCapturedPhoto<D>::Frame() const
{
    Windows::Media::Capture::CapturedFrame value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAdvancedCapturedPhoto)->get_Frame(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Devices::AdvancedPhotoMode consume_Windows_Media_Capture_IAdvancedCapturedPhoto<D>::Mode() const
{
    Windows::Media::Devices::AdvancedPhotoMode value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAdvancedCapturedPhoto)->get_Mode(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_Media_Capture_IAdvancedCapturedPhoto<D>::Context() const
{
    Windows::Foundation::IInspectable value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAdvancedCapturedPhoto)->get_Context(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::Rect> consume_Windows_Media_Capture_IAdvancedCapturedPhoto2<D>::FrameBoundsRelativeToReferencePhoto() const
{
    Windows::Foundation::IReference<Windows::Foundation::Rect> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAdvancedCapturedPhoto2)->get_FrameBoundsRelativeToReferencePhoto(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::Capture::AdvancedCapturedPhoto> consume_Windows_Media_Capture_IAdvancedPhotoCapture<D>::CaptureAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::Capture::AdvancedCapturedPhoto> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAdvancedPhotoCapture)->CaptureAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::Capture::AdvancedCapturedPhoto> consume_Windows_Media_Capture_IAdvancedPhotoCapture<D>::CaptureAsync(Windows::Foundation::IInspectable const& context) const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::Capture::AdvancedCapturedPhoto> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAdvancedPhotoCapture)->CaptureWithContextAsync(get_abi(context), put_abi(operation)));
    return operation;
}

template <typename D> winrt::event_token consume_Windows_Media_Capture_IAdvancedPhotoCapture<D>::OptionalReferencePhotoCaptured(Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AdvancedPhotoCapture, Windows::Media::Capture::OptionalReferencePhotoCapturedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAdvancedPhotoCapture)->add_OptionalReferencePhotoCaptured(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Capture_IAdvancedPhotoCapture<D>::OptionalReferencePhotoCaptured_revoker consume_Windows_Media_Capture_IAdvancedPhotoCapture<D>::OptionalReferencePhotoCaptured(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AdvancedPhotoCapture, Windows::Media::Capture::OptionalReferencePhotoCapturedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, OptionalReferencePhotoCaptured_revoker>(this, OptionalReferencePhotoCaptured(handler));
}

template <typename D> void consume_Windows_Media_Capture_IAdvancedPhotoCapture<D>::OptionalReferencePhotoCaptured(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Capture::IAdvancedPhotoCapture)->remove_OptionalReferencePhotoCaptured(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Capture_IAdvancedPhotoCapture<D>::AllPhotosCaptured(Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AdvancedPhotoCapture, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAdvancedPhotoCapture)->add_AllPhotosCaptured(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Capture_IAdvancedPhotoCapture<D>::AllPhotosCaptured_revoker consume_Windows_Media_Capture_IAdvancedPhotoCapture<D>::AllPhotosCaptured(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AdvancedPhotoCapture, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, AllPhotosCaptured_revoker>(this, AllPhotosCaptured(handler));
}

template <typename D> void consume_Windows_Media_Capture_IAdvancedPhotoCapture<D>::AllPhotosCaptured(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Capture::IAdvancedPhotoCapture)->remove_AllPhotosCaptured(get_abi(token)));
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_Capture_IAdvancedPhotoCapture<D>::FinishAsync() const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAdvancedPhotoCapture)->FinishAsync(put_abi(operation)));
    return operation;
}

template <typename D> void consume_Windows_Media_Capture_IAppBroadcastBackgroundService<D>::PlugInState(Windows::Media::Capture::AppBroadcastPlugInState const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastBackgroundService)->put_PlugInState(get_abi(value)));
}

template <typename D> Windows::Media::Capture::AppBroadcastPlugInState consume_Windows_Media_Capture_IAppBroadcastBackgroundService<D>::PlugInState() const
{
    Windows::Media::Capture::AppBroadcastPlugInState value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastBackgroundService)->get_PlugInState(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppBroadcastBackgroundService<D>::SignInInfo(Windows::Media::Capture::AppBroadcastBackgroundServiceSignInInfo const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastBackgroundService)->put_SignInInfo(get_abi(value)));
}

template <typename D> Windows::Media::Capture::AppBroadcastBackgroundServiceSignInInfo consume_Windows_Media_Capture_IAppBroadcastBackgroundService<D>::SignInInfo() const
{
    Windows::Media::Capture::AppBroadcastBackgroundServiceSignInInfo value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastBackgroundService)->get_SignInInfo(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppBroadcastBackgroundService<D>::StreamInfo(Windows::Media::Capture::AppBroadcastBackgroundServiceStreamInfo const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastBackgroundService)->put_StreamInfo(get_abi(value)));
}

template <typename D> Windows::Media::Capture::AppBroadcastBackgroundServiceStreamInfo consume_Windows_Media_Capture_IAppBroadcastBackgroundService<D>::StreamInfo() const
{
    Windows::Media::Capture::AppBroadcastBackgroundServiceStreamInfo value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastBackgroundService)->get_StreamInfo(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Capture_IAppBroadcastBackgroundService<D>::AppId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastBackgroundService)->get_AppId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Capture_IAppBroadcastBackgroundService<D>::BroadcastTitle() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastBackgroundService)->get_BroadcastTitle(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppBroadcastBackgroundService<D>::ViewerCount(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastBackgroundService)->put_ViewerCount(value));
}

template <typename D> uint32_t consume_Windows_Media_Capture_IAppBroadcastBackgroundService<D>::ViewerCount() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastBackgroundService)->get_ViewerCount(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppBroadcastBackgroundService<D>::TerminateBroadcast(Windows::Media::Capture::AppBroadcastTerminationReason const& reason, uint32_t providerSpecificReason) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastBackgroundService)->TerminateBroadcast(get_abi(reason), providerSpecificReason));
}

template <typename D> winrt::event_token consume_Windows_Media_Capture_IAppBroadcastBackgroundService<D>::HeartbeatRequested(Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastBackgroundService, Windows::Media::Capture::AppBroadcastHeartbeatRequestedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastBackgroundService)->add_HeartbeatRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Capture_IAppBroadcastBackgroundService<D>::HeartbeatRequested_revoker consume_Windows_Media_Capture_IAppBroadcastBackgroundService<D>::HeartbeatRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastBackgroundService, Windows::Media::Capture::AppBroadcastHeartbeatRequestedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, HeartbeatRequested_revoker>(this, HeartbeatRequested(handler));
}

template <typename D> void consume_Windows_Media_Capture_IAppBroadcastBackgroundService<D>::HeartbeatRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Capture::IAppBroadcastBackgroundService)->remove_HeartbeatRequested(get_abi(token)));
}

template <typename D> hstring consume_Windows_Media_Capture_IAppBroadcastBackgroundService<D>::TitleId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastBackgroundService)->get_TitleId(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppBroadcastBackgroundService2<D>::BroadcastTitle(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastBackgroundService2)->put_BroadcastTitle(get_abi(value)));
}

template <typename D> hstring consume_Windows_Media_Capture_IAppBroadcastBackgroundService2<D>::BroadcastLanguage() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastBackgroundService2)->get_BroadcastLanguage(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppBroadcastBackgroundService2<D>::BroadcastLanguage(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastBackgroundService2)->put_BroadcastLanguage(get_abi(value)));
}

template <typename D> hstring consume_Windows_Media_Capture_IAppBroadcastBackgroundService2<D>::BroadcastChannel() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastBackgroundService2)->get_BroadcastChannel(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppBroadcastBackgroundService2<D>::BroadcastChannel(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastBackgroundService2)->put_BroadcastChannel(get_abi(value)));
}

template <typename D> winrt::event_token consume_Windows_Media_Capture_IAppBroadcastBackgroundService2<D>::BroadcastTitleChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastBackgroundService, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastBackgroundService2)->add_BroadcastTitleChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Capture_IAppBroadcastBackgroundService2<D>::BroadcastTitleChanged_revoker consume_Windows_Media_Capture_IAppBroadcastBackgroundService2<D>::BroadcastTitleChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastBackgroundService, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, BroadcastTitleChanged_revoker>(this, BroadcastTitleChanged(handler));
}

template <typename D> void consume_Windows_Media_Capture_IAppBroadcastBackgroundService2<D>::BroadcastTitleChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Capture::IAppBroadcastBackgroundService2)->remove_BroadcastTitleChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Capture_IAppBroadcastBackgroundService2<D>::BroadcastLanguageChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastBackgroundService, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastBackgroundService2)->add_BroadcastLanguageChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Capture_IAppBroadcastBackgroundService2<D>::BroadcastLanguageChanged_revoker consume_Windows_Media_Capture_IAppBroadcastBackgroundService2<D>::BroadcastLanguageChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastBackgroundService, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, BroadcastLanguageChanged_revoker>(this, BroadcastLanguageChanged(handler));
}

template <typename D> void consume_Windows_Media_Capture_IAppBroadcastBackgroundService2<D>::BroadcastLanguageChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Capture::IAppBroadcastBackgroundService2)->remove_BroadcastLanguageChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Capture_IAppBroadcastBackgroundService2<D>::BroadcastChannelChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastBackgroundService, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastBackgroundService2)->add_BroadcastChannelChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Capture_IAppBroadcastBackgroundService2<D>::BroadcastChannelChanged_revoker consume_Windows_Media_Capture_IAppBroadcastBackgroundService2<D>::BroadcastChannelChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastBackgroundService, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, BroadcastChannelChanged_revoker>(this, BroadcastChannelChanged(handler));
}

template <typename D> void consume_Windows_Media_Capture_IAppBroadcastBackgroundService2<D>::BroadcastChannelChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Capture::IAppBroadcastBackgroundService2)->remove_BroadcastChannelChanged(get_abi(token)));
}

template <typename D> Windows::Media::Capture::AppBroadcastSignInState consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceSignInInfo<D>::SignInState() const
{
    Windows::Media::Capture::AppBroadcastSignInState value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastBackgroundServiceSignInInfo)->get_SignInState(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceSignInInfo<D>::OAuthRequestUri(Windows::Foundation::Uri const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastBackgroundServiceSignInInfo)->put_OAuthRequestUri(get_abi(value)));
}

template <typename D> Windows::Foundation::Uri consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceSignInInfo<D>::OAuthRequestUri() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastBackgroundServiceSignInInfo)->get_OAuthRequestUri(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceSignInInfo<D>::OAuthCallbackUri(Windows::Foundation::Uri const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastBackgroundServiceSignInInfo)->put_OAuthCallbackUri(get_abi(value)));
}

template <typename D> Windows::Foundation::Uri consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceSignInInfo<D>::OAuthCallbackUri() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastBackgroundServiceSignInInfo)->get_OAuthCallbackUri(put_abi(value)));
    return value;
}

template <typename D> Windows::Security::Authentication::Web::WebAuthenticationResult consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceSignInInfo<D>::AuthenticationResult() const
{
    Windows::Security::Authentication::Web::WebAuthenticationResult value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastBackgroundServiceSignInInfo)->get_AuthenticationResult(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceSignInInfo<D>::UserName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastBackgroundServiceSignInInfo)->put_UserName(get_abi(value)));
}

template <typename D> hstring consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceSignInInfo<D>::UserName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastBackgroundServiceSignInInfo)->get_UserName(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceSignInInfo<D>::SignInStateChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastBackgroundServiceSignInInfo, Windows::Media::Capture::AppBroadcastSignInStateChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastBackgroundServiceSignInInfo)->add_SignInStateChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceSignInInfo<D>::SignInStateChanged_revoker consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceSignInInfo<D>::SignInStateChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastBackgroundServiceSignInInfo, Windows::Media::Capture::AppBroadcastSignInStateChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, SignInStateChanged_revoker>(this, SignInStateChanged(handler));
}

template <typename D> void consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceSignInInfo<D>::SignInStateChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Capture::IAppBroadcastBackgroundServiceSignInInfo)->remove_SignInStateChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceSignInInfo2<D>::UserNameChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastBackgroundServiceSignInInfo, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastBackgroundServiceSignInInfo2)->add_UserNameChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceSignInInfo2<D>::UserNameChanged_revoker consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceSignInInfo2<D>::UserNameChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastBackgroundServiceSignInInfo, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, UserNameChanged_revoker>(this, UserNameChanged(handler));
}

template <typename D> void consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceSignInInfo2<D>::UserNameChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Capture::IAppBroadcastBackgroundServiceSignInInfo2)->remove_UserNameChanged(get_abi(token)));
}

template <typename D> Windows::Media::Capture::AppBroadcastStreamState consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceStreamInfo<D>::StreamState() const
{
    Windows::Media::Capture::AppBroadcastStreamState value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastBackgroundServiceStreamInfo)->get_StreamState(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceStreamInfo<D>::DesiredVideoEncodingBitrate(uint64_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastBackgroundServiceStreamInfo)->put_DesiredVideoEncodingBitrate(value));
}

template <typename D> uint64_t consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceStreamInfo<D>::DesiredVideoEncodingBitrate() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastBackgroundServiceStreamInfo)->get_DesiredVideoEncodingBitrate(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceStreamInfo<D>::BandwidthTestBitrate(uint64_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastBackgroundServiceStreamInfo)->put_BandwidthTestBitrate(value));
}

template <typename D> uint64_t consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceStreamInfo<D>::BandwidthTestBitrate() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastBackgroundServiceStreamInfo)->get_BandwidthTestBitrate(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceStreamInfo<D>::AudioCodec(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastBackgroundServiceStreamInfo)->put_AudioCodec(get_abi(value)));
}

template <typename D> hstring consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceStreamInfo<D>::AudioCodec() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastBackgroundServiceStreamInfo)->get_AudioCodec(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Capture::AppBroadcastStreamReader consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceStreamInfo<D>::BroadcastStreamReader() const
{
    Windows::Media::Capture::AppBroadcastStreamReader value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastBackgroundServiceStreamInfo)->get_BroadcastStreamReader(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceStreamInfo<D>::StreamStateChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastBackgroundServiceStreamInfo, Windows::Media::Capture::AppBroadcastStreamStateChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastBackgroundServiceStreamInfo)->add_StreamStateChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceStreamInfo<D>::StreamStateChanged_revoker consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceStreamInfo<D>::StreamStateChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastBackgroundServiceStreamInfo, Windows::Media::Capture::AppBroadcastStreamStateChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, StreamStateChanged_revoker>(this, StreamStateChanged(handler));
}

template <typename D> void consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceStreamInfo<D>::StreamStateChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Capture::IAppBroadcastBackgroundServiceStreamInfo)->remove_StreamStateChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceStreamInfo<D>::VideoEncodingResolutionChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastBackgroundServiceStreamInfo, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastBackgroundServiceStreamInfo)->add_VideoEncodingResolutionChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceStreamInfo<D>::VideoEncodingResolutionChanged_revoker consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceStreamInfo<D>::VideoEncodingResolutionChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastBackgroundServiceStreamInfo, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, VideoEncodingResolutionChanged_revoker>(this, VideoEncodingResolutionChanged(handler));
}

template <typename D> void consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceStreamInfo<D>::VideoEncodingResolutionChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Capture::IAppBroadcastBackgroundServiceStreamInfo)->remove_VideoEncodingResolutionChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceStreamInfo<D>::VideoEncodingBitrateChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastBackgroundServiceStreamInfo, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastBackgroundServiceStreamInfo)->add_VideoEncodingBitrateChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceStreamInfo<D>::VideoEncodingBitrateChanged_revoker consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceStreamInfo<D>::VideoEncodingBitrateChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastBackgroundServiceStreamInfo, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, VideoEncodingBitrateChanged_revoker>(this, VideoEncodingBitrateChanged(handler));
}

template <typename D> void consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceStreamInfo<D>::VideoEncodingBitrateChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Capture::IAppBroadcastBackgroundServiceStreamInfo)->remove_VideoEncodingBitrateChanged(get_abi(token)));
}

template <typename D> void consume_Windows_Media_Capture_IAppBroadcastBackgroundServiceStreamInfo2<D>::ReportProblemWithStream() const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastBackgroundServiceStreamInfo2)->ReportProblemWithStream());
}

template <typename D> Windows::Media::Capture::AppBroadcastCameraCaptureState consume_Windows_Media_Capture_IAppBroadcastCameraCaptureStateChangedEventArgs<D>::State() const
{
    Windows::Media::Capture::AppBroadcastCameraCaptureState value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastCameraCaptureStateChangedEventArgs)->get_State(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Capture_IAppBroadcastCameraCaptureStateChangedEventArgs<D>::ErrorCode() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastCameraCaptureStateChangedEventArgs)->get_ErrorCode(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_Capture_IAppBroadcastGlobalSettings<D>::IsBroadcastEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastGlobalSettings)->get_IsBroadcastEnabled(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_Capture_IAppBroadcastGlobalSettings<D>::IsDisabledByPolicy() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastGlobalSettings)->get_IsDisabledByPolicy(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_Capture_IAppBroadcastGlobalSettings<D>::IsGpuConstrained() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastGlobalSettings)->get_IsGpuConstrained(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_Capture_IAppBroadcastGlobalSettings<D>::HasHardwareEncoder() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastGlobalSettings)->get_HasHardwareEncoder(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppBroadcastGlobalSettings<D>::IsAudioCaptureEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastGlobalSettings)->put_IsAudioCaptureEnabled(value));
}

template <typename D> bool consume_Windows_Media_Capture_IAppBroadcastGlobalSettings<D>::IsAudioCaptureEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastGlobalSettings)->get_IsAudioCaptureEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppBroadcastGlobalSettings<D>::IsMicrophoneCaptureEnabledByDefault(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastGlobalSettings)->put_IsMicrophoneCaptureEnabledByDefault(value));
}

template <typename D> bool consume_Windows_Media_Capture_IAppBroadcastGlobalSettings<D>::IsMicrophoneCaptureEnabledByDefault() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastGlobalSettings)->get_IsMicrophoneCaptureEnabledByDefault(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppBroadcastGlobalSettings<D>::IsEchoCancellationEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastGlobalSettings)->put_IsEchoCancellationEnabled(value));
}

template <typename D> bool consume_Windows_Media_Capture_IAppBroadcastGlobalSettings<D>::IsEchoCancellationEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastGlobalSettings)->get_IsEchoCancellationEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppBroadcastGlobalSettings<D>::SystemAudioGain(double value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastGlobalSettings)->put_SystemAudioGain(value));
}

template <typename D> double consume_Windows_Media_Capture_IAppBroadcastGlobalSettings<D>::SystemAudioGain() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastGlobalSettings)->get_SystemAudioGain(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppBroadcastGlobalSettings<D>::MicrophoneGain(double value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastGlobalSettings)->put_MicrophoneGain(value));
}

template <typename D> double consume_Windows_Media_Capture_IAppBroadcastGlobalSettings<D>::MicrophoneGain() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastGlobalSettings)->get_MicrophoneGain(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppBroadcastGlobalSettings<D>::IsCameraCaptureEnabledByDefault(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastGlobalSettings)->put_IsCameraCaptureEnabledByDefault(value));
}

template <typename D> bool consume_Windows_Media_Capture_IAppBroadcastGlobalSettings<D>::IsCameraCaptureEnabledByDefault() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastGlobalSettings)->get_IsCameraCaptureEnabledByDefault(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppBroadcastGlobalSettings<D>::SelectedCameraId(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastGlobalSettings)->put_SelectedCameraId(get_abi(value)));
}

template <typename D> hstring consume_Windows_Media_Capture_IAppBroadcastGlobalSettings<D>::SelectedCameraId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastGlobalSettings)->get_SelectedCameraId(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppBroadcastGlobalSettings<D>::CameraOverlayLocation(Windows::Media::Capture::AppBroadcastCameraOverlayLocation const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastGlobalSettings)->put_CameraOverlayLocation(get_abi(value)));
}

template <typename D> Windows::Media::Capture::AppBroadcastCameraOverlayLocation consume_Windows_Media_Capture_IAppBroadcastGlobalSettings<D>::CameraOverlayLocation() const
{
    Windows::Media::Capture::AppBroadcastCameraOverlayLocation value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastGlobalSettings)->get_CameraOverlayLocation(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppBroadcastGlobalSettings<D>::CameraOverlaySize(Windows::Media::Capture::AppBroadcastCameraOverlaySize const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastGlobalSettings)->put_CameraOverlaySize(get_abi(value)));
}

template <typename D> Windows::Media::Capture::AppBroadcastCameraOverlaySize consume_Windows_Media_Capture_IAppBroadcastGlobalSettings<D>::CameraOverlaySize() const
{
    Windows::Media::Capture::AppBroadcastCameraOverlaySize value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastGlobalSettings)->get_CameraOverlaySize(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppBroadcastGlobalSettings<D>::IsCursorImageCaptureEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastGlobalSettings)->put_IsCursorImageCaptureEnabled(value));
}

template <typename D> bool consume_Windows_Media_Capture_IAppBroadcastGlobalSettings<D>::IsCursorImageCaptureEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastGlobalSettings)->get_IsCursorImageCaptureEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppBroadcastHeartbeatRequestedEventArgs<D>::Handled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastHeartbeatRequestedEventArgs)->put_Handled(value));
}

template <typename D> bool consume_Windows_Media_Capture_IAppBroadcastHeartbeatRequestedEventArgs<D>::Handled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastHeartbeatRequestedEventArgs)->get_Handled(&value));
    return value;
}

template <typename D> Windows::Media::Capture::AppBroadcastGlobalSettings consume_Windows_Media_Capture_IAppBroadcastManagerStatics<D>::GetGlobalSettings() const
{
    Windows::Media::Capture::AppBroadcastGlobalSettings value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastManagerStatics)->GetGlobalSettings(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppBroadcastManagerStatics<D>::ApplyGlobalSettings(Windows::Media::Capture::AppBroadcastGlobalSettings const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastManagerStatics)->ApplyGlobalSettings(get_abi(value)));
}

template <typename D> Windows::Media::Capture::AppBroadcastProviderSettings consume_Windows_Media_Capture_IAppBroadcastManagerStatics<D>::GetProviderSettings() const
{
    Windows::Media::Capture::AppBroadcastProviderSettings value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastManagerStatics)->GetProviderSettings(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppBroadcastManagerStatics<D>::ApplyProviderSettings(Windows::Media::Capture::AppBroadcastProviderSettings const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastManagerStatics)->ApplyProviderSettings(get_abi(value)));
}

template <typename D> Windows::Media::Capture::AppBroadcastMicrophoneCaptureState consume_Windows_Media_Capture_IAppBroadcastMicrophoneCaptureStateChangedEventArgs<D>::State() const
{
    Windows::Media::Capture::AppBroadcastMicrophoneCaptureState value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastMicrophoneCaptureStateChangedEventArgs)->get_State(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Capture_IAppBroadcastMicrophoneCaptureStateChangedEventArgs<D>::ErrorCode() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastMicrophoneCaptureStateChangedEventArgs)->get_ErrorCode(&value));
    return value;
}

template <typename D> hstring consume_Windows_Media_Capture_IAppBroadcastPlugIn<D>::AppId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastPlugIn)->get_AppId(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Capture::AppBroadcastProviderSettings consume_Windows_Media_Capture_IAppBroadcastPlugIn<D>::ProviderSettings() const
{
    Windows::Media::Capture::AppBroadcastProviderSettings value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastPlugIn)->get_ProviderSettings(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IRandomAccessStreamReference consume_Windows_Media_Capture_IAppBroadcastPlugIn<D>::Logo() const
{
    Windows::Storage::Streams::IRandomAccessStreamReference value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastPlugIn)->get_Logo(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Capture_IAppBroadcastPlugIn<D>::DisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastPlugIn)->get_DisplayName(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Media_Capture_IAppBroadcastPlugInManager<D>::IsBroadcastProviderAvailable() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastPlugInManager)->get_IsBroadcastProviderAvailable(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Media::Capture::AppBroadcastPlugIn> consume_Windows_Media_Capture_IAppBroadcastPlugInManager<D>::PlugInList() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Media::Capture::AppBroadcastPlugIn> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastPlugInManager)->get_PlugInList(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Capture::AppBroadcastPlugIn consume_Windows_Media_Capture_IAppBroadcastPlugInManager<D>::DefaultPlugIn() const
{
    Windows::Media::Capture::AppBroadcastPlugIn value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastPlugInManager)->get_DefaultPlugIn(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppBroadcastPlugInManager<D>::DefaultPlugIn(Windows::Media::Capture::AppBroadcastPlugIn const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastPlugInManager)->put_DefaultPlugIn(get_abi(value)));
}

template <typename D> Windows::Media::Capture::AppBroadcastPlugInManager consume_Windows_Media_Capture_IAppBroadcastPlugInManagerStatics<D>::GetDefault() const
{
    Windows::Media::Capture::AppBroadcastPlugInManager ppInstance{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastPlugInManagerStatics)->GetDefault(put_abi(ppInstance)));
    return ppInstance;
}

template <typename D> Windows::Media::Capture::AppBroadcastPlugInManager consume_Windows_Media_Capture_IAppBroadcastPlugInManagerStatics<D>::GetForUser(Windows::System::User const& user) const
{
    Windows::Media::Capture::AppBroadcastPlugInManager ppInstance{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastPlugInManagerStatics)->GetForUser(get_abi(user), put_abi(ppInstance)));
    return ppInstance;
}

template <typename D> Windows::Media::Capture::AppBroadcastPlugInState consume_Windows_Media_Capture_IAppBroadcastPlugInStateChangedEventArgs<D>::PlugInState() const
{
    Windows::Media::Capture::AppBroadcastPlugInState value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastPlugInStateChangedEventArgs)->get_PlugInState(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppBroadcastPreview<D>::StopPreview() const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastPreview)->StopPreview());
}

template <typename D> Windows::Media::Capture::AppBroadcastPreviewState consume_Windows_Media_Capture_IAppBroadcastPreview<D>::PreviewState() const
{
    Windows::Media::Capture::AppBroadcastPreviewState value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastPreview)->get_PreviewState(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<uint32_t> consume_Windows_Media_Capture_IAppBroadcastPreview<D>::ErrorCode() const
{
    Windows::Foundation::IReference<uint32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastPreview)->get_ErrorCode(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Media_Capture_IAppBroadcastPreview<D>::PreviewStateChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastPreview, Windows::Media::Capture::AppBroadcastPreviewStateChangedEventArgs> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastPreview)->add_PreviewStateChanged(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Capture_IAppBroadcastPreview<D>::PreviewStateChanged_revoker consume_Windows_Media_Capture_IAppBroadcastPreview<D>::PreviewStateChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastPreview, Windows::Media::Capture::AppBroadcastPreviewStateChangedEventArgs> const& value) const
{
    return impl::make_event_revoker<D, PreviewStateChanged_revoker>(this, PreviewStateChanged(value));
}

template <typename D> void consume_Windows_Media_Capture_IAppBroadcastPreview<D>::PreviewStateChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Capture::IAppBroadcastPreview)->remove_PreviewStateChanged(get_abi(token)));
}

template <typename D> Windows::Media::Capture::AppBroadcastPreviewStreamReader consume_Windows_Media_Capture_IAppBroadcastPreview<D>::PreviewStreamReader() const
{
    Windows::Media::Capture::AppBroadcastPreviewStreamReader value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastPreview)->get_PreviewStreamReader(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Capture::AppBroadcastPreviewState consume_Windows_Media_Capture_IAppBroadcastPreviewStateChangedEventArgs<D>::PreviewState() const
{
    Windows::Media::Capture::AppBroadcastPreviewState value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastPreviewStateChangedEventArgs)->get_PreviewState(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Capture_IAppBroadcastPreviewStateChangedEventArgs<D>::ErrorCode() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastPreviewStateChangedEventArgs)->get_ErrorCode(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Capture_IAppBroadcastPreviewStreamReader<D>::VideoWidth() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastPreviewStreamReader)->get_VideoWidth(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Capture_IAppBroadcastPreviewStreamReader<D>::VideoHeight() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastPreviewStreamReader)->get_VideoHeight(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Capture_IAppBroadcastPreviewStreamReader<D>::VideoStride() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastPreviewStreamReader)->get_VideoStride(&value));
    return value;
}

template <typename D> Windows::Graphics::Imaging::BitmapPixelFormat consume_Windows_Media_Capture_IAppBroadcastPreviewStreamReader<D>::VideoBitmapPixelFormat() const
{
    Windows::Graphics::Imaging::BitmapPixelFormat value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastPreviewStreamReader)->get_VideoBitmapPixelFormat(put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::Imaging::BitmapAlphaMode consume_Windows_Media_Capture_IAppBroadcastPreviewStreamReader<D>::VideoBitmapAlphaMode() const
{
    Windows::Graphics::Imaging::BitmapAlphaMode value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastPreviewStreamReader)->get_VideoBitmapAlphaMode(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Capture::AppBroadcastPreviewStreamVideoFrame consume_Windows_Media_Capture_IAppBroadcastPreviewStreamReader<D>::TryGetNextVideoFrame() const
{
    Windows::Media::Capture::AppBroadcastPreviewStreamVideoFrame frame{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastPreviewStreamReader)->TryGetNextVideoFrame(put_abi(frame)));
    return frame;
}

template <typename D> winrt::event_token consume_Windows_Media_Capture_IAppBroadcastPreviewStreamReader<D>::VideoFrameArrived(Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastPreviewStreamReader, Windows::Foundation::IInspectable> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastPreviewStreamReader)->add_VideoFrameArrived(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Capture_IAppBroadcastPreviewStreamReader<D>::VideoFrameArrived_revoker consume_Windows_Media_Capture_IAppBroadcastPreviewStreamReader<D>::VideoFrameArrived(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastPreviewStreamReader, Windows::Foundation::IInspectable> const& value) const
{
    return impl::make_event_revoker<D, VideoFrameArrived_revoker>(this, VideoFrameArrived(value));
}

template <typename D> void consume_Windows_Media_Capture_IAppBroadcastPreviewStreamReader<D>::VideoFrameArrived(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Capture::IAppBroadcastPreviewStreamReader)->remove_VideoFrameArrived(get_abi(token)));
}

template <typename D> Windows::Media::Capture::AppBroadcastPreviewStreamVideoHeader consume_Windows_Media_Capture_IAppBroadcastPreviewStreamVideoFrame<D>::VideoHeader() const
{
    Windows::Media::Capture::AppBroadcastPreviewStreamVideoHeader value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastPreviewStreamVideoFrame)->get_VideoHeader(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Media_Capture_IAppBroadcastPreviewStreamVideoFrame<D>::VideoBuffer() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastPreviewStreamVideoFrame)->get_VideoBuffer(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_Media_Capture_IAppBroadcastPreviewStreamVideoHeader<D>::AbsoluteTimestamp() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastPreviewStreamVideoHeader)->get_AbsoluteTimestamp(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_Capture_IAppBroadcastPreviewStreamVideoHeader<D>::RelativeTimestamp() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastPreviewStreamVideoHeader)->get_RelativeTimestamp(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_Capture_IAppBroadcastPreviewStreamVideoHeader<D>::Duration() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastPreviewStreamVideoHeader)->get_Duration(put_abi(value)));
    return value;
}

template <typename D> uint64_t consume_Windows_Media_Capture_IAppBroadcastPreviewStreamVideoHeader<D>::FrameId() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastPreviewStreamVideoHeader)->get_FrameId(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppBroadcastProviderSettings<D>::DefaultBroadcastTitle(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastProviderSettings)->put_DefaultBroadcastTitle(get_abi(value)));
}

template <typename D> hstring consume_Windows_Media_Capture_IAppBroadcastProviderSettings<D>::DefaultBroadcastTitle() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastProviderSettings)->get_DefaultBroadcastTitle(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppBroadcastProviderSettings<D>::AudioEncodingBitrate(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastProviderSettings)->put_AudioEncodingBitrate(value));
}

template <typename D> uint32_t consume_Windows_Media_Capture_IAppBroadcastProviderSettings<D>::AudioEncodingBitrate() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastProviderSettings)->get_AudioEncodingBitrate(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppBroadcastProviderSettings<D>::CustomVideoEncodingBitrate(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastProviderSettings)->put_CustomVideoEncodingBitrate(value));
}

template <typename D> uint32_t consume_Windows_Media_Capture_IAppBroadcastProviderSettings<D>::CustomVideoEncodingBitrate() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastProviderSettings)->get_CustomVideoEncodingBitrate(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppBroadcastProviderSettings<D>::CustomVideoEncodingHeight(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastProviderSettings)->put_CustomVideoEncodingHeight(value));
}

template <typename D> uint32_t consume_Windows_Media_Capture_IAppBroadcastProviderSettings<D>::CustomVideoEncodingHeight() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastProviderSettings)->get_CustomVideoEncodingHeight(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppBroadcastProviderSettings<D>::CustomVideoEncodingWidth(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastProviderSettings)->put_CustomVideoEncodingWidth(value));
}

template <typename D> uint32_t consume_Windows_Media_Capture_IAppBroadcastProviderSettings<D>::CustomVideoEncodingWidth() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastProviderSettings)->get_CustomVideoEncodingWidth(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppBroadcastProviderSettings<D>::VideoEncodingBitrateMode(Windows::Media::Capture::AppBroadcastVideoEncodingBitrateMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastProviderSettings)->put_VideoEncodingBitrateMode(get_abi(value)));
}

template <typename D> Windows::Media::Capture::AppBroadcastVideoEncodingBitrateMode consume_Windows_Media_Capture_IAppBroadcastProviderSettings<D>::VideoEncodingBitrateMode() const
{
    Windows::Media::Capture::AppBroadcastVideoEncodingBitrateMode value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastProviderSettings)->get_VideoEncodingBitrateMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppBroadcastProviderSettings<D>::VideoEncodingResolutionMode(Windows::Media::Capture::AppBroadcastVideoEncodingResolutionMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastProviderSettings)->put_VideoEncodingResolutionMode(get_abi(value)));
}

template <typename D> Windows::Media::Capture::AppBroadcastVideoEncodingResolutionMode consume_Windows_Media_Capture_IAppBroadcastProviderSettings<D>::VideoEncodingResolutionMode() const
{
    Windows::Media::Capture::AppBroadcastVideoEncodingResolutionMode value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastProviderSettings)->get_VideoEncodingResolutionMode(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Capture::AppBroadcastCaptureTargetType consume_Windows_Media_Capture_IAppBroadcastServices<D>::CaptureTargetType() const
{
    Windows::Media::Capture::AppBroadcastCaptureTargetType value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastServices)->get_CaptureTargetType(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppBroadcastServices<D>::CaptureTargetType(Windows::Media::Capture::AppBroadcastCaptureTargetType const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastServices)->put_CaptureTargetType(get_abi(value)));
}

template <typename D> hstring consume_Windows_Media_Capture_IAppBroadcastServices<D>::BroadcastTitle() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastServices)->get_BroadcastTitle(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppBroadcastServices<D>::BroadcastTitle(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastServices)->put_BroadcastTitle(get_abi(value)));
}

template <typename D> hstring consume_Windows_Media_Capture_IAppBroadcastServices<D>::BroadcastLanguage() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastServices)->get_BroadcastLanguage(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppBroadcastServices<D>::BroadcastLanguage(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastServices)->put_BroadcastLanguage(get_abi(value)));
}

template <typename D> hstring consume_Windows_Media_Capture_IAppBroadcastServices<D>::UserName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastServices)->get_UserName(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Media_Capture_IAppBroadcastServices<D>::CanCapture() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastServices)->get_CanCapture(&value));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<uint32_t> consume_Windows_Media_Capture_IAppBroadcastServices<D>::EnterBroadcastModeAsync(Windows::Media::Capture::AppBroadcastPlugIn const& plugIn) const
{
    Windows::Foundation::IAsyncOperation<uint32_t> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastServices)->EnterBroadcastModeAsync(get_abi(plugIn), put_abi(operation)));
    return operation;
}

template <typename D> void consume_Windows_Media_Capture_IAppBroadcastServices<D>::ExitBroadcastMode(Windows::Media::Capture::AppBroadcastExitBroadcastModeReason const& reason) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastServices)->ExitBroadcastMode(get_abi(reason)));
}

template <typename D> void consume_Windows_Media_Capture_IAppBroadcastServices<D>::StartBroadcast() const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastServices)->StartBroadcast());
}

template <typename D> void consume_Windows_Media_Capture_IAppBroadcastServices<D>::PauseBroadcast() const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastServices)->PauseBroadcast());
}

template <typename D> void consume_Windows_Media_Capture_IAppBroadcastServices<D>::ResumeBroadcast() const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastServices)->ResumeBroadcast());
}

template <typename D> Windows::Media::Capture::AppBroadcastPreview consume_Windows_Media_Capture_IAppBroadcastServices<D>::StartPreview(Windows::Foundation::Size const& desiredSize) const
{
    Windows::Media::Capture::AppBroadcastPreview preview{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastServices)->StartPreview(get_abi(desiredSize), put_abi(preview)));
    return preview;
}

template <typename D> Windows::Media::Capture::AppBroadcastState consume_Windows_Media_Capture_IAppBroadcastServices<D>::State() const
{
    Windows::Media::Capture::AppBroadcastState value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastServices)->get_State(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Capture::AppBroadcastSignInState consume_Windows_Media_Capture_IAppBroadcastSignInStateChangedEventArgs<D>::SignInState() const
{
    Windows::Media::Capture::AppBroadcastSignInState value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastSignInStateChangedEventArgs)->get_SignInState(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Capture::AppBroadcastSignInResult consume_Windows_Media_Capture_IAppBroadcastSignInStateChangedEventArgs<D>::Result() const
{
    Windows::Media::Capture::AppBroadcastSignInResult value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastSignInStateChangedEventArgs)->get_Result(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Media_Capture_IAppBroadcastState<D>::IsCaptureTargetRunning() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastState)->get_IsCaptureTargetRunning(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Capture_IAppBroadcastState<D>::ViewerCount() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastState)->get_ViewerCount(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_Capture_IAppBroadcastState<D>::ShouldCaptureMicrophone() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastState)->get_ShouldCaptureMicrophone(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppBroadcastState<D>::ShouldCaptureMicrophone(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastState)->put_ShouldCaptureMicrophone(value));
}

template <typename D> void consume_Windows_Media_Capture_IAppBroadcastState<D>::RestartMicrophoneCapture() const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastState)->RestartMicrophoneCapture());
}

template <typename D> bool consume_Windows_Media_Capture_IAppBroadcastState<D>::ShouldCaptureCamera() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastState)->get_ShouldCaptureCamera(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppBroadcastState<D>::ShouldCaptureCamera(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastState)->put_ShouldCaptureCamera(value));
}

template <typename D> void consume_Windows_Media_Capture_IAppBroadcastState<D>::RestartCameraCapture() const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastState)->RestartCameraCapture());
}

template <typename D> Windows::Foundation::Size consume_Windows_Media_Capture_IAppBroadcastState<D>::EncodedVideoSize() const
{
    Windows::Foundation::Size value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastState)->get_EncodedVideoSize(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Capture::AppBroadcastMicrophoneCaptureState consume_Windows_Media_Capture_IAppBroadcastState<D>::MicrophoneCaptureState() const
{
    Windows::Media::Capture::AppBroadcastMicrophoneCaptureState value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastState)->get_MicrophoneCaptureState(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Capture_IAppBroadcastState<D>::MicrophoneCaptureError() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastState)->get_MicrophoneCaptureError(&value));
    return value;
}

template <typename D> Windows::Media::Capture::AppBroadcastCameraCaptureState consume_Windows_Media_Capture_IAppBroadcastState<D>::CameraCaptureState() const
{
    Windows::Media::Capture::AppBroadcastCameraCaptureState value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastState)->get_CameraCaptureState(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Capture_IAppBroadcastState<D>::CameraCaptureError() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastState)->get_CameraCaptureError(&value));
    return value;
}

template <typename D> Windows::Media::Capture::AppBroadcastStreamState consume_Windows_Media_Capture_IAppBroadcastState<D>::StreamState() const
{
    Windows::Media::Capture::AppBroadcastStreamState value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastState)->get_StreamState(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Capture::AppBroadcastPlugInState consume_Windows_Media_Capture_IAppBroadcastState<D>::PlugInState() const
{
    Windows::Media::Capture::AppBroadcastPlugInState value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastState)->get_PlugInState(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Uri consume_Windows_Media_Capture_IAppBroadcastState<D>::OAuthRequestUri() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastState)->get_OAuthRequestUri(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Uri consume_Windows_Media_Capture_IAppBroadcastState<D>::OAuthCallbackUri() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastState)->get_OAuthCallbackUri(put_abi(value)));
    return value;
}

template <typename D> Windows::Security::Authentication::Web::WebAuthenticationResult consume_Windows_Media_Capture_IAppBroadcastState<D>::AuthenticationResult() const
{
    Windows::Security::Authentication::Web::WebAuthenticationResult value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastState)->get_AuthenticationResult(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppBroadcastState<D>::AuthenticationResult(Windows::Security::Authentication::Web::WebAuthenticationResult const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastState)->put_AuthenticationResult(get_abi(value)));
}

template <typename D> void consume_Windows_Media_Capture_IAppBroadcastState<D>::SignInState(Windows::Media::Capture::AppBroadcastSignInState const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastState)->put_SignInState(get_abi(value)));
}

template <typename D> Windows::Media::Capture::AppBroadcastSignInState consume_Windows_Media_Capture_IAppBroadcastState<D>::SignInState() const
{
    Windows::Media::Capture::AppBroadcastSignInState value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastState)->get_SignInState(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Capture::AppBroadcastTerminationReason consume_Windows_Media_Capture_IAppBroadcastState<D>::TerminationReason() const
{
    Windows::Media::Capture::AppBroadcastTerminationReason value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastState)->get_TerminationReason(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Capture_IAppBroadcastState<D>::TerminationReasonPlugInSpecific() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastState)->get_TerminationReasonPlugInSpecific(&value));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Media_Capture_IAppBroadcastState<D>::ViewerCountChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastState, Windows::Media::Capture::AppBroadcastViewerCountChangedEventArgs> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastState)->add_ViewerCountChanged(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Capture_IAppBroadcastState<D>::ViewerCountChanged_revoker consume_Windows_Media_Capture_IAppBroadcastState<D>::ViewerCountChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastState, Windows::Media::Capture::AppBroadcastViewerCountChangedEventArgs> const& value) const
{
    return impl::make_event_revoker<D, ViewerCountChanged_revoker>(this, ViewerCountChanged(value));
}

template <typename D> void consume_Windows_Media_Capture_IAppBroadcastState<D>::ViewerCountChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Capture::IAppBroadcastState)->remove_ViewerCountChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Capture_IAppBroadcastState<D>::MicrophoneCaptureStateChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastState, Windows::Media::Capture::AppBroadcastMicrophoneCaptureStateChangedEventArgs> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastState)->add_MicrophoneCaptureStateChanged(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Capture_IAppBroadcastState<D>::MicrophoneCaptureStateChanged_revoker consume_Windows_Media_Capture_IAppBroadcastState<D>::MicrophoneCaptureStateChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastState, Windows::Media::Capture::AppBroadcastMicrophoneCaptureStateChangedEventArgs> const& value) const
{
    return impl::make_event_revoker<D, MicrophoneCaptureStateChanged_revoker>(this, MicrophoneCaptureStateChanged(value));
}

template <typename D> void consume_Windows_Media_Capture_IAppBroadcastState<D>::MicrophoneCaptureStateChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Capture::IAppBroadcastState)->remove_MicrophoneCaptureStateChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Capture_IAppBroadcastState<D>::CameraCaptureStateChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastState, Windows::Media::Capture::AppBroadcastCameraCaptureStateChangedEventArgs> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastState)->add_CameraCaptureStateChanged(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Capture_IAppBroadcastState<D>::CameraCaptureStateChanged_revoker consume_Windows_Media_Capture_IAppBroadcastState<D>::CameraCaptureStateChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastState, Windows::Media::Capture::AppBroadcastCameraCaptureStateChangedEventArgs> const& value) const
{
    return impl::make_event_revoker<D, CameraCaptureStateChanged_revoker>(this, CameraCaptureStateChanged(value));
}

template <typename D> void consume_Windows_Media_Capture_IAppBroadcastState<D>::CameraCaptureStateChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Capture::IAppBroadcastState)->remove_CameraCaptureStateChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Capture_IAppBroadcastState<D>::PlugInStateChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastState, Windows::Media::Capture::AppBroadcastPlugInStateChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastState)->add_PlugInStateChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Capture_IAppBroadcastState<D>::PlugInStateChanged_revoker consume_Windows_Media_Capture_IAppBroadcastState<D>::PlugInStateChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastState, Windows::Media::Capture::AppBroadcastPlugInStateChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, PlugInStateChanged_revoker>(this, PlugInStateChanged(handler));
}

template <typename D> void consume_Windows_Media_Capture_IAppBroadcastState<D>::PlugInStateChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Capture::IAppBroadcastState)->remove_PlugInStateChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Capture_IAppBroadcastState<D>::StreamStateChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastState, Windows::Media::Capture::AppBroadcastStreamStateChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastState)->add_StreamStateChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Capture_IAppBroadcastState<D>::StreamStateChanged_revoker consume_Windows_Media_Capture_IAppBroadcastState<D>::StreamStateChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastState, Windows::Media::Capture::AppBroadcastStreamStateChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, StreamStateChanged_revoker>(this, StreamStateChanged(handler));
}

template <typename D> void consume_Windows_Media_Capture_IAppBroadcastState<D>::StreamStateChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Capture::IAppBroadcastState)->remove_StreamStateChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Capture_IAppBroadcastState<D>::CaptureTargetClosed(Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastState, Windows::Foundation::IInspectable> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastState)->add_CaptureTargetClosed(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Capture_IAppBroadcastState<D>::CaptureTargetClosed_revoker consume_Windows_Media_Capture_IAppBroadcastState<D>::CaptureTargetClosed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastState, Windows::Foundation::IInspectable> const& value) const
{
    return impl::make_event_revoker<D, CaptureTargetClosed_revoker>(this, CaptureTargetClosed(value));
}

template <typename D> void consume_Windows_Media_Capture_IAppBroadcastState<D>::CaptureTargetClosed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Capture::IAppBroadcastState)->remove_CaptureTargetClosed(get_abi(token)));
}

template <typename D> Windows::Media::Capture::AppBroadcastStreamAudioHeader consume_Windows_Media_Capture_IAppBroadcastStreamAudioFrame<D>::AudioHeader() const
{
    Windows::Media::Capture::AppBroadcastStreamAudioHeader value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastStreamAudioFrame)->get_AudioHeader(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Media_Capture_IAppBroadcastStreamAudioFrame<D>::AudioBuffer() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastStreamAudioFrame)->get_AudioBuffer(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_Media_Capture_IAppBroadcastStreamAudioHeader<D>::AbsoluteTimestamp() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastStreamAudioHeader)->get_AbsoluteTimestamp(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_Capture_IAppBroadcastStreamAudioHeader<D>::RelativeTimestamp() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastStreamAudioHeader)->get_RelativeTimestamp(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_Capture_IAppBroadcastStreamAudioHeader<D>::Duration() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastStreamAudioHeader)->get_Duration(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Media_Capture_IAppBroadcastStreamAudioHeader<D>::HasDiscontinuity() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastStreamAudioHeader)->get_HasDiscontinuity(&value));
    return value;
}

template <typename D> uint64_t consume_Windows_Media_Capture_IAppBroadcastStreamAudioHeader<D>::FrameId() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastStreamAudioHeader)->get_FrameId(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Capture_IAppBroadcastStreamReader<D>::AudioChannels() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastStreamReader)->get_AudioChannels(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Capture_IAppBroadcastStreamReader<D>::AudioSampleRate() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastStreamReader)->get_AudioSampleRate(&value));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Media_Capture_IAppBroadcastStreamReader<D>::AudioAacSequence() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastStreamReader)->get_AudioAacSequence(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Capture_IAppBroadcastStreamReader<D>::AudioBitrate() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastStreamReader)->get_AudioBitrate(&value));
    return value;
}

template <typename D> Windows::Media::Capture::AppBroadcastStreamAudioFrame consume_Windows_Media_Capture_IAppBroadcastStreamReader<D>::TryGetNextAudioFrame() const
{
    Windows::Media::Capture::AppBroadcastStreamAudioFrame frame{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastStreamReader)->TryGetNextAudioFrame(put_abi(frame)));
    return frame;
}

template <typename D> uint32_t consume_Windows_Media_Capture_IAppBroadcastStreamReader<D>::VideoWidth() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastStreamReader)->get_VideoWidth(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Capture_IAppBroadcastStreamReader<D>::VideoHeight() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastStreamReader)->get_VideoHeight(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Capture_IAppBroadcastStreamReader<D>::VideoBitrate() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastStreamReader)->get_VideoBitrate(&value));
    return value;
}

template <typename D> Windows::Media::Capture::AppBroadcastStreamVideoFrame consume_Windows_Media_Capture_IAppBroadcastStreamReader<D>::TryGetNextVideoFrame() const
{
    Windows::Media::Capture::AppBroadcastStreamVideoFrame frame{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastStreamReader)->TryGetNextVideoFrame(put_abi(frame)));
    return frame;
}

template <typename D> winrt::event_token consume_Windows_Media_Capture_IAppBroadcastStreamReader<D>::AudioFrameArrived(Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastStreamReader, Windows::Foundation::IInspectable> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastStreamReader)->add_AudioFrameArrived(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Capture_IAppBroadcastStreamReader<D>::AudioFrameArrived_revoker consume_Windows_Media_Capture_IAppBroadcastStreamReader<D>::AudioFrameArrived(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastStreamReader, Windows::Foundation::IInspectable> const& value) const
{
    return impl::make_event_revoker<D, AudioFrameArrived_revoker>(this, AudioFrameArrived(value));
}

template <typename D> void consume_Windows_Media_Capture_IAppBroadcastStreamReader<D>::AudioFrameArrived(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Capture::IAppBroadcastStreamReader)->remove_AudioFrameArrived(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Capture_IAppBroadcastStreamReader<D>::VideoFrameArrived(Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastStreamReader, Windows::Foundation::IInspectable> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastStreamReader)->add_VideoFrameArrived(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Capture_IAppBroadcastStreamReader<D>::VideoFrameArrived_revoker consume_Windows_Media_Capture_IAppBroadcastStreamReader<D>::VideoFrameArrived(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastStreamReader, Windows::Foundation::IInspectable> const& value) const
{
    return impl::make_event_revoker<D, VideoFrameArrived_revoker>(this, VideoFrameArrived(value));
}

template <typename D> void consume_Windows_Media_Capture_IAppBroadcastStreamReader<D>::VideoFrameArrived(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Capture::IAppBroadcastStreamReader)->remove_VideoFrameArrived(get_abi(token)));
}

template <typename D> Windows::Media::Capture::AppBroadcastStreamState consume_Windows_Media_Capture_IAppBroadcastStreamStateChangedEventArgs<D>::StreamState() const
{
    Windows::Media::Capture::AppBroadcastStreamState value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastStreamStateChangedEventArgs)->get_StreamState(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Capture::AppBroadcastStreamVideoHeader consume_Windows_Media_Capture_IAppBroadcastStreamVideoFrame<D>::VideoHeader() const
{
    Windows::Media::Capture::AppBroadcastStreamVideoHeader value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastStreamVideoFrame)->get_VideoHeader(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Media_Capture_IAppBroadcastStreamVideoFrame<D>::VideoBuffer() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastStreamVideoFrame)->get_VideoBuffer(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_Media_Capture_IAppBroadcastStreamVideoHeader<D>::AbsoluteTimestamp() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastStreamVideoHeader)->get_AbsoluteTimestamp(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_Capture_IAppBroadcastStreamVideoHeader<D>::RelativeTimestamp() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastStreamVideoHeader)->get_RelativeTimestamp(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_Capture_IAppBroadcastStreamVideoHeader<D>::Duration() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastStreamVideoHeader)->get_Duration(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Media_Capture_IAppBroadcastStreamVideoHeader<D>::IsKeyFrame() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastStreamVideoHeader)->get_IsKeyFrame(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_Capture_IAppBroadcastStreamVideoHeader<D>::HasDiscontinuity() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastStreamVideoHeader)->get_HasDiscontinuity(&value));
    return value;
}

template <typename D> uint64_t consume_Windows_Media_Capture_IAppBroadcastStreamVideoHeader<D>::FrameId() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastStreamVideoHeader)->get_FrameId(&value));
    return value;
}

template <typename D> Windows::Media::Capture::AppBroadcastBackgroundService consume_Windows_Media_Capture_IAppBroadcastTriggerDetails<D>::BackgroundService() const
{
    Windows::Media::Capture::AppBroadcastBackgroundService value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastTriggerDetails)->get_BackgroundService(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Capture_IAppBroadcastViewerCountChangedEventArgs<D>::ViewerCount() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppBroadcastViewerCountChangedEventArgs)->get_ViewerCount(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_Capture_IAppCapture<D>::IsCapturingAudio() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCapture)->get_IsCapturingAudio(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_Capture_IAppCapture<D>::IsCapturingVideo() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCapture)->get_IsCapturingVideo(&value));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Media_Capture_IAppCapture<D>::CapturingChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppCapture, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCapture)->add_CapturingChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Capture_IAppCapture<D>::CapturingChanged_revoker consume_Windows_Media_Capture_IAppCapture<D>::CapturingChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppCapture, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, CapturingChanged_revoker>(this, CapturingChanged(handler));
}

template <typename D> void consume_Windows_Media_Capture_IAppCapture<D>::CapturingChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Capture::IAppCapture)->remove_CapturingChanged(get_abi(token)));
}

template <typename D> void consume_Windows_Media_Capture_IAppCaptureAlternateShortcutKeys<D>::ToggleGameBarKey(Windows::System::VirtualKey const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureAlternateShortcutKeys)->put_ToggleGameBarKey(get_abi(value)));
}

template <typename D> Windows::System::VirtualKey consume_Windows_Media_Capture_IAppCaptureAlternateShortcutKeys<D>::ToggleGameBarKey() const
{
    Windows::System::VirtualKey value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureAlternateShortcutKeys)->get_ToggleGameBarKey(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppCaptureAlternateShortcutKeys<D>::ToggleGameBarKeyModifiers(Windows::System::VirtualKeyModifiers const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureAlternateShortcutKeys)->put_ToggleGameBarKeyModifiers(get_abi(value)));
}

template <typename D> Windows::System::VirtualKeyModifiers consume_Windows_Media_Capture_IAppCaptureAlternateShortcutKeys<D>::ToggleGameBarKeyModifiers() const
{
    Windows::System::VirtualKeyModifiers value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureAlternateShortcutKeys)->get_ToggleGameBarKeyModifiers(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppCaptureAlternateShortcutKeys<D>::SaveHistoricalVideoKey(Windows::System::VirtualKey const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureAlternateShortcutKeys)->put_SaveHistoricalVideoKey(get_abi(value)));
}

template <typename D> Windows::System::VirtualKey consume_Windows_Media_Capture_IAppCaptureAlternateShortcutKeys<D>::SaveHistoricalVideoKey() const
{
    Windows::System::VirtualKey value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureAlternateShortcutKeys)->get_SaveHistoricalVideoKey(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppCaptureAlternateShortcutKeys<D>::SaveHistoricalVideoKeyModifiers(Windows::System::VirtualKeyModifiers const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureAlternateShortcutKeys)->put_SaveHistoricalVideoKeyModifiers(get_abi(value)));
}

template <typename D> Windows::System::VirtualKeyModifiers consume_Windows_Media_Capture_IAppCaptureAlternateShortcutKeys<D>::SaveHistoricalVideoKeyModifiers() const
{
    Windows::System::VirtualKeyModifiers value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureAlternateShortcutKeys)->get_SaveHistoricalVideoKeyModifiers(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppCaptureAlternateShortcutKeys<D>::ToggleRecordingKey(Windows::System::VirtualKey const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureAlternateShortcutKeys)->put_ToggleRecordingKey(get_abi(value)));
}

template <typename D> Windows::System::VirtualKey consume_Windows_Media_Capture_IAppCaptureAlternateShortcutKeys<D>::ToggleRecordingKey() const
{
    Windows::System::VirtualKey value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureAlternateShortcutKeys)->get_ToggleRecordingKey(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppCaptureAlternateShortcutKeys<D>::ToggleRecordingKeyModifiers(Windows::System::VirtualKeyModifiers const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureAlternateShortcutKeys)->put_ToggleRecordingKeyModifiers(get_abi(value)));
}

template <typename D> Windows::System::VirtualKeyModifiers consume_Windows_Media_Capture_IAppCaptureAlternateShortcutKeys<D>::ToggleRecordingKeyModifiers() const
{
    Windows::System::VirtualKeyModifiers value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureAlternateShortcutKeys)->get_ToggleRecordingKeyModifiers(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppCaptureAlternateShortcutKeys<D>::TakeScreenshotKey(Windows::System::VirtualKey const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureAlternateShortcutKeys)->put_TakeScreenshotKey(get_abi(value)));
}

template <typename D> Windows::System::VirtualKey consume_Windows_Media_Capture_IAppCaptureAlternateShortcutKeys<D>::TakeScreenshotKey() const
{
    Windows::System::VirtualKey value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureAlternateShortcutKeys)->get_TakeScreenshotKey(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppCaptureAlternateShortcutKeys<D>::TakeScreenshotKeyModifiers(Windows::System::VirtualKeyModifiers const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureAlternateShortcutKeys)->put_TakeScreenshotKeyModifiers(get_abi(value)));
}

template <typename D> Windows::System::VirtualKeyModifiers consume_Windows_Media_Capture_IAppCaptureAlternateShortcutKeys<D>::TakeScreenshotKeyModifiers() const
{
    Windows::System::VirtualKeyModifiers value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureAlternateShortcutKeys)->get_TakeScreenshotKeyModifiers(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppCaptureAlternateShortcutKeys<D>::ToggleRecordingIndicatorKey(Windows::System::VirtualKey const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureAlternateShortcutKeys)->put_ToggleRecordingIndicatorKey(get_abi(value)));
}

template <typename D> Windows::System::VirtualKey consume_Windows_Media_Capture_IAppCaptureAlternateShortcutKeys<D>::ToggleRecordingIndicatorKey() const
{
    Windows::System::VirtualKey value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureAlternateShortcutKeys)->get_ToggleRecordingIndicatorKey(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppCaptureAlternateShortcutKeys<D>::ToggleRecordingIndicatorKeyModifiers(Windows::System::VirtualKeyModifiers const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureAlternateShortcutKeys)->put_ToggleRecordingIndicatorKeyModifiers(get_abi(value)));
}

template <typename D> Windows::System::VirtualKeyModifiers consume_Windows_Media_Capture_IAppCaptureAlternateShortcutKeys<D>::ToggleRecordingIndicatorKeyModifiers() const
{
    Windows::System::VirtualKeyModifiers value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureAlternateShortcutKeys)->get_ToggleRecordingIndicatorKeyModifiers(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppCaptureAlternateShortcutKeys2<D>::ToggleMicrophoneCaptureKey(Windows::System::VirtualKey const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureAlternateShortcutKeys2)->put_ToggleMicrophoneCaptureKey(get_abi(value)));
}

template <typename D> Windows::System::VirtualKey consume_Windows_Media_Capture_IAppCaptureAlternateShortcutKeys2<D>::ToggleMicrophoneCaptureKey() const
{
    Windows::System::VirtualKey value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureAlternateShortcutKeys2)->get_ToggleMicrophoneCaptureKey(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppCaptureAlternateShortcutKeys2<D>::ToggleMicrophoneCaptureKeyModifiers(Windows::System::VirtualKeyModifiers const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureAlternateShortcutKeys2)->put_ToggleMicrophoneCaptureKeyModifiers(get_abi(value)));
}

template <typename D> Windows::System::VirtualKeyModifiers consume_Windows_Media_Capture_IAppCaptureAlternateShortcutKeys2<D>::ToggleMicrophoneCaptureKeyModifiers() const
{
    Windows::System::VirtualKeyModifiers value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureAlternateShortcutKeys2)->get_ToggleMicrophoneCaptureKeyModifiers(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppCaptureAlternateShortcutKeys3<D>::ToggleCameraCaptureKey(Windows::System::VirtualKey const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureAlternateShortcutKeys3)->put_ToggleCameraCaptureKey(get_abi(value)));
}

template <typename D> Windows::System::VirtualKey consume_Windows_Media_Capture_IAppCaptureAlternateShortcutKeys3<D>::ToggleCameraCaptureKey() const
{
    Windows::System::VirtualKey value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureAlternateShortcutKeys3)->get_ToggleCameraCaptureKey(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppCaptureAlternateShortcutKeys3<D>::ToggleCameraCaptureKeyModifiers(Windows::System::VirtualKeyModifiers const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureAlternateShortcutKeys3)->put_ToggleCameraCaptureKeyModifiers(get_abi(value)));
}

template <typename D> Windows::System::VirtualKeyModifiers consume_Windows_Media_Capture_IAppCaptureAlternateShortcutKeys3<D>::ToggleCameraCaptureKeyModifiers() const
{
    Windows::System::VirtualKeyModifiers value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureAlternateShortcutKeys3)->get_ToggleCameraCaptureKeyModifiers(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppCaptureAlternateShortcutKeys3<D>::ToggleBroadcastKey(Windows::System::VirtualKey const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureAlternateShortcutKeys3)->put_ToggleBroadcastKey(get_abi(value)));
}

template <typename D> Windows::System::VirtualKey consume_Windows_Media_Capture_IAppCaptureAlternateShortcutKeys3<D>::ToggleBroadcastKey() const
{
    Windows::System::VirtualKey value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureAlternateShortcutKeys3)->get_ToggleBroadcastKey(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppCaptureAlternateShortcutKeys3<D>::ToggleBroadcastKeyModifiers(Windows::System::VirtualKeyModifiers const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureAlternateShortcutKeys3)->put_ToggleBroadcastKeyModifiers(get_abi(value)));
}

template <typename D> Windows::System::VirtualKeyModifiers consume_Windows_Media_Capture_IAppCaptureAlternateShortcutKeys3<D>::ToggleBroadcastKeyModifiers() const
{
    Windows::System::VirtualKeyModifiers value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureAlternateShortcutKeys3)->get_ToggleBroadcastKeyModifiers(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_Capture_IAppCaptureDurationGeneratedEventArgs<D>::Duration() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureDurationGeneratedEventArgs)->get_Duration(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::StorageFile consume_Windows_Media_Capture_IAppCaptureFileGeneratedEventArgs<D>::File() const
{
    Windows::Storage::StorageFile value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureFileGeneratedEventArgs)->get_File(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Capture::AppCaptureSettings consume_Windows_Media_Capture_IAppCaptureManagerStatics<D>::GetCurrentSettings() const
{
    Windows::Media::Capture::AppCaptureSettings value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureManagerStatics)->GetCurrentSettings(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppCaptureManagerStatics<D>::ApplySettings(Windows::Media::Capture::AppCaptureSettings const& appCaptureSettings) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureManagerStatics)->ApplySettings(get_abi(appCaptureSettings)));
}

template <typename D> void consume_Windows_Media_Capture_IAppCaptureMetadataWriter<D>::AddStringEvent(param::hstring const& name, param::hstring const& value, Windows::Media::Capture::AppCaptureMetadataPriority const& priority) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureMetadataWriter)->AddStringEvent(get_abi(name), get_abi(value), get_abi(priority)));
}

template <typename D> void consume_Windows_Media_Capture_IAppCaptureMetadataWriter<D>::AddInt32Event(param::hstring const& name, int32_t value, Windows::Media::Capture::AppCaptureMetadataPriority const& priority) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureMetadataWriter)->AddInt32Event(get_abi(name), value, get_abi(priority)));
}

template <typename D> void consume_Windows_Media_Capture_IAppCaptureMetadataWriter<D>::AddDoubleEvent(param::hstring const& name, double value, Windows::Media::Capture::AppCaptureMetadataPriority const& priority) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureMetadataWriter)->AddDoubleEvent(get_abi(name), value, get_abi(priority)));
}

template <typename D> void consume_Windows_Media_Capture_IAppCaptureMetadataWriter<D>::StartStringState(param::hstring const& name, param::hstring const& value, Windows::Media::Capture::AppCaptureMetadataPriority const& priority) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureMetadataWriter)->StartStringState(get_abi(name), get_abi(value), get_abi(priority)));
}

template <typename D> void consume_Windows_Media_Capture_IAppCaptureMetadataWriter<D>::StartInt32State(param::hstring const& name, int32_t value, Windows::Media::Capture::AppCaptureMetadataPriority const& priority) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureMetadataWriter)->StartInt32State(get_abi(name), value, get_abi(priority)));
}

template <typename D> void consume_Windows_Media_Capture_IAppCaptureMetadataWriter<D>::StartDoubleState(param::hstring const& name, double value, Windows::Media::Capture::AppCaptureMetadataPriority const& priority) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureMetadataWriter)->StartDoubleState(get_abi(name), value, get_abi(priority)));
}

template <typename D> void consume_Windows_Media_Capture_IAppCaptureMetadataWriter<D>::StopState(param::hstring const& name) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureMetadataWriter)->StopState(get_abi(name)));
}

template <typename D> void consume_Windows_Media_Capture_IAppCaptureMetadataWriter<D>::StopAllStates() const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureMetadataWriter)->StopAllStates());
}

template <typename D> uint64_t consume_Windows_Media_Capture_IAppCaptureMetadataWriter<D>::RemainingStorageBytesAvailable() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureMetadataWriter)->get_RemainingStorageBytesAvailable(&value));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Media_Capture_IAppCaptureMetadataWriter<D>::MetadataPurged(Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppCaptureMetadataWriter, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureMetadataWriter)->add_MetadataPurged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Capture_IAppCaptureMetadataWriter<D>::MetadataPurged_revoker consume_Windows_Media_Capture_IAppCaptureMetadataWriter<D>::MetadataPurged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppCaptureMetadataWriter, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, MetadataPurged_revoker>(this, MetadataPurged(handler));
}

template <typename D> void consume_Windows_Media_Capture_IAppCaptureMetadataWriter<D>::MetadataPurged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Capture::IAppCaptureMetadataWriter)->remove_MetadataPurged(get_abi(token)));
}

template <typename D> Windows::Media::Capture::AppCaptureMicrophoneCaptureState consume_Windows_Media_Capture_IAppCaptureMicrophoneCaptureStateChangedEventArgs<D>::State() const
{
    Windows::Media::Capture::AppCaptureMicrophoneCaptureState value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureMicrophoneCaptureStateChangedEventArgs)->get_State(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Capture_IAppCaptureMicrophoneCaptureStateChangedEventArgs<D>::ErrorCode() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureMicrophoneCaptureStateChangedEventArgs)->get_ErrorCode(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppCaptureRecordOperation<D>::StopRecording() const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureRecordOperation)->StopRecording());
}

template <typename D> Windows::Media::Capture::AppCaptureRecordingState consume_Windows_Media_Capture_IAppCaptureRecordOperation<D>::State() const
{
    Windows::Media::Capture::AppCaptureRecordingState value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureRecordOperation)->get_State(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<uint32_t> consume_Windows_Media_Capture_IAppCaptureRecordOperation<D>::ErrorCode() const
{
    Windows::Foundation::IReference<uint32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureRecordOperation)->get_ErrorCode(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::TimeSpan> consume_Windows_Media_Capture_IAppCaptureRecordOperation<D>::Duration() const
{
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureRecordOperation)->get_Duration(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::StorageFile consume_Windows_Media_Capture_IAppCaptureRecordOperation<D>::File() const
{
    Windows::Storage::StorageFile value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureRecordOperation)->get_File(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<bool> consume_Windows_Media_Capture_IAppCaptureRecordOperation<D>::IsFileTruncated() const
{
    Windows::Foundation::IReference<bool> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureRecordOperation)->get_IsFileTruncated(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Media_Capture_IAppCaptureRecordOperation<D>::StateChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppCaptureRecordOperation, Windows::Media::Capture::AppCaptureRecordingStateChangedEventArgs> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureRecordOperation)->add_StateChanged(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Capture_IAppCaptureRecordOperation<D>::StateChanged_revoker consume_Windows_Media_Capture_IAppCaptureRecordOperation<D>::StateChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppCaptureRecordOperation, Windows::Media::Capture::AppCaptureRecordingStateChangedEventArgs> const& value) const
{
    return impl::make_event_revoker<D, StateChanged_revoker>(this, StateChanged(value));
}

template <typename D> void consume_Windows_Media_Capture_IAppCaptureRecordOperation<D>::StateChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Capture::IAppCaptureRecordOperation)->remove_StateChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Capture_IAppCaptureRecordOperation<D>::DurationGenerated(Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppCaptureRecordOperation, Windows::Media::Capture::AppCaptureDurationGeneratedEventArgs> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureRecordOperation)->add_DurationGenerated(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Capture_IAppCaptureRecordOperation<D>::DurationGenerated_revoker consume_Windows_Media_Capture_IAppCaptureRecordOperation<D>::DurationGenerated(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppCaptureRecordOperation, Windows::Media::Capture::AppCaptureDurationGeneratedEventArgs> const& value) const
{
    return impl::make_event_revoker<D, DurationGenerated_revoker>(this, DurationGenerated(value));
}

template <typename D> void consume_Windows_Media_Capture_IAppCaptureRecordOperation<D>::DurationGenerated(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Capture::IAppCaptureRecordOperation)->remove_DurationGenerated(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Capture_IAppCaptureRecordOperation<D>::FileGenerated(Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppCaptureRecordOperation, Windows::Media::Capture::AppCaptureFileGeneratedEventArgs> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureRecordOperation)->add_FileGenerated(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Capture_IAppCaptureRecordOperation<D>::FileGenerated_revoker consume_Windows_Media_Capture_IAppCaptureRecordOperation<D>::FileGenerated(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppCaptureRecordOperation, Windows::Media::Capture::AppCaptureFileGeneratedEventArgs> const& value) const
{
    return impl::make_event_revoker<D, FileGenerated_revoker>(this, FileGenerated(value));
}

template <typename D> void consume_Windows_Media_Capture_IAppCaptureRecordOperation<D>::FileGenerated(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Capture::IAppCaptureRecordOperation)->remove_FileGenerated(get_abi(token)));
}

template <typename D> Windows::Media::Capture::AppCaptureRecordingState consume_Windows_Media_Capture_IAppCaptureRecordingStateChangedEventArgs<D>::State() const
{
    Windows::Media::Capture::AppCaptureRecordingState value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureRecordingStateChangedEventArgs)->get_State(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Capture_IAppCaptureRecordingStateChangedEventArgs<D>::ErrorCode() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureRecordingStateChangedEventArgs)->get_ErrorCode(&value));
    return value;
}

template <typename D> Windows::Media::Capture::AppCaptureRecordOperation consume_Windows_Media_Capture_IAppCaptureServices<D>::Record() const
{
    Windows::Media::Capture::AppCaptureRecordOperation operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureServices)->Record(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Media::Capture::AppCaptureRecordOperation consume_Windows_Media_Capture_IAppCaptureServices<D>::RecordTimeSpan(Windows::Foundation::DateTime const& startTime, Windows::Foundation::TimeSpan const& duration) const
{
    Windows::Media::Capture::AppCaptureRecordOperation operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureServices)->RecordTimeSpan(get_abi(startTime), get_abi(duration), put_abi(operation)));
    return operation;
}

template <typename D> bool consume_Windows_Media_Capture_IAppCaptureServices<D>::CanCapture() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureServices)->get_CanCapture(&value));
    return value;
}

template <typename D> Windows::Media::Capture::AppCaptureState consume_Windows_Media_Capture_IAppCaptureServices<D>::State() const
{
    Windows::Media::Capture::AppCaptureState value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureServices)->get_State(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppCaptureSettings<D>::AppCaptureDestinationFolder(Windows::Storage::StorageFolder const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureSettings)->put_AppCaptureDestinationFolder(get_abi(value)));
}

template <typename D> Windows::Storage::StorageFolder consume_Windows_Media_Capture_IAppCaptureSettings<D>::AppCaptureDestinationFolder() const
{
    Windows::Storage::StorageFolder value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureSettings)->get_AppCaptureDestinationFolder(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppCaptureSettings<D>::AudioEncodingBitrate(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureSettings)->put_AudioEncodingBitrate(value));
}

template <typename D> uint32_t consume_Windows_Media_Capture_IAppCaptureSettings<D>::AudioEncodingBitrate() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureSettings)->get_AudioEncodingBitrate(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppCaptureSettings<D>::IsAudioCaptureEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureSettings)->put_IsAudioCaptureEnabled(value));
}

template <typename D> bool consume_Windows_Media_Capture_IAppCaptureSettings<D>::IsAudioCaptureEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureSettings)->get_IsAudioCaptureEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppCaptureSettings<D>::CustomVideoEncodingBitrate(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureSettings)->put_CustomVideoEncodingBitrate(value));
}

template <typename D> uint32_t consume_Windows_Media_Capture_IAppCaptureSettings<D>::CustomVideoEncodingBitrate() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureSettings)->get_CustomVideoEncodingBitrate(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppCaptureSettings<D>::CustomVideoEncodingHeight(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureSettings)->put_CustomVideoEncodingHeight(value));
}

template <typename D> uint32_t consume_Windows_Media_Capture_IAppCaptureSettings<D>::CustomVideoEncodingHeight() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureSettings)->get_CustomVideoEncodingHeight(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppCaptureSettings<D>::CustomVideoEncodingWidth(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureSettings)->put_CustomVideoEncodingWidth(value));
}

template <typename D> uint32_t consume_Windows_Media_Capture_IAppCaptureSettings<D>::CustomVideoEncodingWidth() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureSettings)->get_CustomVideoEncodingWidth(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppCaptureSettings<D>::HistoricalBufferLength(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureSettings)->put_HistoricalBufferLength(value));
}

template <typename D> uint32_t consume_Windows_Media_Capture_IAppCaptureSettings<D>::HistoricalBufferLength() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureSettings)->get_HistoricalBufferLength(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppCaptureSettings<D>::HistoricalBufferLengthUnit(Windows::Media::Capture::AppCaptureHistoricalBufferLengthUnit const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureSettings)->put_HistoricalBufferLengthUnit(get_abi(value)));
}

template <typename D> Windows::Media::Capture::AppCaptureHistoricalBufferLengthUnit consume_Windows_Media_Capture_IAppCaptureSettings<D>::HistoricalBufferLengthUnit() const
{
    Windows::Media::Capture::AppCaptureHistoricalBufferLengthUnit value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureSettings)->get_HistoricalBufferLengthUnit(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppCaptureSettings<D>::IsHistoricalCaptureEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureSettings)->put_IsHistoricalCaptureEnabled(value));
}

template <typename D> bool consume_Windows_Media_Capture_IAppCaptureSettings<D>::IsHistoricalCaptureEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureSettings)->get_IsHistoricalCaptureEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppCaptureSettings<D>::IsHistoricalCaptureOnBatteryAllowed(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureSettings)->put_IsHistoricalCaptureOnBatteryAllowed(value));
}

template <typename D> bool consume_Windows_Media_Capture_IAppCaptureSettings<D>::IsHistoricalCaptureOnBatteryAllowed() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureSettings)->get_IsHistoricalCaptureOnBatteryAllowed(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppCaptureSettings<D>::IsHistoricalCaptureOnWirelessDisplayAllowed(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureSettings)->put_IsHistoricalCaptureOnWirelessDisplayAllowed(value));
}

template <typename D> bool consume_Windows_Media_Capture_IAppCaptureSettings<D>::IsHistoricalCaptureOnWirelessDisplayAllowed() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureSettings)->get_IsHistoricalCaptureOnWirelessDisplayAllowed(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppCaptureSettings<D>::MaximumRecordLength(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureSettings)->put_MaximumRecordLength(get_abi(value)));
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_Capture_IAppCaptureSettings<D>::MaximumRecordLength() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureSettings)->get_MaximumRecordLength(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppCaptureSettings<D>::ScreenshotDestinationFolder(Windows::Storage::StorageFolder const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureSettings)->put_ScreenshotDestinationFolder(get_abi(value)));
}

template <typename D> Windows::Storage::StorageFolder consume_Windows_Media_Capture_IAppCaptureSettings<D>::ScreenshotDestinationFolder() const
{
    Windows::Storage::StorageFolder value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureSettings)->get_ScreenshotDestinationFolder(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppCaptureSettings<D>::VideoEncodingBitrateMode(Windows::Media::Capture::AppCaptureVideoEncodingBitrateMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureSettings)->put_VideoEncodingBitrateMode(get_abi(value)));
}

template <typename D> Windows::Media::Capture::AppCaptureVideoEncodingBitrateMode consume_Windows_Media_Capture_IAppCaptureSettings<D>::VideoEncodingBitrateMode() const
{
    Windows::Media::Capture::AppCaptureVideoEncodingBitrateMode value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureSettings)->get_VideoEncodingBitrateMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppCaptureSettings<D>::VideoEncodingResolutionMode(Windows::Media::Capture::AppCaptureVideoEncodingResolutionMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureSettings)->put_VideoEncodingResolutionMode(get_abi(value)));
}

template <typename D> Windows::Media::Capture::AppCaptureVideoEncodingResolutionMode consume_Windows_Media_Capture_IAppCaptureSettings<D>::VideoEncodingResolutionMode() const
{
    Windows::Media::Capture::AppCaptureVideoEncodingResolutionMode value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureSettings)->get_VideoEncodingResolutionMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppCaptureSettings<D>::IsAppCaptureEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureSettings)->put_IsAppCaptureEnabled(value));
}

template <typename D> bool consume_Windows_Media_Capture_IAppCaptureSettings<D>::IsAppCaptureEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureSettings)->get_IsAppCaptureEnabled(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_Capture_IAppCaptureSettings<D>::IsCpuConstrained() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureSettings)->get_IsCpuConstrained(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_Capture_IAppCaptureSettings<D>::IsDisabledByPolicy() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureSettings)->get_IsDisabledByPolicy(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_Capture_IAppCaptureSettings<D>::IsMemoryConstrained() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureSettings)->get_IsMemoryConstrained(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_Capture_IAppCaptureSettings<D>::HasHardwareEncoder() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureSettings)->get_HasHardwareEncoder(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_Capture_IAppCaptureSettings2<D>::IsGpuConstrained() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureSettings2)->get_IsGpuConstrained(&value));
    return value;
}

template <typename D> Windows::Media::Capture::AppCaptureAlternateShortcutKeys consume_Windows_Media_Capture_IAppCaptureSettings2<D>::AlternateShortcutKeys() const
{
    Windows::Media::Capture::AppCaptureAlternateShortcutKeys value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureSettings2)->get_AlternateShortcutKeys(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppCaptureSettings3<D>::IsMicrophoneCaptureEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureSettings3)->put_IsMicrophoneCaptureEnabled(value));
}

template <typename D> bool consume_Windows_Media_Capture_IAppCaptureSettings3<D>::IsMicrophoneCaptureEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureSettings3)->get_IsMicrophoneCaptureEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppCaptureSettings4<D>::IsMicrophoneCaptureEnabledByDefault(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureSettings4)->put_IsMicrophoneCaptureEnabledByDefault(value));
}

template <typename D> bool consume_Windows_Media_Capture_IAppCaptureSettings4<D>::IsMicrophoneCaptureEnabledByDefault() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureSettings4)->get_IsMicrophoneCaptureEnabledByDefault(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppCaptureSettings4<D>::SystemAudioGain(double value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureSettings4)->put_SystemAudioGain(value));
}

template <typename D> double consume_Windows_Media_Capture_IAppCaptureSettings4<D>::SystemAudioGain() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureSettings4)->get_SystemAudioGain(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppCaptureSettings4<D>::MicrophoneGain(double value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureSettings4)->put_MicrophoneGain(value));
}

template <typename D> double consume_Windows_Media_Capture_IAppCaptureSettings4<D>::MicrophoneGain() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureSettings4)->get_MicrophoneGain(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppCaptureSettings4<D>::VideoEncodingFrameRateMode(Windows::Media::Capture::AppCaptureVideoEncodingFrameRateMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureSettings4)->put_VideoEncodingFrameRateMode(get_abi(value)));
}

template <typename D> Windows::Media::Capture::AppCaptureVideoEncodingFrameRateMode consume_Windows_Media_Capture_IAppCaptureSettings4<D>::VideoEncodingFrameRateMode() const
{
    Windows::Media::Capture::AppCaptureVideoEncodingFrameRateMode value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureSettings4)->get_VideoEncodingFrameRateMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppCaptureSettings5<D>::IsEchoCancellationEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureSettings5)->put_IsEchoCancellationEnabled(value));
}

template <typename D> bool consume_Windows_Media_Capture_IAppCaptureSettings5<D>::IsEchoCancellationEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureSettings5)->get_IsEchoCancellationEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppCaptureSettings5<D>::IsCursorImageCaptureEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureSettings5)->put_IsCursorImageCaptureEnabled(value));
}

template <typename D> bool consume_Windows_Media_Capture_IAppCaptureSettings5<D>::IsCursorImageCaptureEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureSettings5)->get_IsCursorImageCaptureEnabled(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_Capture_IAppCaptureState<D>::IsTargetRunning() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureState)->get_IsTargetRunning(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_Capture_IAppCaptureState<D>::IsHistoricalCaptureEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureState)->get_IsHistoricalCaptureEnabled(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_Capture_IAppCaptureState<D>::ShouldCaptureMicrophone() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureState)->get_ShouldCaptureMicrophone(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IAppCaptureState<D>::ShouldCaptureMicrophone(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureState)->put_ShouldCaptureMicrophone(value));
}

template <typename D> void consume_Windows_Media_Capture_IAppCaptureState<D>::RestartMicrophoneCapture() const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureState)->RestartMicrophoneCapture());
}

template <typename D> Windows::Media::Capture::AppCaptureMicrophoneCaptureState consume_Windows_Media_Capture_IAppCaptureState<D>::MicrophoneCaptureState() const
{
    Windows::Media::Capture::AppCaptureMicrophoneCaptureState value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureState)->get_MicrophoneCaptureState(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Capture_IAppCaptureState<D>::MicrophoneCaptureError() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureState)->get_MicrophoneCaptureError(&value));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Media_Capture_IAppCaptureState<D>::MicrophoneCaptureStateChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppCaptureState, Windows::Media::Capture::AppCaptureMicrophoneCaptureStateChangedEventArgs> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureState)->add_MicrophoneCaptureStateChanged(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Capture_IAppCaptureState<D>::MicrophoneCaptureStateChanged_revoker consume_Windows_Media_Capture_IAppCaptureState<D>::MicrophoneCaptureStateChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppCaptureState, Windows::Media::Capture::AppCaptureMicrophoneCaptureStateChangedEventArgs> const& value) const
{
    return impl::make_event_revoker<D, MicrophoneCaptureStateChanged_revoker>(this, MicrophoneCaptureStateChanged(value));
}

template <typename D> void consume_Windows_Media_Capture_IAppCaptureState<D>::MicrophoneCaptureStateChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Capture::IAppCaptureState)->remove_MicrophoneCaptureStateChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Capture_IAppCaptureState<D>::CaptureTargetClosed(Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppCaptureState, Windows::Foundation::IInspectable> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureState)->add_CaptureTargetClosed(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Capture_IAppCaptureState<D>::CaptureTargetClosed_revoker consume_Windows_Media_Capture_IAppCaptureState<D>::CaptureTargetClosed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppCaptureState, Windows::Foundation::IInspectable> const& value) const
{
    return impl::make_event_revoker<D, CaptureTargetClosed_revoker>(this, CaptureTargetClosed(value));
}

template <typename D> void consume_Windows_Media_Capture_IAppCaptureState<D>::CaptureTargetClosed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Capture::IAppCaptureState)->remove_CaptureTargetClosed(get_abi(token)));
}

template <typename D> Windows::Media::Capture::AppCapture consume_Windows_Media_Capture_IAppCaptureStatics<D>::GetForCurrentView() const
{
    Windows::Media::Capture::AppCapture value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureStatics)->GetForCurrentView(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_Capture_IAppCaptureStatics2<D>::SetAllowedAsync(bool allowed) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IAppCaptureStatics2)->SetAllowedAsync(allowed, put_abi(operation)));
    return operation;
}

template <typename D> Windows::Media::Capture::CameraCaptureUIPhotoCaptureSettings consume_Windows_Media_Capture_ICameraCaptureUI<D>::PhotoSettings() const
{
    Windows::Media::Capture::CameraCaptureUIPhotoCaptureSettings value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::ICameraCaptureUI)->get_PhotoSettings(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Capture::CameraCaptureUIVideoCaptureSettings consume_Windows_Media_Capture_ICameraCaptureUI<D>::VideoSettings() const
{
    Windows::Media::Capture::CameraCaptureUIVideoCaptureSettings value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::ICameraCaptureUI)->get_VideoSettings(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile> consume_Windows_Media_Capture_ICameraCaptureUI<D>::CaptureFileAsync(Windows::Media::Capture::CameraCaptureUIMode const& mode) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile> asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::ICameraCaptureUI)->CaptureFileAsync(get_abi(mode), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Media::Capture::CameraCaptureUIPhotoFormat consume_Windows_Media_Capture_ICameraCaptureUIPhotoCaptureSettings<D>::Format() const
{
    Windows::Media::Capture::CameraCaptureUIPhotoFormat value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::ICameraCaptureUIPhotoCaptureSettings)->get_Format(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_ICameraCaptureUIPhotoCaptureSettings<D>::Format(Windows::Media::Capture::CameraCaptureUIPhotoFormat const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::ICameraCaptureUIPhotoCaptureSettings)->put_Format(get_abi(value)));
}

template <typename D> Windows::Media::Capture::CameraCaptureUIMaxPhotoResolution consume_Windows_Media_Capture_ICameraCaptureUIPhotoCaptureSettings<D>::MaxResolution() const
{
    Windows::Media::Capture::CameraCaptureUIMaxPhotoResolution value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::ICameraCaptureUIPhotoCaptureSettings)->get_MaxResolution(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_ICameraCaptureUIPhotoCaptureSettings<D>::MaxResolution(Windows::Media::Capture::CameraCaptureUIMaxPhotoResolution const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::ICameraCaptureUIPhotoCaptureSettings)->put_MaxResolution(get_abi(value)));
}

template <typename D> Windows::Foundation::Size consume_Windows_Media_Capture_ICameraCaptureUIPhotoCaptureSettings<D>::CroppedSizeInPixels() const
{
    Windows::Foundation::Size value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::ICameraCaptureUIPhotoCaptureSettings)->get_CroppedSizeInPixels(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_ICameraCaptureUIPhotoCaptureSettings<D>::CroppedSizeInPixels(Windows::Foundation::Size const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::ICameraCaptureUIPhotoCaptureSettings)->put_CroppedSizeInPixels(get_abi(value)));
}

template <typename D> Windows::Foundation::Size consume_Windows_Media_Capture_ICameraCaptureUIPhotoCaptureSettings<D>::CroppedAspectRatio() const
{
    Windows::Foundation::Size value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::ICameraCaptureUIPhotoCaptureSettings)->get_CroppedAspectRatio(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_ICameraCaptureUIPhotoCaptureSettings<D>::CroppedAspectRatio(Windows::Foundation::Size const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::ICameraCaptureUIPhotoCaptureSettings)->put_CroppedAspectRatio(get_abi(value)));
}

template <typename D> bool consume_Windows_Media_Capture_ICameraCaptureUIPhotoCaptureSettings<D>::AllowCropping() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::ICameraCaptureUIPhotoCaptureSettings)->get_AllowCropping(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_ICameraCaptureUIPhotoCaptureSettings<D>::AllowCropping(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::ICameraCaptureUIPhotoCaptureSettings)->put_AllowCropping(value));
}

template <typename D> Windows::Media::Capture::CameraCaptureUIVideoFormat consume_Windows_Media_Capture_ICameraCaptureUIVideoCaptureSettings<D>::Format() const
{
    Windows::Media::Capture::CameraCaptureUIVideoFormat value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::ICameraCaptureUIVideoCaptureSettings)->get_Format(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_ICameraCaptureUIVideoCaptureSettings<D>::Format(Windows::Media::Capture::CameraCaptureUIVideoFormat const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::ICameraCaptureUIVideoCaptureSettings)->put_Format(get_abi(value)));
}

template <typename D> Windows::Media::Capture::CameraCaptureUIMaxVideoResolution consume_Windows_Media_Capture_ICameraCaptureUIVideoCaptureSettings<D>::MaxResolution() const
{
    Windows::Media::Capture::CameraCaptureUIMaxVideoResolution value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::ICameraCaptureUIVideoCaptureSettings)->get_MaxResolution(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_ICameraCaptureUIVideoCaptureSettings<D>::MaxResolution(Windows::Media::Capture::CameraCaptureUIMaxVideoResolution const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::ICameraCaptureUIVideoCaptureSettings)->put_MaxResolution(get_abi(value)));
}

template <typename D> float consume_Windows_Media_Capture_ICameraCaptureUIVideoCaptureSettings<D>::MaxDurationInSeconds() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::ICameraCaptureUIVideoCaptureSettings)->get_MaxDurationInSeconds(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_ICameraCaptureUIVideoCaptureSettings<D>::MaxDurationInSeconds(float value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::ICameraCaptureUIVideoCaptureSettings)->put_MaxDurationInSeconds(value));
}

template <typename D> bool consume_Windows_Media_Capture_ICameraCaptureUIVideoCaptureSettings<D>::AllowTrimming() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::ICameraCaptureUIVideoCaptureSettings)->get_AllowTrimming(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_ICameraCaptureUIVideoCaptureSettings<D>::AllowTrimming(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::ICameraCaptureUIVideoCaptureSettings)->put_AllowTrimming(value));
}

template <typename D> void consume_Windows_Media_Capture_ICameraOptionsUIStatics<D>::Show(Windows::Media::Capture::MediaCapture const& mediaCapture) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::ICameraOptionsUIStatics)->Show(get_abi(mediaCapture)));
}

template <typename D> uint32_t consume_Windows_Media_Capture_ICapturedFrame<D>::Width() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::ICapturedFrame)->get_Width(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Capture_ICapturedFrame<D>::Height() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::ICapturedFrame)->get_Height(&value));
    return value;
}

template <typename D> Windows::Media::Capture::CapturedFrameControlValues consume_Windows_Media_Capture_ICapturedFrame2<D>::ControlValues() const
{
    Windows::Media::Capture::CapturedFrameControlValues value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::ICapturedFrame2)->get_ControlValues(put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::Imaging::BitmapPropertySet consume_Windows_Media_Capture_ICapturedFrame2<D>::BitmapProperties() const
{
    Windows::Graphics::Imaging::BitmapPropertySet value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::ICapturedFrame2)->get_BitmapProperties(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::TimeSpan> consume_Windows_Media_Capture_ICapturedFrameControlValues<D>::Exposure() const
{
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::ICapturedFrameControlValues)->get_Exposure(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<float> consume_Windows_Media_Capture_ICapturedFrameControlValues<D>::ExposureCompensation() const
{
    Windows::Foundation::IReference<float> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::ICapturedFrameControlValues)->get_ExposureCompensation(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<uint32_t> consume_Windows_Media_Capture_ICapturedFrameControlValues<D>::IsoSpeed() const
{
    Windows::Foundation::IReference<uint32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::ICapturedFrameControlValues)->get_IsoSpeed(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<uint32_t> consume_Windows_Media_Capture_ICapturedFrameControlValues<D>::Focus() const
{
    Windows::Foundation::IReference<uint32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::ICapturedFrameControlValues)->get_Focus(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Media::Devices::CaptureSceneMode> consume_Windows_Media_Capture_ICapturedFrameControlValues<D>::SceneMode() const
{
    Windows::Foundation::IReference<Windows::Media::Devices::CaptureSceneMode> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::ICapturedFrameControlValues)->get_SceneMode(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<bool> consume_Windows_Media_Capture_ICapturedFrameControlValues<D>::Flashed() const
{
    Windows::Foundation::IReference<bool> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::ICapturedFrameControlValues)->get_Flashed(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<float> consume_Windows_Media_Capture_ICapturedFrameControlValues<D>::FlashPowerPercent() const
{
    Windows::Foundation::IReference<float> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::ICapturedFrameControlValues)->get_FlashPowerPercent(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<uint32_t> consume_Windows_Media_Capture_ICapturedFrameControlValues<D>::WhiteBalance() const
{
    Windows::Foundation::IReference<uint32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::ICapturedFrameControlValues)->get_WhiteBalance(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<float> consume_Windows_Media_Capture_ICapturedFrameControlValues<D>::ZoomFactor() const
{
    Windows::Foundation::IReference<float> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::ICapturedFrameControlValues)->get_ZoomFactor(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Media::Devices::MediaCaptureFocusState> consume_Windows_Media_Capture_ICapturedFrameControlValues2<D>::FocusState() const
{
    Windows::Foundation::IReference<Windows::Media::Devices::MediaCaptureFocusState> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::ICapturedFrameControlValues2)->get_FocusState(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<double> consume_Windows_Media_Capture_ICapturedFrameControlValues2<D>::IsoDigitalGain() const
{
    Windows::Foundation::IReference<double> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::ICapturedFrameControlValues2)->get_IsoDigitalGain(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<double> consume_Windows_Media_Capture_ICapturedFrameControlValues2<D>::IsoAnalogGain() const
{
    Windows::Foundation::IReference<double> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::ICapturedFrameControlValues2)->get_IsoAnalogGain(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::MediaProperties::MediaRatio consume_Windows_Media_Capture_ICapturedFrameControlValues2<D>::SensorFrameRate() const
{
    Windows::Media::MediaProperties::MediaRatio value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::ICapturedFrameControlValues2)->get_SensorFrameRate(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Media::Capture::WhiteBalanceGain> consume_Windows_Media_Capture_ICapturedFrameControlValues2<D>::WhiteBalanceGain() const
{
    Windows::Foundation::IReference<Windows::Media::Capture::WhiteBalanceGain> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::ICapturedFrameControlValues2)->get_WhiteBalanceGain(put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::Imaging::SoftwareBitmap consume_Windows_Media_Capture_ICapturedFrameWithSoftwareBitmap<D>::SoftwareBitmap() const
{
    Windows::Graphics::Imaging::SoftwareBitmap value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::ICapturedFrameWithSoftwareBitmap)->get_SoftwareBitmap(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Capture::CapturedFrame consume_Windows_Media_Capture_ICapturedPhoto<D>::Frame() const
{
    Windows::Media::Capture::CapturedFrame value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::ICapturedPhoto)->get_Frame(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Capture::CapturedFrame consume_Windows_Media_Capture_ICapturedPhoto<D>::Thumbnail() const
{
    Windows::Media::Capture::CapturedFrame value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::ICapturedPhoto)->get_Thumbnail(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Capture::GameBarTargetCapturePolicy consume_Windows_Media_Capture_IGameBarServices<D>::TargetCapturePolicy() const
{
    Windows::Media::Capture::GameBarTargetCapturePolicy value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IGameBarServices)->get_TargetCapturePolicy(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IGameBarServices<D>::EnableCapture() const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IGameBarServices)->EnableCapture());
}

template <typename D> void consume_Windows_Media_Capture_IGameBarServices<D>::DisableCapture() const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IGameBarServices)->DisableCapture());
}

template <typename D> Windows::Media::Capture::GameBarServicesTargetInfo consume_Windows_Media_Capture_IGameBarServices<D>::TargetInfo() const
{
    Windows::Media::Capture::GameBarServicesTargetInfo value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IGameBarServices)->get_TargetInfo(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Capture_IGameBarServices<D>::SessionId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IGameBarServices)->get_SessionId(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Capture::AppBroadcastServices consume_Windows_Media_Capture_IGameBarServices<D>::AppBroadcastServices() const
{
    Windows::Media::Capture::AppBroadcastServices value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IGameBarServices)->get_AppBroadcastServices(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Capture::AppCaptureServices consume_Windows_Media_Capture_IGameBarServices<D>::AppCaptureServices() const
{
    Windows::Media::Capture::AppCaptureServices value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IGameBarServices)->get_AppCaptureServices(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Media_Capture_IGameBarServices<D>::CommandReceived(Windows::Foundation::TypedEventHandler<Windows::Media::Capture::GameBarServices, Windows::Media::Capture::GameBarServicesCommandEventArgs> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IGameBarServices)->add_CommandReceived(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Capture_IGameBarServices<D>::CommandReceived_revoker consume_Windows_Media_Capture_IGameBarServices<D>::CommandReceived(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Capture::GameBarServices, Windows::Media::Capture::GameBarServicesCommandEventArgs> const& value) const
{
    return impl::make_event_revoker<D, CommandReceived_revoker>(this, CommandReceived(value));
}

template <typename D> void consume_Windows_Media_Capture_IGameBarServices<D>::CommandReceived(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Capture::IGameBarServices)->remove_CommandReceived(get_abi(token)));
}

template <typename D> Windows::Media::Capture::GameBarCommand consume_Windows_Media_Capture_IGameBarServicesCommandEventArgs<D>::Command() const
{
    Windows::Media::Capture::GameBarCommand value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IGameBarServicesCommandEventArgs)->get_Command(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Capture::GameBarCommandOrigin consume_Windows_Media_Capture_IGameBarServicesCommandEventArgs<D>::Origin() const
{
    Windows::Media::Capture::GameBarCommandOrigin value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IGameBarServicesCommandEventArgs)->get_Origin(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Media_Capture_IGameBarServicesManager<D>::GameBarServicesCreated(Windows::Foundation::TypedEventHandler<Windows::Media::Capture::GameBarServicesManager, Windows::Media::Capture::GameBarServicesManagerGameBarServicesCreatedEventArgs> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IGameBarServicesManager)->add_GameBarServicesCreated(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Capture_IGameBarServicesManager<D>::GameBarServicesCreated_revoker consume_Windows_Media_Capture_IGameBarServicesManager<D>::GameBarServicesCreated(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Capture::GameBarServicesManager, Windows::Media::Capture::GameBarServicesManagerGameBarServicesCreatedEventArgs> const& value) const
{
    return impl::make_event_revoker<D, GameBarServicesCreated_revoker>(this, GameBarServicesCreated(value));
}

template <typename D> void consume_Windows_Media_Capture_IGameBarServicesManager<D>::GameBarServicesCreated(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Capture::IGameBarServicesManager)->remove_GameBarServicesCreated(get_abi(token)));
}

template <typename D> Windows::Media::Capture::GameBarServices consume_Windows_Media_Capture_IGameBarServicesManagerGameBarServicesCreatedEventArgs<D>::GameBarServices() const
{
    Windows::Media::Capture::GameBarServices value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IGameBarServicesManagerGameBarServicesCreatedEventArgs)->get_GameBarServices(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Capture::GameBarServicesManager consume_Windows_Media_Capture_IGameBarServicesManagerStatics<D>::GetDefault() const
{
    Windows::Media::Capture::GameBarServicesManager ppInstance{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IGameBarServicesManagerStatics)->GetDefault(put_abi(ppInstance)));
    return ppInstance;
}

template <typename D> hstring consume_Windows_Media_Capture_IGameBarServicesTargetInfo<D>::DisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IGameBarServicesTargetInfo)->get_DisplayName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Capture_IGameBarServicesTargetInfo<D>::AppId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IGameBarServicesTargetInfo)->get_AppId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Capture_IGameBarServicesTargetInfo<D>::TitleId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IGameBarServicesTargetInfo)->get_TitleId(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Capture::GameBarServicesDisplayMode consume_Windows_Media_Capture_IGameBarServicesTargetInfo<D>::DisplayMode() const
{
    Windows::Media::Capture::GameBarServicesDisplayMode value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IGameBarServicesTargetInfo)->get_DisplayMode(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_Capture_ILowLagMediaRecording<D>::StartAsync() const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::ILowLagMediaRecording)->StartAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_Capture_ILowLagMediaRecording<D>::StopAsync() const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::ILowLagMediaRecording)->StopAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_Capture_ILowLagMediaRecording<D>::FinishAsync() const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::ILowLagMediaRecording)->FinishAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_Capture_ILowLagMediaRecording2<D>::PauseAsync(Windows::Media::Devices::MediaCapturePauseBehavior const& behavior) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::ILowLagMediaRecording2)->PauseAsync(get_abi(behavior), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_Capture_ILowLagMediaRecording2<D>::ResumeAsync() const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::ILowLagMediaRecording2)->ResumeAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::Capture::MediaCapturePauseResult> consume_Windows_Media_Capture_ILowLagMediaRecording3<D>::PauseWithResultAsync(Windows::Media::Devices::MediaCapturePauseBehavior const& behavior) const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::Capture::MediaCapturePauseResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::ILowLagMediaRecording3)->PauseWithResultAsync(get_abi(behavior), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::Capture::MediaCaptureStopResult> consume_Windows_Media_Capture_ILowLagMediaRecording3<D>::StopWithResultAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::Capture::MediaCaptureStopResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::ILowLagMediaRecording3)->StopWithResultAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::Capture::CapturedPhoto> consume_Windows_Media_Capture_ILowLagPhotoCapture<D>::CaptureAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::Capture::CapturedPhoto> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::ILowLagPhotoCapture)->CaptureAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_Capture_ILowLagPhotoCapture<D>::FinishAsync() const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::ILowLagPhotoCapture)->FinishAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_Capture_ILowLagPhotoSequenceCapture<D>::StartAsync() const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::ILowLagPhotoSequenceCapture)->StartAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_Capture_ILowLagPhotoSequenceCapture<D>::StopAsync() const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::ILowLagPhotoSequenceCapture)->StopAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_Capture_ILowLagPhotoSequenceCapture<D>::FinishAsync() const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::ILowLagPhotoSequenceCapture)->FinishAsync(put_abi(operation)));
    return operation;
}

template <typename D> winrt::event_token consume_Windows_Media_Capture_ILowLagPhotoSequenceCapture<D>::PhotoCaptured(Windows::Foundation::TypedEventHandler<Windows::Media::Capture::LowLagPhotoSequenceCapture, Windows::Media::Capture::PhotoCapturedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::ILowLagPhotoSequenceCapture)->add_PhotoCaptured(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Capture_ILowLagPhotoSequenceCapture<D>::PhotoCaptured_revoker consume_Windows_Media_Capture_ILowLagPhotoSequenceCapture<D>::PhotoCaptured(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Capture::LowLagPhotoSequenceCapture, Windows::Media::Capture::PhotoCapturedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, PhotoCaptured_revoker>(this, PhotoCaptured(handler));
}

template <typename D> void consume_Windows_Media_Capture_ILowLagPhotoSequenceCapture<D>::PhotoCaptured(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Capture::ILowLagPhotoSequenceCapture)->remove_PhotoCaptured(get_abi(token)));
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_Capture_IMediaCapture<D>::InitializeAsync() const
{
    Windows::Foundation::IAsyncAction asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCapture)->InitializeAsync(put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_Capture_IMediaCapture<D>::InitializeAsync(Windows::Media::Capture::MediaCaptureInitializationSettings const& mediaCaptureInitializationSettings) const
{
    Windows::Foundation::IAsyncAction asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCapture)->InitializeWithSettingsAsync(get_abi(mediaCaptureInitializationSettings), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_Capture_IMediaCapture<D>::StartRecordToStorageFileAsync(Windows::Media::MediaProperties::MediaEncodingProfile const& encodingProfile, Windows::Storage::IStorageFile const& file) const
{
    Windows::Foundation::IAsyncAction asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCapture)->StartRecordToStorageFileAsync(get_abi(encodingProfile), get_abi(file), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_Capture_IMediaCapture<D>::StartRecordToStreamAsync(Windows::Media::MediaProperties::MediaEncodingProfile const& encodingProfile, Windows::Storage::Streams::IRandomAccessStream const& stream) const
{
    Windows::Foundation::IAsyncAction asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCapture)->StartRecordToStreamAsync(get_abi(encodingProfile), get_abi(stream), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_Capture_IMediaCapture<D>::StartRecordToCustomSinkAsync(Windows::Media::MediaProperties::MediaEncodingProfile const& encodingProfile, Windows::Media::IMediaExtension const& customMediaSink) const
{
    Windows::Foundation::IAsyncAction asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCapture)->StartRecordToCustomSinkAsync(get_abi(encodingProfile), get_abi(customMediaSink), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_Capture_IMediaCapture<D>::StartRecordToCustomSinkAsync(Windows::Media::MediaProperties::MediaEncodingProfile const& encodingProfile, param::hstring const& customSinkActivationId, Windows::Foundation::Collections::IPropertySet const& customSinkSettings) const
{
    Windows::Foundation::IAsyncAction asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCapture)->StartRecordToCustomSinkIdAsync(get_abi(encodingProfile), get_abi(customSinkActivationId), get_abi(customSinkSettings), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_Capture_IMediaCapture<D>::StopRecordAsync() const
{
    Windows::Foundation::IAsyncAction asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCapture)->StopRecordAsync(put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_Capture_IMediaCapture<D>::CapturePhotoToStorageFileAsync(Windows::Media::MediaProperties::ImageEncodingProperties const& type, Windows::Storage::IStorageFile const& file) const
{
    Windows::Foundation::IAsyncAction asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCapture)->CapturePhotoToStorageFileAsync(get_abi(type), get_abi(file), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_Capture_IMediaCapture<D>::CapturePhotoToStreamAsync(Windows::Media::MediaProperties::ImageEncodingProperties const& type, Windows::Storage::Streams::IRandomAccessStream const& stream) const
{
    Windows::Foundation::IAsyncAction asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCapture)->CapturePhotoToStreamAsync(get_abi(type), get_abi(stream), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_Capture_IMediaCapture<D>::AddEffectAsync(Windows::Media::Capture::MediaStreamType const& mediaStreamType, param::hstring const& effectActivationID, Windows::Foundation::Collections::IPropertySet const& effectSettings) const
{
    Windows::Foundation::IAsyncAction asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCapture)->AddEffectAsync(get_abi(mediaStreamType), get_abi(effectActivationID), get_abi(effectSettings), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_Capture_IMediaCapture<D>::ClearEffectsAsync(Windows::Media::Capture::MediaStreamType const& mediaStreamType) const
{
    Windows::Foundation::IAsyncAction asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCapture)->ClearEffectsAsync(get_abi(mediaStreamType), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> void consume_Windows_Media_Capture_IMediaCapture<D>::SetEncoderProperty(Windows::Media::Capture::MediaStreamType const& mediaStreamType, winrt::guid const& propertyId, Windows::Foundation::IInspectable const& propertyValue) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCapture)->SetEncoderProperty(get_abi(mediaStreamType), get_abi(propertyId), get_abi(propertyValue)));
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_Media_Capture_IMediaCapture<D>::GetEncoderProperty(Windows::Media::Capture::MediaStreamType const& mediaStreamType, winrt::guid const& propertyId) const
{
    Windows::Foundation::IInspectable propertyValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCapture)->GetEncoderProperty(get_abi(mediaStreamType), get_abi(propertyId), put_abi(propertyValue)));
    return propertyValue;
}

template <typename D> winrt::event_token consume_Windows_Media_Capture_IMediaCapture<D>::Failed(Windows::Media::Capture::MediaCaptureFailedEventHandler const& errorEventHandler) const
{
    winrt::event_token eventCookie{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCapture)->add_Failed(get_abi(errorEventHandler), put_abi(eventCookie)));
    return eventCookie;
}

template <typename D> typename consume_Windows_Media_Capture_IMediaCapture<D>::Failed_revoker consume_Windows_Media_Capture_IMediaCapture<D>::Failed(auto_revoke_t, Windows::Media::Capture::MediaCaptureFailedEventHandler const& errorEventHandler) const
{
    return impl::make_event_revoker<D, Failed_revoker>(this, Failed(errorEventHandler));
}

template <typename D> void consume_Windows_Media_Capture_IMediaCapture<D>::Failed(winrt::event_token const& eventCookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Capture::IMediaCapture)->remove_Failed(get_abi(eventCookie)));
}

template <typename D> winrt::event_token consume_Windows_Media_Capture_IMediaCapture<D>::RecordLimitationExceeded(Windows::Media::Capture::RecordLimitationExceededEventHandler const& recordLimitationExceededEventHandler) const
{
    winrt::event_token eventCookie{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCapture)->add_RecordLimitationExceeded(get_abi(recordLimitationExceededEventHandler), put_abi(eventCookie)));
    return eventCookie;
}

template <typename D> typename consume_Windows_Media_Capture_IMediaCapture<D>::RecordLimitationExceeded_revoker consume_Windows_Media_Capture_IMediaCapture<D>::RecordLimitationExceeded(auto_revoke_t, Windows::Media::Capture::RecordLimitationExceededEventHandler const& recordLimitationExceededEventHandler) const
{
    return impl::make_event_revoker<D, RecordLimitationExceeded_revoker>(this, RecordLimitationExceeded(recordLimitationExceededEventHandler));
}

template <typename D> void consume_Windows_Media_Capture_IMediaCapture<D>::RecordLimitationExceeded(winrt::event_token const& eventCookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Capture::IMediaCapture)->remove_RecordLimitationExceeded(get_abi(eventCookie)));
}

template <typename D> Windows::Media::Capture::MediaCaptureSettings consume_Windows_Media_Capture_IMediaCapture<D>::MediaCaptureSettings() const
{
    Windows::Media::Capture::MediaCaptureSettings value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCapture)->get_MediaCaptureSettings(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Devices::AudioDeviceController consume_Windows_Media_Capture_IMediaCapture<D>::AudioDeviceController() const
{
    Windows::Media::Devices::AudioDeviceController value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCapture)->get_AudioDeviceController(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Devices::VideoDeviceController consume_Windows_Media_Capture_IMediaCapture<D>::VideoDeviceController() const
{
    Windows::Media::Devices::VideoDeviceController value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCapture)->get_VideoDeviceController(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IMediaCapture<D>::SetPreviewMirroring(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCapture)->SetPreviewMirroring(value));
}

template <typename D> bool consume_Windows_Media_Capture_IMediaCapture<D>::GetPreviewMirroring() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCapture)->GetPreviewMirroring(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IMediaCapture<D>::SetPreviewRotation(Windows::Media::Capture::VideoRotation const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCapture)->SetPreviewRotation(get_abi(value)));
}

template <typename D> Windows::Media::Capture::VideoRotation consume_Windows_Media_Capture_IMediaCapture<D>::GetPreviewRotation() const
{
    Windows::Media::Capture::VideoRotation value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCapture)->GetPreviewRotation(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IMediaCapture<D>::SetRecordRotation(Windows::Media::Capture::VideoRotation const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCapture)->SetRecordRotation(get_abi(value)));
}

template <typename D> Windows::Media::Capture::VideoRotation consume_Windows_Media_Capture_IMediaCapture<D>::GetRecordRotation() const
{
    Windows::Media::Capture::VideoRotation value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCapture)->GetRecordRotation(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::Capture::LowLagMediaRecording> consume_Windows_Media_Capture_IMediaCapture2<D>::PrepareLowLagRecordToStorageFileAsync(Windows::Media::MediaProperties::MediaEncodingProfile const& encodingProfile, Windows::Storage::IStorageFile const& file) const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::Capture::LowLagMediaRecording> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCapture2)->PrepareLowLagRecordToStorageFileAsync(get_abi(encodingProfile), get_abi(file), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::Capture::LowLagMediaRecording> consume_Windows_Media_Capture_IMediaCapture2<D>::PrepareLowLagRecordToStreamAsync(Windows::Media::MediaProperties::MediaEncodingProfile const& encodingProfile, Windows::Storage::Streams::IRandomAccessStream const& stream) const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::Capture::LowLagMediaRecording> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCapture2)->PrepareLowLagRecordToStreamAsync(get_abi(encodingProfile), get_abi(stream), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::Capture::LowLagMediaRecording> consume_Windows_Media_Capture_IMediaCapture2<D>::PrepareLowLagRecordToCustomSinkAsync(Windows::Media::MediaProperties::MediaEncodingProfile const& encodingProfile, Windows::Media::IMediaExtension const& customMediaSink) const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::Capture::LowLagMediaRecording> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCapture2)->PrepareLowLagRecordToCustomSinkAsync(get_abi(encodingProfile), get_abi(customMediaSink), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::Capture::LowLagMediaRecording> consume_Windows_Media_Capture_IMediaCapture2<D>::PrepareLowLagRecordToCustomSinkAsync(Windows::Media::MediaProperties::MediaEncodingProfile const& encodingProfile, param::hstring const& customSinkActivationId, Windows::Foundation::Collections::IPropertySet const& customSinkSettings) const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::Capture::LowLagMediaRecording> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCapture2)->PrepareLowLagRecordToCustomSinkIdAsync(get_abi(encodingProfile), get_abi(customSinkActivationId), get_abi(customSinkSettings), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::Capture::LowLagPhotoCapture> consume_Windows_Media_Capture_IMediaCapture2<D>::PrepareLowLagPhotoCaptureAsync(Windows::Media::MediaProperties::ImageEncodingProperties const& type) const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::Capture::LowLagPhotoCapture> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCapture2)->PrepareLowLagPhotoCaptureAsync(get_abi(type), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::Capture::LowLagPhotoSequenceCapture> consume_Windows_Media_Capture_IMediaCapture2<D>::PrepareLowLagPhotoSequenceCaptureAsync(Windows::Media::MediaProperties::ImageEncodingProperties const& type) const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::Capture::LowLagPhotoSequenceCapture> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCapture2)->PrepareLowLagPhotoSequenceCaptureAsync(get_abi(type), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_Capture_IMediaCapture2<D>::SetEncodingPropertiesAsync(Windows::Media::Capture::MediaStreamType const& mediaStreamType, Windows::Media::MediaProperties::IMediaEncodingProperties const& mediaEncodingProperties, Windows::Media::MediaProperties::MediaPropertySet const& encoderProperties) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCapture2)->SetEncodingPropertiesAsync(get_abi(mediaStreamType), get_abi(mediaEncodingProperties), get_abi(encoderProperties), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::Capture::Core::VariablePhotoSequenceCapture> consume_Windows_Media_Capture_IMediaCapture3<D>::PrepareVariablePhotoSequenceCaptureAsync(Windows::Media::MediaProperties::ImageEncodingProperties const& type) const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::Capture::Core::VariablePhotoSequenceCapture> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCapture3)->PrepareVariablePhotoSequenceCaptureAsync(get_abi(type), put_abi(operation)));
    return operation;
}

template <typename D> winrt::event_token consume_Windows_Media_Capture_IMediaCapture3<D>::FocusChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Capture::MediaCapture, Windows::Media::Capture::MediaCaptureFocusChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCapture3)->add_FocusChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Capture_IMediaCapture3<D>::FocusChanged_revoker consume_Windows_Media_Capture_IMediaCapture3<D>::FocusChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Capture::MediaCapture, Windows::Media::Capture::MediaCaptureFocusChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, FocusChanged_revoker>(this, FocusChanged(handler));
}

template <typename D> void consume_Windows_Media_Capture_IMediaCapture3<D>::FocusChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Capture::IMediaCapture3)->remove_FocusChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Media_Capture_IMediaCapture3<D>::PhotoConfirmationCaptured(Windows::Foundation::TypedEventHandler<Windows::Media::Capture::MediaCapture, Windows::Media::Capture::PhotoConfirmationCapturedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCapture3)->add_PhotoConfirmationCaptured(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Capture_IMediaCapture3<D>::PhotoConfirmationCaptured_revoker consume_Windows_Media_Capture_IMediaCapture3<D>::PhotoConfirmationCaptured(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Capture::MediaCapture, Windows::Media::Capture::PhotoConfirmationCapturedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, PhotoConfirmationCaptured_revoker>(this, PhotoConfirmationCaptured(handler));
}

template <typename D> void consume_Windows_Media_Capture_IMediaCapture3<D>::PhotoConfirmationCaptured(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Capture::IMediaCapture3)->remove_PhotoConfirmationCaptured(get_abi(token)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::IMediaExtension> consume_Windows_Media_Capture_IMediaCapture4<D>::AddAudioEffectAsync(Windows::Media::Effects::IAudioEffectDefinition const& definition) const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::IMediaExtension> op{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCapture4)->AddAudioEffectAsync(get_abi(definition), put_abi(op)));
    return op;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::IMediaExtension> consume_Windows_Media_Capture_IMediaCapture4<D>::AddVideoEffectAsync(Windows::Media::Effects::IVideoEffectDefinition const& definition, Windows::Media::Capture::MediaStreamType const& mediaStreamType) const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::IMediaExtension> op{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCapture4)->AddVideoEffectAsync(get_abi(definition), get_abi(mediaStreamType), put_abi(op)));
    return op;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_Capture_IMediaCapture4<D>::PauseRecordAsync(Windows::Media::Devices::MediaCapturePauseBehavior const& behavior) const
{
    Windows::Foundation::IAsyncAction asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCapture4)->PauseRecordAsync(get_abi(behavior), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_Capture_IMediaCapture4<D>::ResumeRecordAsync() const
{
    Windows::Foundation::IAsyncAction asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCapture4)->ResumeRecordAsync(put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> winrt::event_token consume_Windows_Media_Capture_IMediaCapture4<D>::CameraStreamStateChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Capture::MediaCapture, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCapture4)->add_CameraStreamStateChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Capture_IMediaCapture4<D>::CameraStreamStateChanged_revoker consume_Windows_Media_Capture_IMediaCapture4<D>::CameraStreamStateChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Capture::MediaCapture, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, CameraStreamStateChanged_revoker>(this, CameraStreamStateChanged(handler));
}

template <typename D> void consume_Windows_Media_Capture_IMediaCapture4<D>::CameraStreamStateChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Capture::IMediaCapture4)->remove_CameraStreamStateChanged(get_abi(token)));
}

template <typename D> Windows::Media::Devices::CameraStreamState consume_Windows_Media_Capture_IMediaCapture4<D>::CameraStreamState() const
{
    Windows::Media::Devices::CameraStreamState streamState{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCapture4)->get_CameraStreamState(put_abi(streamState)));
    return streamState;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::VideoFrame> consume_Windows_Media_Capture_IMediaCapture4<D>::GetPreviewFrameAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::VideoFrame> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCapture4)->GetPreviewFrameAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::VideoFrame> consume_Windows_Media_Capture_IMediaCapture4<D>::GetPreviewFrameAsync(Windows::Media::VideoFrame const& destination) const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::VideoFrame> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCapture4)->GetPreviewFrameCopyAsync(get_abi(destination), put_abi(operation)));
    return operation;
}

template <typename D> winrt::event_token consume_Windows_Media_Capture_IMediaCapture4<D>::ThermalStatusChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Capture::MediaCapture, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCapture4)->add_ThermalStatusChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Capture_IMediaCapture4<D>::ThermalStatusChanged_revoker consume_Windows_Media_Capture_IMediaCapture4<D>::ThermalStatusChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Capture::MediaCapture, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, ThermalStatusChanged_revoker>(this, ThermalStatusChanged(handler));
}

template <typename D> void consume_Windows_Media_Capture_IMediaCapture4<D>::ThermalStatusChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Capture::IMediaCapture4)->remove_ThermalStatusChanged(get_abi(token)));
}

template <typename D> Windows::Media::Capture::MediaCaptureThermalStatus consume_Windows_Media_Capture_IMediaCapture4<D>::ThermalStatus() const
{
    Windows::Media::Capture::MediaCaptureThermalStatus value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCapture4)->get_ThermalStatus(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::Capture::AdvancedPhotoCapture> consume_Windows_Media_Capture_IMediaCapture4<D>::PrepareAdvancedPhotoCaptureAsync(Windows::Media::MediaProperties::ImageEncodingProperties const& encodingProperties) const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::Capture::AdvancedPhotoCapture> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCapture4)->PrepareAdvancedPhotoCaptureAsync(get_abi(encodingProperties), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_Capture_IMediaCapture5<D>::RemoveEffectAsync(Windows::Media::IMediaExtension const& effect) const
{
    Windows::Foundation::IAsyncAction asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCapture5)->RemoveEffectAsync(get_abi(effect), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::Capture::MediaCapturePauseResult> consume_Windows_Media_Capture_IMediaCapture5<D>::PauseRecordWithResultAsync(Windows::Media::Devices::MediaCapturePauseBehavior const& behavior) const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::Capture::MediaCapturePauseResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCapture5)->PauseRecordWithResultAsync(get_abi(behavior), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::Capture::MediaCaptureStopResult> consume_Windows_Media_Capture_IMediaCapture5<D>::StopRecordWithResultAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::Capture::MediaCaptureStopResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCapture5)->StopRecordWithResultAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::Collections::IMapView<hstring, Windows::Media::Capture::Frames::MediaFrameSource> consume_Windows_Media_Capture_IMediaCapture5<D>::FrameSources() const
{
    Windows::Foundation::Collections::IMapView<hstring, Windows::Media::Capture::Frames::MediaFrameSource> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCapture5)->get_FrameSources(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::Capture::Frames::MediaFrameReader> consume_Windows_Media_Capture_IMediaCapture5<D>::CreateFrameReaderAsync(Windows::Media::Capture::Frames::MediaFrameSource const& inputSource) const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::Capture::Frames::MediaFrameReader> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCapture5)->CreateFrameReaderAsync(get_abi(inputSource), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::Capture::Frames::MediaFrameReader> consume_Windows_Media_Capture_IMediaCapture5<D>::CreateFrameReaderAsync(Windows::Media::Capture::Frames::MediaFrameSource const& inputSource, param::hstring const& outputSubtype) const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::Capture::Frames::MediaFrameReader> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCapture5)->CreateFrameReaderWithSubtypeAsync(get_abi(inputSource), get_abi(outputSubtype), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::Capture::Frames::MediaFrameReader> consume_Windows_Media_Capture_IMediaCapture5<D>::CreateFrameReaderAsync(Windows::Media::Capture::Frames::MediaFrameSource const& inputSource, param::hstring const& outputSubtype, Windows::Graphics::Imaging::BitmapSize const& outputSize) const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::Capture::Frames::MediaFrameReader> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCapture5)->CreateFrameReaderWithSubtypeAndSizeAsync(get_abi(inputSource), get_abi(outputSubtype), get_abi(outputSize), put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Media_Capture_IMediaCapture6<D>::CaptureDeviceExclusiveControlStatusChanged(Windows::Foundation::TypedEventHandler<Windows::Media::Capture::MediaCapture, Windows::Media::Capture::MediaCaptureDeviceExclusiveControlStatusChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCapture6)->add_CaptureDeviceExclusiveControlStatusChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_Capture_IMediaCapture6<D>::CaptureDeviceExclusiveControlStatusChanged_revoker consume_Windows_Media_Capture_IMediaCapture6<D>::CaptureDeviceExclusiveControlStatusChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Media::Capture::MediaCapture, Windows::Media::Capture::MediaCaptureDeviceExclusiveControlStatusChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, CaptureDeviceExclusiveControlStatusChanged_revoker>(this, CaptureDeviceExclusiveControlStatusChanged(handler));
}

template <typename D> void consume_Windows_Media_Capture_IMediaCapture6<D>::CaptureDeviceExclusiveControlStatusChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::Capture::IMediaCapture6)->remove_CaptureDeviceExclusiveControlStatusChanged(get_abi(token)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::Capture::Frames::MultiSourceMediaFrameReader> consume_Windows_Media_Capture_IMediaCapture6<D>::CreateMultiSourceFrameReaderAsync(param::async_iterable<Windows::Media::Capture::Frames::MediaFrameSource> const& inputSources) const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::Capture::Frames::MultiSourceMediaFrameReader> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCapture6)->CreateMultiSourceFrameReaderAsync(get_abi(inputSources), put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Capture_IMediaCaptureDeviceExclusiveControlStatusChangedEventArgs<D>::DeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureDeviceExclusiveControlStatusChangedEventArgs)->get_DeviceId(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Capture::MediaCaptureDeviceExclusiveControlStatus consume_Windows_Media_Capture_IMediaCaptureDeviceExclusiveControlStatusChangedEventArgs<D>::Status() const
{
    Windows::Media::Capture::MediaCaptureDeviceExclusiveControlStatus value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureDeviceExclusiveControlStatusChangedEventArgs)->get_Status(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Capture_IMediaCaptureFailedEventArgs<D>::Message() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureFailedEventArgs)->get_Message(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Capture_IMediaCaptureFailedEventArgs<D>::Code() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureFailedEventArgs)->get_Code(&value));
    return value;
}

template <typename D> Windows::Media::Devices::MediaCaptureFocusState consume_Windows_Media_Capture_IMediaCaptureFocusChangedEventArgs<D>::FocusState() const
{
    Windows::Media::Devices::MediaCaptureFocusState value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureFocusChangedEventArgs)->get_FocusState(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IMediaCaptureInitializationSettings<D>::AudioDeviceId(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureInitializationSettings)->put_AudioDeviceId(get_abi(value)));
}

template <typename D> hstring consume_Windows_Media_Capture_IMediaCaptureInitializationSettings<D>::AudioDeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureInitializationSettings)->get_AudioDeviceId(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IMediaCaptureInitializationSettings<D>::VideoDeviceId(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureInitializationSettings)->put_VideoDeviceId(get_abi(value)));
}

template <typename D> hstring consume_Windows_Media_Capture_IMediaCaptureInitializationSettings<D>::VideoDeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureInitializationSettings)->get_VideoDeviceId(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IMediaCaptureInitializationSettings<D>::StreamingCaptureMode(Windows::Media::Capture::StreamingCaptureMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureInitializationSettings)->put_StreamingCaptureMode(get_abi(value)));
}

template <typename D> Windows::Media::Capture::StreamingCaptureMode consume_Windows_Media_Capture_IMediaCaptureInitializationSettings<D>::StreamingCaptureMode() const
{
    Windows::Media::Capture::StreamingCaptureMode value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureInitializationSettings)->get_StreamingCaptureMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IMediaCaptureInitializationSettings<D>::PhotoCaptureSource(Windows::Media::Capture::PhotoCaptureSource const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureInitializationSettings)->put_PhotoCaptureSource(get_abi(value)));
}

template <typename D> Windows::Media::Capture::PhotoCaptureSource consume_Windows_Media_Capture_IMediaCaptureInitializationSettings<D>::PhotoCaptureSource() const
{
    Windows::Media::Capture::PhotoCaptureSource value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureInitializationSettings)->get_PhotoCaptureSource(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IMediaCaptureInitializationSettings2<D>::MediaCategory(Windows::Media::Capture::MediaCategory const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureInitializationSettings2)->put_MediaCategory(get_abi(value)));
}

template <typename D> Windows::Media::Capture::MediaCategory consume_Windows_Media_Capture_IMediaCaptureInitializationSettings2<D>::MediaCategory() const
{
    Windows::Media::Capture::MediaCategory value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureInitializationSettings2)->get_MediaCategory(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IMediaCaptureInitializationSettings2<D>::AudioProcessing(Windows::Media::AudioProcessing const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureInitializationSettings2)->put_AudioProcessing(get_abi(value)));
}

template <typename D> Windows::Media::AudioProcessing consume_Windows_Media_Capture_IMediaCaptureInitializationSettings2<D>::AudioProcessing() const
{
    Windows::Media::AudioProcessing value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureInitializationSettings2)->get_AudioProcessing(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IMediaCaptureInitializationSettings3<D>::AudioSource(Windows::Media::Core::IMediaSource const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureInitializationSettings3)->put_AudioSource(get_abi(value)));
}

template <typename D> Windows::Media::Core::IMediaSource consume_Windows_Media_Capture_IMediaCaptureInitializationSettings3<D>::AudioSource() const
{
    Windows::Media::Core::IMediaSource value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureInitializationSettings3)->get_AudioSource(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IMediaCaptureInitializationSettings3<D>::VideoSource(Windows::Media::Core::IMediaSource const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureInitializationSettings3)->put_VideoSource(get_abi(value)));
}

template <typename D> Windows::Media::Core::IMediaSource consume_Windows_Media_Capture_IMediaCaptureInitializationSettings3<D>::VideoSource() const
{
    Windows::Media::Core::IMediaSource value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureInitializationSettings3)->get_VideoSource(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Capture::MediaCaptureVideoProfile consume_Windows_Media_Capture_IMediaCaptureInitializationSettings4<D>::VideoProfile() const
{
    Windows::Media::Capture::MediaCaptureVideoProfile value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureInitializationSettings4)->get_VideoProfile(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IMediaCaptureInitializationSettings4<D>::VideoProfile(Windows::Media::Capture::MediaCaptureVideoProfile const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureInitializationSettings4)->put_VideoProfile(get_abi(value)));
}

template <typename D> Windows::Media::Capture::MediaCaptureVideoProfileMediaDescription consume_Windows_Media_Capture_IMediaCaptureInitializationSettings4<D>::PreviewMediaDescription() const
{
    Windows::Media::Capture::MediaCaptureVideoProfileMediaDescription value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureInitializationSettings4)->get_PreviewMediaDescription(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IMediaCaptureInitializationSettings4<D>::PreviewMediaDescription(Windows::Media::Capture::MediaCaptureVideoProfileMediaDescription const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureInitializationSettings4)->put_PreviewMediaDescription(get_abi(value)));
}

template <typename D> Windows::Media::Capture::MediaCaptureVideoProfileMediaDescription consume_Windows_Media_Capture_IMediaCaptureInitializationSettings4<D>::RecordMediaDescription() const
{
    Windows::Media::Capture::MediaCaptureVideoProfileMediaDescription value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureInitializationSettings4)->get_RecordMediaDescription(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IMediaCaptureInitializationSettings4<D>::RecordMediaDescription(Windows::Media::Capture::MediaCaptureVideoProfileMediaDescription const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureInitializationSettings4)->put_RecordMediaDescription(get_abi(value)));
}

template <typename D> Windows::Media::Capture::MediaCaptureVideoProfileMediaDescription consume_Windows_Media_Capture_IMediaCaptureInitializationSettings4<D>::PhotoMediaDescription() const
{
    Windows::Media::Capture::MediaCaptureVideoProfileMediaDescription value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureInitializationSettings4)->get_PhotoMediaDescription(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IMediaCaptureInitializationSettings4<D>::PhotoMediaDescription(Windows::Media::Capture::MediaCaptureVideoProfileMediaDescription const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureInitializationSettings4)->put_PhotoMediaDescription(get_abi(value)));
}

template <typename D> Windows::Media::Capture::Frames::MediaFrameSourceGroup consume_Windows_Media_Capture_IMediaCaptureInitializationSettings5<D>::SourceGroup() const
{
    Windows::Media::Capture::Frames::MediaFrameSourceGroup value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureInitializationSettings5)->get_SourceGroup(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IMediaCaptureInitializationSettings5<D>::SourceGroup(Windows::Media::Capture::Frames::MediaFrameSourceGroup const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureInitializationSettings5)->put_SourceGroup(get_abi(value)));
}

template <typename D> Windows::Media::Capture::MediaCaptureSharingMode consume_Windows_Media_Capture_IMediaCaptureInitializationSettings5<D>::SharingMode() const
{
    Windows::Media::Capture::MediaCaptureSharingMode value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureInitializationSettings5)->get_SharingMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IMediaCaptureInitializationSettings5<D>::SharingMode(Windows::Media::Capture::MediaCaptureSharingMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureInitializationSettings5)->put_SharingMode(get_abi(value)));
}

template <typename D> Windows::Media::Capture::MediaCaptureMemoryPreference consume_Windows_Media_Capture_IMediaCaptureInitializationSettings5<D>::MemoryPreference() const
{
    Windows::Media::Capture::MediaCaptureMemoryPreference value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureInitializationSettings5)->get_MemoryPreference(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IMediaCaptureInitializationSettings5<D>::MemoryPreference(Windows::Media::Capture::MediaCaptureMemoryPreference const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureInitializationSettings5)->put_MemoryPreference(get_abi(value)));
}

template <typename D> bool consume_Windows_Media_Capture_IMediaCaptureInitializationSettings6<D>::AlwaysPlaySystemShutterSound() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureInitializationSettings6)->get_AlwaysPlaySystemShutterSound(&value));
    return value;
}

template <typename D> void consume_Windows_Media_Capture_IMediaCaptureInitializationSettings6<D>::AlwaysPlaySystemShutterSound(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureInitializationSettings6)->put_AlwaysPlaySystemShutterSound(value));
}

template <typename D> Windows::Media::VideoFrame consume_Windows_Media_Capture_IMediaCapturePauseResult<D>::LastFrame() const
{
    Windows::Media::VideoFrame value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCapturePauseResult)->get_LastFrame(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_Capture_IMediaCapturePauseResult<D>::RecordDuration() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCapturePauseResult)->get_RecordDuration(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Capture_IMediaCaptureSettings<D>::AudioDeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureSettings)->get_AudioDeviceId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Capture_IMediaCaptureSettings<D>::VideoDeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureSettings)->get_VideoDeviceId(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Capture::StreamingCaptureMode consume_Windows_Media_Capture_IMediaCaptureSettings<D>::StreamingCaptureMode() const
{
    Windows::Media::Capture::StreamingCaptureMode value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureSettings)->get_StreamingCaptureMode(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Capture::PhotoCaptureSource consume_Windows_Media_Capture_IMediaCaptureSettings<D>::PhotoCaptureSource() const
{
    Windows::Media::Capture::PhotoCaptureSource value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureSettings)->get_PhotoCaptureSource(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Capture::VideoDeviceCharacteristic consume_Windows_Media_Capture_IMediaCaptureSettings<D>::VideoDeviceCharacteristic() const
{
    Windows::Media::Capture::VideoDeviceCharacteristic value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureSettings)->get_VideoDeviceCharacteristic(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Media_Capture_IMediaCaptureSettings2<D>::ConcurrentRecordAndPhotoSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureSettings2)->get_ConcurrentRecordAndPhotoSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_Capture_IMediaCaptureSettings2<D>::ConcurrentRecordAndPhotoSequenceSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureSettings2)->get_ConcurrentRecordAndPhotoSequenceSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_Capture_IMediaCaptureSettings2<D>::CameraSoundRequiredForRegion() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureSettings2)->get_CameraSoundRequiredForRegion(&value));
    return value;
}

template <typename D> Windows::Foundation::IReference<uint32_t> consume_Windows_Media_Capture_IMediaCaptureSettings2<D>::Horizontal35mmEquivalentFocalLength() const
{
    Windows::Foundation::IReference<uint32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureSettings2)->get_Horizontal35mmEquivalentFocalLength(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_Media_Capture_IMediaCaptureSettings2<D>::PitchOffsetDegrees() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureSettings2)->get_PitchOffsetDegrees(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<uint32_t> consume_Windows_Media_Capture_IMediaCaptureSettings2<D>::Vertical35mmEquivalentFocalLength() const
{
    Windows::Foundation::IReference<uint32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureSettings2)->get_Vertical35mmEquivalentFocalLength(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Capture::MediaCategory consume_Windows_Media_Capture_IMediaCaptureSettings2<D>::MediaCategory() const
{
    Windows::Media::Capture::MediaCategory value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureSettings2)->get_MediaCategory(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::AudioProcessing consume_Windows_Media_Capture_IMediaCaptureSettings2<D>::AudioProcessing() const
{
    Windows::Media::AudioProcessing value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureSettings2)->get_AudioProcessing(put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice consume_Windows_Media_Capture_IMediaCaptureSettings3<D>::Direct3D11Device() const
{
    Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureSettings3)->get_Direct3D11Device(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Media_Capture_IMediaCaptureStatics<D>::IsVideoProfileSupported(param::hstring const& videoDeviceId) const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureStatics)->IsVideoProfileSupported(get_abi(videoDeviceId), &value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Media::Capture::MediaCaptureVideoProfile> consume_Windows_Media_Capture_IMediaCaptureStatics<D>::FindAllVideoProfiles(param::hstring const& videoDeviceId) const
{
    Windows::Foundation::Collections::IVectorView<Windows::Media::Capture::MediaCaptureVideoProfile> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureStatics)->FindAllVideoProfiles(get_abi(videoDeviceId), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Media::Capture::MediaCaptureVideoProfile> consume_Windows_Media_Capture_IMediaCaptureStatics<D>::FindConcurrentProfiles(param::hstring const& videoDeviceId) const
{
    Windows::Foundation::Collections::IVectorView<Windows::Media::Capture::MediaCaptureVideoProfile> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureStatics)->FindConcurrentProfiles(get_abi(videoDeviceId), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Media::Capture::MediaCaptureVideoProfile> consume_Windows_Media_Capture_IMediaCaptureStatics<D>::FindKnownVideoProfiles(param::hstring const& videoDeviceId, Windows::Media::Capture::KnownVideoProfile const& name) const
{
    Windows::Foundation::Collections::IVectorView<Windows::Media::Capture::MediaCaptureVideoProfile> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureStatics)->FindKnownVideoProfiles(get_abi(videoDeviceId), get_abi(name), put_abi(value)));
    return value;
}

template <typename D> Windows::Media::VideoFrame consume_Windows_Media_Capture_IMediaCaptureStopResult<D>::LastFrame() const
{
    Windows::Media::VideoFrame value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureStopResult)->get_LastFrame(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_Capture_IMediaCaptureStopResult<D>::RecordDuration() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureStopResult)->get_RecordDuration(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_Capture_IMediaCaptureVideoPreview<D>::StartPreviewAsync() const
{
    Windows::Foundation::IAsyncAction asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureVideoPreview)->StartPreviewAsync(put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_Capture_IMediaCaptureVideoPreview<D>::StartPreviewToCustomSinkAsync(Windows::Media::MediaProperties::MediaEncodingProfile const& encodingProfile, Windows::Media::IMediaExtension const& customMediaSink) const
{
    Windows::Foundation::IAsyncAction asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureVideoPreview)->StartPreviewToCustomSinkAsync(get_abi(encodingProfile), get_abi(customMediaSink), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_Capture_IMediaCaptureVideoPreview<D>::StartPreviewToCustomSinkAsync(Windows::Media::MediaProperties::MediaEncodingProfile const& encodingProfile, param::hstring const& customSinkActivationId, Windows::Foundation::Collections::IPropertySet const& customSinkSettings) const
{
    Windows::Foundation::IAsyncAction asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureVideoPreview)->StartPreviewToCustomSinkIdAsync(get_abi(encodingProfile), get_abi(customSinkActivationId), get_abi(customSinkSettings), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_Capture_IMediaCaptureVideoPreview<D>::StopPreviewAsync() const
{
    Windows::Foundation::IAsyncAction asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureVideoPreview)->StopPreviewAsync(put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> hstring consume_Windows_Media_Capture_IMediaCaptureVideoProfile<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureVideoProfile)->get_Id(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_Capture_IMediaCaptureVideoProfile<D>::VideoDeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureVideoProfile)->get_VideoDeviceId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Media::Capture::MediaCaptureVideoProfileMediaDescription> consume_Windows_Media_Capture_IMediaCaptureVideoProfile<D>::SupportedPreviewMediaDescription() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Media::Capture::MediaCaptureVideoProfileMediaDescription> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureVideoProfile)->get_SupportedPreviewMediaDescription(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Media::Capture::MediaCaptureVideoProfileMediaDescription> consume_Windows_Media_Capture_IMediaCaptureVideoProfile<D>::SupportedRecordMediaDescription() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Media::Capture::MediaCaptureVideoProfileMediaDescription> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureVideoProfile)->get_SupportedRecordMediaDescription(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Media::Capture::MediaCaptureVideoProfileMediaDescription> consume_Windows_Media_Capture_IMediaCaptureVideoProfile<D>::SupportedPhotoMediaDescription() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Media::Capture::MediaCaptureVideoProfileMediaDescription> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureVideoProfile)->get_SupportedPhotoMediaDescription(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Media::Capture::MediaCaptureVideoProfile> consume_Windows_Media_Capture_IMediaCaptureVideoProfile<D>::GetConcurrency() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Media::Capture::MediaCaptureVideoProfile> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureVideoProfile)->GetConcurrency(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Media::Capture::Frames::MediaFrameSourceInfo> consume_Windows_Media_Capture_IMediaCaptureVideoProfile2<D>::FrameSourceInfos() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Media::Capture::Frames::MediaFrameSourceInfo> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureVideoProfile2)->get_FrameSourceInfos(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IMapView<winrt::guid, Windows::Foundation::IInspectable> consume_Windows_Media_Capture_IMediaCaptureVideoProfile2<D>::Properties() const
{
    Windows::Foundation::Collections::IMapView<winrt::guid, Windows::Foundation::IInspectable> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureVideoProfile2)->get_Properties(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Capture_IMediaCaptureVideoProfileMediaDescription<D>::Width() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureVideoProfileMediaDescription)->get_Width(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Media_Capture_IMediaCaptureVideoProfileMediaDescription<D>::Height() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureVideoProfileMediaDescription)->get_Height(&value));
    return value;
}

template <typename D> double consume_Windows_Media_Capture_IMediaCaptureVideoProfileMediaDescription<D>::FrameRate() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureVideoProfileMediaDescription)->get_FrameRate(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_Capture_IMediaCaptureVideoProfileMediaDescription<D>::IsVariablePhotoSequenceSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureVideoProfileMediaDescription)->get_IsVariablePhotoSequenceSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Media_Capture_IMediaCaptureVideoProfileMediaDescription<D>::IsHdrVideoSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureVideoProfileMediaDescription)->get_IsHdrVideoSupported(&value));
    return value;
}

template <typename D> hstring consume_Windows_Media_Capture_IMediaCaptureVideoProfileMediaDescription2<D>::Subtype() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureVideoProfileMediaDescription2)->get_Subtype(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IMapView<winrt::guid, Windows::Foundation::IInspectable> consume_Windows_Media_Capture_IMediaCaptureVideoProfileMediaDescription2<D>::Properties() const
{
    Windows::Foundation::Collections::IMapView<winrt::guid, Windows::Foundation::IInspectable> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IMediaCaptureVideoProfileMediaDescription2)->get_Properties(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Capture::CapturedFrame consume_Windows_Media_Capture_IOptionalReferencePhotoCapturedEventArgs<D>::Frame() const
{
    Windows::Media::Capture::CapturedFrame value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IOptionalReferencePhotoCapturedEventArgs)->get_Frame(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_Media_Capture_IOptionalReferencePhotoCapturedEventArgs<D>::Context() const
{
    Windows::Foundation::IInspectable value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IOptionalReferencePhotoCapturedEventArgs)->get_Context(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Capture::CapturedFrame consume_Windows_Media_Capture_IPhotoCapturedEventArgs<D>::Frame() const
{
    Windows::Media::Capture::CapturedFrame value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IPhotoCapturedEventArgs)->get_Frame(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Capture::CapturedFrame consume_Windows_Media_Capture_IPhotoCapturedEventArgs<D>::Thumbnail() const
{
    Windows::Media::Capture::CapturedFrame value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IPhotoCapturedEventArgs)->get_Thumbnail(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_Capture_IPhotoCapturedEventArgs<D>::CaptureTimeOffset() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IPhotoCapturedEventArgs)->get_CaptureTimeOffset(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::Capture::CapturedFrame consume_Windows_Media_Capture_IPhotoConfirmationCapturedEventArgs<D>::Frame() const
{
    Windows::Media::Capture::CapturedFrame value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IPhotoConfirmationCapturedEventArgs)->get_Frame(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Media_Capture_IPhotoConfirmationCapturedEventArgs<D>::CaptureTimeOffset() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IPhotoConfirmationCapturedEventArgs)->get_CaptureTimeOffset(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::MediaProperties::VideoEncodingProperties consume_Windows_Media_Capture_IVideoStreamConfiguration<D>::InputProperties() const
{
    Windows::Media::MediaProperties::VideoEncodingProperties value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IVideoStreamConfiguration)->get_InputProperties(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::MediaProperties::VideoEncodingProperties consume_Windows_Media_Capture_IVideoStreamConfiguration<D>::OutputProperties() const
{
    Windows::Media::MediaProperties::VideoEncodingProperties value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Capture::IVideoStreamConfiguration)->get_OutputProperties(put_abi(value)));
    return value;
}

template <> struct delegate<Windows::Media::Capture::MediaCaptureFailedEventHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::Media::Capture::MediaCaptureFailedEventHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::Media::Capture::MediaCaptureFailedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* sender, void* errorEventArgs) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Media::Capture::MediaCapture const*>(&sender), *reinterpret_cast<Windows::Media::Capture::MediaCaptureFailedEventArgs const*>(&errorEventArgs));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <> struct delegate<Windows::Media::Capture::RecordLimitationExceededEventHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::Media::Capture::RecordLimitationExceededEventHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::Media::Capture::RecordLimitationExceededEventHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* sender) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Media::Capture::MediaCapture const*>(&sender));
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
struct produce<D, Windows::Media::Capture::IAdvancedCapturedPhoto> : produce_base<D, Windows::Media::Capture::IAdvancedCapturedPhoto>
{
    int32_t WINRT_CALL get_Frame(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Frame, WINRT_WRAP(Windows::Media::Capture::CapturedFrame));
            *value = detach_from<Windows::Media::Capture::CapturedFrame>(this->shim().Frame());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Mode(Windows::Media::Devices::AdvancedPhotoMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Mode, WINRT_WRAP(Windows::Media::Devices::AdvancedPhotoMode));
            *value = detach_from<Windows::Media::Devices::AdvancedPhotoMode>(this->shim().Mode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Context(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Context, WINRT_WRAP(Windows::Foundation::IInspectable));
            *value = detach_from<Windows::Foundation::IInspectable>(this->shim().Context());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IAdvancedCapturedPhoto2> : produce_base<D, Windows::Media::Capture::IAdvancedCapturedPhoto2>
{
    int32_t WINRT_CALL get_FrameBoundsRelativeToReferencePhoto(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FrameBoundsRelativeToReferencePhoto, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::Rect>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::Rect>>(this->shim().FrameBoundsRelativeToReferencePhoto());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IAdvancedPhotoCapture> : produce_base<D, Windows::Media::Capture::IAdvancedPhotoCapture>
{
    int32_t WINRT_CALL CaptureAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CaptureAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::Capture::AdvancedCapturedPhoto>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::Capture::AdvancedCapturedPhoto>>(this->shim().CaptureAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CaptureWithContextAsync(void* context, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CaptureAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::Capture::AdvancedCapturedPhoto>), Windows::Foundation::IInspectable const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::Capture::AdvancedCapturedPhoto>>(this->shim().CaptureAsync(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&context)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_OptionalReferencePhotoCaptured(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OptionalReferencePhotoCaptured, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AdvancedPhotoCapture, Windows::Media::Capture::OptionalReferencePhotoCapturedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().OptionalReferencePhotoCaptured(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AdvancedPhotoCapture, Windows::Media::Capture::OptionalReferencePhotoCapturedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_OptionalReferencePhotoCaptured(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(OptionalReferencePhotoCaptured, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().OptionalReferencePhotoCaptured(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_AllPhotosCaptured(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllPhotosCaptured, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AdvancedPhotoCapture, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().AllPhotosCaptured(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AdvancedPhotoCapture, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_AllPhotosCaptured(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(AllPhotosCaptured, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().AllPhotosCaptured(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL FinishAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FinishAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().FinishAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IAppBroadcastBackgroundService> : produce_base<D, Windows::Media::Capture::IAppBroadcastBackgroundService>
{
    int32_t WINRT_CALL put_PlugInState(Windows::Media::Capture::AppBroadcastPlugInState value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PlugInState, WINRT_WRAP(void), Windows::Media::Capture::AppBroadcastPlugInState const&);
            this->shim().PlugInState(*reinterpret_cast<Windows::Media::Capture::AppBroadcastPlugInState const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PlugInState(Windows::Media::Capture::AppBroadcastPlugInState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PlugInState, WINRT_WRAP(Windows::Media::Capture::AppBroadcastPlugInState));
            *value = detach_from<Windows::Media::Capture::AppBroadcastPlugInState>(this->shim().PlugInState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SignInInfo(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SignInInfo, WINRT_WRAP(void), Windows::Media::Capture::AppBroadcastBackgroundServiceSignInInfo const&);
            this->shim().SignInInfo(*reinterpret_cast<Windows::Media::Capture::AppBroadcastBackgroundServiceSignInInfo const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SignInInfo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SignInInfo, WINRT_WRAP(Windows::Media::Capture::AppBroadcastBackgroundServiceSignInInfo));
            *value = detach_from<Windows::Media::Capture::AppBroadcastBackgroundServiceSignInInfo>(this->shim().SignInInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_StreamInfo(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StreamInfo, WINRT_WRAP(void), Windows::Media::Capture::AppBroadcastBackgroundServiceStreamInfo const&);
            this->shim().StreamInfo(*reinterpret_cast<Windows::Media::Capture::AppBroadcastBackgroundServiceStreamInfo const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StreamInfo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StreamInfo, WINRT_WRAP(Windows::Media::Capture::AppBroadcastBackgroundServiceStreamInfo));
            *value = detach_from<Windows::Media::Capture::AppBroadcastBackgroundServiceStreamInfo>(this->shim().StreamInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AppId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AppId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BroadcastTitle(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BroadcastTitle, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().BroadcastTitle());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ViewerCount(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ViewerCount, WINRT_WRAP(void), uint32_t);
            this->shim().ViewerCount(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ViewerCount(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ViewerCount, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().ViewerCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TerminateBroadcast(Windows::Media::Capture::AppBroadcastTerminationReason reason, uint32_t providerSpecificReason) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TerminateBroadcast, WINRT_WRAP(void), Windows::Media::Capture::AppBroadcastTerminationReason const&, uint32_t);
            this->shim().TerminateBroadcast(*reinterpret_cast<Windows::Media::Capture::AppBroadcastTerminationReason const*>(&reason), providerSpecificReason);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_HeartbeatRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HeartbeatRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastBackgroundService, Windows::Media::Capture::AppBroadcastHeartbeatRequestedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().HeartbeatRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastBackgroundService, Windows::Media::Capture::AppBroadcastHeartbeatRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_HeartbeatRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(HeartbeatRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().HeartbeatRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL get_TitleId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TitleId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().TitleId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IAppBroadcastBackgroundService2> : produce_base<D, Windows::Media::Capture::IAppBroadcastBackgroundService2>
{
    int32_t WINRT_CALL put_BroadcastTitle(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BroadcastTitle, WINRT_WRAP(void), hstring const&);
            this->shim().BroadcastTitle(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BroadcastLanguage(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BroadcastLanguage, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().BroadcastLanguage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_BroadcastLanguage(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BroadcastLanguage, WINRT_WRAP(void), hstring const&);
            this->shim().BroadcastLanguage(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BroadcastChannel(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BroadcastChannel, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().BroadcastChannel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_BroadcastChannel(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BroadcastChannel, WINRT_WRAP(void), hstring const&);
            this->shim().BroadcastChannel(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_BroadcastTitleChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BroadcastTitleChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastBackgroundService, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().BroadcastTitleChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastBackgroundService, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_BroadcastTitleChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(BroadcastTitleChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().BroadcastTitleChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_BroadcastLanguageChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BroadcastLanguageChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastBackgroundService, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().BroadcastLanguageChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastBackgroundService, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_BroadcastLanguageChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(BroadcastLanguageChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().BroadcastLanguageChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_BroadcastChannelChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BroadcastChannelChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastBackgroundService, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().BroadcastChannelChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastBackgroundService, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_BroadcastChannelChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(BroadcastChannelChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().BroadcastChannelChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IAppBroadcastBackgroundServiceSignInInfo> : produce_base<D, Windows::Media::Capture::IAppBroadcastBackgroundServiceSignInInfo>
{
    int32_t WINRT_CALL get_SignInState(Windows::Media::Capture::AppBroadcastSignInState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SignInState, WINRT_WRAP(Windows::Media::Capture::AppBroadcastSignInState));
            *value = detach_from<Windows::Media::Capture::AppBroadcastSignInState>(this->shim().SignInState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_OAuthRequestUri(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OAuthRequestUri, WINRT_WRAP(void), Windows::Foundation::Uri const&);
            this->shim().OAuthRequestUri(*reinterpret_cast<Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OAuthRequestUri(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OAuthRequestUri, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().OAuthRequestUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_OAuthCallbackUri(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OAuthCallbackUri, WINRT_WRAP(void), Windows::Foundation::Uri const&);
            this->shim().OAuthCallbackUri(*reinterpret_cast<Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OAuthCallbackUri(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OAuthCallbackUri, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().OAuthCallbackUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AuthenticationResult(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AuthenticationResult, WINRT_WRAP(Windows::Security::Authentication::Web::WebAuthenticationResult));
            *value = detach_from<Windows::Security::Authentication::Web::WebAuthenticationResult>(this->shim().AuthenticationResult());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_UserName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UserName, WINRT_WRAP(void), hstring const&);
            this->shim().UserName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UserName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UserName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().UserName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_SignInStateChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SignInStateChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastBackgroundServiceSignInInfo, Windows::Media::Capture::AppBroadcastSignInStateChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().SignInStateChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastBackgroundServiceSignInInfo, Windows::Media::Capture::AppBroadcastSignInStateChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_SignInStateChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(SignInStateChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().SignInStateChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IAppBroadcastBackgroundServiceSignInInfo2> : produce_base<D, Windows::Media::Capture::IAppBroadcastBackgroundServiceSignInInfo2>
{
    int32_t WINRT_CALL add_UserNameChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UserNameChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastBackgroundServiceSignInInfo, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().UserNameChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastBackgroundServiceSignInInfo, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_UserNameChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(UserNameChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().UserNameChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IAppBroadcastBackgroundServiceStreamInfo> : produce_base<D, Windows::Media::Capture::IAppBroadcastBackgroundServiceStreamInfo>
{
    int32_t WINRT_CALL get_StreamState(Windows::Media::Capture::AppBroadcastStreamState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StreamState, WINRT_WRAP(Windows::Media::Capture::AppBroadcastStreamState));
            *value = detach_from<Windows::Media::Capture::AppBroadcastStreamState>(this->shim().StreamState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DesiredVideoEncodingBitrate(uint64_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesiredVideoEncodingBitrate, WINRT_WRAP(void), uint64_t);
            this->shim().DesiredVideoEncodingBitrate(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DesiredVideoEncodingBitrate(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesiredVideoEncodingBitrate, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().DesiredVideoEncodingBitrate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_BandwidthTestBitrate(uint64_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BandwidthTestBitrate, WINRT_WRAP(void), uint64_t);
            this->shim().BandwidthTestBitrate(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BandwidthTestBitrate(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BandwidthTestBitrate, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().BandwidthTestBitrate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AudioCodec(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioCodec, WINRT_WRAP(void), hstring const&);
            this->shim().AudioCodec(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AudioCodec(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioCodec, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AudioCodec());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BroadcastStreamReader(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BroadcastStreamReader, WINRT_WRAP(Windows::Media::Capture::AppBroadcastStreamReader));
            *value = detach_from<Windows::Media::Capture::AppBroadcastStreamReader>(this->shim().BroadcastStreamReader());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_StreamStateChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StreamStateChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastBackgroundServiceStreamInfo, Windows::Media::Capture::AppBroadcastStreamStateChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().StreamStateChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastBackgroundServiceStreamInfo, Windows::Media::Capture::AppBroadcastStreamStateChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_StreamStateChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(StreamStateChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().StreamStateChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_VideoEncodingResolutionChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoEncodingResolutionChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastBackgroundServiceStreamInfo, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().VideoEncodingResolutionChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastBackgroundServiceStreamInfo, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_VideoEncodingResolutionChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(VideoEncodingResolutionChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().VideoEncodingResolutionChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_VideoEncodingBitrateChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoEncodingBitrateChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastBackgroundServiceStreamInfo, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().VideoEncodingBitrateChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastBackgroundServiceStreamInfo, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_VideoEncodingBitrateChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(VideoEncodingBitrateChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().VideoEncodingBitrateChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IAppBroadcastBackgroundServiceStreamInfo2> : produce_base<D, Windows::Media::Capture::IAppBroadcastBackgroundServiceStreamInfo2>
{
    int32_t WINRT_CALL ReportProblemWithStream() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportProblemWithStream, WINRT_WRAP(void));
            this->shim().ReportProblemWithStream();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IAppBroadcastCameraCaptureStateChangedEventArgs> : produce_base<D, Windows::Media::Capture::IAppBroadcastCameraCaptureStateChangedEventArgs>
{
    int32_t WINRT_CALL get_State(Windows::Media::Capture::AppBroadcastCameraCaptureState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(State, WINRT_WRAP(Windows::Media::Capture::AppBroadcastCameraCaptureState));
            *value = detach_from<Windows::Media::Capture::AppBroadcastCameraCaptureState>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ErrorCode(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ErrorCode, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().ErrorCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IAppBroadcastGlobalSettings> : produce_base<D, Windows::Media::Capture::IAppBroadcastGlobalSettings>
{
    int32_t WINRT_CALL get_IsBroadcastEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsBroadcastEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsBroadcastEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsDisabledByPolicy(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDisabledByPolicy, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsDisabledByPolicy());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsGpuConstrained(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsGpuConstrained, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsGpuConstrained());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HasHardwareEncoder(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HasHardwareEncoder, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().HasHardwareEncoder());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsAudioCaptureEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsAudioCaptureEnabled, WINRT_WRAP(void), bool);
            this->shim().IsAudioCaptureEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsAudioCaptureEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsAudioCaptureEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsAudioCaptureEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsMicrophoneCaptureEnabledByDefault(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsMicrophoneCaptureEnabledByDefault, WINRT_WRAP(void), bool);
            this->shim().IsMicrophoneCaptureEnabledByDefault(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsMicrophoneCaptureEnabledByDefault(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsMicrophoneCaptureEnabledByDefault, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsMicrophoneCaptureEnabledByDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsEchoCancellationEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsEchoCancellationEnabled, WINRT_WRAP(void), bool);
            this->shim().IsEchoCancellationEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsEchoCancellationEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsEchoCancellationEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsEchoCancellationEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SystemAudioGain(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SystemAudioGain, WINRT_WRAP(void), double);
            this->shim().SystemAudioGain(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SystemAudioGain(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SystemAudioGain, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().SystemAudioGain());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MicrophoneGain(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MicrophoneGain, WINRT_WRAP(void), double);
            this->shim().MicrophoneGain(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MicrophoneGain(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MicrophoneGain, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().MicrophoneGain());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsCameraCaptureEnabledByDefault(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsCameraCaptureEnabledByDefault, WINRT_WRAP(void), bool);
            this->shim().IsCameraCaptureEnabledByDefault(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsCameraCaptureEnabledByDefault(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsCameraCaptureEnabledByDefault, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsCameraCaptureEnabledByDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SelectedCameraId(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedCameraId, WINRT_WRAP(void), hstring const&);
            this->shim().SelectedCameraId(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SelectedCameraId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectedCameraId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SelectedCameraId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CameraOverlayLocation(Windows::Media::Capture::AppBroadcastCameraOverlayLocation value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CameraOverlayLocation, WINRT_WRAP(void), Windows::Media::Capture::AppBroadcastCameraOverlayLocation const&);
            this->shim().CameraOverlayLocation(*reinterpret_cast<Windows::Media::Capture::AppBroadcastCameraOverlayLocation const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CameraOverlayLocation(Windows::Media::Capture::AppBroadcastCameraOverlayLocation* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CameraOverlayLocation, WINRT_WRAP(Windows::Media::Capture::AppBroadcastCameraOverlayLocation));
            *value = detach_from<Windows::Media::Capture::AppBroadcastCameraOverlayLocation>(this->shim().CameraOverlayLocation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CameraOverlaySize(Windows::Media::Capture::AppBroadcastCameraOverlaySize value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CameraOverlaySize, WINRT_WRAP(void), Windows::Media::Capture::AppBroadcastCameraOverlaySize const&);
            this->shim().CameraOverlaySize(*reinterpret_cast<Windows::Media::Capture::AppBroadcastCameraOverlaySize const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CameraOverlaySize(Windows::Media::Capture::AppBroadcastCameraOverlaySize* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CameraOverlaySize, WINRT_WRAP(Windows::Media::Capture::AppBroadcastCameraOverlaySize));
            *value = detach_from<Windows::Media::Capture::AppBroadcastCameraOverlaySize>(this->shim().CameraOverlaySize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsCursorImageCaptureEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsCursorImageCaptureEnabled, WINRT_WRAP(void), bool);
            this->shim().IsCursorImageCaptureEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsCursorImageCaptureEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsCursorImageCaptureEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsCursorImageCaptureEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IAppBroadcastHeartbeatRequestedEventArgs> : produce_base<D, Windows::Media::Capture::IAppBroadcastHeartbeatRequestedEventArgs>
{
    int32_t WINRT_CALL put_Handled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Handled, WINRT_WRAP(void), bool);
            this->shim().Handled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Handled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Handled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Handled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IAppBroadcastManagerStatics> : produce_base<D, Windows::Media::Capture::IAppBroadcastManagerStatics>
{
    int32_t WINRT_CALL GetGlobalSettings(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetGlobalSettings, WINRT_WRAP(Windows::Media::Capture::AppBroadcastGlobalSettings));
            *value = detach_from<Windows::Media::Capture::AppBroadcastGlobalSettings>(this->shim().GetGlobalSettings());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ApplyGlobalSettings(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ApplyGlobalSettings, WINRT_WRAP(void), Windows::Media::Capture::AppBroadcastGlobalSettings const&);
            this->shim().ApplyGlobalSettings(*reinterpret_cast<Windows::Media::Capture::AppBroadcastGlobalSettings const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetProviderSettings(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetProviderSettings, WINRT_WRAP(Windows::Media::Capture::AppBroadcastProviderSettings));
            *value = detach_from<Windows::Media::Capture::AppBroadcastProviderSettings>(this->shim().GetProviderSettings());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ApplyProviderSettings(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ApplyProviderSettings, WINRT_WRAP(void), Windows::Media::Capture::AppBroadcastProviderSettings const&);
            this->shim().ApplyProviderSettings(*reinterpret_cast<Windows::Media::Capture::AppBroadcastProviderSettings const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IAppBroadcastMicrophoneCaptureStateChangedEventArgs> : produce_base<D, Windows::Media::Capture::IAppBroadcastMicrophoneCaptureStateChangedEventArgs>
{
    int32_t WINRT_CALL get_State(Windows::Media::Capture::AppBroadcastMicrophoneCaptureState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(State, WINRT_WRAP(Windows::Media::Capture::AppBroadcastMicrophoneCaptureState));
            *value = detach_from<Windows::Media::Capture::AppBroadcastMicrophoneCaptureState>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ErrorCode(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ErrorCode, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().ErrorCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IAppBroadcastPlugIn> : produce_base<D, Windows::Media::Capture::IAppBroadcastPlugIn>
{
    int32_t WINRT_CALL get_AppId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AppId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProviderSettings(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProviderSettings, WINRT_WRAP(Windows::Media::Capture::AppBroadcastProviderSettings));
            *value = detach_from<Windows::Media::Capture::AppBroadcastProviderSettings>(this->shim().ProviderSettings());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Logo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Logo, WINRT_WRAP(Windows::Storage::Streams::IRandomAccessStreamReference));
            *value = detach_from<Windows::Storage::Streams::IRandomAccessStreamReference>(this->shim().Logo());
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
struct produce<D, Windows::Media::Capture::IAppBroadcastPlugInManager> : produce_base<D, Windows::Media::Capture::IAppBroadcastPlugInManager>
{
    int32_t WINRT_CALL get_IsBroadcastProviderAvailable(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsBroadcastProviderAvailable, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsBroadcastProviderAvailable());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PlugInList(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PlugInList, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Media::Capture::AppBroadcastPlugIn>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Media::Capture::AppBroadcastPlugIn>>(this->shim().PlugInList());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DefaultPlugIn(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DefaultPlugIn, WINRT_WRAP(Windows::Media::Capture::AppBroadcastPlugIn));
            *value = detach_from<Windows::Media::Capture::AppBroadcastPlugIn>(this->shim().DefaultPlugIn());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DefaultPlugIn(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DefaultPlugIn, WINRT_WRAP(void), Windows::Media::Capture::AppBroadcastPlugIn const&);
            this->shim().DefaultPlugIn(*reinterpret_cast<Windows::Media::Capture::AppBroadcastPlugIn const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IAppBroadcastPlugInManagerStatics> : produce_base<D, Windows::Media::Capture::IAppBroadcastPlugInManagerStatics>
{
    int32_t WINRT_CALL GetDefault(void** ppInstance) noexcept final
    {
        try
        {
            *ppInstance = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefault, WINRT_WRAP(Windows::Media::Capture::AppBroadcastPlugInManager));
            *ppInstance = detach_from<Windows::Media::Capture::AppBroadcastPlugInManager>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetForUser(void* user, void** ppInstance) noexcept final
    {
        try
        {
            *ppInstance = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForUser, WINRT_WRAP(Windows::Media::Capture::AppBroadcastPlugInManager), Windows::System::User const&);
            *ppInstance = detach_from<Windows::Media::Capture::AppBroadcastPlugInManager>(this->shim().GetForUser(*reinterpret_cast<Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IAppBroadcastPlugInStateChangedEventArgs> : produce_base<D, Windows::Media::Capture::IAppBroadcastPlugInStateChangedEventArgs>
{
    int32_t WINRT_CALL get_PlugInState(Windows::Media::Capture::AppBroadcastPlugInState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PlugInState, WINRT_WRAP(Windows::Media::Capture::AppBroadcastPlugInState));
            *value = detach_from<Windows::Media::Capture::AppBroadcastPlugInState>(this->shim().PlugInState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IAppBroadcastPreview> : produce_base<D, Windows::Media::Capture::IAppBroadcastPreview>
{
    int32_t WINRT_CALL StopPreview() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StopPreview, WINRT_WRAP(void));
            this->shim().StopPreview();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PreviewState(Windows::Media::Capture::AppBroadcastPreviewState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PreviewState, WINRT_WRAP(Windows::Media::Capture::AppBroadcastPreviewState));
            *value = detach_from<Windows::Media::Capture::AppBroadcastPreviewState>(this->shim().PreviewState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ErrorCode(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ErrorCode, WINRT_WRAP(Windows::Foundation::IReference<uint32_t>));
            *value = detach_from<Windows::Foundation::IReference<uint32_t>>(this->shim().ErrorCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_PreviewStateChanged(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PreviewStateChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastPreview, Windows::Media::Capture::AppBroadcastPreviewStateChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().PreviewStateChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastPreview, Windows::Media::Capture::AppBroadcastPreviewStateChangedEventArgs> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PreviewStateChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PreviewStateChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PreviewStateChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL get_PreviewStreamReader(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PreviewStreamReader, WINRT_WRAP(Windows::Media::Capture::AppBroadcastPreviewStreamReader));
            *value = detach_from<Windows::Media::Capture::AppBroadcastPreviewStreamReader>(this->shim().PreviewStreamReader());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IAppBroadcastPreviewStateChangedEventArgs> : produce_base<D, Windows::Media::Capture::IAppBroadcastPreviewStateChangedEventArgs>
{
    int32_t WINRT_CALL get_PreviewState(Windows::Media::Capture::AppBroadcastPreviewState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PreviewState, WINRT_WRAP(Windows::Media::Capture::AppBroadcastPreviewState));
            *value = detach_from<Windows::Media::Capture::AppBroadcastPreviewState>(this->shim().PreviewState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ErrorCode(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ErrorCode, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().ErrorCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IAppBroadcastPreviewStreamReader> : produce_base<D, Windows::Media::Capture::IAppBroadcastPreviewStreamReader>
{
    int32_t WINRT_CALL get_VideoWidth(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoWidth, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().VideoWidth());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VideoHeight(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoHeight, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().VideoHeight());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VideoStride(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoStride, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().VideoStride());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VideoBitmapPixelFormat(Windows::Graphics::Imaging::BitmapPixelFormat* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoBitmapPixelFormat, WINRT_WRAP(Windows::Graphics::Imaging::BitmapPixelFormat));
            *value = detach_from<Windows::Graphics::Imaging::BitmapPixelFormat>(this->shim().VideoBitmapPixelFormat());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VideoBitmapAlphaMode(Windows::Graphics::Imaging::BitmapAlphaMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoBitmapAlphaMode, WINRT_WRAP(Windows::Graphics::Imaging::BitmapAlphaMode));
            *value = detach_from<Windows::Graphics::Imaging::BitmapAlphaMode>(this->shim().VideoBitmapAlphaMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryGetNextVideoFrame(void** frame) noexcept final
    {
        try
        {
            *frame = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryGetNextVideoFrame, WINRT_WRAP(Windows::Media::Capture::AppBroadcastPreviewStreamVideoFrame));
            *frame = detach_from<Windows::Media::Capture::AppBroadcastPreviewStreamVideoFrame>(this->shim().TryGetNextVideoFrame());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_VideoFrameArrived(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoFrameArrived, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastPreviewStreamReader, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().VideoFrameArrived(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastPreviewStreamReader, Windows::Foundation::IInspectable> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_VideoFrameArrived(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(VideoFrameArrived, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().VideoFrameArrived(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IAppBroadcastPreviewStreamVideoFrame> : produce_base<D, Windows::Media::Capture::IAppBroadcastPreviewStreamVideoFrame>
{
    int32_t WINRT_CALL get_VideoHeader(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoHeader, WINRT_WRAP(Windows::Media::Capture::AppBroadcastPreviewStreamVideoHeader));
            *value = detach_from<Windows::Media::Capture::AppBroadcastPreviewStreamVideoHeader>(this->shim().VideoHeader());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VideoBuffer(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoBuffer, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().VideoBuffer());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IAppBroadcastPreviewStreamVideoHeader> : produce_base<D, Windows::Media::Capture::IAppBroadcastPreviewStreamVideoHeader>
{
    int32_t WINRT_CALL get_AbsoluteTimestamp(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AbsoluteTimestamp, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().AbsoluteTimestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RelativeTimestamp(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RelativeTimestamp, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().RelativeTimestamp());
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

    int32_t WINRT_CALL get_FrameId(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FrameId, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().FrameId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IAppBroadcastProviderSettings> : produce_base<D, Windows::Media::Capture::IAppBroadcastProviderSettings>
{
    int32_t WINRT_CALL put_DefaultBroadcastTitle(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DefaultBroadcastTitle, WINRT_WRAP(void), hstring const&);
            this->shim().DefaultBroadcastTitle(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DefaultBroadcastTitle(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DefaultBroadcastTitle, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DefaultBroadcastTitle());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AudioEncodingBitrate(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioEncodingBitrate, WINRT_WRAP(void), uint32_t);
            this->shim().AudioEncodingBitrate(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AudioEncodingBitrate(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioEncodingBitrate, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().AudioEncodingBitrate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CustomVideoEncodingBitrate(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CustomVideoEncodingBitrate, WINRT_WRAP(void), uint32_t);
            this->shim().CustomVideoEncodingBitrate(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CustomVideoEncodingBitrate(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CustomVideoEncodingBitrate, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().CustomVideoEncodingBitrate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CustomVideoEncodingHeight(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CustomVideoEncodingHeight, WINRT_WRAP(void), uint32_t);
            this->shim().CustomVideoEncodingHeight(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CustomVideoEncodingHeight(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CustomVideoEncodingHeight, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().CustomVideoEncodingHeight());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CustomVideoEncodingWidth(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CustomVideoEncodingWidth, WINRT_WRAP(void), uint32_t);
            this->shim().CustomVideoEncodingWidth(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CustomVideoEncodingWidth(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CustomVideoEncodingWidth, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().CustomVideoEncodingWidth());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_VideoEncodingBitrateMode(Windows::Media::Capture::AppBroadcastVideoEncodingBitrateMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoEncodingBitrateMode, WINRT_WRAP(void), Windows::Media::Capture::AppBroadcastVideoEncodingBitrateMode const&);
            this->shim().VideoEncodingBitrateMode(*reinterpret_cast<Windows::Media::Capture::AppBroadcastVideoEncodingBitrateMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VideoEncodingBitrateMode(Windows::Media::Capture::AppBroadcastVideoEncodingBitrateMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoEncodingBitrateMode, WINRT_WRAP(Windows::Media::Capture::AppBroadcastVideoEncodingBitrateMode));
            *value = detach_from<Windows::Media::Capture::AppBroadcastVideoEncodingBitrateMode>(this->shim().VideoEncodingBitrateMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_VideoEncodingResolutionMode(Windows::Media::Capture::AppBroadcastVideoEncodingResolutionMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoEncodingResolutionMode, WINRT_WRAP(void), Windows::Media::Capture::AppBroadcastVideoEncodingResolutionMode const&);
            this->shim().VideoEncodingResolutionMode(*reinterpret_cast<Windows::Media::Capture::AppBroadcastVideoEncodingResolutionMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VideoEncodingResolutionMode(Windows::Media::Capture::AppBroadcastVideoEncodingResolutionMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoEncodingResolutionMode, WINRT_WRAP(Windows::Media::Capture::AppBroadcastVideoEncodingResolutionMode));
            *value = detach_from<Windows::Media::Capture::AppBroadcastVideoEncodingResolutionMode>(this->shim().VideoEncodingResolutionMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IAppBroadcastServices> : produce_base<D, Windows::Media::Capture::IAppBroadcastServices>
{
    int32_t WINRT_CALL get_CaptureTargetType(Windows::Media::Capture::AppBroadcastCaptureTargetType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CaptureTargetType, WINRT_WRAP(Windows::Media::Capture::AppBroadcastCaptureTargetType));
            *value = detach_from<Windows::Media::Capture::AppBroadcastCaptureTargetType>(this->shim().CaptureTargetType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CaptureTargetType(Windows::Media::Capture::AppBroadcastCaptureTargetType value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CaptureTargetType, WINRT_WRAP(void), Windows::Media::Capture::AppBroadcastCaptureTargetType const&);
            this->shim().CaptureTargetType(*reinterpret_cast<Windows::Media::Capture::AppBroadcastCaptureTargetType const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BroadcastTitle(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BroadcastTitle, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().BroadcastTitle());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_BroadcastTitle(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BroadcastTitle, WINRT_WRAP(void), hstring const&);
            this->shim().BroadcastTitle(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BroadcastLanguage(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BroadcastLanguage, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().BroadcastLanguage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_BroadcastLanguage(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BroadcastLanguage, WINRT_WRAP(void), hstring const&);
            this->shim().BroadcastLanguage(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UserName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UserName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().UserName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanCapture(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanCapture, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanCapture());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL EnterBroadcastModeAsync(void* plugIn, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnterBroadcastModeAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<uint32_t>), Windows::Media::Capture::AppBroadcastPlugIn const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<uint32_t>>(this->shim().EnterBroadcastModeAsync(*reinterpret_cast<Windows::Media::Capture::AppBroadcastPlugIn const*>(&plugIn)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ExitBroadcastMode(Windows::Media::Capture::AppBroadcastExitBroadcastModeReason reason) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExitBroadcastMode, WINRT_WRAP(void), Windows::Media::Capture::AppBroadcastExitBroadcastModeReason const&);
            this->shim().ExitBroadcastMode(*reinterpret_cast<Windows::Media::Capture::AppBroadcastExitBroadcastModeReason const*>(&reason));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StartBroadcast() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartBroadcast, WINRT_WRAP(void));
            this->shim().StartBroadcast();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PauseBroadcast() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PauseBroadcast, WINRT_WRAP(void));
            this->shim().PauseBroadcast();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ResumeBroadcast() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResumeBroadcast, WINRT_WRAP(void));
            this->shim().ResumeBroadcast();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StartPreview(Windows::Foundation::Size desiredSize, void** preview) noexcept final
    {
        try
        {
            *preview = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartPreview, WINRT_WRAP(Windows::Media::Capture::AppBroadcastPreview), Windows::Foundation::Size const&);
            *preview = detach_from<Windows::Media::Capture::AppBroadcastPreview>(this->shim().StartPreview(*reinterpret_cast<Windows::Foundation::Size const*>(&desiredSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_State(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(State, WINRT_WRAP(Windows::Media::Capture::AppBroadcastState));
            *value = detach_from<Windows::Media::Capture::AppBroadcastState>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IAppBroadcastSignInStateChangedEventArgs> : produce_base<D, Windows::Media::Capture::IAppBroadcastSignInStateChangedEventArgs>
{
    int32_t WINRT_CALL get_SignInState(Windows::Media::Capture::AppBroadcastSignInState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SignInState, WINRT_WRAP(Windows::Media::Capture::AppBroadcastSignInState));
            *value = detach_from<Windows::Media::Capture::AppBroadcastSignInState>(this->shim().SignInState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Result(Windows::Media::Capture::AppBroadcastSignInResult* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Result, WINRT_WRAP(Windows::Media::Capture::AppBroadcastSignInResult));
            *value = detach_from<Windows::Media::Capture::AppBroadcastSignInResult>(this->shim().Result());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IAppBroadcastState> : produce_base<D, Windows::Media::Capture::IAppBroadcastState>
{
    int32_t WINRT_CALL get_IsCaptureTargetRunning(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsCaptureTargetRunning, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsCaptureTargetRunning());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ViewerCount(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ViewerCount, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().ViewerCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ShouldCaptureMicrophone(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShouldCaptureMicrophone, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().ShouldCaptureMicrophone());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ShouldCaptureMicrophone(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShouldCaptureMicrophone, WINRT_WRAP(void), bool);
            this->shim().ShouldCaptureMicrophone(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RestartMicrophoneCapture() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RestartMicrophoneCapture, WINRT_WRAP(void));
            this->shim().RestartMicrophoneCapture();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ShouldCaptureCamera(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShouldCaptureCamera, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().ShouldCaptureCamera());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ShouldCaptureCamera(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShouldCaptureCamera, WINRT_WRAP(void), bool);
            this->shim().ShouldCaptureCamera(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RestartCameraCapture() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RestartCameraCapture, WINRT_WRAP(void));
            this->shim().RestartCameraCapture();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EncodedVideoSize(Windows::Foundation::Size* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EncodedVideoSize, WINRT_WRAP(Windows::Foundation::Size));
            *value = detach_from<Windows::Foundation::Size>(this->shim().EncodedVideoSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MicrophoneCaptureState(Windows::Media::Capture::AppBroadcastMicrophoneCaptureState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MicrophoneCaptureState, WINRT_WRAP(Windows::Media::Capture::AppBroadcastMicrophoneCaptureState));
            *value = detach_from<Windows::Media::Capture::AppBroadcastMicrophoneCaptureState>(this->shim().MicrophoneCaptureState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MicrophoneCaptureError(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MicrophoneCaptureError, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().MicrophoneCaptureError());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CameraCaptureState(Windows::Media::Capture::AppBroadcastCameraCaptureState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CameraCaptureState, WINRT_WRAP(Windows::Media::Capture::AppBroadcastCameraCaptureState));
            *value = detach_from<Windows::Media::Capture::AppBroadcastCameraCaptureState>(this->shim().CameraCaptureState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CameraCaptureError(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CameraCaptureError, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().CameraCaptureError());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StreamState(Windows::Media::Capture::AppBroadcastStreamState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StreamState, WINRT_WRAP(Windows::Media::Capture::AppBroadcastStreamState));
            *value = detach_from<Windows::Media::Capture::AppBroadcastStreamState>(this->shim().StreamState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PlugInState(Windows::Media::Capture::AppBroadcastPlugInState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PlugInState, WINRT_WRAP(Windows::Media::Capture::AppBroadcastPlugInState));
            *value = detach_from<Windows::Media::Capture::AppBroadcastPlugInState>(this->shim().PlugInState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OAuthRequestUri(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OAuthRequestUri, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().OAuthRequestUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OAuthCallbackUri(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OAuthCallbackUri, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().OAuthCallbackUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AuthenticationResult(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AuthenticationResult, WINRT_WRAP(Windows::Security::Authentication::Web::WebAuthenticationResult));
            *value = detach_from<Windows::Security::Authentication::Web::WebAuthenticationResult>(this->shim().AuthenticationResult());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AuthenticationResult(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AuthenticationResult, WINRT_WRAP(void), Windows::Security::Authentication::Web::WebAuthenticationResult const&);
            this->shim().AuthenticationResult(*reinterpret_cast<Windows::Security::Authentication::Web::WebAuthenticationResult const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SignInState(Windows::Media::Capture::AppBroadcastSignInState value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SignInState, WINRT_WRAP(void), Windows::Media::Capture::AppBroadcastSignInState const&);
            this->shim().SignInState(*reinterpret_cast<Windows::Media::Capture::AppBroadcastSignInState const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SignInState(Windows::Media::Capture::AppBroadcastSignInState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SignInState, WINRT_WRAP(Windows::Media::Capture::AppBroadcastSignInState));
            *value = detach_from<Windows::Media::Capture::AppBroadcastSignInState>(this->shim().SignInState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TerminationReason(Windows::Media::Capture::AppBroadcastTerminationReason* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TerminationReason, WINRT_WRAP(Windows::Media::Capture::AppBroadcastTerminationReason));
            *value = detach_from<Windows::Media::Capture::AppBroadcastTerminationReason>(this->shim().TerminationReason());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TerminationReasonPlugInSpecific(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TerminationReasonPlugInSpecific, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().TerminationReasonPlugInSpecific());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_ViewerCountChanged(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ViewerCountChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastState, Windows::Media::Capture::AppBroadcastViewerCountChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ViewerCountChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastState, Windows::Media::Capture::AppBroadcastViewerCountChangedEventArgs> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ViewerCountChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ViewerCountChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ViewerCountChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_MicrophoneCaptureStateChanged(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MicrophoneCaptureStateChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastState, Windows::Media::Capture::AppBroadcastMicrophoneCaptureStateChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().MicrophoneCaptureStateChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastState, Windows::Media::Capture::AppBroadcastMicrophoneCaptureStateChangedEventArgs> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_MicrophoneCaptureStateChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(MicrophoneCaptureStateChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().MicrophoneCaptureStateChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_CameraCaptureStateChanged(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CameraCaptureStateChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastState, Windows::Media::Capture::AppBroadcastCameraCaptureStateChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().CameraCaptureStateChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastState, Windows::Media::Capture::AppBroadcastCameraCaptureStateChangedEventArgs> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_CameraCaptureStateChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(CameraCaptureStateChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().CameraCaptureStateChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_PlugInStateChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PlugInStateChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastState, Windows::Media::Capture::AppBroadcastPlugInStateChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().PlugInStateChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastState, Windows::Media::Capture::AppBroadcastPlugInStateChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PlugInStateChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PlugInStateChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PlugInStateChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_StreamStateChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StreamStateChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastState, Windows::Media::Capture::AppBroadcastStreamStateChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().StreamStateChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastState, Windows::Media::Capture::AppBroadcastStreamStateChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_StreamStateChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(StreamStateChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().StreamStateChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_CaptureTargetClosed(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CaptureTargetClosed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastState, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().CaptureTargetClosed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastState, Windows::Foundation::IInspectable> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_CaptureTargetClosed(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(CaptureTargetClosed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().CaptureTargetClosed(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IAppBroadcastStreamAudioFrame> : produce_base<D, Windows::Media::Capture::IAppBroadcastStreamAudioFrame>
{
    int32_t WINRT_CALL get_AudioHeader(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioHeader, WINRT_WRAP(Windows::Media::Capture::AppBroadcastStreamAudioHeader));
            *value = detach_from<Windows::Media::Capture::AppBroadcastStreamAudioHeader>(this->shim().AudioHeader());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AudioBuffer(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioBuffer, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().AudioBuffer());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IAppBroadcastStreamAudioHeader> : produce_base<D, Windows::Media::Capture::IAppBroadcastStreamAudioHeader>
{
    int32_t WINRT_CALL get_AbsoluteTimestamp(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AbsoluteTimestamp, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().AbsoluteTimestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RelativeTimestamp(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RelativeTimestamp, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().RelativeTimestamp());
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

    int32_t WINRT_CALL get_HasDiscontinuity(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HasDiscontinuity, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().HasDiscontinuity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FrameId(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FrameId, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().FrameId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IAppBroadcastStreamReader> : produce_base<D, Windows::Media::Capture::IAppBroadcastStreamReader>
{
    int32_t WINRT_CALL get_AudioChannels(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioChannels, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().AudioChannels());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AudioSampleRate(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioSampleRate, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().AudioSampleRate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AudioAacSequence(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioAacSequence, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().AudioAacSequence());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AudioBitrate(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioBitrate, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().AudioBitrate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryGetNextAudioFrame(void** frame) noexcept final
    {
        try
        {
            *frame = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryGetNextAudioFrame, WINRT_WRAP(Windows::Media::Capture::AppBroadcastStreamAudioFrame));
            *frame = detach_from<Windows::Media::Capture::AppBroadcastStreamAudioFrame>(this->shim().TryGetNextAudioFrame());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VideoWidth(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoWidth, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().VideoWidth());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VideoHeight(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoHeight, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().VideoHeight());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VideoBitrate(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoBitrate, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().VideoBitrate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryGetNextVideoFrame(void** frame) noexcept final
    {
        try
        {
            *frame = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryGetNextVideoFrame, WINRT_WRAP(Windows::Media::Capture::AppBroadcastStreamVideoFrame));
            *frame = detach_from<Windows::Media::Capture::AppBroadcastStreamVideoFrame>(this->shim().TryGetNextVideoFrame());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_AudioFrameArrived(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioFrameArrived, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastStreamReader, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().AudioFrameArrived(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastStreamReader, Windows::Foundation::IInspectable> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_AudioFrameArrived(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(AudioFrameArrived, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().AudioFrameArrived(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_VideoFrameArrived(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoFrameArrived, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastStreamReader, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().VideoFrameArrived(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppBroadcastStreamReader, Windows::Foundation::IInspectable> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_VideoFrameArrived(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(VideoFrameArrived, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().VideoFrameArrived(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IAppBroadcastStreamStateChangedEventArgs> : produce_base<D, Windows::Media::Capture::IAppBroadcastStreamStateChangedEventArgs>
{
    int32_t WINRT_CALL get_StreamState(Windows::Media::Capture::AppBroadcastStreamState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StreamState, WINRT_WRAP(Windows::Media::Capture::AppBroadcastStreamState));
            *value = detach_from<Windows::Media::Capture::AppBroadcastStreamState>(this->shim().StreamState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IAppBroadcastStreamVideoFrame> : produce_base<D, Windows::Media::Capture::IAppBroadcastStreamVideoFrame>
{
    int32_t WINRT_CALL get_VideoHeader(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoHeader, WINRT_WRAP(Windows::Media::Capture::AppBroadcastStreamVideoHeader));
            *value = detach_from<Windows::Media::Capture::AppBroadcastStreamVideoHeader>(this->shim().VideoHeader());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VideoBuffer(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoBuffer, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().VideoBuffer());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IAppBroadcastStreamVideoHeader> : produce_base<D, Windows::Media::Capture::IAppBroadcastStreamVideoHeader>
{
    int32_t WINRT_CALL get_AbsoluteTimestamp(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AbsoluteTimestamp, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().AbsoluteTimestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RelativeTimestamp(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RelativeTimestamp, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().RelativeTimestamp());
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

    int32_t WINRT_CALL get_IsKeyFrame(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsKeyFrame, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsKeyFrame());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HasDiscontinuity(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HasDiscontinuity, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().HasDiscontinuity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FrameId(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FrameId, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().FrameId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IAppBroadcastTriggerDetails> : produce_base<D, Windows::Media::Capture::IAppBroadcastTriggerDetails>
{
    int32_t WINRT_CALL get_BackgroundService(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BackgroundService, WINRT_WRAP(Windows::Media::Capture::AppBroadcastBackgroundService));
            *value = detach_from<Windows::Media::Capture::AppBroadcastBackgroundService>(this->shim().BackgroundService());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IAppBroadcastViewerCountChangedEventArgs> : produce_base<D, Windows::Media::Capture::IAppBroadcastViewerCountChangedEventArgs>
{
    int32_t WINRT_CALL get_ViewerCount(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ViewerCount, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().ViewerCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IAppCapture> : produce_base<D, Windows::Media::Capture::IAppCapture>
{
    int32_t WINRT_CALL get_IsCapturingAudio(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsCapturingAudio, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsCapturingAudio());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsCapturingVideo(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsCapturingVideo, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsCapturingVideo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_CapturingChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CapturingChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppCapture, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().CapturingChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppCapture, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_CapturingChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(CapturingChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().CapturingChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IAppCaptureAlternateShortcutKeys> : produce_base<D, Windows::Media::Capture::IAppCaptureAlternateShortcutKeys>
{
    int32_t WINRT_CALL put_ToggleGameBarKey(Windows::System::VirtualKey value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ToggleGameBarKey, WINRT_WRAP(void), Windows::System::VirtualKey const&);
            this->shim().ToggleGameBarKey(*reinterpret_cast<Windows::System::VirtualKey const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ToggleGameBarKey(Windows::System::VirtualKey* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ToggleGameBarKey, WINRT_WRAP(Windows::System::VirtualKey));
            *value = detach_from<Windows::System::VirtualKey>(this->shim().ToggleGameBarKey());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ToggleGameBarKeyModifiers(Windows::System::VirtualKeyModifiers value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ToggleGameBarKeyModifiers, WINRT_WRAP(void), Windows::System::VirtualKeyModifiers const&);
            this->shim().ToggleGameBarKeyModifiers(*reinterpret_cast<Windows::System::VirtualKeyModifiers const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ToggleGameBarKeyModifiers(Windows::System::VirtualKeyModifiers* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ToggleGameBarKeyModifiers, WINRT_WRAP(Windows::System::VirtualKeyModifiers));
            *value = detach_from<Windows::System::VirtualKeyModifiers>(this->shim().ToggleGameBarKeyModifiers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SaveHistoricalVideoKey(Windows::System::VirtualKey value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SaveHistoricalVideoKey, WINRT_WRAP(void), Windows::System::VirtualKey const&);
            this->shim().SaveHistoricalVideoKey(*reinterpret_cast<Windows::System::VirtualKey const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SaveHistoricalVideoKey(Windows::System::VirtualKey* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SaveHistoricalVideoKey, WINRT_WRAP(Windows::System::VirtualKey));
            *value = detach_from<Windows::System::VirtualKey>(this->shim().SaveHistoricalVideoKey());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SaveHistoricalVideoKeyModifiers(Windows::System::VirtualKeyModifiers value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SaveHistoricalVideoKeyModifiers, WINRT_WRAP(void), Windows::System::VirtualKeyModifiers const&);
            this->shim().SaveHistoricalVideoKeyModifiers(*reinterpret_cast<Windows::System::VirtualKeyModifiers const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SaveHistoricalVideoKeyModifiers(Windows::System::VirtualKeyModifiers* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SaveHistoricalVideoKeyModifiers, WINRT_WRAP(Windows::System::VirtualKeyModifiers));
            *value = detach_from<Windows::System::VirtualKeyModifiers>(this->shim().SaveHistoricalVideoKeyModifiers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ToggleRecordingKey(Windows::System::VirtualKey value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ToggleRecordingKey, WINRT_WRAP(void), Windows::System::VirtualKey const&);
            this->shim().ToggleRecordingKey(*reinterpret_cast<Windows::System::VirtualKey const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ToggleRecordingKey(Windows::System::VirtualKey* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ToggleRecordingKey, WINRT_WRAP(Windows::System::VirtualKey));
            *value = detach_from<Windows::System::VirtualKey>(this->shim().ToggleRecordingKey());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ToggleRecordingKeyModifiers(Windows::System::VirtualKeyModifiers value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ToggleRecordingKeyModifiers, WINRT_WRAP(void), Windows::System::VirtualKeyModifiers const&);
            this->shim().ToggleRecordingKeyModifiers(*reinterpret_cast<Windows::System::VirtualKeyModifiers const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ToggleRecordingKeyModifiers(Windows::System::VirtualKeyModifiers* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ToggleRecordingKeyModifiers, WINRT_WRAP(Windows::System::VirtualKeyModifiers));
            *value = detach_from<Windows::System::VirtualKeyModifiers>(this->shim().ToggleRecordingKeyModifiers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TakeScreenshotKey(Windows::System::VirtualKey value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TakeScreenshotKey, WINRT_WRAP(void), Windows::System::VirtualKey const&);
            this->shim().TakeScreenshotKey(*reinterpret_cast<Windows::System::VirtualKey const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TakeScreenshotKey(Windows::System::VirtualKey* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TakeScreenshotKey, WINRT_WRAP(Windows::System::VirtualKey));
            *value = detach_from<Windows::System::VirtualKey>(this->shim().TakeScreenshotKey());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TakeScreenshotKeyModifiers(Windows::System::VirtualKeyModifiers value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TakeScreenshotKeyModifiers, WINRT_WRAP(void), Windows::System::VirtualKeyModifiers const&);
            this->shim().TakeScreenshotKeyModifiers(*reinterpret_cast<Windows::System::VirtualKeyModifiers const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TakeScreenshotKeyModifiers(Windows::System::VirtualKeyModifiers* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TakeScreenshotKeyModifiers, WINRT_WRAP(Windows::System::VirtualKeyModifiers));
            *value = detach_from<Windows::System::VirtualKeyModifiers>(this->shim().TakeScreenshotKeyModifiers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ToggleRecordingIndicatorKey(Windows::System::VirtualKey value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ToggleRecordingIndicatorKey, WINRT_WRAP(void), Windows::System::VirtualKey const&);
            this->shim().ToggleRecordingIndicatorKey(*reinterpret_cast<Windows::System::VirtualKey const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ToggleRecordingIndicatorKey(Windows::System::VirtualKey* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ToggleRecordingIndicatorKey, WINRT_WRAP(Windows::System::VirtualKey));
            *value = detach_from<Windows::System::VirtualKey>(this->shim().ToggleRecordingIndicatorKey());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ToggleRecordingIndicatorKeyModifiers(Windows::System::VirtualKeyModifiers value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ToggleRecordingIndicatorKeyModifiers, WINRT_WRAP(void), Windows::System::VirtualKeyModifiers const&);
            this->shim().ToggleRecordingIndicatorKeyModifiers(*reinterpret_cast<Windows::System::VirtualKeyModifiers const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ToggleRecordingIndicatorKeyModifiers(Windows::System::VirtualKeyModifiers* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ToggleRecordingIndicatorKeyModifiers, WINRT_WRAP(Windows::System::VirtualKeyModifiers));
            *value = detach_from<Windows::System::VirtualKeyModifiers>(this->shim().ToggleRecordingIndicatorKeyModifiers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IAppCaptureAlternateShortcutKeys2> : produce_base<D, Windows::Media::Capture::IAppCaptureAlternateShortcutKeys2>
{
    int32_t WINRT_CALL put_ToggleMicrophoneCaptureKey(Windows::System::VirtualKey value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ToggleMicrophoneCaptureKey, WINRT_WRAP(void), Windows::System::VirtualKey const&);
            this->shim().ToggleMicrophoneCaptureKey(*reinterpret_cast<Windows::System::VirtualKey const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ToggleMicrophoneCaptureKey(Windows::System::VirtualKey* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ToggleMicrophoneCaptureKey, WINRT_WRAP(Windows::System::VirtualKey));
            *value = detach_from<Windows::System::VirtualKey>(this->shim().ToggleMicrophoneCaptureKey());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ToggleMicrophoneCaptureKeyModifiers(Windows::System::VirtualKeyModifiers value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ToggleMicrophoneCaptureKeyModifiers, WINRT_WRAP(void), Windows::System::VirtualKeyModifiers const&);
            this->shim().ToggleMicrophoneCaptureKeyModifiers(*reinterpret_cast<Windows::System::VirtualKeyModifiers const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ToggleMicrophoneCaptureKeyModifiers(Windows::System::VirtualKeyModifiers* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ToggleMicrophoneCaptureKeyModifiers, WINRT_WRAP(Windows::System::VirtualKeyModifiers));
            *value = detach_from<Windows::System::VirtualKeyModifiers>(this->shim().ToggleMicrophoneCaptureKeyModifiers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IAppCaptureAlternateShortcutKeys3> : produce_base<D, Windows::Media::Capture::IAppCaptureAlternateShortcutKeys3>
{
    int32_t WINRT_CALL put_ToggleCameraCaptureKey(Windows::System::VirtualKey value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ToggleCameraCaptureKey, WINRT_WRAP(void), Windows::System::VirtualKey const&);
            this->shim().ToggleCameraCaptureKey(*reinterpret_cast<Windows::System::VirtualKey const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ToggleCameraCaptureKey(Windows::System::VirtualKey* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ToggleCameraCaptureKey, WINRT_WRAP(Windows::System::VirtualKey));
            *value = detach_from<Windows::System::VirtualKey>(this->shim().ToggleCameraCaptureKey());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ToggleCameraCaptureKeyModifiers(Windows::System::VirtualKeyModifiers value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ToggleCameraCaptureKeyModifiers, WINRT_WRAP(void), Windows::System::VirtualKeyModifiers const&);
            this->shim().ToggleCameraCaptureKeyModifiers(*reinterpret_cast<Windows::System::VirtualKeyModifiers const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ToggleCameraCaptureKeyModifiers(Windows::System::VirtualKeyModifiers* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ToggleCameraCaptureKeyModifiers, WINRT_WRAP(Windows::System::VirtualKeyModifiers));
            *value = detach_from<Windows::System::VirtualKeyModifiers>(this->shim().ToggleCameraCaptureKeyModifiers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ToggleBroadcastKey(Windows::System::VirtualKey value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ToggleBroadcastKey, WINRT_WRAP(void), Windows::System::VirtualKey const&);
            this->shim().ToggleBroadcastKey(*reinterpret_cast<Windows::System::VirtualKey const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ToggleBroadcastKey(Windows::System::VirtualKey* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ToggleBroadcastKey, WINRT_WRAP(Windows::System::VirtualKey));
            *value = detach_from<Windows::System::VirtualKey>(this->shim().ToggleBroadcastKey());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ToggleBroadcastKeyModifiers(Windows::System::VirtualKeyModifiers value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ToggleBroadcastKeyModifiers, WINRT_WRAP(void), Windows::System::VirtualKeyModifiers const&);
            this->shim().ToggleBroadcastKeyModifiers(*reinterpret_cast<Windows::System::VirtualKeyModifiers const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ToggleBroadcastKeyModifiers(Windows::System::VirtualKeyModifiers* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ToggleBroadcastKeyModifiers, WINRT_WRAP(Windows::System::VirtualKeyModifiers));
            *value = detach_from<Windows::System::VirtualKeyModifiers>(this->shim().ToggleBroadcastKeyModifiers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IAppCaptureDurationGeneratedEventArgs> : produce_base<D, Windows::Media::Capture::IAppCaptureDurationGeneratedEventArgs>
{
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
};

template <typename D>
struct produce<D, Windows::Media::Capture::IAppCaptureFileGeneratedEventArgs> : produce_base<D, Windows::Media::Capture::IAppCaptureFileGeneratedEventArgs>
{
    int32_t WINRT_CALL get_File(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(File, WINRT_WRAP(Windows::Storage::StorageFile));
            *value = detach_from<Windows::Storage::StorageFile>(this->shim().File());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IAppCaptureManagerStatics> : produce_base<D, Windows::Media::Capture::IAppCaptureManagerStatics>
{
    int32_t WINRT_CALL GetCurrentSettings(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCurrentSettings, WINRT_WRAP(Windows::Media::Capture::AppCaptureSettings));
            *value = detach_from<Windows::Media::Capture::AppCaptureSettings>(this->shim().GetCurrentSettings());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ApplySettings(void* appCaptureSettings) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ApplySettings, WINRT_WRAP(void), Windows::Media::Capture::AppCaptureSettings const&);
            this->shim().ApplySettings(*reinterpret_cast<Windows::Media::Capture::AppCaptureSettings const*>(&appCaptureSettings));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IAppCaptureMetadataWriter> : produce_base<D, Windows::Media::Capture::IAppCaptureMetadataWriter>
{
    int32_t WINRT_CALL AddStringEvent(void* name, void* value, Windows::Media::Capture::AppCaptureMetadataPriority priority) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddStringEvent, WINRT_WRAP(void), hstring const&, hstring const&, Windows::Media::Capture::AppCaptureMetadataPriority const&);
            this->shim().AddStringEvent(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<hstring const*>(&value), *reinterpret_cast<Windows::Media::Capture::AppCaptureMetadataPriority const*>(&priority));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AddInt32Event(void* name, int32_t value, Windows::Media::Capture::AppCaptureMetadataPriority priority) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddInt32Event, WINRT_WRAP(void), hstring const&, int32_t, Windows::Media::Capture::AppCaptureMetadataPriority const&);
            this->shim().AddInt32Event(*reinterpret_cast<hstring const*>(&name), value, *reinterpret_cast<Windows::Media::Capture::AppCaptureMetadataPriority const*>(&priority));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AddDoubleEvent(void* name, double value, Windows::Media::Capture::AppCaptureMetadataPriority priority) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddDoubleEvent, WINRT_WRAP(void), hstring const&, double, Windows::Media::Capture::AppCaptureMetadataPriority const&);
            this->shim().AddDoubleEvent(*reinterpret_cast<hstring const*>(&name), value, *reinterpret_cast<Windows::Media::Capture::AppCaptureMetadataPriority const*>(&priority));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StartStringState(void* name, void* value, Windows::Media::Capture::AppCaptureMetadataPriority priority) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartStringState, WINRT_WRAP(void), hstring const&, hstring const&, Windows::Media::Capture::AppCaptureMetadataPriority const&);
            this->shim().StartStringState(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<hstring const*>(&value), *reinterpret_cast<Windows::Media::Capture::AppCaptureMetadataPriority const*>(&priority));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StartInt32State(void* name, int32_t value, Windows::Media::Capture::AppCaptureMetadataPriority priority) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartInt32State, WINRT_WRAP(void), hstring const&, int32_t, Windows::Media::Capture::AppCaptureMetadataPriority const&);
            this->shim().StartInt32State(*reinterpret_cast<hstring const*>(&name), value, *reinterpret_cast<Windows::Media::Capture::AppCaptureMetadataPriority const*>(&priority));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StartDoubleState(void* name, double value, Windows::Media::Capture::AppCaptureMetadataPriority priority) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartDoubleState, WINRT_WRAP(void), hstring const&, double, Windows::Media::Capture::AppCaptureMetadataPriority const&);
            this->shim().StartDoubleState(*reinterpret_cast<hstring const*>(&name), value, *reinterpret_cast<Windows::Media::Capture::AppCaptureMetadataPriority const*>(&priority));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StopState(void* name) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StopState, WINRT_WRAP(void), hstring const&);
            this->shim().StopState(*reinterpret_cast<hstring const*>(&name));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StopAllStates() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StopAllStates, WINRT_WRAP(void));
            this->shim().StopAllStates();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RemainingStorageBytesAvailable(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemainingStorageBytesAvailable, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().RemainingStorageBytesAvailable());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_MetadataPurged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MetadataPurged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppCaptureMetadataWriter, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().MetadataPurged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppCaptureMetadataWriter, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_MetadataPurged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(MetadataPurged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().MetadataPurged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IAppCaptureMicrophoneCaptureStateChangedEventArgs> : produce_base<D, Windows::Media::Capture::IAppCaptureMicrophoneCaptureStateChangedEventArgs>
{
    int32_t WINRT_CALL get_State(Windows::Media::Capture::AppCaptureMicrophoneCaptureState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(State, WINRT_WRAP(Windows::Media::Capture::AppCaptureMicrophoneCaptureState));
            *value = detach_from<Windows::Media::Capture::AppCaptureMicrophoneCaptureState>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ErrorCode(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ErrorCode, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().ErrorCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IAppCaptureRecordOperation> : produce_base<D, Windows::Media::Capture::IAppCaptureRecordOperation>
{
    int32_t WINRT_CALL StopRecording() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StopRecording, WINRT_WRAP(void));
            this->shim().StopRecording();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_State(Windows::Media::Capture::AppCaptureRecordingState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(State, WINRT_WRAP(Windows::Media::Capture::AppCaptureRecordingState));
            *value = detach_from<Windows::Media::Capture::AppCaptureRecordingState>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ErrorCode(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ErrorCode, WINRT_WRAP(Windows::Foundation::IReference<uint32_t>));
            *value = detach_from<Windows::Foundation::IReference<uint32_t>>(this->shim().ErrorCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Duration(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Duration, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::TimeSpan>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::TimeSpan>>(this->shim().Duration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_File(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(File, WINRT_WRAP(Windows::Storage::StorageFile));
            *value = detach_from<Windows::Storage::StorageFile>(this->shim().File());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsFileTruncated(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsFileTruncated, WINRT_WRAP(Windows::Foundation::IReference<bool>));
            *value = detach_from<Windows::Foundation::IReference<bool>>(this->shim().IsFileTruncated());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_StateChanged(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StateChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppCaptureRecordOperation, Windows::Media::Capture::AppCaptureRecordingStateChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().StateChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppCaptureRecordOperation, Windows::Media::Capture::AppCaptureRecordingStateChangedEventArgs> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_StateChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(StateChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().StateChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_DurationGenerated(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DurationGenerated, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppCaptureRecordOperation, Windows::Media::Capture::AppCaptureDurationGeneratedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().DurationGenerated(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppCaptureRecordOperation, Windows::Media::Capture::AppCaptureDurationGeneratedEventArgs> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_DurationGenerated(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(DurationGenerated, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().DurationGenerated(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_FileGenerated(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FileGenerated, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppCaptureRecordOperation, Windows::Media::Capture::AppCaptureFileGeneratedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().FileGenerated(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppCaptureRecordOperation, Windows::Media::Capture::AppCaptureFileGeneratedEventArgs> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_FileGenerated(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(FileGenerated, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().FileGenerated(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IAppCaptureRecordingStateChangedEventArgs> : produce_base<D, Windows::Media::Capture::IAppCaptureRecordingStateChangedEventArgs>
{
    int32_t WINRT_CALL get_State(Windows::Media::Capture::AppCaptureRecordingState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(State, WINRT_WRAP(Windows::Media::Capture::AppCaptureRecordingState));
            *value = detach_from<Windows::Media::Capture::AppCaptureRecordingState>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ErrorCode(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ErrorCode, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().ErrorCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IAppCaptureServices> : produce_base<D, Windows::Media::Capture::IAppCaptureServices>
{
    int32_t WINRT_CALL Record(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Record, WINRT_WRAP(Windows::Media::Capture::AppCaptureRecordOperation));
            *operation = detach_from<Windows::Media::Capture::AppCaptureRecordOperation>(this->shim().Record());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RecordTimeSpan(Windows::Foundation::DateTime startTime, Windows::Foundation::TimeSpan duration, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RecordTimeSpan, WINRT_WRAP(Windows::Media::Capture::AppCaptureRecordOperation), Windows::Foundation::DateTime const&, Windows::Foundation::TimeSpan const&);
            *operation = detach_from<Windows::Media::Capture::AppCaptureRecordOperation>(this->shim().RecordTimeSpan(*reinterpret_cast<Windows::Foundation::DateTime const*>(&startTime), *reinterpret_cast<Windows::Foundation::TimeSpan const*>(&duration)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanCapture(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanCapture, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanCapture());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_State(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(State, WINRT_WRAP(Windows::Media::Capture::AppCaptureState));
            *value = detach_from<Windows::Media::Capture::AppCaptureState>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IAppCaptureSettings> : produce_base<D, Windows::Media::Capture::IAppCaptureSettings>
{
    int32_t WINRT_CALL put_AppCaptureDestinationFolder(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppCaptureDestinationFolder, WINRT_WRAP(void), Windows::Storage::StorageFolder const&);
            this->shim().AppCaptureDestinationFolder(*reinterpret_cast<Windows::Storage::StorageFolder const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AppCaptureDestinationFolder(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppCaptureDestinationFolder, WINRT_WRAP(Windows::Storage::StorageFolder));
            *value = detach_from<Windows::Storage::StorageFolder>(this->shim().AppCaptureDestinationFolder());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AudioEncodingBitrate(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioEncodingBitrate, WINRT_WRAP(void), uint32_t);
            this->shim().AudioEncodingBitrate(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AudioEncodingBitrate(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioEncodingBitrate, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().AudioEncodingBitrate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsAudioCaptureEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsAudioCaptureEnabled, WINRT_WRAP(void), bool);
            this->shim().IsAudioCaptureEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsAudioCaptureEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsAudioCaptureEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsAudioCaptureEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CustomVideoEncodingBitrate(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CustomVideoEncodingBitrate, WINRT_WRAP(void), uint32_t);
            this->shim().CustomVideoEncodingBitrate(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CustomVideoEncodingBitrate(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CustomVideoEncodingBitrate, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().CustomVideoEncodingBitrate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CustomVideoEncodingHeight(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CustomVideoEncodingHeight, WINRT_WRAP(void), uint32_t);
            this->shim().CustomVideoEncodingHeight(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CustomVideoEncodingHeight(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CustomVideoEncodingHeight, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().CustomVideoEncodingHeight());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CustomVideoEncodingWidth(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CustomVideoEncodingWidth, WINRT_WRAP(void), uint32_t);
            this->shim().CustomVideoEncodingWidth(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CustomVideoEncodingWidth(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CustomVideoEncodingWidth, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().CustomVideoEncodingWidth());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_HistoricalBufferLength(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HistoricalBufferLength, WINRT_WRAP(void), uint32_t);
            this->shim().HistoricalBufferLength(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HistoricalBufferLength(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HistoricalBufferLength, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().HistoricalBufferLength());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_HistoricalBufferLengthUnit(Windows::Media::Capture::AppCaptureHistoricalBufferLengthUnit value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HistoricalBufferLengthUnit, WINRT_WRAP(void), Windows::Media::Capture::AppCaptureHistoricalBufferLengthUnit const&);
            this->shim().HistoricalBufferLengthUnit(*reinterpret_cast<Windows::Media::Capture::AppCaptureHistoricalBufferLengthUnit const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HistoricalBufferLengthUnit(Windows::Media::Capture::AppCaptureHistoricalBufferLengthUnit* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HistoricalBufferLengthUnit, WINRT_WRAP(Windows::Media::Capture::AppCaptureHistoricalBufferLengthUnit));
            *value = detach_from<Windows::Media::Capture::AppCaptureHistoricalBufferLengthUnit>(this->shim().HistoricalBufferLengthUnit());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsHistoricalCaptureEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsHistoricalCaptureEnabled, WINRT_WRAP(void), bool);
            this->shim().IsHistoricalCaptureEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsHistoricalCaptureEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsHistoricalCaptureEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsHistoricalCaptureEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsHistoricalCaptureOnBatteryAllowed(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsHistoricalCaptureOnBatteryAllowed, WINRT_WRAP(void), bool);
            this->shim().IsHistoricalCaptureOnBatteryAllowed(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsHistoricalCaptureOnBatteryAllowed(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsHistoricalCaptureOnBatteryAllowed, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsHistoricalCaptureOnBatteryAllowed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsHistoricalCaptureOnWirelessDisplayAllowed(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsHistoricalCaptureOnWirelessDisplayAllowed, WINRT_WRAP(void), bool);
            this->shim().IsHistoricalCaptureOnWirelessDisplayAllowed(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsHistoricalCaptureOnWirelessDisplayAllowed(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsHistoricalCaptureOnWirelessDisplayAllowed, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsHistoricalCaptureOnWirelessDisplayAllowed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MaximumRecordLength(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaximumRecordLength, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().MaximumRecordLength(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaximumRecordLength(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaximumRecordLength, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().MaximumRecordLength());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ScreenshotDestinationFolder(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScreenshotDestinationFolder, WINRT_WRAP(void), Windows::Storage::StorageFolder const&);
            this->shim().ScreenshotDestinationFolder(*reinterpret_cast<Windows::Storage::StorageFolder const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ScreenshotDestinationFolder(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScreenshotDestinationFolder, WINRT_WRAP(Windows::Storage::StorageFolder));
            *value = detach_from<Windows::Storage::StorageFolder>(this->shim().ScreenshotDestinationFolder());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_VideoEncodingBitrateMode(Windows::Media::Capture::AppCaptureVideoEncodingBitrateMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoEncodingBitrateMode, WINRT_WRAP(void), Windows::Media::Capture::AppCaptureVideoEncodingBitrateMode const&);
            this->shim().VideoEncodingBitrateMode(*reinterpret_cast<Windows::Media::Capture::AppCaptureVideoEncodingBitrateMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VideoEncodingBitrateMode(Windows::Media::Capture::AppCaptureVideoEncodingBitrateMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoEncodingBitrateMode, WINRT_WRAP(Windows::Media::Capture::AppCaptureVideoEncodingBitrateMode));
            *value = detach_from<Windows::Media::Capture::AppCaptureVideoEncodingBitrateMode>(this->shim().VideoEncodingBitrateMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_VideoEncodingResolutionMode(Windows::Media::Capture::AppCaptureVideoEncodingResolutionMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoEncodingResolutionMode, WINRT_WRAP(void), Windows::Media::Capture::AppCaptureVideoEncodingResolutionMode const&);
            this->shim().VideoEncodingResolutionMode(*reinterpret_cast<Windows::Media::Capture::AppCaptureVideoEncodingResolutionMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VideoEncodingResolutionMode(Windows::Media::Capture::AppCaptureVideoEncodingResolutionMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoEncodingResolutionMode, WINRT_WRAP(Windows::Media::Capture::AppCaptureVideoEncodingResolutionMode));
            *value = detach_from<Windows::Media::Capture::AppCaptureVideoEncodingResolutionMode>(this->shim().VideoEncodingResolutionMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsAppCaptureEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsAppCaptureEnabled, WINRT_WRAP(void), bool);
            this->shim().IsAppCaptureEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsAppCaptureEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsAppCaptureEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsAppCaptureEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsCpuConstrained(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsCpuConstrained, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsCpuConstrained());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsDisabledByPolicy(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDisabledByPolicy, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsDisabledByPolicy());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsMemoryConstrained(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsMemoryConstrained, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsMemoryConstrained());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HasHardwareEncoder(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HasHardwareEncoder, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().HasHardwareEncoder());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IAppCaptureSettings2> : produce_base<D, Windows::Media::Capture::IAppCaptureSettings2>
{
    int32_t WINRT_CALL get_IsGpuConstrained(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsGpuConstrained, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsGpuConstrained());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AlternateShortcutKeys(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AlternateShortcutKeys, WINRT_WRAP(Windows::Media::Capture::AppCaptureAlternateShortcutKeys));
            *value = detach_from<Windows::Media::Capture::AppCaptureAlternateShortcutKeys>(this->shim().AlternateShortcutKeys());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IAppCaptureSettings3> : produce_base<D, Windows::Media::Capture::IAppCaptureSettings3>
{
    int32_t WINRT_CALL put_IsMicrophoneCaptureEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsMicrophoneCaptureEnabled, WINRT_WRAP(void), bool);
            this->shim().IsMicrophoneCaptureEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsMicrophoneCaptureEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsMicrophoneCaptureEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsMicrophoneCaptureEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IAppCaptureSettings4> : produce_base<D, Windows::Media::Capture::IAppCaptureSettings4>
{
    int32_t WINRT_CALL put_IsMicrophoneCaptureEnabledByDefault(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsMicrophoneCaptureEnabledByDefault, WINRT_WRAP(void), bool);
            this->shim().IsMicrophoneCaptureEnabledByDefault(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsMicrophoneCaptureEnabledByDefault(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsMicrophoneCaptureEnabledByDefault, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsMicrophoneCaptureEnabledByDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SystemAudioGain(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SystemAudioGain, WINRT_WRAP(void), double);
            this->shim().SystemAudioGain(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SystemAudioGain(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SystemAudioGain, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().SystemAudioGain());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MicrophoneGain(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MicrophoneGain, WINRT_WRAP(void), double);
            this->shim().MicrophoneGain(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MicrophoneGain(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MicrophoneGain, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().MicrophoneGain());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_VideoEncodingFrameRateMode(Windows::Media::Capture::AppCaptureVideoEncodingFrameRateMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoEncodingFrameRateMode, WINRT_WRAP(void), Windows::Media::Capture::AppCaptureVideoEncodingFrameRateMode const&);
            this->shim().VideoEncodingFrameRateMode(*reinterpret_cast<Windows::Media::Capture::AppCaptureVideoEncodingFrameRateMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VideoEncodingFrameRateMode(Windows::Media::Capture::AppCaptureVideoEncodingFrameRateMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoEncodingFrameRateMode, WINRT_WRAP(Windows::Media::Capture::AppCaptureVideoEncodingFrameRateMode));
            *value = detach_from<Windows::Media::Capture::AppCaptureVideoEncodingFrameRateMode>(this->shim().VideoEncodingFrameRateMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IAppCaptureSettings5> : produce_base<D, Windows::Media::Capture::IAppCaptureSettings5>
{
    int32_t WINRT_CALL put_IsEchoCancellationEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsEchoCancellationEnabled, WINRT_WRAP(void), bool);
            this->shim().IsEchoCancellationEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsEchoCancellationEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsEchoCancellationEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsEchoCancellationEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsCursorImageCaptureEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsCursorImageCaptureEnabled, WINRT_WRAP(void), bool);
            this->shim().IsCursorImageCaptureEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsCursorImageCaptureEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsCursorImageCaptureEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsCursorImageCaptureEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IAppCaptureState> : produce_base<D, Windows::Media::Capture::IAppCaptureState>
{
    int32_t WINRT_CALL get_IsTargetRunning(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsTargetRunning, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsTargetRunning());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsHistoricalCaptureEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsHistoricalCaptureEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsHistoricalCaptureEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ShouldCaptureMicrophone(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShouldCaptureMicrophone, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().ShouldCaptureMicrophone());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ShouldCaptureMicrophone(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShouldCaptureMicrophone, WINRT_WRAP(void), bool);
            this->shim().ShouldCaptureMicrophone(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RestartMicrophoneCapture() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RestartMicrophoneCapture, WINRT_WRAP(void));
            this->shim().RestartMicrophoneCapture();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MicrophoneCaptureState(Windows::Media::Capture::AppCaptureMicrophoneCaptureState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MicrophoneCaptureState, WINRT_WRAP(Windows::Media::Capture::AppCaptureMicrophoneCaptureState));
            *value = detach_from<Windows::Media::Capture::AppCaptureMicrophoneCaptureState>(this->shim().MicrophoneCaptureState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MicrophoneCaptureError(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MicrophoneCaptureError, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().MicrophoneCaptureError());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_MicrophoneCaptureStateChanged(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MicrophoneCaptureStateChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppCaptureState, Windows::Media::Capture::AppCaptureMicrophoneCaptureStateChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().MicrophoneCaptureStateChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppCaptureState, Windows::Media::Capture::AppCaptureMicrophoneCaptureStateChangedEventArgs> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_MicrophoneCaptureStateChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(MicrophoneCaptureStateChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().MicrophoneCaptureStateChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_CaptureTargetClosed(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CaptureTargetClosed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppCaptureState, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().CaptureTargetClosed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Capture::AppCaptureState, Windows::Foundation::IInspectable> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_CaptureTargetClosed(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(CaptureTargetClosed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().CaptureTargetClosed(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IAppCaptureStatics> : produce_base<D, Windows::Media::Capture::IAppCaptureStatics>
{
    int32_t WINRT_CALL GetForCurrentView(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForCurrentView, WINRT_WRAP(Windows::Media::Capture::AppCapture));
            *value = detach_from<Windows::Media::Capture::AppCapture>(this->shim().GetForCurrentView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IAppCaptureStatics2> : produce_base<D, Windows::Media::Capture::IAppCaptureStatics2>
{
    int32_t WINRT_CALL SetAllowedAsync(bool allowed, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetAllowedAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), bool);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SetAllowedAsync(allowed));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::ICameraCaptureUI> : produce_base<D, Windows::Media::Capture::ICameraCaptureUI>
{
    int32_t WINRT_CALL get_PhotoSettings(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PhotoSettings, WINRT_WRAP(Windows::Media::Capture::CameraCaptureUIPhotoCaptureSettings));
            *value = detach_from<Windows::Media::Capture::CameraCaptureUIPhotoCaptureSettings>(this->shim().PhotoSettings());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VideoSettings(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoSettings, WINRT_WRAP(Windows::Media::Capture::CameraCaptureUIVideoCaptureSettings));
            *value = detach_from<Windows::Media::Capture::CameraCaptureUIVideoCaptureSettings>(this->shim().VideoSettings());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CaptureFileAsync(Windows::Media::Capture::CameraCaptureUIMode mode, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CaptureFileAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile>), Windows::Media::Capture::CameraCaptureUIMode const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile>>(this->shim().CaptureFileAsync(*reinterpret_cast<Windows::Media::Capture::CameraCaptureUIMode const*>(&mode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::ICameraCaptureUIPhotoCaptureSettings> : produce_base<D, Windows::Media::Capture::ICameraCaptureUIPhotoCaptureSettings>
{
    int32_t WINRT_CALL get_Format(Windows::Media::Capture::CameraCaptureUIPhotoFormat* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Format, WINRT_WRAP(Windows::Media::Capture::CameraCaptureUIPhotoFormat));
            *value = detach_from<Windows::Media::Capture::CameraCaptureUIPhotoFormat>(this->shim().Format());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Format(Windows::Media::Capture::CameraCaptureUIPhotoFormat value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Format, WINRT_WRAP(void), Windows::Media::Capture::CameraCaptureUIPhotoFormat const&);
            this->shim().Format(*reinterpret_cast<Windows::Media::Capture::CameraCaptureUIPhotoFormat const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxResolution(Windows::Media::Capture::CameraCaptureUIMaxPhotoResolution* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxResolution, WINRT_WRAP(Windows::Media::Capture::CameraCaptureUIMaxPhotoResolution));
            *value = detach_from<Windows::Media::Capture::CameraCaptureUIMaxPhotoResolution>(this->shim().MaxResolution());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MaxResolution(Windows::Media::Capture::CameraCaptureUIMaxPhotoResolution value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxResolution, WINRT_WRAP(void), Windows::Media::Capture::CameraCaptureUIMaxPhotoResolution const&);
            this->shim().MaxResolution(*reinterpret_cast<Windows::Media::Capture::CameraCaptureUIMaxPhotoResolution const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CroppedSizeInPixels(Windows::Foundation::Size* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CroppedSizeInPixels, WINRT_WRAP(Windows::Foundation::Size));
            *value = detach_from<Windows::Foundation::Size>(this->shim().CroppedSizeInPixels());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CroppedSizeInPixels(Windows::Foundation::Size value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CroppedSizeInPixels, WINRT_WRAP(void), Windows::Foundation::Size const&);
            this->shim().CroppedSizeInPixels(*reinterpret_cast<Windows::Foundation::Size const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CroppedAspectRatio(Windows::Foundation::Size* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CroppedAspectRatio, WINRT_WRAP(Windows::Foundation::Size));
            *value = detach_from<Windows::Foundation::Size>(this->shim().CroppedAspectRatio());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CroppedAspectRatio(Windows::Foundation::Size value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CroppedAspectRatio, WINRT_WRAP(void), Windows::Foundation::Size const&);
            this->shim().CroppedAspectRatio(*reinterpret_cast<Windows::Foundation::Size const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AllowCropping(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllowCropping, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AllowCropping());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AllowCropping(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllowCropping, WINRT_WRAP(void), bool);
            this->shim().AllowCropping(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::ICameraCaptureUIVideoCaptureSettings> : produce_base<D, Windows::Media::Capture::ICameraCaptureUIVideoCaptureSettings>
{
    int32_t WINRT_CALL get_Format(Windows::Media::Capture::CameraCaptureUIVideoFormat* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Format, WINRT_WRAP(Windows::Media::Capture::CameraCaptureUIVideoFormat));
            *value = detach_from<Windows::Media::Capture::CameraCaptureUIVideoFormat>(this->shim().Format());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Format(Windows::Media::Capture::CameraCaptureUIVideoFormat value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Format, WINRT_WRAP(void), Windows::Media::Capture::CameraCaptureUIVideoFormat const&);
            this->shim().Format(*reinterpret_cast<Windows::Media::Capture::CameraCaptureUIVideoFormat const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxResolution(Windows::Media::Capture::CameraCaptureUIMaxVideoResolution* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxResolution, WINRT_WRAP(Windows::Media::Capture::CameraCaptureUIMaxVideoResolution));
            *value = detach_from<Windows::Media::Capture::CameraCaptureUIMaxVideoResolution>(this->shim().MaxResolution());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MaxResolution(Windows::Media::Capture::CameraCaptureUIMaxVideoResolution value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxResolution, WINRT_WRAP(void), Windows::Media::Capture::CameraCaptureUIMaxVideoResolution const&);
            this->shim().MaxResolution(*reinterpret_cast<Windows::Media::Capture::CameraCaptureUIMaxVideoResolution const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxDurationInSeconds(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxDurationInSeconds, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().MaxDurationInSeconds());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MaxDurationInSeconds(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxDurationInSeconds, WINRT_WRAP(void), float);
            this->shim().MaxDurationInSeconds(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AllowTrimming(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllowTrimming, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AllowTrimming());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AllowTrimming(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllowTrimming, WINRT_WRAP(void), bool);
            this->shim().AllowTrimming(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::ICameraOptionsUIStatics> : produce_base<D, Windows::Media::Capture::ICameraOptionsUIStatics>
{
    int32_t WINRT_CALL Show(void* mediaCapture) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Show, WINRT_WRAP(void), Windows::Media::Capture::MediaCapture const&);
            this->shim().Show(*reinterpret_cast<Windows::Media::Capture::MediaCapture const*>(&mediaCapture));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::ICapturedFrame> : produce_base<D, Windows::Media::Capture::ICapturedFrame>
{
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
};

template <typename D>
struct produce<D, Windows::Media::Capture::ICapturedFrame2> : produce_base<D, Windows::Media::Capture::ICapturedFrame2>
{
    int32_t WINRT_CALL get_ControlValues(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ControlValues, WINRT_WRAP(Windows::Media::Capture::CapturedFrameControlValues));
            *value = detach_from<Windows::Media::Capture::CapturedFrameControlValues>(this->shim().ControlValues());
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
            WINRT_ASSERT_DECLARATION(BitmapProperties, WINRT_WRAP(Windows::Graphics::Imaging::BitmapPropertySet));
            *value = detach_from<Windows::Graphics::Imaging::BitmapPropertySet>(this->shim().BitmapProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::ICapturedFrameControlValues> : produce_base<D, Windows::Media::Capture::ICapturedFrameControlValues>
{
    int32_t WINRT_CALL get_Exposure(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Exposure, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::TimeSpan>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::TimeSpan>>(this->shim().Exposure());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExposureCompensation(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExposureCompensation, WINRT_WRAP(Windows::Foundation::IReference<float>));
            *value = detach_from<Windows::Foundation::IReference<float>>(this->shim().ExposureCompensation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsoSpeed(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsoSpeed, WINRT_WRAP(Windows::Foundation::IReference<uint32_t>));
            *value = detach_from<Windows::Foundation::IReference<uint32_t>>(this->shim().IsoSpeed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Focus(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Focus, WINRT_WRAP(Windows::Foundation::IReference<uint32_t>));
            *value = detach_from<Windows::Foundation::IReference<uint32_t>>(this->shim().Focus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SceneMode(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SceneMode, WINRT_WRAP(Windows::Foundation::IReference<Windows::Media::Devices::CaptureSceneMode>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Media::Devices::CaptureSceneMode>>(this->shim().SceneMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Flashed(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Flashed, WINRT_WRAP(Windows::Foundation::IReference<bool>));
            *value = detach_from<Windows::Foundation::IReference<bool>>(this->shim().Flashed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FlashPowerPercent(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FlashPowerPercent, WINRT_WRAP(Windows::Foundation::IReference<float>));
            *value = detach_from<Windows::Foundation::IReference<float>>(this->shim().FlashPowerPercent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WhiteBalance(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WhiteBalance, WINRT_WRAP(Windows::Foundation::IReference<uint32_t>));
            *value = detach_from<Windows::Foundation::IReference<uint32_t>>(this->shim().WhiteBalance());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ZoomFactor(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ZoomFactor, WINRT_WRAP(Windows::Foundation::IReference<float>));
            *value = detach_from<Windows::Foundation::IReference<float>>(this->shim().ZoomFactor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::ICapturedFrameControlValues2> : produce_base<D, Windows::Media::Capture::ICapturedFrameControlValues2>
{
    int32_t WINRT_CALL get_FocusState(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FocusState, WINRT_WRAP(Windows::Foundation::IReference<Windows::Media::Devices::MediaCaptureFocusState>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Media::Devices::MediaCaptureFocusState>>(this->shim().FocusState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsoDigitalGain(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsoDigitalGain, WINRT_WRAP(Windows::Foundation::IReference<double>));
            *value = detach_from<Windows::Foundation::IReference<double>>(this->shim().IsoDigitalGain());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsoAnalogGain(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsoAnalogGain, WINRT_WRAP(Windows::Foundation::IReference<double>));
            *value = detach_from<Windows::Foundation::IReference<double>>(this->shim().IsoAnalogGain());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SensorFrameRate(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SensorFrameRate, WINRT_WRAP(Windows::Media::MediaProperties::MediaRatio));
            *value = detach_from<Windows::Media::MediaProperties::MediaRatio>(this->shim().SensorFrameRate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WhiteBalanceGain(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WhiteBalanceGain, WINRT_WRAP(Windows::Foundation::IReference<Windows::Media::Capture::WhiteBalanceGain>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Media::Capture::WhiteBalanceGain>>(this->shim().WhiteBalanceGain());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::ICapturedFrameWithSoftwareBitmap> : produce_base<D, Windows::Media::Capture::ICapturedFrameWithSoftwareBitmap>
{
    int32_t WINRT_CALL get_SoftwareBitmap(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SoftwareBitmap, WINRT_WRAP(Windows::Graphics::Imaging::SoftwareBitmap));
            *value = detach_from<Windows::Graphics::Imaging::SoftwareBitmap>(this->shim().SoftwareBitmap());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::ICapturedPhoto> : produce_base<D, Windows::Media::Capture::ICapturedPhoto>
{
    int32_t WINRT_CALL get_Frame(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Frame, WINRT_WRAP(Windows::Media::Capture::CapturedFrame));
            *value = detach_from<Windows::Media::Capture::CapturedFrame>(this->shim().Frame());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Thumbnail(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Thumbnail, WINRT_WRAP(Windows::Media::Capture::CapturedFrame));
            *value = detach_from<Windows::Media::Capture::CapturedFrame>(this->shim().Thumbnail());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IGameBarServices> : produce_base<D, Windows::Media::Capture::IGameBarServices>
{
    int32_t WINRT_CALL get_TargetCapturePolicy(Windows::Media::Capture::GameBarTargetCapturePolicy* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetCapturePolicy, WINRT_WRAP(Windows::Media::Capture::GameBarTargetCapturePolicy));
            *value = detach_from<Windows::Media::Capture::GameBarTargetCapturePolicy>(this->shim().TargetCapturePolicy());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL EnableCapture() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnableCapture, WINRT_WRAP(void));
            this->shim().EnableCapture();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DisableCapture() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisableCapture, WINRT_WRAP(void));
            this->shim().DisableCapture();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TargetInfo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetInfo, WINRT_WRAP(Windows::Media::Capture::GameBarServicesTargetInfo));
            *value = detach_from<Windows::Media::Capture::GameBarServicesTargetInfo>(this->shim().TargetInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SessionId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SessionId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SessionId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AppBroadcastServices(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppBroadcastServices, WINRT_WRAP(Windows::Media::Capture::AppBroadcastServices));
            *value = detach_from<Windows::Media::Capture::AppBroadcastServices>(this->shim().AppBroadcastServices());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AppCaptureServices(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppCaptureServices, WINRT_WRAP(Windows::Media::Capture::AppCaptureServices));
            *value = detach_from<Windows::Media::Capture::AppCaptureServices>(this->shim().AppCaptureServices());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_CommandReceived(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CommandReceived, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Capture::GameBarServices, Windows::Media::Capture::GameBarServicesCommandEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().CommandReceived(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Capture::GameBarServices, Windows::Media::Capture::GameBarServicesCommandEventArgs> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_CommandReceived(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(CommandReceived, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().CommandReceived(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IGameBarServicesCommandEventArgs> : produce_base<D, Windows::Media::Capture::IGameBarServicesCommandEventArgs>
{
    int32_t WINRT_CALL get_Command(Windows::Media::Capture::GameBarCommand* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Command, WINRT_WRAP(Windows::Media::Capture::GameBarCommand));
            *value = detach_from<Windows::Media::Capture::GameBarCommand>(this->shim().Command());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Origin(Windows::Media::Capture::GameBarCommandOrigin* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Origin, WINRT_WRAP(Windows::Media::Capture::GameBarCommandOrigin));
            *value = detach_from<Windows::Media::Capture::GameBarCommandOrigin>(this->shim().Origin());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IGameBarServicesManager> : produce_base<D, Windows::Media::Capture::IGameBarServicesManager>
{
    int32_t WINRT_CALL add_GameBarServicesCreated(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GameBarServicesCreated, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Capture::GameBarServicesManager, Windows::Media::Capture::GameBarServicesManagerGameBarServicesCreatedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().GameBarServicesCreated(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Capture::GameBarServicesManager, Windows::Media::Capture::GameBarServicesManagerGameBarServicesCreatedEventArgs> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_GameBarServicesCreated(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(GameBarServicesCreated, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().GameBarServicesCreated(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IGameBarServicesManagerGameBarServicesCreatedEventArgs> : produce_base<D, Windows::Media::Capture::IGameBarServicesManagerGameBarServicesCreatedEventArgs>
{
    int32_t WINRT_CALL get_GameBarServices(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GameBarServices, WINRT_WRAP(Windows::Media::Capture::GameBarServices));
            *value = detach_from<Windows::Media::Capture::GameBarServices>(this->shim().GameBarServices());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IGameBarServicesManagerStatics> : produce_base<D, Windows::Media::Capture::IGameBarServicesManagerStatics>
{
    int32_t WINRT_CALL GetDefault(void** ppInstance) noexcept final
    {
        try
        {
            *ppInstance = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefault, WINRT_WRAP(Windows::Media::Capture::GameBarServicesManager));
            *ppInstance = detach_from<Windows::Media::Capture::GameBarServicesManager>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IGameBarServicesTargetInfo> : produce_base<D, Windows::Media::Capture::IGameBarServicesTargetInfo>
{
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

    int32_t WINRT_CALL get_AppId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AppId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TitleId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TitleId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().TitleId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DisplayMode(Windows::Media::Capture::GameBarServicesDisplayMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayMode, WINRT_WRAP(Windows::Media::Capture::GameBarServicesDisplayMode));
            *value = detach_from<Windows::Media::Capture::GameBarServicesDisplayMode>(this->shim().DisplayMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::ILowLagMediaRecording> : produce_base<D, Windows::Media::Capture::ILowLagMediaRecording>
{
    int32_t WINRT_CALL StartAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().StartAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StopAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StopAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().StopAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FinishAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FinishAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().FinishAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::ILowLagMediaRecording2> : produce_base<D, Windows::Media::Capture::ILowLagMediaRecording2>
{
    int32_t WINRT_CALL PauseAsync(Windows::Media::Devices::MediaCapturePauseBehavior behavior, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PauseAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Media::Devices::MediaCapturePauseBehavior const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().PauseAsync(*reinterpret_cast<Windows::Media::Devices::MediaCapturePauseBehavior const*>(&behavior)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ResumeAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResumeAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ResumeAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::ILowLagMediaRecording3> : produce_base<D, Windows::Media::Capture::ILowLagMediaRecording3>
{
    int32_t WINRT_CALL PauseWithResultAsync(Windows::Media::Devices::MediaCapturePauseBehavior behavior, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PauseWithResultAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::Capture::MediaCapturePauseResult>), Windows::Media::Devices::MediaCapturePauseBehavior const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::Capture::MediaCapturePauseResult>>(this->shim().PauseWithResultAsync(*reinterpret_cast<Windows::Media::Devices::MediaCapturePauseBehavior const*>(&behavior)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StopWithResultAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StopWithResultAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::Capture::MediaCaptureStopResult>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::Capture::MediaCaptureStopResult>>(this->shim().StopWithResultAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::ILowLagPhotoCapture> : produce_base<D, Windows::Media::Capture::ILowLagPhotoCapture>
{
    int32_t WINRT_CALL CaptureAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CaptureAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::Capture::CapturedPhoto>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::Capture::CapturedPhoto>>(this->shim().CaptureAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FinishAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FinishAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().FinishAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::ILowLagPhotoSequenceCapture> : produce_base<D, Windows::Media::Capture::ILowLagPhotoSequenceCapture>
{
    int32_t WINRT_CALL StartAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().StartAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StopAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StopAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().StopAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FinishAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FinishAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().FinishAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_PhotoCaptured(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PhotoCaptured, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Capture::LowLagPhotoSequenceCapture, Windows::Media::Capture::PhotoCapturedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().PhotoCaptured(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Capture::LowLagPhotoSequenceCapture, Windows::Media::Capture::PhotoCapturedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PhotoCaptured(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PhotoCaptured, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PhotoCaptured(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IMediaCapture> : produce_base<D, Windows::Media::Capture::IMediaCapture>
{
    int32_t WINRT_CALL InitializeAsync(void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InitializeAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *asyncInfo = detach_from<Windows::Foundation::IAsyncAction>(this->shim().InitializeAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL InitializeWithSettingsAsync(void* mediaCaptureInitializationSettings, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InitializeAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Media::Capture::MediaCaptureInitializationSettings const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncAction>(this->shim().InitializeAsync(*reinterpret_cast<Windows::Media::Capture::MediaCaptureInitializationSettings const*>(&mediaCaptureInitializationSettings)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StartRecordToStorageFileAsync(void* encodingProfile, void* file, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartRecordToStorageFileAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Media::MediaProperties::MediaEncodingProfile const, Windows::Storage::IStorageFile const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncAction>(this->shim().StartRecordToStorageFileAsync(*reinterpret_cast<Windows::Media::MediaProperties::MediaEncodingProfile const*>(&encodingProfile), *reinterpret_cast<Windows::Storage::IStorageFile const*>(&file)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StartRecordToStreamAsync(void* encodingProfile, void* stream, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartRecordToStreamAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Media::MediaProperties::MediaEncodingProfile const, Windows::Storage::Streams::IRandomAccessStream const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncAction>(this->shim().StartRecordToStreamAsync(*reinterpret_cast<Windows::Media::MediaProperties::MediaEncodingProfile const*>(&encodingProfile), *reinterpret_cast<Windows::Storage::Streams::IRandomAccessStream const*>(&stream)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StartRecordToCustomSinkAsync(void* encodingProfile, void* customMediaSink, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartRecordToCustomSinkAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Media::MediaProperties::MediaEncodingProfile const, Windows::Media::IMediaExtension const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncAction>(this->shim().StartRecordToCustomSinkAsync(*reinterpret_cast<Windows::Media::MediaProperties::MediaEncodingProfile const*>(&encodingProfile), *reinterpret_cast<Windows::Media::IMediaExtension const*>(&customMediaSink)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StartRecordToCustomSinkIdAsync(void* encodingProfile, void* customSinkActivationId, void* customSinkSettings, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartRecordToCustomSinkAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Media::MediaProperties::MediaEncodingProfile const, hstring const, Windows::Foundation::Collections::IPropertySet const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncAction>(this->shim().StartRecordToCustomSinkAsync(*reinterpret_cast<Windows::Media::MediaProperties::MediaEncodingProfile const*>(&encodingProfile), *reinterpret_cast<hstring const*>(&customSinkActivationId), *reinterpret_cast<Windows::Foundation::Collections::IPropertySet const*>(&customSinkSettings)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StopRecordAsync(void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StopRecordAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *asyncInfo = detach_from<Windows::Foundation::IAsyncAction>(this->shim().StopRecordAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CapturePhotoToStorageFileAsync(void* type, void* file, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CapturePhotoToStorageFileAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Media::MediaProperties::ImageEncodingProperties const, Windows::Storage::IStorageFile const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncAction>(this->shim().CapturePhotoToStorageFileAsync(*reinterpret_cast<Windows::Media::MediaProperties::ImageEncodingProperties const*>(&type), *reinterpret_cast<Windows::Storage::IStorageFile const*>(&file)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CapturePhotoToStreamAsync(void* type, void* stream, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CapturePhotoToStreamAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Media::MediaProperties::ImageEncodingProperties const, Windows::Storage::Streams::IRandomAccessStream const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncAction>(this->shim().CapturePhotoToStreamAsync(*reinterpret_cast<Windows::Media::MediaProperties::ImageEncodingProperties const*>(&type), *reinterpret_cast<Windows::Storage::Streams::IRandomAccessStream const*>(&stream)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AddEffectAsync(Windows::Media::Capture::MediaStreamType mediaStreamType, void* effectActivationID, void* effectSettings, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddEffectAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Media::Capture::MediaStreamType const, hstring const, Windows::Foundation::Collections::IPropertySet const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncAction>(this->shim().AddEffectAsync(*reinterpret_cast<Windows::Media::Capture::MediaStreamType const*>(&mediaStreamType), *reinterpret_cast<hstring const*>(&effectActivationID), *reinterpret_cast<Windows::Foundation::Collections::IPropertySet const*>(&effectSettings)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ClearEffectsAsync(Windows::Media::Capture::MediaStreamType mediaStreamType, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClearEffectsAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Media::Capture::MediaStreamType const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ClearEffectsAsync(*reinterpret_cast<Windows::Media::Capture::MediaStreamType const*>(&mediaStreamType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetEncoderProperty(Windows::Media::Capture::MediaStreamType mediaStreamType, winrt::guid propertyId, void* propertyValue) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetEncoderProperty, WINRT_WRAP(void), Windows::Media::Capture::MediaStreamType const&, winrt::guid const&, Windows::Foundation::IInspectable const&);
            this->shim().SetEncoderProperty(*reinterpret_cast<Windows::Media::Capture::MediaStreamType const*>(&mediaStreamType), *reinterpret_cast<winrt::guid const*>(&propertyId), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&propertyValue));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetEncoderProperty(Windows::Media::Capture::MediaStreamType mediaStreamType, winrt::guid propertyId, void** propertyValue) noexcept final
    {
        try
        {
            *propertyValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetEncoderProperty, WINRT_WRAP(Windows::Foundation::IInspectable), Windows::Media::Capture::MediaStreamType const&, winrt::guid const&);
            *propertyValue = detach_from<Windows::Foundation::IInspectable>(this->shim().GetEncoderProperty(*reinterpret_cast<Windows::Media::Capture::MediaStreamType const*>(&mediaStreamType), *reinterpret_cast<winrt::guid const*>(&propertyId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_Failed(void* errorEventHandler, winrt::event_token* eventCookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Failed, WINRT_WRAP(winrt::event_token), Windows::Media::Capture::MediaCaptureFailedEventHandler const&);
            *eventCookie = detach_from<winrt::event_token>(this->shim().Failed(*reinterpret_cast<Windows::Media::Capture::MediaCaptureFailedEventHandler const*>(&errorEventHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Failed(winrt::event_token eventCookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Failed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Failed(*reinterpret_cast<winrt::event_token const*>(&eventCookie));
        return 0;
    }

    int32_t WINRT_CALL add_RecordLimitationExceeded(void* recordLimitationExceededEventHandler, winrt::event_token* eventCookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RecordLimitationExceeded, WINRT_WRAP(winrt::event_token), Windows::Media::Capture::RecordLimitationExceededEventHandler const&);
            *eventCookie = detach_from<winrt::event_token>(this->shim().RecordLimitationExceeded(*reinterpret_cast<Windows::Media::Capture::RecordLimitationExceededEventHandler const*>(&recordLimitationExceededEventHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_RecordLimitationExceeded(winrt::event_token eventCookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(RecordLimitationExceeded, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().RecordLimitationExceeded(*reinterpret_cast<winrt::event_token const*>(&eventCookie));
        return 0;
    }

    int32_t WINRT_CALL get_MediaCaptureSettings(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MediaCaptureSettings, WINRT_WRAP(Windows::Media::Capture::MediaCaptureSettings));
            *value = detach_from<Windows::Media::Capture::MediaCaptureSettings>(this->shim().MediaCaptureSettings());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AudioDeviceController(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioDeviceController, WINRT_WRAP(Windows::Media::Devices::AudioDeviceController));
            *value = detach_from<Windows::Media::Devices::AudioDeviceController>(this->shim().AudioDeviceController());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VideoDeviceController(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoDeviceController, WINRT_WRAP(Windows::Media::Devices::VideoDeviceController));
            *value = detach_from<Windows::Media::Devices::VideoDeviceController>(this->shim().VideoDeviceController());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetPreviewMirroring(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetPreviewMirroring, WINRT_WRAP(void), bool);
            this->shim().SetPreviewMirroring(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetPreviewMirroring(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetPreviewMirroring, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().GetPreviewMirroring());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetPreviewRotation(Windows::Media::Capture::VideoRotation value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetPreviewRotation, WINRT_WRAP(void), Windows::Media::Capture::VideoRotation const&);
            this->shim().SetPreviewRotation(*reinterpret_cast<Windows::Media::Capture::VideoRotation const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetPreviewRotation(Windows::Media::Capture::VideoRotation* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetPreviewRotation, WINRT_WRAP(Windows::Media::Capture::VideoRotation));
            *value = detach_from<Windows::Media::Capture::VideoRotation>(this->shim().GetPreviewRotation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetRecordRotation(Windows::Media::Capture::VideoRotation value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetRecordRotation, WINRT_WRAP(void), Windows::Media::Capture::VideoRotation const&);
            this->shim().SetRecordRotation(*reinterpret_cast<Windows::Media::Capture::VideoRotation const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetRecordRotation(Windows::Media::Capture::VideoRotation* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetRecordRotation, WINRT_WRAP(Windows::Media::Capture::VideoRotation));
            *value = detach_from<Windows::Media::Capture::VideoRotation>(this->shim().GetRecordRotation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IMediaCapture2> : produce_base<D, Windows::Media::Capture::IMediaCapture2>
{
    int32_t WINRT_CALL PrepareLowLagRecordToStorageFileAsync(void* encodingProfile, void* file, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PrepareLowLagRecordToStorageFileAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::Capture::LowLagMediaRecording>), Windows::Media::MediaProperties::MediaEncodingProfile const, Windows::Storage::IStorageFile const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::Capture::LowLagMediaRecording>>(this->shim().PrepareLowLagRecordToStorageFileAsync(*reinterpret_cast<Windows::Media::MediaProperties::MediaEncodingProfile const*>(&encodingProfile), *reinterpret_cast<Windows::Storage::IStorageFile const*>(&file)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PrepareLowLagRecordToStreamAsync(void* encodingProfile, void* stream, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PrepareLowLagRecordToStreamAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::Capture::LowLagMediaRecording>), Windows::Media::MediaProperties::MediaEncodingProfile const, Windows::Storage::Streams::IRandomAccessStream const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::Capture::LowLagMediaRecording>>(this->shim().PrepareLowLagRecordToStreamAsync(*reinterpret_cast<Windows::Media::MediaProperties::MediaEncodingProfile const*>(&encodingProfile), *reinterpret_cast<Windows::Storage::Streams::IRandomAccessStream const*>(&stream)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PrepareLowLagRecordToCustomSinkAsync(void* encodingProfile, void* customMediaSink, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PrepareLowLagRecordToCustomSinkAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::Capture::LowLagMediaRecording>), Windows::Media::MediaProperties::MediaEncodingProfile const, Windows::Media::IMediaExtension const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::Capture::LowLagMediaRecording>>(this->shim().PrepareLowLagRecordToCustomSinkAsync(*reinterpret_cast<Windows::Media::MediaProperties::MediaEncodingProfile const*>(&encodingProfile), *reinterpret_cast<Windows::Media::IMediaExtension const*>(&customMediaSink)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PrepareLowLagRecordToCustomSinkIdAsync(void* encodingProfile, void* customSinkActivationId, void* customSinkSettings, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PrepareLowLagRecordToCustomSinkAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::Capture::LowLagMediaRecording>), Windows::Media::MediaProperties::MediaEncodingProfile const, hstring const, Windows::Foundation::Collections::IPropertySet const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::Capture::LowLagMediaRecording>>(this->shim().PrepareLowLagRecordToCustomSinkAsync(*reinterpret_cast<Windows::Media::MediaProperties::MediaEncodingProfile const*>(&encodingProfile), *reinterpret_cast<hstring const*>(&customSinkActivationId), *reinterpret_cast<Windows::Foundation::Collections::IPropertySet const*>(&customSinkSettings)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PrepareLowLagPhotoCaptureAsync(void* type, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PrepareLowLagPhotoCaptureAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::Capture::LowLagPhotoCapture>), Windows::Media::MediaProperties::ImageEncodingProperties const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::Capture::LowLagPhotoCapture>>(this->shim().PrepareLowLagPhotoCaptureAsync(*reinterpret_cast<Windows::Media::MediaProperties::ImageEncodingProperties const*>(&type)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PrepareLowLagPhotoSequenceCaptureAsync(void* type, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PrepareLowLagPhotoSequenceCaptureAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::Capture::LowLagPhotoSequenceCapture>), Windows::Media::MediaProperties::ImageEncodingProperties const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::Capture::LowLagPhotoSequenceCapture>>(this->shim().PrepareLowLagPhotoSequenceCaptureAsync(*reinterpret_cast<Windows::Media::MediaProperties::ImageEncodingProperties const*>(&type)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetEncodingPropertiesAsync(Windows::Media::Capture::MediaStreamType mediaStreamType, void* mediaEncodingProperties, void* encoderProperties, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetEncodingPropertiesAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Media::Capture::MediaStreamType const, Windows::Media::MediaProperties::IMediaEncodingProperties const, Windows::Media::MediaProperties::MediaPropertySet const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SetEncodingPropertiesAsync(*reinterpret_cast<Windows::Media::Capture::MediaStreamType const*>(&mediaStreamType), *reinterpret_cast<Windows::Media::MediaProperties::IMediaEncodingProperties const*>(&mediaEncodingProperties), *reinterpret_cast<Windows::Media::MediaProperties::MediaPropertySet const*>(&encoderProperties)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IMediaCapture3> : produce_base<D, Windows::Media::Capture::IMediaCapture3>
{
    int32_t WINRT_CALL PrepareVariablePhotoSequenceCaptureAsync(void* type, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PrepareVariablePhotoSequenceCaptureAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::Capture::Core::VariablePhotoSequenceCapture>), Windows::Media::MediaProperties::ImageEncodingProperties const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::Capture::Core::VariablePhotoSequenceCapture>>(this->shim().PrepareVariablePhotoSequenceCaptureAsync(*reinterpret_cast<Windows::Media::MediaProperties::ImageEncodingProperties const*>(&type)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_FocusChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FocusChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Capture::MediaCapture, Windows::Media::Capture::MediaCaptureFocusChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().FocusChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Capture::MediaCapture, Windows::Media::Capture::MediaCaptureFocusChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_FocusChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(FocusChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().FocusChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_PhotoConfirmationCaptured(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PhotoConfirmationCaptured, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Capture::MediaCapture, Windows::Media::Capture::PhotoConfirmationCapturedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().PhotoConfirmationCaptured(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Capture::MediaCapture, Windows::Media::Capture::PhotoConfirmationCapturedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PhotoConfirmationCaptured(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PhotoConfirmationCaptured, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PhotoConfirmationCaptured(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IMediaCapture4> : produce_base<D, Windows::Media::Capture::IMediaCapture4>
{
    int32_t WINRT_CALL AddAudioEffectAsync(void* definition, void** op) noexcept final
    {
        try
        {
            *op = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddAudioEffectAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::IMediaExtension>), Windows::Media::Effects::IAudioEffectDefinition const);
            *op = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::IMediaExtension>>(this->shim().AddAudioEffectAsync(*reinterpret_cast<Windows::Media::Effects::IAudioEffectDefinition const*>(&definition)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AddVideoEffectAsync(void* definition, Windows::Media::Capture::MediaStreamType mediaStreamType, void** op) noexcept final
    {
        try
        {
            *op = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddVideoEffectAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::IMediaExtension>), Windows::Media::Effects::IVideoEffectDefinition const, Windows::Media::Capture::MediaStreamType const);
            *op = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::IMediaExtension>>(this->shim().AddVideoEffectAsync(*reinterpret_cast<Windows::Media::Effects::IVideoEffectDefinition const*>(&definition), *reinterpret_cast<Windows::Media::Capture::MediaStreamType const*>(&mediaStreamType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PauseRecordAsync(Windows::Media::Devices::MediaCapturePauseBehavior behavior, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PauseRecordAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Media::Devices::MediaCapturePauseBehavior const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncAction>(this->shim().PauseRecordAsync(*reinterpret_cast<Windows::Media::Devices::MediaCapturePauseBehavior const*>(&behavior)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ResumeRecordAsync(void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResumeRecordAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *asyncInfo = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ResumeRecordAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_CameraStreamStateChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CameraStreamStateChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Capture::MediaCapture, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().CameraStreamStateChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Capture::MediaCapture, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_CameraStreamStateChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(CameraStreamStateChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().CameraStreamStateChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL get_CameraStreamState(Windows::Media::Devices::CameraStreamState* streamState) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CameraStreamState, WINRT_WRAP(Windows::Media::Devices::CameraStreamState));
            *streamState = detach_from<Windows::Media::Devices::CameraStreamState>(this->shim().CameraStreamState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetPreviewFrameAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetPreviewFrameAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::VideoFrame>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::VideoFrame>>(this->shim().GetPreviewFrameAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetPreviewFrameCopyAsync(void* destination, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetPreviewFrameAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::VideoFrame>), Windows::Media::VideoFrame const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::VideoFrame>>(this->shim().GetPreviewFrameAsync(*reinterpret_cast<Windows::Media::VideoFrame const*>(&destination)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_ThermalStatusChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ThermalStatusChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Capture::MediaCapture, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().ThermalStatusChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Capture::MediaCapture, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ThermalStatusChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ThermalStatusChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ThermalStatusChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL get_ThermalStatus(Windows::Media::Capture::MediaCaptureThermalStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ThermalStatus, WINRT_WRAP(Windows::Media::Capture::MediaCaptureThermalStatus));
            *value = detach_from<Windows::Media::Capture::MediaCaptureThermalStatus>(this->shim().ThermalStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PrepareAdvancedPhotoCaptureAsync(void* encodingProperties, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PrepareAdvancedPhotoCaptureAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::Capture::AdvancedPhotoCapture>), Windows::Media::MediaProperties::ImageEncodingProperties const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::Capture::AdvancedPhotoCapture>>(this->shim().PrepareAdvancedPhotoCaptureAsync(*reinterpret_cast<Windows::Media::MediaProperties::ImageEncodingProperties const*>(&encodingProperties)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IMediaCapture5> : produce_base<D, Windows::Media::Capture::IMediaCapture5>
{
    int32_t WINRT_CALL RemoveEffectAsync(void* effect, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoveEffectAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Media::IMediaExtension const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncAction>(this->shim().RemoveEffectAsync(*reinterpret_cast<Windows::Media::IMediaExtension const*>(&effect)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PauseRecordWithResultAsync(Windows::Media::Devices::MediaCapturePauseBehavior behavior, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PauseRecordWithResultAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::Capture::MediaCapturePauseResult>), Windows::Media::Devices::MediaCapturePauseBehavior const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::Capture::MediaCapturePauseResult>>(this->shim().PauseRecordWithResultAsync(*reinterpret_cast<Windows::Media::Devices::MediaCapturePauseBehavior const*>(&behavior)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StopRecordWithResultAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StopRecordWithResultAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::Capture::MediaCaptureStopResult>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::Capture::MediaCaptureStopResult>>(this->shim().StopRecordWithResultAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FrameSources(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FrameSources, WINRT_WRAP(Windows::Foundation::Collections::IMapView<hstring, Windows::Media::Capture::Frames::MediaFrameSource>));
            *value = detach_from<Windows::Foundation::Collections::IMapView<hstring, Windows::Media::Capture::Frames::MediaFrameSource>>(this->shim().FrameSources());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFrameReaderAsync(void* inputSource, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFrameReaderAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::Capture::Frames::MediaFrameReader>), Windows::Media::Capture::Frames::MediaFrameSource const);
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::Capture::Frames::MediaFrameReader>>(this->shim().CreateFrameReaderAsync(*reinterpret_cast<Windows::Media::Capture::Frames::MediaFrameSource const*>(&inputSource)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFrameReaderWithSubtypeAsync(void* inputSource, void* outputSubtype, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFrameReaderAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::Capture::Frames::MediaFrameReader>), Windows::Media::Capture::Frames::MediaFrameSource const, hstring const);
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::Capture::Frames::MediaFrameReader>>(this->shim().CreateFrameReaderAsync(*reinterpret_cast<Windows::Media::Capture::Frames::MediaFrameSource const*>(&inputSource), *reinterpret_cast<hstring const*>(&outputSubtype)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFrameReaderWithSubtypeAndSizeAsync(void* inputSource, void* outputSubtype, struct struct_Windows_Graphics_Imaging_BitmapSize outputSize, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFrameReaderAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::Capture::Frames::MediaFrameReader>), Windows::Media::Capture::Frames::MediaFrameSource const, hstring const, Windows::Graphics::Imaging::BitmapSize const);
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::Capture::Frames::MediaFrameReader>>(this->shim().CreateFrameReaderAsync(*reinterpret_cast<Windows::Media::Capture::Frames::MediaFrameSource const*>(&inputSource), *reinterpret_cast<hstring const*>(&outputSubtype), *reinterpret_cast<Windows::Graphics::Imaging::BitmapSize const*>(&outputSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IMediaCapture6> : produce_base<D, Windows::Media::Capture::IMediaCapture6>
{
    int32_t WINRT_CALL add_CaptureDeviceExclusiveControlStatusChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CaptureDeviceExclusiveControlStatusChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Media::Capture::MediaCapture, Windows::Media::Capture::MediaCaptureDeviceExclusiveControlStatusChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().CaptureDeviceExclusiveControlStatusChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Media::Capture::MediaCapture, Windows::Media::Capture::MediaCaptureDeviceExclusiveControlStatusChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_CaptureDeviceExclusiveControlStatusChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(CaptureDeviceExclusiveControlStatusChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().CaptureDeviceExclusiveControlStatusChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL CreateMultiSourceFrameReaderAsync(void* inputSources, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateMultiSourceFrameReaderAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::Capture::Frames::MultiSourceMediaFrameReader>), Windows::Foundation::Collections::IIterable<Windows::Media::Capture::Frames::MediaFrameSource> const);
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::Capture::Frames::MultiSourceMediaFrameReader>>(this->shim().CreateMultiSourceFrameReaderAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Media::Capture::Frames::MediaFrameSource> const*>(&inputSources)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IMediaCaptureDeviceExclusiveControlStatusChangedEventArgs> : produce_base<D, Windows::Media::Capture::IMediaCaptureDeviceExclusiveControlStatusChangedEventArgs>
{
    int32_t WINRT_CALL get_DeviceId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Status(Windows::Media::Capture::MediaCaptureDeviceExclusiveControlStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Media::Capture::MediaCaptureDeviceExclusiveControlStatus));
            *value = detach_from<Windows::Media::Capture::MediaCaptureDeviceExclusiveControlStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IMediaCaptureFailedEventArgs> : produce_base<D, Windows::Media::Capture::IMediaCaptureFailedEventArgs>
{
    int32_t WINRT_CALL get_Message(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Message, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Message());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Code(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Code, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Code());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IMediaCaptureFocusChangedEventArgs> : produce_base<D, Windows::Media::Capture::IMediaCaptureFocusChangedEventArgs>
{
    int32_t WINRT_CALL get_FocusState(Windows::Media::Devices::MediaCaptureFocusState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FocusState, WINRT_WRAP(Windows::Media::Devices::MediaCaptureFocusState));
            *value = detach_from<Windows::Media::Devices::MediaCaptureFocusState>(this->shim().FocusState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IMediaCaptureInitializationSettings> : produce_base<D, Windows::Media::Capture::IMediaCaptureInitializationSettings>
{
    int32_t WINRT_CALL put_AudioDeviceId(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioDeviceId, WINRT_WRAP(void), hstring const&);
            this->shim().AudioDeviceId(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AudioDeviceId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioDeviceId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AudioDeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_VideoDeviceId(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoDeviceId, WINRT_WRAP(void), hstring const&);
            this->shim().VideoDeviceId(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VideoDeviceId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoDeviceId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().VideoDeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_StreamingCaptureMode(Windows::Media::Capture::StreamingCaptureMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StreamingCaptureMode, WINRT_WRAP(void), Windows::Media::Capture::StreamingCaptureMode const&);
            this->shim().StreamingCaptureMode(*reinterpret_cast<Windows::Media::Capture::StreamingCaptureMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StreamingCaptureMode(Windows::Media::Capture::StreamingCaptureMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StreamingCaptureMode, WINRT_WRAP(Windows::Media::Capture::StreamingCaptureMode));
            *value = detach_from<Windows::Media::Capture::StreamingCaptureMode>(this->shim().StreamingCaptureMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PhotoCaptureSource(Windows::Media::Capture::PhotoCaptureSource value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PhotoCaptureSource, WINRT_WRAP(void), Windows::Media::Capture::PhotoCaptureSource const&);
            this->shim().PhotoCaptureSource(*reinterpret_cast<Windows::Media::Capture::PhotoCaptureSource const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PhotoCaptureSource(Windows::Media::Capture::PhotoCaptureSource* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PhotoCaptureSource, WINRT_WRAP(Windows::Media::Capture::PhotoCaptureSource));
            *value = detach_from<Windows::Media::Capture::PhotoCaptureSource>(this->shim().PhotoCaptureSource());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IMediaCaptureInitializationSettings2> : produce_base<D, Windows::Media::Capture::IMediaCaptureInitializationSettings2>
{
    int32_t WINRT_CALL put_MediaCategory(Windows::Media::Capture::MediaCategory value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MediaCategory, WINRT_WRAP(void), Windows::Media::Capture::MediaCategory const&);
            this->shim().MediaCategory(*reinterpret_cast<Windows::Media::Capture::MediaCategory const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MediaCategory(Windows::Media::Capture::MediaCategory* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MediaCategory, WINRT_WRAP(Windows::Media::Capture::MediaCategory));
            *value = detach_from<Windows::Media::Capture::MediaCategory>(this->shim().MediaCategory());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AudioProcessing(Windows::Media::AudioProcessing value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioProcessing, WINRT_WRAP(void), Windows::Media::AudioProcessing const&);
            this->shim().AudioProcessing(*reinterpret_cast<Windows::Media::AudioProcessing const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AudioProcessing(Windows::Media::AudioProcessing* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioProcessing, WINRT_WRAP(Windows::Media::AudioProcessing));
            *value = detach_from<Windows::Media::AudioProcessing>(this->shim().AudioProcessing());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IMediaCaptureInitializationSettings3> : produce_base<D, Windows::Media::Capture::IMediaCaptureInitializationSettings3>
{
    int32_t WINRT_CALL put_AudioSource(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioSource, WINRT_WRAP(void), Windows::Media::Core::IMediaSource const&);
            this->shim().AudioSource(*reinterpret_cast<Windows::Media::Core::IMediaSource const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AudioSource(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioSource, WINRT_WRAP(Windows::Media::Core::IMediaSource));
            *value = detach_from<Windows::Media::Core::IMediaSource>(this->shim().AudioSource());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_VideoSource(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoSource, WINRT_WRAP(void), Windows::Media::Core::IMediaSource const&);
            this->shim().VideoSource(*reinterpret_cast<Windows::Media::Core::IMediaSource const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VideoSource(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoSource, WINRT_WRAP(Windows::Media::Core::IMediaSource));
            *value = detach_from<Windows::Media::Core::IMediaSource>(this->shim().VideoSource());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IMediaCaptureInitializationSettings4> : produce_base<D, Windows::Media::Capture::IMediaCaptureInitializationSettings4>
{
    int32_t WINRT_CALL get_VideoProfile(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoProfile, WINRT_WRAP(Windows::Media::Capture::MediaCaptureVideoProfile));
            *value = detach_from<Windows::Media::Capture::MediaCaptureVideoProfile>(this->shim().VideoProfile());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_VideoProfile(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoProfile, WINRT_WRAP(void), Windows::Media::Capture::MediaCaptureVideoProfile const&);
            this->shim().VideoProfile(*reinterpret_cast<Windows::Media::Capture::MediaCaptureVideoProfile const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PreviewMediaDescription(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PreviewMediaDescription, WINRT_WRAP(Windows::Media::Capture::MediaCaptureVideoProfileMediaDescription));
            *value = detach_from<Windows::Media::Capture::MediaCaptureVideoProfileMediaDescription>(this->shim().PreviewMediaDescription());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PreviewMediaDescription(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PreviewMediaDescription, WINRT_WRAP(void), Windows::Media::Capture::MediaCaptureVideoProfileMediaDescription const&);
            this->shim().PreviewMediaDescription(*reinterpret_cast<Windows::Media::Capture::MediaCaptureVideoProfileMediaDescription const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RecordMediaDescription(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RecordMediaDescription, WINRT_WRAP(Windows::Media::Capture::MediaCaptureVideoProfileMediaDescription));
            *value = detach_from<Windows::Media::Capture::MediaCaptureVideoProfileMediaDescription>(this->shim().RecordMediaDescription());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RecordMediaDescription(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RecordMediaDescription, WINRT_WRAP(void), Windows::Media::Capture::MediaCaptureVideoProfileMediaDescription const&);
            this->shim().RecordMediaDescription(*reinterpret_cast<Windows::Media::Capture::MediaCaptureVideoProfileMediaDescription const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PhotoMediaDescription(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PhotoMediaDescription, WINRT_WRAP(Windows::Media::Capture::MediaCaptureVideoProfileMediaDescription));
            *value = detach_from<Windows::Media::Capture::MediaCaptureVideoProfileMediaDescription>(this->shim().PhotoMediaDescription());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PhotoMediaDescription(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PhotoMediaDescription, WINRT_WRAP(void), Windows::Media::Capture::MediaCaptureVideoProfileMediaDescription const&);
            this->shim().PhotoMediaDescription(*reinterpret_cast<Windows::Media::Capture::MediaCaptureVideoProfileMediaDescription const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IMediaCaptureInitializationSettings5> : produce_base<D, Windows::Media::Capture::IMediaCaptureInitializationSettings5>
{
    int32_t WINRT_CALL get_SourceGroup(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourceGroup, WINRT_WRAP(Windows::Media::Capture::Frames::MediaFrameSourceGroup));
            *value = detach_from<Windows::Media::Capture::Frames::MediaFrameSourceGroup>(this->shim().SourceGroup());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SourceGroup(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourceGroup, WINRT_WRAP(void), Windows::Media::Capture::Frames::MediaFrameSourceGroup const&);
            this->shim().SourceGroup(*reinterpret_cast<Windows::Media::Capture::Frames::MediaFrameSourceGroup const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SharingMode(Windows::Media::Capture::MediaCaptureSharingMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SharingMode, WINRT_WRAP(Windows::Media::Capture::MediaCaptureSharingMode));
            *value = detach_from<Windows::Media::Capture::MediaCaptureSharingMode>(this->shim().SharingMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SharingMode(Windows::Media::Capture::MediaCaptureSharingMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SharingMode, WINRT_WRAP(void), Windows::Media::Capture::MediaCaptureSharingMode const&);
            this->shim().SharingMode(*reinterpret_cast<Windows::Media::Capture::MediaCaptureSharingMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MemoryPreference(Windows::Media::Capture::MediaCaptureMemoryPreference* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MemoryPreference, WINRT_WRAP(Windows::Media::Capture::MediaCaptureMemoryPreference));
            *value = detach_from<Windows::Media::Capture::MediaCaptureMemoryPreference>(this->shim().MemoryPreference());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MemoryPreference(Windows::Media::Capture::MediaCaptureMemoryPreference value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MemoryPreference, WINRT_WRAP(void), Windows::Media::Capture::MediaCaptureMemoryPreference const&);
            this->shim().MemoryPreference(*reinterpret_cast<Windows::Media::Capture::MediaCaptureMemoryPreference const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IMediaCaptureInitializationSettings6> : produce_base<D, Windows::Media::Capture::IMediaCaptureInitializationSettings6>
{
    int32_t WINRT_CALL get_AlwaysPlaySystemShutterSound(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AlwaysPlaySystemShutterSound, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AlwaysPlaySystemShutterSound());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AlwaysPlaySystemShutterSound(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AlwaysPlaySystemShutterSound, WINRT_WRAP(void), bool);
            this->shim().AlwaysPlaySystemShutterSound(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IMediaCapturePauseResult> : produce_base<D, Windows::Media::Capture::IMediaCapturePauseResult>
{
    int32_t WINRT_CALL get_LastFrame(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LastFrame, WINRT_WRAP(Windows::Media::VideoFrame));
            *value = detach_from<Windows::Media::VideoFrame>(this->shim().LastFrame());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RecordDuration(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RecordDuration, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().RecordDuration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IMediaCaptureSettings> : produce_base<D, Windows::Media::Capture::IMediaCaptureSettings>
{
    int32_t WINRT_CALL get_AudioDeviceId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioDeviceId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AudioDeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VideoDeviceId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoDeviceId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().VideoDeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StreamingCaptureMode(Windows::Media::Capture::StreamingCaptureMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StreamingCaptureMode, WINRT_WRAP(Windows::Media::Capture::StreamingCaptureMode));
            *value = detach_from<Windows::Media::Capture::StreamingCaptureMode>(this->shim().StreamingCaptureMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PhotoCaptureSource(Windows::Media::Capture::PhotoCaptureSource* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PhotoCaptureSource, WINRT_WRAP(Windows::Media::Capture::PhotoCaptureSource));
            *value = detach_from<Windows::Media::Capture::PhotoCaptureSource>(this->shim().PhotoCaptureSource());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VideoDeviceCharacteristic(Windows::Media::Capture::VideoDeviceCharacteristic* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoDeviceCharacteristic, WINRT_WRAP(Windows::Media::Capture::VideoDeviceCharacteristic));
            *value = detach_from<Windows::Media::Capture::VideoDeviceCharacteristic>(this->shim().VideoDeviceCharacteristic());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IMediaCaptureSettings2> : produce_base<D, Windows::Media::Capture::IMediaCaptureSettings2>
{
    int32_t WINRT_CALL get_ConcurrentRecordAndPhotoSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConcurrentRecordAndPhotoSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().ConcurrentRecordAndPhotoSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ConcurrentRecordAndPhotoSequenceSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConcurrentRecordAndPhotoSequenceSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().ConcurrentRecordAndPhotoSequenceSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CameraSoundRequiredForRegion(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CameraSoundRequiredForRegion, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CameraSoundRequiredForRegion());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Horizontal35mmEquivalentFocalLength(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Horizontal35mmEquivalentFocalLength, WINRT_WRAP(Windows::Foundation::IReference<uint32_t>));
            *value = detach_from<Windows::Foundation::IReference<uint32_t>>(this->shim().Horizontal35mmEquivalentFocalLength());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PitchOffsetDegrees(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PitchOffsetDegrees, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().PitchOffsetDegrees());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Vertical35mmEquivalentFocalLength(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Vertical35mmEquivalentFocalLength, WINRT_WRAP(Windows::Foundation::IReference<uint32_t>));
            *value = detach_from<Windows::Foundation::IReference<uint32_t>>(this->shim().Vertical35mmEquivalentFocalLength());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MediaCategory(Windows::Media::Capture::MediaCategory* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MediaCategory, WINRT_WRAP(Windows::Media::Capture::MediaCategory));
            *value = detach_from<Windows::Media::Capture::MediaCategory>(this->shim().MediaCategory());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AudioProcessing(Windows::Media::AudioProcessing* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioProcessing, WINRT_WRAP(Windows::Media::AudioProcessing));
            *value = detach_from<Windows::Media::AudioProcessing>(this->shim().AudioProcessing());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IMediaCaptureSettings3> : produce_base<D, Windows::Media::Capture::IMediaCaptureSettings3>
{
    int32_t WINRT_CALL get_Direct3D11Device(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Direct3D11Device, WINRT_WRAP(Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice));
            *value = detach_from<Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice>(this->shim().Direct3D11Device());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IMediaCaptureStatics> : produce_base<D, Windows::Media::Capture::IMediaCaptureStatics>
{
    int32_t WINRT_CALL IsVideoProfileSupported(void* videoDeviceId, bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsVideoProfileSupported, WINRT_WRAP(bool), hstring const&);
            *value = detach_from<bool>(this->shim().IsVideoProfileSupported(*reinterpret_cast<hstring const*>(&videoDeviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindAllVideoProfiles(void* videoDeviceId, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindAllVideoProfiles, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Media::Capture::MediaCaptureVideoProfile>), hstring const&);
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Media::Capture::MediaCaptureVideoProfile>>(this->shim().FindAllVideoProfiles(*reinterpret_cast<hstring const*>(&videoDeviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindConcurrentProfiles(void* videoDeviceId, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindConcurrentProfiles, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Media::Capture::MediaCaptureVideoProfile>), hstring const&);
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Media::Capture::MediaCaptureVideoProfile>>(this->shim().FindConcurrentProfiles(*reinterpret_cast<hstring const*>(&videoDeviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindKnownVideoProfiles(void* videoDeviceId, Windows::Media::Capture::KnownVideoProfile name, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindKnownVideoProfiles, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Media::Capture::MediaCaptureVideoProfile>), hstring const&, Windows::Media::Capture::KnownVideoProfile const&);
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Media::Capture::MediaCaptureVideoProfile>>(this->shim().FindKnownVideoProfiles(*reinterpret_cast<hstring const*>(&videoDeviceId), *reinterpret_cast<Windows::Media::Capture::KnownVideoProfile const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IMediaCaptureStopResult> : produce_base<D, Windows::Media::Capture::IMediaCaptureStopResult>
{
    int32_t WINRT_CALL get_LastFrame(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LastFrame, WINRT_WRAP(Windows::Media::VideoFrame));
            *value = detach_from<Windows::Media::VideoFrame>(this->shim().LastFrame());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RecordDuration(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RecordDuration, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().RecordDuration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IMediaCaptureVideoPreview> : produce_base<D, Windows::Media::Capture::IMediaCaptureVideoPreview>
{
    int32_t WINRT_CALL StartPreviewAsync(void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartPreviewAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *asyncInfo = detach_from<Windows::Foundation::IAsyncAction>(this->shim().StartPreviewAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StartPreviewToCustomSinkAsync(void* encodingProfile, void* customMediaSink, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartPreviewToCustomSinkAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Media::MediaProperties::MediaEncodingProfile const, Windows::Media::IMediaExtension const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncAction>(this->shim().StartPreviewToCustomSinkAsync(*reinterpret_cast<Windows::Media::MediaProperties::MediaEncodingProfile const*>(&encodingProfile), *reinterpret_cast<Windows::Media::IMediaExtension const*>(&customMediaSink)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StartPreviewToCustomSinkIdAsync(void* encodingProfile, void* customSinkActivationId, void* customSinkSettings, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartPreviewToCustomSinkAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Media::MediaProperties::MediaEncodingProfile const, hstring const, Windows::Foundation::Collections::IPropertySet const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncAction>(this->shim().StartPreviewToCustomSinkAsync(*reinterpret_cast<Windows::Media::MediaProperties::MediaEncodingProfile const*>(&encodingProfile), *reinterpret_cast<hstring const*>(&customSinkActivationId), *reinterpret_cast<Windows::Foundation::Collections::IPropertySet const*>(&customSinkSettings)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StopPreviewAsync(void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StopPreviewAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *asyncInfo = detach_from<Windows::Foundation::IAsyncAction>(this->shim().StopPreviewAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IMediaCaptureVideoProfile> : produce_base<D, Windows::Media::Capture::IMediaCaptureVideoProfile>
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

    int32_t WINRT_CALL get_VideoDeviceId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoDeviceId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().VideoDeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportedPreviewMediaDescription(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedPreviewMediaDescription, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Media::Capture::MediaCaptureVideoProfileMediaDescription>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Media::Capture::MediaCaptureVideoProfileMediaDescription>>(this->shim().SupportedPreviewMediaDescription());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportedRecordMediaDescription(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedRecordMediaDescription, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Media::Capture::MediaCaptureVideoProfileMediaDescription>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Media::Capture::MediaCaptureVideoProfileMediaDescription>>(this->shim().SupportedRecordMediaDescription());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportedPhotoMediaDescription(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedPhotoMediaDescription, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Media::Capture::MediaCaptureVideoProfileMediaDescription>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Media::Capture::MediaCaptureVideoProfileMediaDescription>>(this->shim().SupportedPhotoMediaDescription());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetConcurrency(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetConcurrency, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Media::Capture::MediaCaptureVideoProfile>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Media::Capture::MediaCaptureVideoProfile>>(this->shim().GetConcurrency());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IMediaCaptureVideoProfile2> : produce_base<D, Windows::Media::Capture::IMediaCaptureVideoProfile2>
{
    int32_t WINRT_CALL get_FrameSourceInfos(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FrameSourceInfos, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Media::Capture::Frames::MediaFrameSourceInfo>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Media::Capture::Frames::MediaFrameSourceInfo>>(this->shim().FrameSourceInfos());
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
            WINRT_ASSERT_DECLARATION(Properties, WINRT_WRAP(Windows::Foundation::Collections::IMapView<winrt::guid, Windows::Foundation::IInspectable>));
            *value = detach_from<Windows::Foundation::Collections::IMapView<winrt::guid, Windows::Foundation::IInspectable>>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IMediaCaptureVideoProfileMediaDescription> : produce_base<D, Windows::Media::Capture::IMediaCaptureVideoProfileMediaDescription>
{
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

    int32_t WINRT_CALL get_FrameRate(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FrameRate, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().FrameRate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsVariablePhotoSequenceSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsVariablePhotoSequenceSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsVariablePhotoSequenceSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsHdrVideoSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsHdrVideoSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsHdrVideoSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IMediaCaptureVideoProfileMediaDescription2> : produce_base<D, Windows::Media::Capture::IMediaCaptureVideoProfileMediaDescription2>
{
    int32_t WINRT_CALL get_Subtype(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Subtype, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Subtype());
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
            WINRT_ASSERT_DECLARATION(Properties, WINRT_WRAP(Windows::Foundation::Collections::IMapView<winrt::guid, Windows::Foundation::IInspectable>));
            *value = detach_from<Windows::Foundation::Collections::IMapView<winrt::guid, Windows::Foundation::IInspectable>>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IOptionalReferencePhotoCapturedEventArgs> : produce_base<D, Windows::Media::Capture::IOptionalReferencePhotoCapturedEventArgs>
{
    int32_t WINRT_CALL get_Frame(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Frame, WINRT_WRAP(Windows::Media::Capture::CapturedFrame));
            *value = detach_from<Windows::Media::Capture::CapturedFrame>(this->shim().Frame());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Context(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Context, WINRT_WRAP(Windows::Foundation::IInspectable));
            *value = detach_from<Windows::Foundation::IInspectable>(this->shim().Context());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IPhotoCapturedEventArgs> : produce_base<D, Windows::Media::Capture::IPhotoCapturedEventArgs>
{
    int32_t WINRT_CALL get_Frame(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Frame, WINRT_WRAP(Windows::Media::Capture::CapturedFrame));
            *value = detach_from<Windows::Media::Capture::CapturedFrame>(this->shim().Frame());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Thumbnail(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Thumbnail, WINRT_WRAP(Windows::Media::Capture::CapturedFrame));
            *value = detach_from<Windows::Media::Capture::CapturedFrame>(this->shim().Thumbnail());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CaptureTimeOffset(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CaptureTimeOffset, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().CaptureTimeOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IPhotoConfirmationCapturedEventArgs> : produce_base<D, Windows::Media::Capture::IPhotoConfirmationCapturedEventArgs>
{
    int32_t WINRT_CALL get_Frame(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Frame, WINRT_WRAP(Windows::Media::Capture::CapturedFrame));
            *value = detach_from<Windows::Media::Capture::CapturedFrame>(this->shim().Frame());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CaptureTimeOffset(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CaptureTimeOffset, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().CaptureTimeOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Capture::IVideoStreamConfiguration> : produce_base<D, Windows::Media::Capture::IVideoStreamConfiguration>
{
    int32_t WINRT_CALL get_InputProperties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InputProperties, WINRT_WRAP(Windows::Media::MediaProperties::VideoEncodingProperties));
            *value = detach_from<Windows::Media::MediaProperties::VideoEncodingProperties>(this->shim().InputProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OutputProperties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OutputProperties, WINRT_WRAP(Windows::Media::MediaProperties::VideoEncodingProperties));
            *value = detach_from<Windows::Media::MediaProperties::VideoEncodingProperties>(this->shim().OutputProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Media::Capture {

inline Windows::Media::Capture::AppBroadcastGlobalSettings AppBroadcastManager::GetGlobalSettings()
{
    return impl::call_factory<AppBroadcastManager, Windows::Media::Capture::IAppBroadcastManagerStatics>([&](auto&& f) { return f.GetGlobalSettings(); });
}

inline void AppBroadcastManager::ApplyGlobalSettings(Windows::Media::Capture::AppBroadcastGlobalSettings const& value)
{
    impl::call_factory<AppBroadcastManager, Windows::Media::Capture::IAppBroadcastManagerStatics>([&](auto&& f) { return f.ApplyGlobalSettings(value); });
}

inline Windows::Media::Capture::AppBroadcastProviderSettings AppBroadcastManager::GetProviderSettings()
{
    return impl::call_factory<AppBroadcastManager, Windows::Media::Capture::IAppBroadcastManagerStatics>([&](auto&& f) { return f.GetProviderSettings(); });
}

inline void AppBroadcastManager::ApplyProviderSettings(Windows::Media::Capture::AppBroadcastProviderSettings const& value)
{
    impl::call_factory<AppBroadcastManager, Windows::Media::Capture::IAppBroadcastManagerStatics>([&](auto&& f) { return f.ApplyProviderSettings(value); });
}

inline Windows::Media::Capture::AppBroadcastPlugInManager AppBroadcastPlugInManager::GetDefault()
{
    return impl::call_factory<AppBroadcastPlugInManager, Windows::Media::Capture::IAppBroadcastPlugInManagerStatics>([&](auto&& f) { return f.GetDefault(); });
}

inline Windows::Media::Capture::AppBroadcastPlugInManager AppBroadcastPlugInManager::GetForUser(Windows::System::User const& user)
{
    return impl::call_factory<AppBroadcastPlugInManager, Windows::Media::Capture::IAppBroadcastPlugInManagerStatics>([&](auto&& f) { return f.GetForUser(user); });
}

inline Windows::Media::Capture::AppCapture AppCapture::GetForCurrentView()
{
    return impl::call_factory<AppCapture, Windows::Media::Capture::IAppCaptureStatics>([&](auto&& f) { return f.GetForCurrentView(); });
}

inline Windows::Foundation::IAsyncAction AppCapture::SetAllowedAsync(bool allowed)
{
    return impl::call_factory<AppCapture, Windows::Media::Capture::IAppCaptureStatics2>([&](auto&& f) { return f.SetAllowedAsync(allowed); });
}

inline Windows::Media::Capture::AppCaptureSettings AppCaptureManager::GetCurrentSettings()
{
    return impl::call_factory<AppCaptureManager, Windows::Media::Capture::IAppCaptureManagerStatics>([&](auto&& f) { return f.GetCurrentSettings(); });
}

inline void AppCaptureManager::ApplySettings(Windows::Media::Capture::AppCaptureSettings const& appCaptureSettings)
{
    impl::call_factory<AppCaptureManager, Windows::Media::Capture::IAppCaptureManagerStatics>([&](auto&& f) { return f.ApplySettings(appCaptureSettings); });
}

inline AppCaptureMetadataWriter::AppCaptureMetadataWriter() :
    AppCaptureMetadataWriter(impl::call_factory<AppCaptureMetadataWriter>([](auto&& f) { return f.template ActivateInstance<AppCaptureMetadataWriter>(); }))
{}

inline CameraCaptureUI::CameraCaptureUI() :
    CameraCaptureUI(impl::call_factory<CameraCaptureUI>([](auto&& f) { return f.template ActivateInstance<CameraCaptureUI>(); }))
{}

inline void CameraOptionsUI::Show(Windows::Media::Capture::MediaCapture const& mediaCapture)
{
    impl::call_factory<CameraOptionsUI, Windows::Media::Capture::ICameraOptionsUIStatics>([&](auto&& f) { return f.Show(mediaCapture); });
}

inline Windows::Media::Capture::GameBarServicesManager GameBarServicesManager::GetDefault()
{
    return impl::call_factory<GameBarServicesManager, Windows::Media::Capture::IGameBarServicesManagerStatics>([&](auto&& f) { return f.GetDefault(); });
}

inline MediaCapture::MediaCapture() :
    MediaCapture(impl::call_factory<MediaCapture>([](auto&& f) { return f.template ActivateInstance<MediaCapture>(); }))
{}

inline bool MediaCapture::IsVideoProfileSupported(param::hstring const& videoDeviceId)
{
    return impl::call_factory<MediaCapture, Windows::Media::Capture::IMediaCaptureStatics>([&](auto&& f) { return f.IsVideoProfileSupported(videoDeviceId); });
}

inline Windows::Foundation::Collections::IVectorView<Windows::Media::Capture::MediaCaptureVideoProfile> MediaCapture::FindAllVideoProfiles(param::hstring const& videoDeviceId)
{
    return impl::call_factory<MediaCapture, Windows::Media::Capture::IMediaCaptureStatics>([&](auto&& f) { return f.FindAllVideoProfiles(videoDeviceId); });
}

inline Windows::Foundation::Collections::IVectorView<Windows::Media::Capture::MediaCaptureVideoProfile> MediaCapture::FindConcurrentProfiles(param::hstring const& videoDeviceId)
{
    return impl::call_factory<MediaCapture, Windows::Media::Capture::IMediaCaptureStatics>([&](auto&& f) { return f.FindConcurrentProfiles(videoDeviceId); });
}

inline Windows::Foundation::Collections::IVectorView<Windows::Media::Capture::MediaCaptureVideoProfile> MediaCapture::FindKnownVideoProfiles(param::hstring const& videoDeviceId, Windows::Media::Capture::KnownVideoProfile const& name)
{
    return impl::call_factory<MediaCapture, Windows::Media::Capture::IMediaCaptureStatics>([&](auto&& f) { return f.FindKnownVideoProfiles(videoDeviceId, name); });
}

inline MediaCaptureInitializationSettings::MediaCaptureInitializationSettings() :
    MediaCaptureInitializationSettings(impl::call_factory<MediaCaptureInitializationSettings>([](auto&& f) { return f.template ActivateInstance<MediaCaptureInitializationSettings>(); }))
{}

template <typename L> MediaCaptureFailedEventHandler::MediaCaptureFailedEventHandler(L handler) :
    MediaCaptureFailedEventHandler(impl::make_delegate<MediaCaptureFailedEventHandler>(std::forward<L>(handler)))
{}

template <typename F> MediaCaptureFailedEventHandler::MediaCaptureFailedEventHandler(F* handler) :
    MediaCaptureFailedEventHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> MediaCaptureFailedEventHandler::MediaCaptureFailedEventHandler(O* object, M method) :
    MediaCaptureFailedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> MediaCaptureFailedEventHandler::MediaCaptureFailedEventHandler(com_ptr<O>&& object, M method) :
    MediaCaptureFailedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> MediaCaptureFailedEventHandler::MediaCaptureFailedEventHandler(weak_ref<O>&& object, M method) :
    MediaCaptureFailedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void MediaCaptureFailedEventHandler::operator()(Windows::Media::Capture::MediaCapture const& sender, Windows::Media::Capture::MediaCaptureFailedEventArgs const& errorEventArgs) const
{
    check_hresult((*(impl::abi_t<MediaCaptureFailedEventHandler>**)this)->Invoke(get_abi(sender), get_abi(errorEventArgs)));
}

template <typename L> RecordLimitationExceededEventHandler::RecordLimitationExceededEventHandler(L handler) :
    RecordLimitationExceededEventHandler(impl::make_delegate<RecordLimitationExceededEventHandler>(std::forward<L>(handler)))
{}

template <typename F> RecordLimitationExceededEventHandler::RecordLimitationExceededEventHandler(F* handler) :
    RecordLimitationExceededEventHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> RecordLimitationExceededEventHandler::RecordLimitationExceededEventHandler(O* object, M method) :
    RecordLimitationExceededEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> RecordLimitationExceededEventHandler::RecordLimitationExceededEventHandler(com_ptr<O>&& object, M method) :
    RecordLimitationExceededEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> RecordLimitationExceededEventHandler::RecordLimitationExceededEventHandler(weak_ref<O>&& object, M method) :
    RecordLimitationExceededEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void RecordLimitationExceededEventHandler::operator()(Windows::Media::Capture::MediaCapture const& sender) const
{
    check_hresult((*(impl::abi_t<RecordLimitationExceededEventHandler>**)this)->Invoke(get_abi(sender)));
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Media::Capture::IAdvancedCapturedPhoto> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IAdvancedCapturedPhoto> {};
template<> struct hash<winrt::Windows::Media::Capture::IAdvancedCapturedPhoto2> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IAdvancedCapturedPhoto2> {};
template<> struct hash<winrt::Windows::Media::Capture::IAdvancedPhotoCapture> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IAdvancedPhotoCapture> {};
template<> struct hash<winrt::Windows::Media::Capture::IAppBroadcastBackgroundService> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IAppBroadcastBackgroundService> {};
template<> struct hash<winrt::Windows::Media::Capture::IAppBroadcastBackgroundService2> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IAppBroadcastBackgroundService2> {};
template<> struct hash<winrt::Windows::Media::Capture::IAppBroadcastBackgroundServiceSignInInfo> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IAppBroadcastBackgroundServiceSignInInfo> {};
template<> struct hash<winrt::Windows::Media::Capture::IAppBroadcastBackgroundServiceSignInInfo2> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IAppBroadcastBackgroundServiceSignInInfo2> {};
template<> struct hash<winrt::Windows::Media::Capture::IAppBroadcastBackgroundServiceStreamInfo> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IAppBroadcastBackgroundServiceStreamInfo> {};
template<> struct hash<winrt::Windows::Media::Capture::IAppBroadcastBackgroundServiceStreamInfo2> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IAppBroadcastBackgroundServiceStreamInfo2> {};
template<> struct hash<winrt::Windows::Media::Capture::IAppBroadcastCameraCaptureStateChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IAppBroadcastCameraCaptureStateChangedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Capture::IAppBroadcastGlobalSettings> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IAppBroadcastGlobalSettings> {};
template<> struct hash<winrt::Windows::Media::Capture::IAppBroadcastHeartbeatRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IAppBroadcastHeartbeatRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Capture::IAppBroadcastManagerStatics> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IAppBroadcastManagerStatics> {};
template<> struct hash<winrt::Windows::Media::Capture::IAppBroadcastMicrophoneCaptureStateChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IAppBroadcastMicrophoneCaptureStateChangedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Capture::IAppBroadcastPlugIn> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IAppBroadcastPlugIn> {};
template<> struct hash<winrt::Windows::Media::Capture::IAppBroadcastPlugInManager> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IAppBroadcastPlugInManager> {};
template<> struct hash<winrt::Windows::Media::Capture::IAppBroadcastPlugInManagerStatics> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IAppBroadcastPlugInManagerStatics> {};
template<> struct hash<winrt::Windows::Media::Capture::IAppBroadcastPlugInStateChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IAppBroadcastPlugInStateChangedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Capture::IAppBroadcastPreview> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IAppBroadcastPreview> {};
template<> struct hash<winrt::Windows::Media::Capture::IAppBroadcastPreviewStateChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IAppBroadcastPreviewStateChangedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Capture::IAppBroadcastPreviewStreamReader> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IAppBroadcastPreviewStreamReader> {};
template<> struct hash<winrt::Windows::Media::Capture::IAppBroadcastPreviewStreamVideoFrame> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IAppBroadcastPreviewStreamVideoFrame> {};
template<> struct hash<winrt::Windows::Media::Capture::IAppBroadcastPreviewStreamVideoHeader> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IAppBroadcastPreviewStreamVideoHeader> {};
template<> struct hash<winrt::Windows::Media::Capture::IAppBroadcastProviderSettings> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IAppBroadcastProviderSettings> {};
template<> struct hash<winrt::Windows::Media::Capture::IAppBroadcastServices> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IAppBroadcastServices> {};
template<> struct hash<winrt::Windows::Media::Capture::IAppBroadcastSignInStateChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IAppBroadcastSignInStateChangedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Capture::IAppBroadcastState> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IAppBroadcastState> {};
template<> struct hash<winrt::Windows::Media::Capture::IAppBroadcastStreamAudioFrame> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IAppBroadcastStreamAudioFrame> {};
template<> struct hash<winrt::Windows::Media::Capture::IAppBroadcastStreamAudioHeader> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IAppBroadcastStreamAudioHeader> {};
template<> struct hash<winrt::Windows::Media::Capture::IAppBroadcastStreamReader> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IAppBroadcastStreamReader> {};
template<> struct hash<winrt::Windows::Media::Capture::IAppBroadcastStreamStateChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IAppBroadcastStreamStateChangedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Capture::IAppBroadcastStreamVideoFrame> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IAppBroadcastStreamVideoFrame> {};
template<> struct hash<winrt::Windows::Media::Capture::IAppBroadcastStreamVideoHeader> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IAppBroadcastStreamVideoHeader> {};
template<> struct hash<winrt::Windows::Media::Capture::IAppBroadcastTriggerDetails> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IAppBroadcastTriggerDetails> {};
template<> struct hash<winrt::Windows::Media::Capture::IAppBroadcastViewerCountChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IAppBroadcastViewerCountChangedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Capture::IAppCapture> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IAppCapture> {};
template<> struct hash<winrt::Windows::Media::Capture::IAppCaptureAlternateShortcutKeys> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IAppCaptureAlternateShortcutKeys> {};
template<> struct hash<winrt::Windows::Media::Capture::IAppCaptureAlternateShortcutKeys2> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IAppCaptureAlternateShortcutKeys2> {};
template<> struct hash<winrt::Windows::Media::Capture::IAppCaptureAlternateShortcutKeys3> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IAppCaptureAlternateShortcutKeys3> {};
template<> struct hash<winrt::Windows::Media::Capture::IAppCaptureDurationGeneratedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IAppCaptureDurationGeneratedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Capture::IAppCaptureFileGeneratedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IAppCaptureFileGeneratedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Capture::IAppCaptureManagerStatics> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IAppCaptureManagerStatics> {};
template<> struct hash<winrt::Windows::Media::Capture::IAppCaptureMetadataWriter> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IAppCaptureMetadataWriter> {};
template<> struct hash<winrt::Windows::Media::Capture::IAppCaptureMicrophoneCaptureStateChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IAppCaptureMicrophoneCaptureStateChangedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Capture::IAppCaptureRecordOperation> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IAppCaptureRecordOperation> {};
template<> struct hash<winrt::Windows::Media::Capture::IAppCaptureRecordingStateChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IAppCaptureRecordingStateChangedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Capture::IAppCaptureServices> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IAppCaptureServices> {};
template<> struct hash<winrt::Windows::Media::Capture::IAppCaptureSettings> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IAppCaptureSettings> {};
template<> struct hash<winrt::Windows::Media::Capture::IAppCaptureSettings2> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IAppCaptureSettings2> {};
template<> struct hash<winrt::Windows::Media::Capture::IAppCaptureSettings3> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IAppCaptureSettings3> {};
template<> struct hash<winrt::Windows::Media::Capture::IAppCaptureSettings4> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IAppCaptureSettings4> {};
template<> struct hash<winrt::Windows::Media::Capture::IAppCaptureSettings5> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IAppCaptureSettings5> {};
template<> struct hash<winrt::Windows::Media::Capture::IAppCaptureState> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IAppCaptureState> {};
template<> struct hash<winrt::Windows::Media::Capture::IAppCaptureStatics> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IAppCaptureStatics> {};
template<> struct hash<winrt::Windows::Media::Capture::IAppCaptureStatics2> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IAppCaptureStatics2> {};
template<> struct hash<winrt::Windows::Media::Capture::ICameraCaptureUI> : winrt::impl::hash_base<winrt::Windows::Media::Capture::ICameraCaptureUI> {};
template<> struct hash<winrt::Windows::Media::Capture::ICameraCaptureUIPhotoCaptureSettings> : winrt::impl::hash_base<winrt::Windows::Media::Capture::ICameraCaptureUIPhotoCaptureSettings> {};
template<> struct hash<winrt::Windows::Media::Capture::ICameraCaptureUIVideoCaptureSettings> : winrt::impl::hash_base<winrt::Windows::Media::Capture::ICameraCaptureUIVideoCaptureSettings> {};
template<> struct hash<winrt::Windows::Media::Capture::ICameraOptionsUIStatics> : winrt::impl::hash_base<winrt::Windows::Media::Capture::ICameraOptionsUIStatics> {};
template<> struct hash<winrt::Windows::Media::Capture::ICapturedFrame> : winrt::impl::hash_base<winrt::Windows::Media::Capture::ICapturedFrame> {};
template<> struct hash<winrt::Windows::Media::Capture::ICapturedFrame2> : winrt::impl::hash_base<winrt::Windows::Media::Capture::ICapturedFrame2> {};
template<> struct hash<winrt::Windows::Media::Capture::ICapturedFrameControlValues> : winrt::impl::hash_base<winrt::Windows::Media::Capture::ICapturedFrameControlValues> {};
template<> struct hash<winrt::Windows::Media::Capture::ICapturedFrameControlValues2> : winrt::impl::hash_base<winrt::Windows::Media::Capture::ICapturedFrameControlValues2> {};
template<> struct hash<winrt::Windows::Media::Capture::ICapturedFrameWithSoftwareBitmap> : winrt::impl::hash_base<winrt::Windows::Media::Capture::ICapturedFrameWithSoftwareBitmap> {};
template<> struct hash<winrt::Windows::Media::Capture::ICapturedPhoto> : winrt::impl::hash_base<winrt::Windows::Media::Capture::ICapturedPhoto> {};
template<> struct hash<winrt::Windows::Media::Capture::IGameBarServices> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IGameBarServices> {};
template<> struct hash<winrt::Windows::Media::Capture::IGameBarServicesCommandEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IGameBarServicesCommandEventArgs> {};
template<> struct hash<winrt::Windows::Media::Capture::IGameBarServicesManager> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IGameBarServicesManager> {};
template<> struct hash<winrt::Windows::Media::Capture::IGameBarServicesManagerGameBarServicesCreatedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IGameBarServicesManagerGameBarServicesCreatedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Capture::IGameBarServicesManagerStatics> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IGameBarServicesManagerStatics> {};
template<> struct hash<winrt::Windows::Media::Capture::IGameBarServicesTargetInfo> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IGameBarServicesTargetInfo> {};
template<> struct hash<winrt::Windows::Media::Capture::ILowLagMediaRecording> : winrt::impl::hash_base<winrt::Windows::Media::Capture::ILowLagMediaRecording> {};
template<> struct hash<winrt::Windows::Media::Capture::ILowLagMediaRecording2> : winrt::impl::hash_base<winrt::Windows::Media::Capture::ILowLagMediaRecording2> {};
template<> struct hash<winrt::Windows::Media::Capture::ILowLagMediaRecording3> : winrt::impl::hash_base<winrt::Windows::Media::Capture::ILowLagMediaRecording3> {};
template<> struct hash<winrt::Windows::Media::Capture::ILowLagPhotoCapture> : winrt::impl::hash_base<winrt::Windows::Media::Capture::ILowLagPhotoCapture> {};
template<> struct hash<winrt::Windows::Media::Capture::ILowLagPhotoSequenceCapture> : winrt::impl::hash_base<winrt::Windows::Media::Capture::ILowLagPhotoSequenceCapture> {};
template<> struct hash<winrt::Windows::Media::Capture::IMediaCapture> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IMediaCapture> {};
template<> struct hash<winrt::Windows::Media::Capture::IMediaCapture2> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IMediaCapture2> {};
template<> struct hash<winrt::Windows::Media::Capture::IMediaCapture3> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IMediaCapture3> {};
template<> struct hash<winrt::Windows::Media::Capture::IMediaCapture4> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IMediaCapture4> {};
template<> struct hash<winrt::Windows::Media::Capture::IMediaCapture5> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IMediaCapture5> {};
template<> struct hash<winrt::Windows::Media::Capture::IMediaCapture6> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IMediaCapture6> {};
template<> struct hash<winrt::Windows::Media::Capture::IMediaCaptureDeviceExclusiveControlStatusChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IMediaCaptureDeviceExclusiveControlStatusChangedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Capture::IMediaCaptureFailedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IMediaCaptureFailedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Capture::IMediaCaptureFocusChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IMediaCaptureFocusChangedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Capture::IMediaCaptureInitializationSettings> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IMediaCaptureInitializationSettings> {};
template<> struct hash<winrt::Windows::Media::Capture::IMediaCaptureInitializationSettings2> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IMediaCaptureInitializationSettings2> {};
template<> struct hash<winrt::Windows::Media::Capture::IMediaCaptureInitializationSettings3> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IMediaCaptureInitializationSettings3> {};
template<> struct hash<winrt::Windows::Media::Capture::IMediaCaptureInitializationSettings4> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IMediaCaptureInitializationSettings4> {};
template<> struct hash<winrt::Windows::Media::Capture::IMediaCaptureInitializationSettings5> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IMediaCaptureInitializationSettings5> {};
template<> struct hash<winrt::Windows::Media::Capture::IMediaCaptureInitializationSettings6> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IMediaCaptureInitializationSettings6> {};
template<> struct hash<winrt::Windows::Media::Capture::IMediaCapturePauseResult> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IMediaCapturePauseResult> {};
template<> struct hash<winrt::Windows::Media::Capture::IMediaCaptureSettings> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IMediaCaptureSettings> {};
template<> struct hash<winrt::Windows::Media::Capture::IMediaCaptureSettings2> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IMediaCaptureSettings2> {};
template<> struct hash<winrt::Windows::Media::Capture::IMediaCaptureSettings3> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IMediaCaptureSettings3> {};
template<> struct hash<winrt::Windows::Media::Capture::IMediaCaptureStatics> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IMediaCaptureStatics> {};
template<> struct hash<winrt::Windows::Media::Capture::IMediaCaptureStopResult> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IMediaCaptureStopResult> {};
template<> struct hash<winrt::Windows::Media::Capture::IMediaCaptureVideoPreview> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IMediaCaptureVideoPreview> {};
template<> struct hash<winrt::Windows::Media::Capture::IMediaCaptureVideoProfile> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IMediaCaptureVideoProfile> {};
template<> struct hash<winrt::Windows::Media::Capture::IMediaCaptureVideoProfile2> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IMediaCaptureVideoProfile2> {};
template<> struct hash<winrt::Windows::Media::Capture::IMediaCaptureVideoProfileMediaDescription> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IMediaCaptureVideoProfileMediaDescription> {};
template<> struct hash<winrt::Windows::Media::Capture::IMediaCaptureVideoProfileMediaDescription2> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IMediaCaptureVideoProfileMediaDescription2> {};
template<> struct hash<winrt::Windows::Media::Capture::IOptionalReferencePhotoCapturedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IOptionalReferencePhotoCapturedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Capture::IPhotoCapturedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IPhotoCapturedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Capture::IPhotoConfirmationCapturedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IPhotoConfirmationCapturedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Capture::IVideoStreamConfiguration> : winrt::impl::hash_base<winrt::Windows::Media::Capture::IVideoStreamConfiguration> {};
template<> struct hash<winrt::Windows::Media::Capture::AdvancedCapturedPhoto> : winrt::impl::hash_base<winrt::Windows::Media::Capture::AdvancedCapturedPhoto> {};
template<> struct hash<winrt::Windows::Media::Capture::AdvancedPhotoCapture> : winrt::impl::hash_base<winrt::Windows::Media::Capture::AdvancedPhotoCapture> {};
template<> struct hash<winrt::Windows::Media::Capture::AppBroadcastBackgroundService> : winrt::impl::hash_base<winrt::Windows::Media::Capture::AppBroadcastBackgroundService> {};
template<> struct hash<winrt::Windows::Media::Capture::AppBroadcastBackgroundServiceSignInInfo> : winrt::impl::hash_base<winrt::Windows::Media::Capture::AppBroadcastBackgroundServiceSignInInfo> {};
template<> struct hash<winrt::Windows::Media::Capture::AppBroadcastBackgroundServiceStreamInfo> : winrt::impl::hash_base<winrt::Windows::Media::Capture::AppBroadcastBackgroundServiceStreamInfo> {};
template<> struct hash<winrt::Windows::Media::Capture::AppBroadcastCameraCaptureStateChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Capture::AppBroadcastCameraCaptureStateChangedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Capture::AppBroadcastGlobalSettings> : winrt::impl::hash_base<winrt::Windows::Media::Capture::AppBroadcastGlobalSettings> {};
template<> struct hash<winrt::Windows::Media::Capture::AppBroadcastHeartbeatRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Capture::AppBroadcastHeartbeatRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Capture::AppBroadcastManager> : winrt::impl::hash_base<winrt::Windows::Media::Capture::AppBroadcastManager> {};
template<> struct hash<winrt::Windows::Media::Capture::AppBroadcastMicrophoneCaptureStateChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Capture::AppBroadcastMicrophoneCaptureStateChangedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Capture::AppBroadcastPlugIn> : winrt::impl::hash_base<winrt::Windows::Media::Capture::AppBroadcastPlugIn> {};
template<> struct hash<winrt::Windows::Media::Capture::AppBroadcastPlugInManager> : winrt::impl::hash_base<winrt::Windows::Media::Capture::AppBroadcastPlugInManager> {};
template<> struct hash<winrt::Windows::Media::Capture::AppBroadcastPlugInStateChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Capture::AppBroadcastPlugInStateChangedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Capture::AppBroadcastPreview> : winrt::impl::hash_base<winrt::Windows::Media::Capture::AppBroadcastPreview> {};
template<> struct hash<winrt::Windows::Media::Capture::AppBroadcastPreviewStateChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Capture::AppBroadcastPreviewStateChangedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Capture::AppBroadcastPreviewStreamReader> : winrt::impl::hash_base<winrt::Windows::Media::Capture::AppBroadcastPreviewStreamReader> {};
template<> struct hash<winrt::Windows::Media::Capture::AppBroadcastPreviewStreamVideoFrame> : winrt::impl::hash_base<winrt::Windows::Media::Capture::AppBroadcastPreviewStreamVideoFrame> {};
template<> struct hash<winrt::Windows::Media::Capture::AppBroadcastPreviewStreamVideoHeader> : winrt::impl::hash_base<winrt::Windows::Media::Capture::AppBroadcastPreviewStreamVideoHeader> {};
template<> struct hash<winrt::Windows::Media::Capture::AppBroadcastProviderSettings> : winrt::impl::hash_base<winrt::Windows::Media::Capture::AppBroadcastProviderSettings> {};
template<> struct hash<winrt::Windows::Media::Capture::AppBroadcastServices> : winrt::impl::hash_base<winrt::Windows::Media::Capture::AppBroadcastServices> {};
template<> struct hash<winrt::Windows::Media::Capture::AppBroadcastSignInStateChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Capture::AppBroadcastSignInStateChangedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Capture::AppBroadcastState> : winrt::impl::hash_base<winrt::Windows::Media::Capture::AppBroadcastState> {};
template<> struct hash<winrt::Windows::Media::Capture::AppBroadcastStreamAudioFrame> : winrt::impl::hash_base<winrt::Windows::Media::Capture::AppBroadcastStreamAudioFrame> {};
template<> struct hash<winrt::Windows::Media::Capture::AppBroadcastStreamAudioHeader> : winrt::impl::hash_base<winrt::Windows::Media::Capture::AppBroadcastStreamAudioHeader> {};
template<> struct hash<winrt::Windows::Media::Capture::AppBroadcastStreamReader> : winrt::impl::hash_base<winrt::Windows::Media::Capture::AppBroadcastStreamReader> {};
template<> struct hash<winrt::Windows::Media::Capture::AppBroadcastStreamStateChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Capture::AppBroadcastStreamStateChangedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Capture::AppBroadcastStreamVideoFrame> : winrt::impl::hash_base<winrt::Windows::Media::Capture::AppBroadcastStreamVideoFrame> {};
template<> struct hash<winrt::Windows::Media::Capture::AppBroadcastStreamVideoHeader> : winrt::impl::hash_base<winrt::Windows::Media::Capture::AppBroadcastStreamVideoHeader> {};
template<> struct hash<winrt::Windows::Media::Capture::AppBroadcastTriggerDetails> : winrt::impl::hash_base<winrt::Windows::Media::Capture::AppBroadcastTriggerDetails> {};
template<> struct hash<winrt::Windows::Media::Capture::AppBroadcastViewerCountChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Capture::AppBroadcastViewerCountChangedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Capture::AppCapture> : winrt::impl::hash_base<winrt::Windows::Media::Capture::AppCapture> {};
template<> struct hash<winrt::Windows::Media::Capture::AppCaptureAlternateShortcutKeys> : winrt::impl::hash_base<winrt::Windows::Media::Capture::AppCaptureAlternateShortcutKeys> {};
template<> struct hash<winrt::Windows::Media::Capture::AppCaptureDurationGeneratedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Capture::AppCaptureDurationGeneratedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Capture::AppCaptureFileGeneratedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Capture::AppCaptureFileGeneratedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Capture::AppCaptureManager> : winrt::impl::hash_base<winrt::Windows::Media::Capture::AppCaptureManager> {};
template<> struct hash<winrt::Windows::Media::Capture::AppCaptureMetadataWriter> : winrt::impl::hash_base<winrt::Windows::Media::Capture::AppCaptureMetadataWriter> {};
template<> struct hash<winrt::Windows::Media::Capture::AppCaptureMicrophoneCaptureStateChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Capture::AppCaptureMicrophoneCaptureStateChangedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Capture::AppCaptureRecordOperation> : winrt::impl::hash_base<winrt::Windows::Media::Capture::AppCaptureRecordOperation> {};
template<> struct hash<winrt::Windows::Media::Capture::AppCaptureRecordingStateChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Capture::AppCaptureRecordingStateChangedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Capture::AppCaptureServices> : winrt::impl::hash_base<winrt::Windows::Media::Capture::AppCaptureServices> {};
template<> struct hash<winrt::Windows::Media::Capture::AppCaptureSettings> : winrt::impl::hash_base<winrt::Windows::Media::Capture::AppCaptureSettings> {};
template<> struct hash<winrt::Windows::Media::Capture::AppCaptureState> : winrt::impl::hash_base<winrt::Windows::Media::Capture::AppCaptureState> {};
template<> struct hash<winrt::Windows::Media::Capture::CameraCaptureUI> : winrt::impl::hash_base<winrt::Windows::Media::Capture::CameraCaptureUI> {};
template<> struct hash<winrt::Windows::Media::Capture::CameraCaptureUIPhotoCaptureSettings> : winrt::impl::hash_base<winrt::Windows::Media::Capture::CameraCaptureUIPhotoCaptureSettings> {};
template<> struct hash<winrt::Windows::Media::Capture::CameraCaptureUIVideoCaptureSettings> : winrt::impl::hash_base<winrt::Windows::Media::Capture::CameraCaptureUIVideoCaptureSettings> {};
template<> struct hash<winrt::Windows::Media::Capture::CameraOptionsUI> : winrt::impl::hash_base<winrt::Windows::Media::Capture::CameraOptionsUI> {};
template<> struct hash<winrt::Windows::Media::Capture::CapturedFrame> : winrt::impl::hash_base<winrt::Windows::Media::Capture::CapturedFrame> {};
template<> struct hash<winrt::Windows::Media::Capture::CapturedFrameControlValues> : winrt::impl::hash_base<winrt::Windows::Media::Capture::CapturedFrameControlValues> {};
template<> struct hash<winrt::Windows::Media::Capture::CapturedPhoto> : winrt::impl::hash_base<winrt::Windows::Media::Capture::CapturedPhoto> {};
template<> struct hash<winrt::Windows::Media::Capture::GameBarServices> : winrt::impl::hash_base<winrt::Windows::Media::Capture::GameBarServices> {};
template<> struct hash<winrt::Windows::Media::Capture::GameBarServicesCommandEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Capture::GameBarServicesCommandEventArgs> {};
template<> struct hash<winrt::Windows::Media::Capture::GameBarServicesManager> : winrt::impl::hash_base<winrt::Windows::Media::Capture::GameBarServicesManager> {};
template<> struct hash<winrt::Windows::Media::Capture::GameBarServicesManagerGameBarServicesCreatedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Capture::GameBarServicesManagerGameBarServicesCreatedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Capture::GameBarServicesTargetInfo> : winrt::impl::hash_base<winrt::Windows::Media::Capture::GameBarServicesTargetInfo> {};
template<> struct hash<winrt::Windows::Media::Capture::LowLagMediaRecording> : winrt::impl::hash_base<winrt::Windows::Media::Capture::LowLagMediaRecording> {};
template<> struct hash<winrt::Windows::Media::Capture::LowLagPhotoCapture> : winrt::impl::hash_base<winrt::Windows::Media::Capture::LowLagPhotoCapture> {};
template<> struct hash<winrt::Windows::Media::Capture::LowLagPhotoSequenceCapture> : winrt::impl::hash_base<winrt::Windows::Media::Capture::LowLagPhotoSequenceCapture> {};
template<> struct hash<winrt::Windows::Media::Capture::MediaCapture> : winrt::impl::hash_base<winrt::Windows::Media::Capture::MediaCapture> {};
template<> struct hash<winrt::Windows::Media::Capture::MediaCaptureDeviceExclusiveControlStatusChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Capture::MediaCaptureDeviceExclusiveControlStatusChangedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Capture::MediaCaptureFailedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Capture::MediaCaptureFailedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Capture::MediaCaptureFocusChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Capture::MediaCaptureFocusChangedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Capture::MediaCaptureInitializationSettings> : winrt::impl::hash_base<winrt::Windows::Media::Capture::MediaCaptureInitializationSettings> {};
template<> struct hash<winrt::Windows::Media::Capture::MediaCapturePauseResult> : winrt::impl::hash_base<winrt::Windows::Media::Capture::MediaCapturePauseResult> {};
template<> struct hash<winrt::Windows::Media::Capture::MediaCaptureSettings> : winrt::impl::hash_base<winrt::Windows::Media::Capture::MediaCaptureSettings> {};
template<> struct hash<winrt::Windows::Media::Capture::MediaCaptureStopResult> : winrt::impl::hash_base<winrt::Windows::Media::Capture::MediaCaptureStopResult> {};
template<> struct hash<winrt::Windows::Media::Capture::MediaCaptureVideoProfile> : winrt::impl::hash_base<winrt::Windows::Media::Capture::MediaCaptureVideoProfile> {};
template<> struct hash<winrt::Windows::Media::Capture::MediaCaptureVideoProfileMediaDescription> : winrt::impl::hash_base<winrt::Windows::Media::Capture::MediaCaptureVideoProfileMediaDescription> {};
template<> struct hash<winrt::Windows::Media::Capture::OptionalReferencePhotoCapturedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Capture::OptionalReferencePhotoCapturedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Capture::PhotoCapturedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Capture::PhotoCapturedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Capture::PhotoConfirmationCapturedEventArgs> : winrt::impl::hash_base<winrt::Windows::Media::Capture::PhotoConfirmationCapturedEventArgs> {};
template<> struct hash<winrt::Windows::Media::Capture::VideoStreamConfiguration> : winrt::impl::hash_base<winrt::Windows::Media::Capture::VideoStreamConfiguration> {};

}
