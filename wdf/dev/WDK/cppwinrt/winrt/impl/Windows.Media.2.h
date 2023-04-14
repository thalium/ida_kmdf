// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.ApplicationModel.AppService.1.h"
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.Foundation.Collections.1.h"
#include "winrt/impl/Windows.Graphics.DirectX.1.h"
#include "winrt/impl/Windows.Graphics.DirectX.Direct3D11.1.h"
#include "winrt/impl/Windows.Graphics.Imaging.1.h"
#include "winrt/impl/Windows.Storage.1.h"
#include "winrt/impl/Windows.Storage.Streams.1.h"
#include "winrt/impl/Windows.Media.1.h"

WINRT_EXPORT namespace winrt::Windows::Media {

struct MediaTimeRange
{
    Windows::Foundation::TimeSpan Start;
    Windows::Foundation::TimeSpan End;
};

inline bool operator==(MediaTimeRange const& left, MediaTimeRange const& right) noexcept
{
    return left.Start == right.Start && left.End == right.End;
}

inline bool operator!=(MediaTimeRange const& left, MediaTimeRange const& right) noexcept
{
    return !(left == right);
}

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::Media {

struct WINRT_EBO AudioBuffer :
    Windows::Media::IAudioBuffer
{
    AudioBuffer(std::nullptr_t) noexcept {}
};

struct WINRT_EBO AudioFrame :
    Windows::Media::IAudioFrame
{
    AudioFrame(std::nullptr_t) noexcept {}
    AudioFrame(uint32_t capacity);
};

struct WINRT_EBO AutoRepeatModeChangeRequestedEventArgs :
    Windows::Media::IAutoRepeatModeChangeRequestedEventArgs
{
    AutoRepeatModeChangeRequestedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO ImageDisplayProperties :
    Windows::Media::IImageDisplayProperties
{
    ImageDisplayProperties(std::nullptr_t) noexcept {}
};

struct MediaControl
{
    MediaControl() = delete;
    static winrt::event_token SoundLevelChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler);
    using SoundLevelChanged_revoker = impl::factory_event_revoker<Windows::Media::IMediaControl, &impl::abi_t<Windows::Media::IMediaControl>::remove_SoundLevelChanged>;
    static SoundLevelChanged_revoker SoundLevelChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler);
    static void SoundLevelChanged(winrt::event_token const& cookie);
    static winrt::event_token PlayPressed(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler);
    using PlayPressed_revoker = impl::factory_event_revoker<Windows::Media::IMediaControl, &impl::abi_t<Windows::Media::IMediaControl>::remove_PlayPressed>;
    static PlayPressed_revoker PlayPressed(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler);
    static void PlayPressed(winrt::event_token const& cookie);
    static winrt::event_token PausePressed(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler);
    using PausePressed_revoker = impl::factory_event_revoker<Windows::Media::IMediaControl, &impl::abi_t<Windows::Media::IMediaControl>::remove_PausePressed>;
    static PausePressed_revoker PausePressed(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler);
    static void PausePressed(winrt::event_token const& cookie);
    static winrt::event_token StopPressed(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler);
    using StopPressed_revoker = impl::factory_event_revoker<Windows::Media::IMediaControl, &impl::abi_t<Windows::Media::IMediaControl>::remove_StopPressed>;
    static StopPressed_revoker StopPressed(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler);
    static void StopPressed(winrt::event_token const& cookie);
    static winrt::event_token PlayPauseTogglePressed(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler);
    using PlayPauseTogglePressed_revoker = impl::factory_event_revoker<Windows::Media::IMediaControl, &impl::abi_t<Windows::Media::IMediaControl>::remove_PlayPauseTogglePressed>;
    static PlayPauseTogglePressed_revoker PlayPauseTogglePressed(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler);
    static void PlayPauseTogglePressed(winrt::event_token const& cookie);
    static winrt::event_token RecordPressed(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler);
    using RecordPressed_revoker = impl::factory_event_revoker<Windows::Media::IMediaControl, &impl::abi_t<Windows::Media::IMediaControl>::remove_RecordPressed>;
    static RecordPressed_revoker RecordPressed(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler);
    static void RecordPressed(winrt::event_token const& cookie);
    static winrt::event_token NextTrackPressed(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler);
    using NextTrackPressed_revoker = impl::factory_event_revoker<Windows::Media::IMediaControl, &impl::abi_t<Windows::Media::IMediaControl>::remove_NextTrackPressed>;
    static NextTrackPressed_revoker NextTrackPressed(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler);
    static void NextTrackPressed(winrt::event_token const& cookie);
    static winrt::event_token PreviousTrackPressed(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler);
    using PreviousTrackPressed_revoker = impl::factory_event_revoker<Windows::Media::IMediaControl, &impl::abi_t<Windows::Media::IMediaControl>::remove_PreviousTrackPressed>;
    static PreviousTrackPressed_revoker PreviousTrackPressed(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler);
    static void PreviousTrackPressed(winrt::event_token const& cookie);
    static winrt::event_token FastForwardPressed(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler);
    using FastForwardPressed_revoker = impl::factory_event_revoker<Windows::Media::IMediaControl, &impl::abi_t<Windows::Media::IMediaControl>::remove_FastForwardPressed>;
    static FastForwardPressed_revoker FastForwardPressed(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler);
    static void FastForwardPressed(winrt::event_token const& cookie);
    static winrt::event_token RewindPressed(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler);
    using RewindPressed_revoker = impl::factory_event_revoker<Windows::Media::IMediaControl, &impl::abi_t<Windows::Media::IMediaControl>::remove_RewindPressed>;
    static RewindPressed_revoker RewindPressed(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler);
    static void RewindPressed(winrt::event_token const& cookie);
    static winrt::event_token ChannelUpPressed(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler);
    using ChannelUpPressed_revoker = impl::factory_event_revoker<Windows::Media::IMediaControl, &impl::abi_t<Windows::Media::IMediaControl>::remove_ChannelUpPressed>;
    static ChannelUpPressed_revoker ChannelUpPressed(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler);
    static void ChannelUpPressed(winrt::event_token const& cookie);
    static winrt::event_token ChannelDownPressed(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler);
    using ChannelDownPressed_revoker = impl::factory_event_revoker<Windows::Media::IMediaControl, &impl::abi_t<Windows::Media::IMediaControl>::remove_ChannelDownPressed>;
    static ChannelDownPressed_revoker ChannelDownPressed(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler);
    static void ChannelDownPressed(winrt::event_token const& cookie);
    static Windows::Media::SoundLevel SoundLevel();
    static void TrackName(param::hstring const& value);
    static hstring TrackName();
    static void ArtistName(param::hstring const& value);
    static hstring ArtistName();
    static void IsPlaying(bool value);
    static bool IsPlaying();
    static void AlbumArt(Windows::Foundation::Uri const& value);
    static Windows::Foundation::Uri AlbumArt();
};

struct WINRT_EBO MediaExtensionManager :
    Windows::Media::IMediaExtensionManager,
    impl::require<MediaExtensionManager, Windows::Media::IMediaExtensionManager2>
{
    MediaExtensionManager(std::nullptr_t) noexcept {}
    MediaExtensionManager();
};

struct MediaMarkerTypes
{
    MediaMarkerTypes() = delete;
    static hstring Bookmark();
};

struct WINRT_EBO MediaProcessingTriggerDetails :
    Windows::Media::IMediaProcessingTriggerDetails
{
    MediaProcessingTriggerDetails(std::nullptr_t) noexcept {}
};

struct WINRT_EBO MediaTimelineController :
    Windows::Media::IMediaTimelineController,
    impl::require<MediaTimelineController, Windows::Media::IMediaTimelineController2>
{
    MediaTimelineController(std::nullptr_t) noexcept {}
    MediaTimelineController();
};

struct WINRT_EBO MediaTimelineControllerFailedEventArgs :
    Windows::Media::IMediaTimelineControllerFailedEventArgs
{
    MediaTimelineControllerFailedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO MusicDisplayProperties :
    Windows::Media::IMusicDisplayProperties,
    impl::require<MusicDisplayProperties, Windows::Media::IMusicDisplayProperties2, Windows::Media::IMusicDisplayProperties3>
{
    MusicDisplayProperties(std::nullptr_t) noexcept {}
};

struct WINRT_EBO PlaybackPositionChangeRequestedEventArgs :
    Windows::Media::IPlaybackPositionChangeRequestedEventArgs
{
    PlaybackPositionChangeRequestedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO PlaybackRateChangeRequestedEventArgs :
    Windows::Media::IPlaybackRateChangeRequestedEventArgs
{
    PlaybackRateChangeRequestedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO ShuffleEnabledChangeRequestedEventArgs :
    Windows::Media::IShuffleEnabledChangeRequestedEventArgs
{
    ShuffleEnabledChangeRequestedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO SystemMediaTransportControls :
    Windows::Media::ISystemMediaTransportControls,
    impl::require<SystemMediaTransportControls, Windows::Media::ISystemMediaTransportControls2>
{
    SystemMediaTransportControls(std::nullptr_t) noexcept {}
    static Windows::Media::SystemMediaTransportControls GetForCurrentView();
};

struct WINRT_EBO SystemMediaTransportControlsButtonPressedEventArgs :
    Windows::Media::ISystemMediaTransportControlsButtonPressedEventArgs
{
    SystemMediaTransportControlsButtonPressedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO SystemMediaTransportControlsDisplayUpdater :
    Windows::Media::ISystemMediaTransportControlsDisplayUpdater
{
    SystemMediaTransportControlsDisplayUpdater(std::nullptr_t) noexcept {}
};

struct WINRT_EBO SystemMediaTransportControlsPropertyChangedEventArgs :
    Windows::Media::ISystemMediaTransportControlsPropertyChangedEventArgs
{
    SystemMediaTransportControlsPropertyChangedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO SystemMediaTransportControlsTimelineProperties :
    Windows::Media::ISystemMediaTransportControlsTimelineProperties
{
    SystemMediaTransportControlsTimelineProperties(std::nullptr_t) noexcept {}
    SystemMediaTransportControlsTimelineProperties();
};

struct WINRT_EBO VideoDisplayProperties :
    Windows::Media::IVideoDisplayProperties,
    impl::require<VideoDisplayProperties, Windows::Media::IVideoDisplayProperties2>
{
    VideoDisplayProperties(std::nullptr_t) noexcept {}
};

struct VideoEffects
{
    VideoEffects() = delete;
    static hstring VideoStabilization();
};

struct WINRT_EBO VideoFrame :
    Windows::Media::IVideoFrame,
    impl::require<VideoFrame, Windows::Media::IVideoFrame2>
{
    VideoFrame(std::nullptr_t) noexcept {}
    VideoFrame(Windows::Graphics::Imaging::BitmapPixelFormat const& format, int32_t width, int32_t height);
    VideoFrame(Windows::Graphics::Imaging::BitmapPixelFormat const& format, int32_t width, int32_t height, Windows::Graphics::Imaging::BitmapAlphaMode const& alpha);
    using impl::consume_t<VideoFrame, Windows::Media::IVideoFrame2>::CopyToAsync;
    using Windows::Media::IVideoFrame::CopyToAsync;
    static Windows::Media::VideoFrame CreateAsDirect3D11SurfaceBacked(Windows::Graphics::DirectX::DirectXPixelFormat const& format, int32_t width, int32_t height);
    static Windows::Media::VideoFrame CreateAsDirect3D11SurfaceBacked(Windows::Graphics::DirectX::DirectXPixelFormat const& format, int32_t width, int32_t height, Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice const& device);
    static Windows::Media::VideoFrame CreateWithSoftwareBitmap(Windows::Graphics::Imaging::SoftwareBitmap const& bitmap);
    static Windows::Media::VideoFrame CreateWithDirect3D11Surface(Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const& surface);
};

}
