// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Media.1.h"
#include "winrt/impl/Windows.Storage.Streams.1.h"
#include "winrt/impl/Windows.Media.Control.1.h"

WINRT_EXPORT namespace winrt::Windows::Media::Control {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::Media::Control {

struct WINRT_EBO CurrentSessionChangedEventArgs :
    Windows::Media::Control::ICurrentSessionChangedEventArgs
{
    CurrentSessionChangedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO GlobalSystemMediaTransportControlsSession :
    Windows::Media::Control::IGlobalSystemMediaTransportControlsSession
{
    GlobalSystemMediaTransportControlsSession(std::nullptr_t) noexcept {}
};

struct WINRT_EBO GlobalSystemMediaTransportControlsSessionManager :
    Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionManager
{
    GlobalSystemMediaTransportControlsSessionManager(std::nullptr_t) noexcept {}
    static Windows::Foundation::IAsyncOperation<Windows::Media::Control::GlobalSystemMediaTransportControlsSessionManager> RequestAsync();
};

struct WINRT_EBO GlobalSystemMediaTransportControlsSessionMediaProperties :
    Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionMediaProperties
{
    GlobalSystemMediaTransportControlsSessionMediaProperties(std::nullptr_t) noexcept {}
};

struct WINRT_EBO GlobalSystemMediaTransportControlsSessionPlaybackControls :
    Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackControls
{
    GlobalSystemMediaTransportControlsSessionPlaybackControls(std::nullptr_t) noexcept {}
};

struct WINRT_EBO GlobalSystemMediaTransportControlsSessionPlaybackInfo :
    Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionPlaybackInfo
{
    GlobalSystemMediaTransportControlsSessionPlaybackInfo(std::nullptr_t) noexcept {}
};

struct WINRT_EBO GlobalSystemMediaTransportControlsSessionTimelineProperties :
    Windows::Media::Control::IGlobalSystemMediaTransportControlsSessionTimelineProperties
{
    GlobalSystemMediaTransportControlsSessionTimelineProperties(std::nullptr_t) noexcept {}
};

struct WINRT_EBO MediaPropertiesChangedEventArgs :
    Windows::Media::Control::IMediaPropertiesChangedEventArgs
{
    MediaPropertiesChangedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO PlaybackInfoChangedEventArgs :
    Windows::Media::Control::IPlaybackInfoChangedEventArgs
{
    PlaybackInfoChangedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO SessionsChangedEventArgs :
    Windows::Media::Control::ISessionsChangedEventArgs
{
    SessionsChangedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO TimelinePropertiesChangedEventArgs :
    Windows::Media::Control::ITimelinePropertiesChangedEventArgs
{
    TimelinePropertiesChangedEventArgs(std::nullptr_t) noexcept {}
};

}
