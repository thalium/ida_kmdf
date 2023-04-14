// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Media.0.h"
#include "winrt/impl/Windows.Storage.Streams.0.h"
#include "winrt/impl/Windows.Media.Control.0.h"

WINRT_EXPORT namespace winrt::Windows::Media::Control {

struct WINRT_EBO ICurrentSessionChangedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICurrentSessionChangedEventArgs>
{
    ICurrentSessionChangedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IGlobalSystemMediaTransportControlsSession :
    Windows::Foundation::IInspectable,
    impl::consume_t<IGlobalSystemMediaTransportControlsSession>
{
    IGlobalSystemMediaTransportControlsSession(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IGlobalSystemMediaTransportControlsSessionManager :
    Windows::Foundation::IInspectable,
    impl::consume_t<IGlobalSystemMediaTransportControlsSessionManager>
{
    IGlobalSystemMediaTransportControlsSessionManager(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IGlobalSystemMediaTransportControlsSessionManagerStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IGlobalSystemMediaTransportControlsSessionManagerStatics>
{
    IGlobalSystemMediaTransportControlsSessionManagerStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IGlobalSystemMediaTransportControlsSessionMediaProperties :
    Windows::Foundation::IInspectable,
    impl::consume_t<IGlobalSystemMediaTransportControlsSessionMediaProperties>
{
    IGlobalSystemMediaTransportControlsSessionMediaProperties(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IGlobalSystemMediaTransportControlsSessionPlaybackControls :
    Windows::Foundation::IInspectable,
    impl::consume_t<IGlobalSystemMediaTransportControlsSessionPlaybackControls>
{
    IGlobalSystemMediaTransportControlsSessionPlaybackControls(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IGlobalSystemMediaTransportControlsSessionPlaybackInfo :
    Windows::Foundation::IInspectable,
    impl::consume_t<IGlobalSystemMediaTransportControlsSessionPlaybackInfo>
{
    IGlobalSystemMediaTransportControlsSessionPlaybackInfo(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IGlobalSystemMediaTransportControlsSessionTimelineProperties :
    Windows::Foundation::IInspectable,
    impl::consume_t<IGlobalSystemMediaTransportControlsSessionTimelineProperties>
{
    IGlobalSystemMediaTransportControlsSessionTimelineProperties(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IMediaPropertiesChangedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IMediaPropertiesChangedEventArgs>
{
    IMediaPropertiesChangedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPlaybackInfoChangedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPlaybackInfoChangedEventArgs>
{
    IPlaybackInfoChangedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISessionsChangedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISessionsChangedEventArgs>
{
    ISessionsChangedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ITimelinePropertiesChangedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<ITimelinePropertiesChangedEventArgs>
{
    ITimelinePropertiesChangedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

}
