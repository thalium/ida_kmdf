// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.Foundation.Collections.1.h"
#include "winrt/impl/Windows.Storage.Streams.1.h"
#include "winrt/impl/Windows.Media.PlayTo.1.h"

WINRT_EXPORT namespace winrt::Windows::Media::PlayTo {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::Media::PlayTo {

struct WINRT_EBO CurrentTimeChangeRequestedEventArgs :
    Windows::Media::PlayTo::ICurrentTimeChangeRequestedEventArgs
{
    CurrentTimeChangeRequestedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO MuteChangeRequestedEventArgs :
    Windows::Media::PlayTo::IMuteChangeRequestedEventArgs
{
    MuteChangeRequestedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO PlayToConnection :
    Windows::Media::PlayTo::IPlayToConnection
{
    PlayToConnection(std::nullptr_t) noexcept {}
};

struct WINRT_EBO PlayToConnectionErrorEventArgs :
    Windows::Media::PlayTo::IPlayToConnectionErrorEventArgs
{
    PlayToConnectionErrorEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO PlayToConnectionStateChangedEventArgs :
    Windows::Media::PlayTo::IPlayToConnectionStateChangedEventArgs
{
    PlayToConnectionStateChangedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO PlayToConnectionTransferredEventArgs :
    Windows::Media::PlayTo::IPlayToConnectionTransferredEventArgs
{
    PlayToConnectionTransferredEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO PlayToManager :
    Windows::Media::PlayTo::IPlayToManager
{
    PlayToManager(std::nullptr_t) noexcept {}
    static Windows::Media::PlayTo::PlayToManager GetForCurrentView();
    static void ShowPlayToUI();
};

struct WINRT_EBO PlayToReceiver :
    Windows::Media::PlayTo::IPlayToReceiver
{
    PlayToReceiver(std::nullptr_t) noexcept {}
    PlayToReceiver();
};

struct WINRT_EBO PlayToSource :
    Windows::Media::PlayTo::IPlayToSource,
    impl::require<PlayToSource, Windows::Media::PlayTo::IPlayToSourceWithPreferredSourceUri>
{
    PlayToSource(std::nullptr_t) noexcept {}
};

struct WINRT_EBO PlayToSourceDeferral :
    Windows::Media::PlayTo::IPlayToSourceDeferral
{
    PlayToSourceDeferral(std::nullptr_t) noexcept {}
};

struct WINRT_EBO PlayToSourceRequest :
    Windows::Media::PlayTo::IPlayToSourceRequest
{
    PlayToSourceRequest(std::nullptr_t) noexcept {}
};

struct WINRT_EBO PlayToSourceRequestedEventArgs :
    Windows::Media::PlayTo::IPlayToSourceRequestedEventArgs
{
    PlayToSourceRequestedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO PlayToSourceSelectedEventArgs :
    Windows::Media::PlayTo::IPlayToSourceSelectedEventArgs
{
    PlayToSourceSelectedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO PlaybackRateChangeRequestedEventArgs :
    Windows::Media::PlayTo::IPlaybackRateChangeRequestedEventArgs
{
    PlaybackRateChangeRequestedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO SourceChangeRequestedEventArgs :
    Windows::Media::PlayTo::ISourceChangeRequestedEventArgs
{
    SourceChangeRequestedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO VolumeChangeRequestedEventArgs :
    Windows::Media::PlayTo::IVolumeChangeRequestedEventArgs
{
    VolumeChangeRequestedEventArgs(std::nullptr_t) noexcept {}
};

}
