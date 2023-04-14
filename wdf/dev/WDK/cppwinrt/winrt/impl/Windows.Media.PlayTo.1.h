// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Foundation.0.h"
#include "winrt/impl/Windows.Foundation.Collections.0.h"
#include "winrt/impl/Windows.Storage.Streams.0.h"
#include "winrt/impl/Windows.Media.PlayTo.0.h"

WINRT_EXPORT namespace winrt::Windows::Media::PlayTo {

struct WINRT_EBO ICurrentTimeChangeRequestedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICurrentTimeChangeRequestedEventArgs>
{
    ICurrentTimeChangeRequestedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IMuteChangeRequestedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IMuteChangeRequestedEventArgs>
{
    IMuteChangeRequestedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPlayToConnection :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPlayToConnection>
{
    IPlayToConnection(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPlayToConnectionErrorEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPlayToConnectionErrorEventArgs>
{
    IPlayToConnectionErrorEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPlayToConnectionStateChangedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPlayToConnectionStateChangedEventArgs>
{
    IPlayToConnectionStateChangedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPlayToConnectionTransferredEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPlayToConnectionTransferredEventArgs>
{
    IPlayToConnectionTransferredEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPlayToManager :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPlayToManager>
{
    IPlayToManager(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPlayToManagerStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPlayToManagerStatics>
{
    IPlayToManagerStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPlayToReceiver :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPlayToReceiver>
{
    IPlayToReceiver(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPlayToSource :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPlayToSource>
{
    IPlayToSource(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPlayToSourceDeferral :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPlayToSourceDeferral>
{
    IPlayToSourceDeferral(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPlayToSourceRequest :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPlayToSourceRequest>
{
    IPlayToSourceRequest(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPlayToSourceRequestedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPlayToSourceRequestedEventArgs>
{
    IPlayToSourceRequestedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPlayToSourceSelectedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPlayToSourceSelectedEventArgs>
{
    IPlayToSourceSelectedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPlayToSourceWithPreferredSourceUri :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPlayToSourceWithPreferredSourceUri>
{
    IPlayToSourceWithPreferredSourceUri(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPlaybackRateChangeRequestedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPlaybackRateChangeRequestedEventArgs>
{
    IPlaybackRateChangeRequestedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISourceChangeRequestedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISourceChangeRequestedEventArgs>
{
    ISourceChangeRequestedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IVolumeChangeRequestedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IVolumeChangeRequestedEventArgs>
{
    IVolumeChangeRequestedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

}
