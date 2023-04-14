// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.ApplicationModel.Core.1.h"
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.Graphics.1.h"
#include "winrt/impl/Windows.Media.Core.1.h"
#include "winrt/impl/Windows.Storage.Streams.1.h"
#include "winrt/impl/Windows.Media.Miracast.1.h"

WINRT_EXPORT namespace winrt::Windows::Media::Miracast {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::Media::Miracast {

struct WINRT_EBO MiracastReceiver :
    Windows::Media::Miracast::IMiracastReceiver
{
    MiracastReceiver(std::nullptr_t) noexcept {}
    MiracastReceiver();
};

struct WINRT_EBO MiracastReceiverApplySettingsResult :
    Windows::Media::Miracast::IMiracastReceiverApplySettingsResult
{
    MiracastReceiverApplySettingsResult(std::nullptr_t) noexcept {}
};

struct WINRT_EBO MiracastReceiverConnection :
    Windows::Media::Miracast::IMiracastReceiverConnection,
    impl::require<MiracastReceiverConnection, Windows::Foundation::IClosable>
{
    MiracastReceiverConnection(std::nullptr_t) noexcept {}
};

struct WINRT_EBO MiracastReceiverConnectionCreatedEventArgs :
    Windows::Media::Miracast::IMiracastReceiverConnectionCreatedEventArgs
{
    MiracastReceiverConnectionCreatedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO MiracastReceiverCursorImageChannel :
    Windows::Media::Miracast::IMiracastReceiverCursorImageChannel
{
    MiracastReceiverCursorImageChannel(std::nullptr_t) noexcept {}
};

struct WINRT_EBO MiracastReceiverCursorImageChannelSettings :
    Windows::Media::Miracast::IMiracastReceiverCursorImageChannelSettings
{
    MiracastReceiverCursorImageChannelSettings(std::nullptr_t) noexcept {}
};

struct WINRT_EBO MiracastReceiverDisconnectedEventArgs :
    Windows::Media::Miracast::IMiracastReceiverDisconnectedEventArgs
{
    MiracastReceiverDisconnectedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO MiracastReceiverGameControllerDevice :
    Windows::Media::Miracast::IMiracastReceiverGameControllerDevice
{
    MiracastReceiverGameControllerDevice(std::nullptr_t) noexcept {}
};

struct WINRT_EBO MiracastReceiverInputDevices :
    Windows::Media::Miracast::IMiracastReceiverInputDevices
{
    MiracastReceiverInputDevices(std::nullptr_t) noexcept {}
};

struct WINRT_EBO MiracastReceiverKeyboardDevice :
    Windows::Media::Miracast::IMiracastReceiverKeyboardDevice
{
    MiracastReceiverKeyboardDevice(std::nullptr_t) noexcept {}
};

struct WINRT_EBO MiracastReceiverMediaSourceCreatedEventArgs :
    Windows::Media::Miracast::IMiracastReceiverMediaSourceCreatedEventArgs
{
    MiracastReceiverMediaSourceCreatedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO MiracastReceiverSession :
    Windows::Media::Miracast::IMiracastReceiverSession,
    impl::require<MiracastReceiverSession, Windows::Foundation::IClosable>
{
    MiracastReceiverSession(std::nullptr_t) noexcept {}
};

struct WINRT_EBO MiracastReceiverSessionStartResult :
    Windows::Media::Miracast::IMiracastReceiverSessionStartResult
{
    MiracastReceiverSessionStartResult(std::nullptr_t) noexcept {}
};

struct WINRT_EBO MiracastReceiverSettings :
    Windows::Media::Miracast::IMiracastReceiverSettings
{
    MiracastReceiverSettings(std::nullptr_t) noexcept {}
};

struct WINRT_EBO MiracastReceiverStatus :
    Windows::Media::Miracast::IMiracastReceiverStatus
{
    MiracastReceiverStatus(std::nullptr_t) noexcept {}
};

struct WINRT_EBO MiracastReceiverStreamControl :
    Windows::Media::Miracast::IMiracastReceiverStreamControl
{
    MiracastReceiverStreamControl(std::nullptr_t) noexcept {}
};

struct WINRT_EBO MiracastReceiverVideoStreamSettings :
    Windows::Media::Miracast::IMiracastReceiverVideoStreamSettings
{
    MiracastReceiverVideoStreamSettings(std::nullptr_t) noexcept {}
};

struct WINRT_EBO MiracastTransmitter :
    Windows::Media::Miracast::IMiracastTransmitter
{
    MiracastTransmitter(std::nullptr_t) noexcept {}
};

}
