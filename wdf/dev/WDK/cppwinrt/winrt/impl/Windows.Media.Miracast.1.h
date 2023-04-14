// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.ApplicationModel.Core.0.h"
#include "winrt/impl/Windows.Foundation.0.h"
#include "winrt/impl/Windows.Graphics.0.h"
#include "winrt/impl/Windows.Media.Core.0.h"
#include "winrt/impl/Windows.Storage.Streams.0.h"
#include "winrt/impl/Windows.Media.Miracast.0.h"

WINRT_EXPORT namespace winrt::Windows::Media::Miracast {

struct WINRT_EBO IMiracastReceiver :
    Windows::Foundation::IInspectable,
    impl::consume_t<IMiracastReceiver>
{
    IMiracastReceiver(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IMiracastReceiverApplySettingsResult :
    Windows::Foundation::IInspectable,
    impl::consume_t<IMiracastReceiverApplySettingsResult>
{
    IMiracastReceiverApplySettingsResult(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IMiracastReceiverConnection :
    Windows::Foundation::IInspectable,
    impl::consume_t<IMiracastReceiverConnection>
{
    IMiracastReceiverConnection(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IMiracastReceiverConnectionCreatedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IMiracastReceiverConnectionCreatedEventArgs>
{
    IMiracastReceiverConnectionCreatedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IMiracastReceiverCursorImageChannel :
    Windows::Foundation::IInspectable,
    impl::consume_t<IMiracastReceiverCursorImageChannel>
{
    IMiracastReceiverCursorImageChannel(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IMiracastReceiverCursorImageChannelSettings :
    Windows::Foundation::IInspectable,
    impl::consume_t<IMiracastReceiverCursorImageChannelSettings>
{
    IMiracastReceiverCursorImageChannelSettings(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IMiracastReceiverDisconnectedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IMiracastReceiverDisconnectedEventArgs>
{
    IMiracastReceiverDisconnectedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IMiracastReceiverGameControllerDevice :
    Windows::Foundation::IInspectable,
    impl::consume_t<IMiracastReceiverGameControllerDevice>
{
    IMiracastReceiverGameControllerDevice(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IMiracastReceiverInputDevices :
    Windows::Foundation::IInspectable,
    impl::consume_t<IMiracastReceiverInputDevices>
{
    IMiracastReceiverInputDevices(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IMiracastReceiverKeyboardDevice :
    Windows::Foundation::IInspectable,
    impl::consume_t<IMiracastReceiverKeyboardDevice>
{
    IMiracastReceiverKeyboardDevice(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IMiracastReceiverMediaSourceCreatedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IMiracastReceiverMediaSourceCreatedEventArgs>
{
    IMiracastReceiverMediaSourceCreatedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IMiracastReceiverSession :
    Windows::Foundation::IInspectable,
    impl::consume_t<IMiracastReceiverSession>
{
    IMiracastReceiverSession(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IMiracastReceiverSessionStartResult :
    Windows::Foundation::IInspectable,
    impl::consume_t<IMiracastReceiverSessionStartResult>
{
    IMiracastReceiverSessionStartResult(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IMiracastReceiverSettings :
    Windows::Foundation::IInspectable,
    impl::consume_t<IMiracastReceiverSettings>
{
    IMiracastReceiverSettings(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IMiracastReceiverStatus :
    Windows::Foundation::IInspectable,
    impl::consume_t<IMiracastReceiverStatus>
{
    IMiracastReceiverStatus(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IMiracastReceiverStreamControl :
    Windows::Foundation::IInspectable,
    impl::consume_t<IMiracastReceiverStreamControl>
{
    IMiracastReceiverStreamControl(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IMiracastReceiverVideoStreamSettings :
    Windows::Foundation::IInspectable,
    impl::consume_t<IMiracastReceiverVideoStreamSettings>
{
    IMiracastReceiverVideoStreamSettings(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IMiracastTransmitter :
    Windows::Foundation::IInspectable,
    impl::consume_t<IMiracastTransmitter>
{
    IMiracastTransmitter(std::nullptr_t = nullptr) noexcept {}
};

}
