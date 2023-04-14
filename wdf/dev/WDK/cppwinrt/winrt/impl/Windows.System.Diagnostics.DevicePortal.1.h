// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.ApplicationModel.AppService.0.h"
#include "winrt/impl/Windows.Foundation.0.h"
#include "winrt/impl/Windows.Networking.Sockets.0.h"
#include "winrt/impl/Windows.Web.Http.0.h"
#include "winrt/impl/Windows.System.Diagnostics.DevicePortal.0.h"

WINRT_EXPORT namespace winrt::Windows::System::Diagnostics::DevicePortal {

struct WINRT_EBO IDevicePortalConnection :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDevicePortalConnection>
{
    IDevicePortalConnection(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IDevicePortalConnectionClosedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDevicePortalConnectionClosedEventArgs>
{
    IDevicePortalConnectionClosedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IDevicePortalConnectionRequestReceivedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDevicePortalConnectionRequestReceivedEventArgs>
{
    IDevicePortalConnectionRequestReceivedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IDevicePortalConnectionStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDevicePortalConnectionStatics>
{
    IDevicePortalConnectionStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IDevicePortalWebSocketConnection :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDevicePortalWebSocketConnection>
{
    IDevicePortalWebSocketConnection(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IDevicePortalWebSocketConnectionRequestReceivedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDevicePortalWebSocketConnectionRequestReceivedEventArgs>
{
    IDevicePortalWebSocketConnectionRequestReceivedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

}
