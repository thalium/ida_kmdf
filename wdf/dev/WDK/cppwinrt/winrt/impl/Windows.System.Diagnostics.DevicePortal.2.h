// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.ApplicationModel.AppService.1.h"
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.Networking.Sockets.1.h"
#include "winrt/impl/Windows.Web.Http.1.h"
#include "winrt/impl/Windows.System.Diagnostics.DevicePortal.1.h"

WINRT_EXPORT namespace winrt::Windows::System::Diagnostics::DevicePortal {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::System::Diagnostics::DevicePortal {

struct WINRT_EBO DevicePortalConnection :
    Windows::System::Diagnostics::DevicePortal::IDevicePortalConnection,
    impl::require<DevicePortalConnection, Windows::System::Diagnostics::DevicePortal::IDevicePortalWebSocketConnection>
{
    DevicePortalConnection(std::nullptr_t) noexcept {}
    static Windows::System::Diagnostics::DevicePortal::DevicePortalConnection GetForAppServiceConnection(Windows::ApplicationModel::AppService::AppServiceConnection const& appServiceConnection);
};

struct WINRT_EBO DevicePortalConnectionClosedEventArgs :
    Windows::System::Diagnostics::DevicePortal::IDevicePortalConnectionClosedEventArgs
{
    DevicePortalConnectionClosedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO DevicePortalConnectionRequestReceivedEventArgs :
    Windows::System::Diagnostics::DevicePortal::IDevicePortalConnectionRequestReceivedEventArgs,
    impl::require<DevicePortalConnectionRequestReceivedEventArgs, Windows::System::Diagnostics::DevicePortal::IDevicePortalWebSocketConnectionRequestReceivedEventArgs>
{
    DevicePortalConnectionRequestReceivedEventArgs(std::nullptr_t) noexcept {}
};

}
