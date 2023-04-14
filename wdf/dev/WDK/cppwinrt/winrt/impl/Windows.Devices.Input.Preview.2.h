// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Devices.HumanInterfaceDevice.1.h"
#include "winrt/impl/Windows.Devices.Input.Preview.1.h"

WINRT_EXPORT namespace winrt::Windows::Devices::Input::Preview {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::Devices::Input::Preview {

struct WINRT_EBO GazeDevicePreview :
    Windows::Devices::Input::Preview::IGazeDevicePreview
{
    GazeDevicePreview(std::nullptr_t) noexcept {}
};

struct WINRT_EBO GazeDeviceWatcherAddedPreviewEventArgs :
    Windows::Devices::Input::Preview::IGazeDeviceWatcherAddedPreviewEventArgs
{
    GazeDeviceWatcherAddedPreviewEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO GazeDeviceWatcherPreview :
    Windows::Devices::Input::Preview::IGazeDeviceWatcherPreview
{
    GazeDeviceWatcherPreview(std::nullptr_t) noexcept {}
};

struct WINRT_EBO GazeDeviceWatcherRemovedPreviewEventArgs :
    Windows::Devices::Input::Preview::IGazeDeviceWatcherRemovedPreviewEventArgs
{
    GazeDeviceWatcherRemovedPreviewEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO GazeDeviceWatcherUpdatedPreviewEventArgs :
    Windows::Devices::Input::Preview::IGazeDeviceWatcherUpdatedPreviewEventArgs
{
    GazeDeviceWatcherUpdatedPreviewEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO GazeEnteredPreviewEventArgs :
    Windows::Devices::Input::Preview::IGazeEnteredPreviewEventArgs
{
    GazeEnteredPreviewEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO GazeExitedPreviewEventArgs :
    Windows::Devices::Input::Preview::IGazeExitedPreviewEventArgs
{
    GazeExitedPreviewEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO GazeInputSourcePreview :
    Windows::Devices::Input::Preview::IGazeInputSourcePreview
{
    GazeInputSourcePreview(std::nullptr_t) noexcept {}
    static Windows::Devices::Input::Preview::GazeInputSourcePreview GetForCurrentView();
    static Windows::Devices::Input::Preview::GazeDeviceWatcherPreview CreateWatcher();
};

struct WINRT_EBO GazeMovedPreviewEventArgs :
    Windows::Devices::Input::Preview::IGazeMovedPreviewEventArgs
{
    GazeMovedPreviewEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO GazePointPreview :
    Windows::Devices::Input::Preview::IGazePointPreview
{
    GazePointPreview(std::nullptr_t) noexcept {}
};

}
