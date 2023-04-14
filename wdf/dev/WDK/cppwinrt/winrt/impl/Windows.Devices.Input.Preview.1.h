// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Devices.HumanInterfaceDevice.0.h"
#include "winrt/impl/Windows.Devices.Input.Preview.0.h"

WINRT_EXPORT namespace winrt::Windows::Devices::Input::Preview {

struct WINRT_EBO IGazeDevicePreview :
    Windows::Foundation::IInspectable,
    impl::consume_t<IGazeDevicePreview>
{
    IGazeDevicePreview(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IGazeDeviceWatcherAddedPreviewEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IGazeDeviceWatcherAddedPreviewEventArgs>
{
    IGazeDeviceWatcherAddedPreviewEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IGazeDeviceWatcherPreview :
    Windows::Foundation::IInspectable,
    impl::consume_t<IGazeDeviceWatcherPreview>
{
    IGazeDeviceWatcherPreview(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IGazeDeviceWatcherRemovedPreviewEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IGazeDeviceWatcherRemovedPreviewEventArgs>
{
    IGazeDeviceWatcherRemovedPreviewEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IGazeDeviceWatcherUpdatedPreviewEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IGazeDeviceWatcherUpdatedPreviewEventArgs>
{
    IGazeDeviceWatcherUpdatedPreviewEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IGazeEnteredPreviewEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IGazeEnteredPreviewEventArgs>
{
    IGazeEnteredPreviewEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IGazeExitedPreviewEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IGazeExitedPreviewEventArgs>
{
    IGazeExitedPreviewEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IGazeInputSourcePreview :
    Windows::Foundation::IInspectable,
    impl::consume_t<IGazeInputSourcePreview>
{
    IGazeInputSourcePreview(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IGazeInputSourcePreviewStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IGazeInputSourcePreviewStatics>
{
    IGazeInputSourcePreviewStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IGazeMovedPreviewEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IGazeMovedPreviewEventArgs>
{
    IGazeMovedPreviewEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IGazePointPreview :
    Windows::Foundation::IInspectable,
    impl::consume_t<IGazePointPreview>
{
    IGazePointPreview(std::nullptr_t = nullptr) noexcept {}
};

}
