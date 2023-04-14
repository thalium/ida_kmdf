// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Devices.Display.0.h"
#include "winrt/impl/Windows.Foundation.0.h"
#include "winrt/impl/Windows.Foundation.Numerics.0.h"
#include "winrt/impl/Windows.Graphics.0.h"
#include "winrt/impl/Windows.Graphics.DirectX.0.h"
#include "winrt/impl/Windows.Graphics.DirectX.Direct3D11.0.h"
#include "winrt/impl/Windows.Storage.Streams.0.h"
#include "winrt/impl/Windows.Devices.Display.Core.0.h"

WINRT_EXPORT namespace winrt::Windows::Devices::Display::Core {

struct WINRT_EBO IDisplayAdapter :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDisplayAdapter>
{
    IDisplayAdapter(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IDisplayAdapterStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDisplayAdapterStatics>
{
    IDisplayAdapterStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IDisplayDevice :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDisplayDevice>
{
    IDisplayDevice(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IDisplayFence :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDisplayFence>
{
    IDisplayFence(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IDisplayManager :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDisplayManager>
{
    IDisplayManager(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IDisplayManagerChangedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDisplayManagerChangedEventArgs>
{
    IDisplayManagerChangedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IDisplayManagerDisabledEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDisplayManagerDisabledEventArgs>
{
    IDisplayManagerDisabledEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IDisplayManagerEnabledEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDisplayManagerEnabledEventArgs>
{
    IDisplayManagerEnabledEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IDisplayManagerPathsFailedOrInvalidatedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDisplayManagerPathsFailedOrInvalidatedEventArgs>
{
    IDisplayManagerPathsFailedOrInvalidatedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IDisplayManagerResultWithState :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDisplayManagerResultWithState>
{
    IDisplayManagerResultWithState(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IDisplayManagerStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDisplayManagerStatics>
{
    IDisplayManagerStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IDisplayModeInfo :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDisplayModeInfo>
{
    IDisplayModeInfo(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IDisplayPath :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDisplayPath>
{
    IDisplayPath(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IDisplayPrimaryDescription :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDisplayPrimaryDescription>
{
    IDisplayPrimaryDescription(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IDisplayPrimaryDescriptionFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDisplayPrimaryDescriptionFactory>
{
    IDisplayPrimaryDescriptionFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IDisplayPrimaryDescriptionStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDisplayPrimaryDescriptionStatics>
{
    IDisplayPrimaryDescriptionStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IDisplayScanout :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDisplayScanout>
{
    IDisplayScanout(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IDisplaySource :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDisplaySource>
{
    IDisplaySource(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IDisplayState :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDisplayState>
{
    IDisplayState(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IDisplayStateOperationResult :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDisplayStateOperationResult>
{
    IDisplayStateOperationResult(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IDisplaySurface :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDisplaySurface>
{
    IDisplaySurface(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IDisplayTarget :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDisplayTarget>
{
    IDisplayTarget(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IDisplayTask :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDisplayTask>
{
    IDisplayTask(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IDisplayTaskPool :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDisplayTaskPool>
{
    IDisplayTaskPool(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IDisplayView :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDisplayView>
{
    IDisplayView(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IDisplayWireFormat :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDisplayWireFormat>
{
    IDisplayWireFormat(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IDisplayWireFormatFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDisplayWireFormatFactory>
{
    IDisplayWireFormatFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IDisplayWireFormatStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDisplayWireFormatStatics>
{
    IDisplayWireFormatStatics(std::nullptr_t = nullptr) noexcept {}
};

}
