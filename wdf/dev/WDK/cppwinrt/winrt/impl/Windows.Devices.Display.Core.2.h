// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Devices.Display.1.h"
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.Foundation.Numerics.1.h"
#include "winrt/impl/Windows.Graphics.1.h"
#include "winrt/impl/Windows.Graphics.DirectX.1.h"
#include "winrt/impl/Windows.Graphics.DirectX.Direct3D11.1.h"
#include "winrt/impl/Windows.Storage.Streams.1.h"
#include "winrt/impl/Windows.Devices.Display.Core.1.h"
#include "winrt/impl/Windows.Foundation.Numerics.2.h"

WINRT_EXPORT namespace winrt::Windows::Devices::Display::Core {

struct DisplayPresentationRate
{
    Windows::Foundation::Numerics::Rational VerticalSyncRate;
    int32_t VerticalSyncsPerPresentation;
};

inline bool operator==(DisplayPresentationRate const& left, DisplayPresentationRate const& right) noexcept
{
    return left.VerticalSyncRate == right.VerticalSyncRate && left.VerticalSyncsPerPresentation == right.VerticalSyncsPerPresentation;
}

inline bool operator!=(DisplayPresentationRate const& left, DisplayPresentationRate const& right) noexcept
{
    return !(left == right);
}

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::Devices::Display::Core {

struct WINRT_EBO DisplayAdapter :
    Windows::Devices::Display::Core::IDisplayAdapter
{
    DisplayAdapter(std::nullptr_t) noexcept {}
    static Windows::Devices::Display::Core::DisplayAdapter FromId(Windows::Graphics::DisplayAdapterId const& id);
};

struct WINRT_EBO DisplayDevice :
    Windows::Devices::Display::Core::IDisplayDevice
{
    DisplayDevice(std::nullptr_t) noexcept {}
};

struct WINRT_EBO DisplayFence :
    Windows::Devices::Display::Core::IDisplayFence
{
    DisplayFence(std::nullptr_t) noexcept {}
};

struct WINRT_EBO DisplayManager :
    Windows::Devices::Display::Core::IDisplayManager,
    impl::require<DisplayManager, Windows::Foundation::IClosable>
{
    DisplayManager(std::nullptr_t) noexcept {}
    static Windows::Devices::Display::Core::DisplayManager Create(Windows::Devices::Display::Core::DisplayManagerOptions const& options);
};

struct WINRT_EBO DisplayManagerChangedEventArgs :
    Windows::Devices::Display::Core::IDisplayManagerChangedEventArgs
{
    DisplayManagerChangedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO DisplayManagerDisabledEventArgs :
    Windows::Devices::Display::Core::IDisplayManagerDisabledEventArgs
{
    DisplayManagerDisabledEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO DisplayManagerEnabledEventArgs :
    Windows::Devices::Display::Core::IDisplayManagerEnabledEventArgs
{
    DisplayManagerEnabledEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO DisplayManagerPathsFailedOrInvalidatedEventArgs :
    Windows::Devices::Display::Core::IDisplayManagerPathsFailedOrInvalidatedEventArgs
{
    DisplayManagerPathsFailedOrInvalidatedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO DisplayManagerResultWithState :
    Windows::Devices::Display::Core::IDisplayManagerResultWithState
{
    DisplayManagerResultWithState(std::nullptr_t) noexcept {}
};

struct WINRT_EBO DisplayModeInfo :
    Windows::Devices::Display::Core::IDisplayModeInfo
{
    DisplayModeInfo(std::nullptr_t) noexcept {}
};

struct WINRT_EBO DisplayPath :
    Windows::Devices::Display::Core::IDisplayPath
{
    DisplayPath(std::nullptr_t) noexcept {}
};

struct WINRT_EBO DisplayPrimaryDescription :
    Windows::Devices::Display::Core::IDisplayPrimaryDescription
{
    DisplayPrimaryDescription(std::nullptr_t) noexcept {}
    DisplayPrimaryDescription(uint32_t width, uint32_t height, Windows::Graphics::DirectX::DirectXPixelFormat const& pixelFormat, Windows::Graphics::DirectX::DirectXColorSpace const& colorSpace, bool isStereo, Windows::Graphics::DirectX::Direct3D11::Direct3DMultisampleDescription const& multisampleDescription);
    static Windows::Devices::Display::Core::DisplayPrimaryDescription CreateWithProperties(param::iterable<Windows::Foundation::Collections::IKeyValuePair<winrt::guid, Windows::Foundation::IInspectable>> const& extraProperties, uint32_t width, uint32_t height, Windows::Graphics::DirectX::DirectXPixelFormat const& pixelFormat, Windows::Graphics::DirectX::DirectXColorSpace const& colorSpace, bool isStereo, Windows::Graphics::DirectX::Direct3D11::Direct3DMultisampleDescription const& multisampleDescription);
};

struct WINRT_EBO DisplayScanout :
    Windows::Devices::Display::Core::IDisplayScanout
{
    DisplayScanout(std::nullptr_t) noexcept {}
};

struct WINRT_EBO DisplaySource :
    Windows::Devices::Display::Core::IDisplaySource
{
    DisplaySource(std::nullptr_t) noexcept {}
};

struct WINRT_EBO DisplayState :
    Windows::Devices::Display::Core::IDisplayState
{
    DisplayState(std::nullptr_t) noexcept {}
};

struct WINRT_EBO DisplayStateOperationResult :
    Windows::Devices::Display::Core::IDisplayStateOperationResult
{
    DisplayStateOperationResult(std::nullptr_t) noexcept {}
};

struct WINRT_EBO DisplaySurface :
    Windows::Devices::Display::Core::IDisplaySurface
{
    DisplaySurface(std::nullptr_t) noexcept {}
};

struct WINRT_EBO DisplayTarget :
    Windows::Devices::Display::Core::IDisplayTarget
{
    DisplayTarget(std::nullptr_t) noexcept {}
};

struct WINRT_EBO DisplayTask :
    Windows::Devices::Display::Core::IDisplayTask
{
    DisplayTask(std::nullptr_t) noexcept {}
};

struct WINRT_EBO DisplayTaskPool :
    Windows::Devices::Display::Core::IDisplayTaskPool
{
    DisplayTaskPool(std::nullptr_t) noexcept {}
};

struct WINRT_EBO DisplayView :
    Windows::Devices::Display::Core::IDisplayView
{
    DisplayView(std::nullptr_t) noexcept {}
};

struct WINRT_EBO DisplayWireFormat :
    Windows::Devices::Display::Core::IDisplayWireFormat
{
    DisplayWireFormat(std::nullptr_t) noexcept {}
    DisplayWireFormat(Windows::Devices::Display::Core::DisplayWireFormatPixelEncoding const& pixelEncoding, int32_t bitsPerChannel, Windows::Devices::Display::Core::DisplayWireFormatColorSpace const& colorSpace, Windows::Devices::Display::Core::DisplayWireFormatEotf const& eotf, Windows::Devices::Display::Core::DisplayWireFormatHdrMetadata const& hdrMetadata);
    static Windows::Devices::Display::Core::DisplayWireFormat CreateWithProperties(param::iterable<Windows::Foundation::Collections::IKeyValuePair<winrt::guid, Windows::Foundation::IInspectable>> const& extraProperties, Windows::Devices::Display::Core::DisplayWireFormatPixelEncoding const& pixelEncoding, int32_t bitsPerChannel, Windows::Devices::Display::Core::DisplayWireFormatColorSpace const& colorSpace, Windows::Devices::Display::Core::DisplayWireFormatEotf const& eotf, Windows::Devices::Display::Core::DisplayWireFormatHdrMetadata const& hdrMetadata);
};

}
