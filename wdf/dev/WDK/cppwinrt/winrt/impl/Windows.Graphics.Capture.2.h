// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Graphics.1.h"
#include "winrt/impl/Windows.Graphics.DirectX.1.h"
#include "winrt/impl/Windows.Graphics.DirectX.Direct3D11.1.h"
#include "winrt/impl/Windows.System.1.h"
#include "winrt/impl/Windows.UI.Composition.1.h"
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.Graphics.Capture.1.h"

WINRT_EXPORT namespace winrt::Windows::Graphics::Capture {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::Graphics::Capture {

struct WINRT_EBO Direct3D11CaptureFrame :
    Windows::Graphics::Capture::IDirect3D11CaptureFrame,
    impl::require<Direct3D11CaptureFrame, Windows::Foundation::IClosable>
{
    Direct3D11CaptureFrame(std::nullptr_t) noexcept {}
};

struct WINRT_EBO Direct3D11CaptureFramePool :
    Windows::Graphics::Capture::IDirect3D11CaptureFramePool,
    impl::require<Direct3D11CaptureFramePool, Windows::Foundation::IClosable>
{
    Direct3D11CaptureFramePool(std::nullptr_t) noexcept {}
    static Windows::Graphics::Capture::Direct3D11CaptureFramePool Create(Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice const& device, Windows::Graphics::DirectX::DirectXPixelFormat const& pixelFormat, int32_t numberOfBuffers, Windows::Graphics::SizeInt32 const& size);
    static Windows::Graphics::Capture::Direct3D11CaptureFramePool CreateFreeThreaded(Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice const& device, Windows::Graphics::DirectX::DirectXPixelFormat const& pixelFormat, int32_t numberOfBuffers, Windows::Graphics::SizeInt32 const& size);
};

struct WINRT_EBO GraphicsCaptureItem :
    Windows::Graphics::Capture::IGraphicsCaptureItem
{
    GraphicsCaptureItem(std::nullptr_t) noexcept {}
    static Windows::Graphics::Capture::GraphicsCaptureItem CreateFromVisual(Windows::UI::Composition::Visual const& visual);
};

struct WINRT_EBO GraphicsCapturePicker :
    Windows::Graphics::Capture::IGraphicsCapturePicker
{
    GraphicsCapturePicker(std::nullptr_t) noexcept {}
    GraphicsCapturePicker();
};

struct WINRT_EBO GraphicsCaptureSession :
    Windows::Graphics::Capture::IGraphicsCaptureSession,
    impl::require<GraphicsCaptureSession, Windows::Foundation::IClosable>
{
    GraphicsCaptureSession(std::nullptr_t) noexcept {}
    static bool IsSupported();
};

}
