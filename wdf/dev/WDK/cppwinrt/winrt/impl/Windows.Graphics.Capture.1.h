// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Graphics.0.h"
#include "winrt/impl/Windows.Graphics.DirectX.0.h"
#include "winrt/impl/Windows.Graphics.DirectX.Direct3D11.0.h"
#include "winrt/impl/Windows.System.0.h"
#include "winrt/impl/Windows.UI.Composition.0.h"
#include "winrt/impl/Windows.Foundation.0.h"
#include "winrt/impl/Windows.Graphics.Capture.0.h"

WINRT_EXPORT namespace winrt::Windows::Graphics::Capture {

struct WINRT_EBO IDirect3D11CaptureFrame :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDirect3D11CaptureFrame>
{
    IDirect3D11CaptureFrame(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IDirect3D11CaptureFramePool :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDirect3D11CaptureFramePool>
{
    IDirect3D11CaptureFramePool(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IDirect3D11CaptureFramePoolStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDirect3D11CaptureFramePoolStatics>
{
    IDirect3D11CaptureFramePoolStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IDirect3D11CaptureFramePoolStatics2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IDirect3D11CaptureFramePoolStatics2>
{
    IDirect3D11CaptureFramePoolStatics2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IGraphicsCaptureItem :
    Windows::Foundation::IInspectable,
    impl::consume_t<IGraphicsCaptureItem>
{
    IGraphicsCaptureItem(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IGraphicsCaptureItemStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IGraphicsCaptureItemStatics>
{
    IGraphicsCaptureItemStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IGraphicsCapturePicker :
    Windows::Foundation::IInspectable,
    impl::consume_t<IGraphicsCapturePicker>
{
    IGraphicsCapturePicker(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IGraphicsCaptureSession :
    Windows::Foundation::IInspectable,
    impl::consume_t<IGraphicsCaptureSession>
{
    IGraphicsCaptureSession(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IGraphicsCaptureSessionStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IGraphicsCaptureSessionStatics>
{
    IGraphicsCaptureSessionStatics(std::nullptr_t = nullptr) noexcept {}
};

}
