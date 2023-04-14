// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Graphics {

struct SizeInt32;

}

WINRT_EXPORT namespace winrt::Windows::Graphics::DirectX {

enum class DirectXPixelFormat;

}

WINRT_EXPORT namespace winrt::Windows::Graphics::DirectX::Direct3D11 {

struct IDirect3DDevice;
struct IDirect3DSurface;

}

WINRT_EXPORT namespace winrt::Windows::System {

struct DispatcherQueue;

}

WINRT_EXPORT namespace winrt::Windows::UI::Composition {

struct Visual;

}

WINRT_EXPORT namespace winrt::Windows::Graphics::Capture {

struct IDirect3D11CaptureFrame;
struct IDirect3D11CaptureFramePool;
struct IDirect3D11CaptureFramePoolStatics;
struct IDirect3D11CaptureFramePoolStatics2;
struct IGraphicsCaptureItem;
struct IGraphicsCaptureItemStatics;
struct IGraphicsCapturePicker;
struct IGraphicsCaptureSession;
struct IGraphicsCaptureSessionStatics;
struct Direct3D11CaptureFrame;
struct Direct3D11CaptureFramePool;
struct GraphicsCaptureItem;
struct GraphicsCapturePicker;
struct GraphicsCaptureSession;

}

namespace winrt::impl {

template <> struct category<Windows::Graphics::Capture::IDirect3D11CaptureFrame>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Capture::IDirect3D11CaptureFramePool>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Capture::IDirect3D11CaptureFramePoolStatics>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Capture::IDirect3D11CaptureFramePoolStatics2>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Capture::IGraphicsCaptureItem>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Capture::IGraphicsCaptureItemStatics>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Capture::IGraphicsCapturePicker>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Capture::IGraphicsCaptureSession>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Capture::IGraphicsCaptureSessionStatics>{ using type = interface_category; };
template <> struct category<Windows::Graphics::Capture::Direct3D11CaptureFrame>{ using type = class_category; };
template <> struct category<Windows::Graphics::Capture::Direct3D11CaptureFramePool>{ using type = class_category; };
template <> struct category<Windows::Graphics::Capture::GraphicsCaptureItem>{ using type = class_category; };
template <> struct category<Windows::Graphics::Capture::GraphicsCapturePicker>{ using type = class_category; };
template <> struct category<Windows::Graphics::Capture::GraphicsCaptureSession>{ using type = class_category; };
template <> struct name<Windows::Graphics::Capture::IDirect3D11CaptureFrame>{ static constexpr auto & value{ L"Windows.Graphics.Capture.IDirect3D11CaptureFrame" }; };
template <> struct name<Windows::Graphics::Capture::IDirect3D11CaptureFramePool>{ static constexpr auto & value{ L"Windows.Graphics.Capture.IDirect3D11CaptureFramePool" }; };
template <> struct name<Windows::Graphics::Capture::IDirect3D11CaptureFramePoolStatics>{ static constexpr auto & value{ L"Windows.Graphics.Capture.IDirect3D11CaptureFramePoolStatics" }; };
template <> struct name<Windows::Graphics::Capture::IDirect3D11CaptureFramePoolStatics2>{ static constexpr auto & value{ L"Windows.Graphics.Capture.IDirect3D11CaptureFramePoolStatics2" }; };
template <> struct name<Windows::Graphics::Capture::IGraphicsCaptureItem>{ static constexpr auto & value{ L"Windows.Graphics.Capture.IGraphicsCaptureItem" }; };
template <> struct name<Windows::Graphics::Capture::IGraphicsCaptureItemStatics>{ static constexpr auto & value{ L"Windows.Graphics.Capture.IGraphicsCaptureItemStatics" }; };
template <> struct name<Windows::Graphics::Capture::IGraphicsCapturePicker>{ static constexpr auto & value{ L"Windows.Graphics.Capture.IGraphicsCapturePicker" }; };
template <> struct name<Windows::Graphics::Capture::IGraphicsCaptureSession>{ static constexpr auto & value{ L"Windows.Graphics.Capture.IGraphicsCaptureSession" }; };
template <> struct name<Windows::Graphics::Capture::IGraphicsCaptureSessionStatics>{ static constexpr auto & value{ L"Windows.Graphics.Capture.IGraphicsCaptureSessionStatics" }; };
template <> struct name<Windows::Graphics::Capture::Direct3D11CaptureFrame>{ static constexpr auto & value{ L"Windows.Graphics.Capture.Direct3D11CaptureFrame" }; };
template <> struct name<Windows::Graphics::Capture::Direct3D11CaptureFramePool>{ static constexpr auto & value{ L"Windows.Graphics.Capture.Direct3D11CaptureFramePool" }; };
template <> struct name<Windows::Graphics::Capture::GraphicsCaptureItem>{ static constexpr auto & value{ L"Windows.Graphics.Capture.GraphicsCaptureItem" }; };
template <> struct name<Windows::Graphics::Capture::GraphicsCapturePicker>{ static constexpr auto & value{ L"Windows.Graphics.Capture.GraphicsCapturePicker" }; };
template <> struct name<Windows::Graphics::Capture::GraphicsCaptureSession>{ static constexpr auto & value{ L"Windows.Graphics.Capture.GraphicsCaptureSession" }; };
template <> struct guid_storage<Windows::Graphics::Capture::IDirect3D11CaptureFrame>{ static constexpr guid value{ 0xFA50C623,0x38DA,0x4B32,{ 0xAC,0xF3,0xFA,0x97,0x34,0xAD,0x80,0x0E } }; };
template <> struct guid_storage<Windows::Graphics::Capture::IDirect3D11CaptureFramePool>{ static constexpr guid value{ 0x24EB6D22,0x1975,0x422E,{ 0x82,0xE7,0x78,0x0D,0xBD,0x8D,0xDF,0x24 } }; };
template <> struct guid_storage<Windows::Graphics::Capture::IDirect3D11CaptureFramePoolStatics>{ static constexpr guid value{ 0x7784056A,0x67AA,0x4D53,{ 0xAE,0x54,0x10,0x88,0xD5,0xA8,0xCA,0x21 } }; };
template <> struct guid_storage<Windows::Graphics::Capture::IDirect3D11CaptureFramePoolStatics2>{ static constexpr guid value{ 0x589B103F,0x6BBC,0x5DF5,{ 0xA9,0x91,0x02,0xE2,0x8B,0x3B,0x66,0xD5 } }; };
template <> struct guid_storage<Windows::Graphics::Capture::IGraphicsCaptureItem>{ static constexpr guid value{ 0x79C3F95B,0x31F7,0x4EC2,{ 0xA4,0x64,0x63,0x2E,0xF5,0xD3,0x07,0x60 } }; };
template <> struct guid_storage<Windows::Graphics::Capture::IGraphicsCaptureItemStatics>{ static constexpr guid value{ 0xA87EBEA5,0x457C,0x5788,{ 0xAB,0x47,0x0C,0xF1,0xD3,0x63,0x7E,0x74 } }; };
template <> struct guid_storage<Windows::Graphics::Capture::IGraphicsCapturePicker>{ static constexpr guid value{ 0x5A1711B3,0xAD79,0x4B4A,{ 0x93,0x36,0x13,0x18,0xFD,0xDE,0x35,0x39 } }; };
template <> struct guid_storage<Windows::Graphics::Capture::IGraphicsCaptureSession>{ static constexpr guid value{ 0x814E42A9,0xF70F,0x4AD7,{ 0x93,0x9B,0xFD,0xDC,0xC6,0xEB,0x88,0x0D } }; };
template <> struct guid_storage<Windows::Graphics::Capture::IGraphicsCaptureSessionStatics>{ static constexpr guid value{ 0x2224A540,0x5974,0x49AA,{ 0xB2,0x32,0x08,0x82,0x53,0x6F,0x4C,0xB5 } }; };
template <> struct default_interface<Windows::Graphics::Capture::Direct3D11CaptureFrame>{ using type = Windows::Graphics::Capture::IDirect3D11CaptureFrame; };
template <> struct default_interface<Windows::Graphics::Capture::Direct3D11CaptureFramePool>{ using type = Windows::Graphics::Capture::IDirect3D11CaptureFramePool; };
template <> struct default_interface<Windows::Graphics::Capture::GraphicsCaptureItem>{ using type = Windows::Graphics::Capture::IGraphicsCaptureItem; };
template <> struct default_interface<Windows::Graphics::Capture::GraphicsCapturePicker>{ using type = Windows::Graphics::Capture::IGraphicsCapturePicker; };
template <> struct default_interface<Windows::Graphics::Capture::GraphicsCaptureSession>{ using type = Windows::Graphics::Capture::IGraphicsCaptureSession; };

template <> struct abi<Windows::Graphics::Capture::IDirect3D11CaptureFrame>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Surface(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SystemRelativeTime(Windows::Foundation::TimeSpan* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ContentSize(struct struct_Windows_Graphics_SizeInt32* value) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Capture::IDirect3D11CaptureFramePool>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Recreate(void* device, Windows::Graphics::DirectX::DirectXPixelFormat pixelFormat, int32_t numberOfBuffers, struct struct_Windows_Graphics_SizeInt32 size) noexcept = 0;
    virtual int32_t WINRT_CALL TryGetNextFrame(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL add_FrameArrived(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_FrameArrived(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL CreateCaptureSession(void* item, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL get_DispatcherQueue(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Capture::IDirect3D11CaptureFramePoolStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Create(void* device, Windows::Graphics::DirectX::DirectXPixelFormat pixelFormat, int32_t numberOfBuffers, struct struct_Windows_Graphics_SizeInt32 size, void** result) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Capture::IDirect3D11CaptureFramePoolStatics2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateFreeThreaded(void* device, Windows::Graphics::DirectX::DirectXPixelFormat pixelFormat, int32_t numberOfBuffers, struct struct_Windows_Graphics_SizeInt32 size, void** result) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Capture::IGraphicsCaptureItem>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_DisplayName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Size(struct struct_Windows_Graphics_SizeInt32* value) noexcept = 0;
    virtual int32_t WINRT_CALL add_Closed(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_Closed(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Capture::IGraphicsCaptureItemStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateFromVisual(void* visual, void** result) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Capture::IGraphicsCapturePicker>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL PickSingleItemAsync(void** operation) noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Capture::IGraphicsCaptureSession>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL StartCapture() noexcept = 0;
};};

template <> struct abi<Windows::Graphics::Capture::IGraphicsCaptureSessionStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL IsSupported(bool* result) noexcept = 0;
};};

template <typename D>
struct consume_Windows_Graphics_Capture_IDirect3D11CaptureFrame
{
    Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface Surface() const;
    Windows::Foundation::TimeSpan SystemRelativeTime() const;
    Windows::Graphics::SizeInt32 ContentSize() const;
};
template <> struct consume<Windows::Graphics::Capture::IDirect3D11CaptureFrame> { template <typename D> using type = consume_Windows_Graphics_Capture_IDirect3D11CaptureFrame<D>; };

template <typename D>
struct consume_Windows_Graphics_Capture_IDirect3D11CaptureFramePool
{
    void Recreate(Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice const& device, Windows::Graphics::DirectX::DirectXPixelFormat const& pixelFormat, int32_t numberOfBuffers, Windows::Graphics::SizeInt32 const& size) const;
    Windows::Graphics::Capture::Direct3D11CaptureFrame TryGetNextFrame() const;
    winrt::event_token FrameArrived(Windows::Foundation::TypedEventHandler<Windows::Graphics::Capture::Direct3D11CaptureFramePool, Windows::Foundation::IInspectable> const& handler) const;
    using FrameArrived_revoker = impl::event_revoker<Windows::Graphics::Capture::IDirect3D11CaptureFramePool, &impl::abi_t<Windows::Graphics::Capture::IDirect3D11CaptureFramePool>::remove_FrameArrived>;
    FrameArrived_revoker FrameArrived(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Graphics::Capture::Direct3D11CaptureFramePool, Windows::Foundation::IInspectable> const& handler) const;
    void FrameArrived(winrt::event_token const& token) const noexcept;
    Windows::Graphics::Capture::GraphicsCaptureSession CreateCaptureSession(Windows::Graphics::Capture::GraphicsCaptureItem const& item) const;
    Windows::System::DispatcherQueue DispatcherQueue() const;
};
template <> struct consume<Windows::Graphics::Capture::IDirect3D11CaptureFramePool> { template <typename D> using type = consume_Windows_Graphics_Capture_IDirect3D11CaptureFramePool<D>; };

template <typename D>
struct consume_Windows_Graphics_Capture_IDirect3D11CaptureFramePoolStatics
{
    Windows::Graphics::Capture::Direct3D11CaptureFramePool Create(Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice const& device, Windows::Graphics::DirectX::DirectXPixelFormat const& pixelFormat, int32_t numberOfBuffers, Windows::Graphics::SizeInt32 const& size) const;
};
template <> struct consume<Windows::Graphics::Capture::IDirect3D11CaptureFramePoolStatics> { template <typename D> using type = consume_Windows_Graphics_Capture_IDirect3D11CaptureFramePoolStatics<D>; };

template <typename D>
struct consume_Windows_Graphics_Capture_IDirect3D11CaptureFramePoolStatics2
{
    Windows::Graphics::Capture::Direct3D11CaptureFramePool CreateFreeThreaded(Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice const& device, Windows::Graphics::DirectX::DirectXPixelFormat const& pixelFormat, int32_t numberOfBuffers, Windows::Graphics::SizeInt32 const& size) const;
};
template <> struct consume<Windows::Graphics::Capture::IDirect3D11CaptureFramePoolStatics2> { template <typename D> using type = consume_Windows_Graphics_Capture_IDirect3D11CaptureFramePoolStatics2<D>; };

template <typename D>
struct consume_Windows_Graphics_Capture_IGraphicsCaptureItem
{
    hstring DisplayName() const;
    Windows::Graphics::SizeInt32 Size() const;
    winrt::event_token Closed(Windows::Foundation::TypedEventHandler<Windows::Graphics::Capture::GraphicsCaptureItem, Windows::Foundation::IInspectable> const& handler) const;
    using Closed_revoker = impl::event_revoker<Windows::Graphics::Capture::IGraphicsCaptureItem, &impl::abi_t<Windows::Graphics::Capture::IGraphicsCaptureItem>::remove_Closed>;
    Closed_revoker Closed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Graphics::Capture::GraphicsCaptureItem, Windows::Foundation::IInspectable> const& handler) const;
    void Closed(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::Graphics::Capture::IGraphicsCaptureItem> { template <typename D> using type = consume_Windows_Graphics_Capture_IGraphicsCaptureItem<D>; };

template <typename D>
struct consume_Windows_Graphics_Capture_IGraphicsCaptureItemStatics
{
    Windows::Graphics::Capture::GraphicsCaptureItem CreateFromVisual(Windows::UI::Composition::Visual const& visual) const;
};
template <> struct consume<Windows::Graphics::Capture::IGraphicsCaptureItemStatics> { template <typename D> using type = consume_Windows_Graphics_Capture_IGraphicsCaptureItemStatics<D>; };

template <typename D>
struct consume_Windows_Graphics_Capture_IGraphicsCapturePicker
{
    Windows::Foundation::IAsyncOperation<Windows::Graphics::Capture::GraphicsCaptureItem> PickSingleItemAsync() const;
};
template <> struct consume<Windows::Graphics::Capture::IGraphicsCapturePicker> { template <typename D> using type = consume_Windows_Graphics_Capture_IGraphicsCapturePicker<D>; };

template <typename D>
struct consume_Windows_Graphics_Capture_IGraphicsCaptureSession
{
    void StartCapture() const;
};
template <> struct consume<Windows::Graphics::Capture::IGraphicsCaptureSession> { template <typename D> using type = consume_Windows_Graphics_Capture_IGraphicsCaptureSession<D>; };

template <typename D>
struct consume_Windows_Graphics_Capture_IGraphicsCaptureSessionStatics
{
    bool IsSupported() const;
};
template <> struct consume<Windows::Graphics::Capture::IGraphicsCaptureSessionStatics> { template <typename D> using type = consume_Windows_Graphics_Capture_IGraphicsCaptureSessionStatics<D>; };

}
