// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Graphics.2.h"
#include "winrt/impl/Windows.Graphics.DirectX.2.h"
#include "winrt/impl/Windows.Graphics.DirectX.Direct3D11.2.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.UI.Composition.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Graphics.Capture.2.h"
#include "winrt/Windows.Graphics.h"

namespace winrt::impl {

template <typename D> Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface consume_Windows_Graphics_Capture_IDirect3D11CaptureFrame<D>::Surface() const
{
    Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Capture::IDirect3D11CaptureFrame)->get_Surface(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Graphics_Capture_IDirect3D11CaptureFrame<D>::SystemRelativeTime() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Capture::IDirect3D11CaptureFrame)->get_SystemRelativeTime(put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::SizeInt32 consume_Windows_Graphics_Capture_IDirect3D11CaptureFrame<D>::ContentSize() const
{
    Windows::Graphics::SizeInt32 value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Capture::IDirect3D11CaptureFrame)->get_ContentSize(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Capture_IDirect3D11CaptureFramePool<D>::Recreate(Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice const& device, Windows::Graphics::DirectX::DirectXPixelFormat const& pixelFormat, int32_t numberOfBuffers, Windows::Graphics::SizeInt32 const& size) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Capture::IDirect3D11CaptureFramePool)->Recreate(get_abi(device), get_abi(pixelFormat), numberOfBuffers, get_abi(size)));
}

template <typename D> Windows::Graphics::Capture::Direct3D11CaptureFrame consume_Windows_Graphics_Capture_IDirect3D11CaptureFramePool<D>::TryGetNextFrame() const
{
    Windows::Graphics::Capture::Direct3D11CaptureFrame result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Capture::IDirect3D11CaptureFramePool)->TryGetNextFrame(put_abi(result)));
    return result;
}

template <typename D> winrt::event_token consume_Windows_Graphics_Capture_IDirect3D11CaptureFramePool<D>::FrameArrived(Windows::Foundation::TypedEventHandler<Windows::Graphics::Capture::Direct3D11CaptureFramePool, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Capture::IDirect3D11CaptureFramePool)->add_FrameArrived(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Graphics_Capture_IDirect3D11CaptureFramePool<D>::FrameArrived_revoker consume_Windows_Graphics_Capture_IDirect3D11CaptureFramePool<D>::FrameArrived(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Graphics::Capture::Direct3D11CaptureFramePool, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, FrameArrived_revoker>(this, FrameArrived(handler));
}

template <typename D> void consume_Windows_Graphics_Capture_IDirect3D11CaptureFramePool<D>::FrameArrived(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Graphics::Capture::IDirect3D11CaptureFramePool)->remove_FrameArrived(get_abi(token)));
}

template <typename D> Windows::Graphics::Capture::GraphicsCaptureSession consume_Windows_Graphics_Capture_IDirect3D11CaptureFramePool<D>::CreateCaptureSession(Windows::Graphics::Capture::GraphicsCaptureItem const& item) const
{
    Windows::Graphics::Capture::GraphicsCaptureSession result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Capture::IDirect3D11CaptureFramePool)->CreateCaptureSession(get_abi(item), put_abi(result)));
    return result;
}

template <typename D> Windows::System::DispatcherQueue consume_Windows_Graphics_Capture_IDirect3D11CaptureFramePool<D>::DispatcherQueue() const
{
    Windows::System::DispatcherQueue value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Capture::IDirect3D11CaptureFramePool)->get_DispatcherQueue(put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::Capture::Direct3D11CaptureFramePool consume_Windows_Graphics_Capture_IDirect3D11CaptureFramePoolStatics<D>::Create(Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice const& device, Windows::Graphics::DirectX::DirectXPixelFormat const& pixelFormat, int32_t numberOfBuffers, Windows::Graphics::SizeInt32 const& size) const
{
    Windows::Graphics::Capture::Direct3D11CaptureFramePool result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Capture::IDirect3D11CaptureFramePoolStatics)->Create(get_abi(device), get_abi(pixelFormat), numberOfBuffers, get_abi(size), put_abi(result)));
    return result;
}

template <typename D> Windows::Graphics::Capture::Direct3D11CaptureFramePool consume_Windows_Graphics_Capture_IDirect3D11CaptureFramePoolStatics2<D>::CreateFreeThreaded(Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice const& device, Windows::Graphics::DirectX::DirectXPixelFormat const& pixelFormat, int32_t numberOfBuffers, Windows::Graphics::SizeInt32 const& size) const
{
    Windows::Graphics::Capture::Direct3D11CaptureFramePool result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Capture::IDirect3D11CaptureFramePoolStatics2)->CreateFreeThreaded(get_abi(device), get_abi(pixelFormat), numberOfBuffers, get_abi(size), put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Graphics_Capture_IGraphicsCaptureItem<D>::DisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Capture::IGraphicsCaptureItem)->get_DisplayName(put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::SizeInt32 consume_Windows_Graphics_Capture_IGraphicsCaptureItem<D>::Size() const
{
    Windows::Graphics::SizeInt32 value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Capture::IGraphicsCaptureItem)->get_Size(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Graphics_Capture_IGraphicsCaptureItem<D>::Closed(Windows::Foundation::TypedEventHandler<Windows::Graphics::Capture::GraphicsCaptureItem, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Capture::IGraphicsCaptureItem)->add_Closed(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Graphics_Capture_IGraphicsCaptureItem<D>::Closed_revoker consume_Windows_Graphics_Capture_IGraphicsCaptureItem<D>::Closed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Graphics::Capture::GraphicsCaptureItem, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, Closed_revoker>(this, Closed(handler));
}

template <typename D> void consume_Windows_Graphics_Capture_IGraphicsCaptureItem<D>::Closed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Graphics::Capture::IGraphicsCaptureItem)->remove_Closed(get_abi(token)));
}

template <typename D> Windows::Graphics::Capture::GraphicsCaptureItem consume_Windows_Graphics_Capture_IGraphicsCaptureItemStatics<D>::CreateFromVisual(Windows::UI::Composition::Visual const& visual) const
{
    Windows::Graphics::Capture::GraphicsCaptureItem result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Capture::IGraphicsCaptureItemStatics)->CreateFromVisual(get_abi(visual), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Graphics::Capture::GraphicsCaptureItem> consume_Windows_Graphics_Capture_IGraphicsCapturePicker<D>::PickSingleItemAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Graphics::Capture::GraphicsCaptureItem> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Capture::IGraphicsCapturePicker)->PickSingleItemAsync(put_abi(operation)));
    return operation;
}

template <typename D> void consume_Windows_Graphics_Capture_IGraphicsCaptureSession<D>::StartCapture() const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Capture::IGraphicsCaptureSession)->StartCapture());
}

template <typename D> bool consume_Windows_Graphics_Capture_IGraphicsCaptureSessionStatics<D>::IsSupported() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Capture::IGraphicsCaptureSessionStatics)->IsSupported(&result));
    return result;
}

template <typename D>
struct produce<D, Windows::Graphics::Capture::IDirect3D11CaptureFrame> : produce_base<D, Windows::Graphics::Capture::IDirect3D11CaptureFrame>
{
    int32_t WINRT_CALL get_Surface(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Surface, WINRT_WRAP(Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface));
            *value = detach_from<Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface>(this->shim().Surface());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SystemRelativeTime(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SystemRelativeTime, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().SystemRelativeTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ContentSize(struct struct_Windows_Graphics_SizeInt32* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentSize, WINRT_WRAP(Windows::Graphics::SizeInt32));
            *value = detach_from<Windows::Graphics::SizeInt32>(this->shim().ContentSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Capture::IDirect3D11CaptureFramePool> : produce_base<D, Windows::Graphics::Capture::IDirect3D11CaptureFramePool>
{
    int32_t WINRT_CALL Recreate(void* device, Windows::Graphics::DirectX::DirectXPixelFormat pixelFormat, int32_t numberOfBuffers, struct struct_Windows_Graphics_SizeInt32 size) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Recreate, WINRT_WRAP(void), Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice const&, Windows::Graphics::DirectX::DirectXPixelFormat const&, int32_t, Windows::Graphics::SizeInt32 const&);
            this->shim().Recreate(*reinterpret_cast<Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice const*>(&device), *reinterpret_cast<Windows::Graphics::DirectX::DirectXPixelFormat const*>(&pixelFormat), numberOfBuffers, *reinterpret_cast<Windows::Graphics::SizeInt32 const*>(&size));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryGetNextFrame(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryGetNextFrame, WINRT_WRAP(Windows::Graphics::Capture::Direct3D11CaptureFrame));
            *result = detach_from<Windows::Graphics::Capture::Direct3D11CaptureFrame>(this->shim().TryGetNextFrame());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_FrameArrived(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FrameArrived, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Graphics::Capture::Direct3D11CaptureFramePool, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().FrameArrived(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Graphics::Capture::Direct3D11CaptureFramePool, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_FrameArrived(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(FrameArrived, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().FrameArrived(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL CreateCaptureSession(void* item, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateCaptureSession, WINRT_WRAP(Windows::Graphics::Capture::GraphicsCaptureSession), Windows::Graphics::Capture::GraphicsCaptureItem const&);
            *result = detach_from<Windows::Graphics::Capture::GraphicsCaptureSession>(this->shim().CreateCaptureSession(*reinterpret_cast<Windows::Graphics::Capture::GraphicsCaptureItem const*>(&item)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DispatcherQueue(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DispatcherQueue, WINRT_WRAP(Windows::System::DispatcherQueue));
            *value = detach_from<Windows::System::DispatcherQueue>(this->shim().DispatcherQueue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Capture::IDirect3D11CaptureFramePoolStatics> : produce_base<D, Windows::Graphics::Capture::IDirect3D11CaptureFramePoolStatics>
{
    int32_t WINRT_CALL Create(void* device, Windows::Graphics::DirectX::DirectXPixelFormat pixelFormat, int32_t numberOfBuffers, struct struct_Windows_Graphics_SizeInt32 size, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Graphics::Capture::Direct3D11CaptureFramePool), Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice const&, Windows::Graphics::DirectX::DirectXPixelFormat const&, int32_t, Windows::Graphics::SizeInt32 const&);
            *result = detach_from<Windows::Graphics::Capture::Direct3D11CaptureFramePool>(this->shim().Create(*reinterpret_cast<Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice const*>(&device), *reinterpret_cast<Windows::Graphics::DirectX::DirectXPixelFormat const*>(&pixelFormat), numberOfBuffers, *reinterpret_cast<Windows::Graphics::SizeInt32 const*>(&size)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Capture::IDirect3D11CaptureFramePoolStatics2> : produce_base<D, Windows::Graphics::Capture::IDirect3D11CaptureFramePoolStatics2>
{
    int32_t WINRT_CALL CreateFreeThreaded(void* device, Windows::Graphics::DirectX::DirectXPixelFormat pixelFormat, int32_t numberOfBuffers, struct struct_Windows_Graphics_SizeInt32 size, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFreeThreaded, WINRT_WRAP(Windows::Graphics::Capture::Direct3D11CaptureFramePool), Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice const&, Windows::Graphics::DirectX::DirectXPixelFormat const&, int32_t, Windows::Graphics::SizeInt32 const&);
            *result = detach_from<Windows::Graphics::Capture::Direct3D11CaptureFramePool>(this->shim().CreateFreeThreaded(*reinterpret_cast<Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice const*>(&device), *reinterpret_cast<Windows::Graphics::DirectX::DirectXPixelFormat const*>(&pixelFormat), numberOfBuffers, *reinterpret_cast<Windows::Graphics::SizeInt32 const*>(&size)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Capture::IGraphicsCaptureItem> : produce_base<D, Windows::Graphics::Capture::IGraphicsCaptureItem>
{
    int32_t WINRT_CALL get_DisplayName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DisplayName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Size(struct struct_Windows_Graphics_SizeInt32* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Size, WINRT_WRAP(Windows::Graphics::SizeInt32));
            *value = detach_from<Windows::Graphics::SizeInt32>(this->shim().Size());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_Closed(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Closed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Graphics::Capture::GraphicsCaptureItem, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().Closed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Graphics::Capture::GraphicsCaptureItem, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Closed(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Closed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Closed(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Capture::IGraphicsCaptureItemStatics> : produce_base<D, Windows::Graphics::Capture::IGraphicsCaptureItemStatics>
{
    int32_t WINRT_CALL CreateFromVisual(void* visual, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromVisual, WINRT_WRAP(Windows::Graphics::Capture::GraphicsCaptureItem), Windows::UI::Composition::Visual const&);
            *result = detach_from<Windows::Graphics::Capture::GraphicsCaptureItem>(this->shim().CreateFromVisual(*reinterpret_cast<Windows::UI::Composition::Visual const*>(&visual)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Capture::IGraphicsCapturePicker> : produce_base<D, Windows::Graphics::Capture::IGraphicsCapturePicker>
{
    int32_t WINRT_CALL PickSingleItemAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PickSingleItemAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Graphics::Capture::GraphicsCaptureItem>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Graphics::Capture::GraphicsCaptureItem>>(this->shim().PickSingleItemAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Capture::IGraphicsCaptureSession> : produce_base<D, Windows::Graphics::Capture::IGraphicsCaptureSession>
{
    int32_t WINRT_CALL StartCapture() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartCapture, WINRT_WRAP(void));
            this->shim().StartCapture();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Capture::IGraphicsCaptureSessionStatics> : produce_base<D, Windows::Graphics::Capture::IGraphicsCaptureSessionStatics>
{
    int32_t WINRT_CALL IsSupported(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSupported, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().IsSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Graphics::Capture {

inline Windows::Graphics::Capture::Direct3D11CaptureFramePool Direct3D11CaptureFramePool::Create(Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice const& device, Windows::Graphics::DirectX::DirectXPixelFormat const& pixelFormat, int32_t numberOfBuffers, Windows::Graphics::SizeInt32 const& size)
{
    return impl::call_factory<Direct3D11CaptureFramePool, Windows::Graphics::Capture::IDirect3D11CaptureFramePoolStatics>([&](auto&& f) { return f.Create(device, pixelFormat, numberOfBuffers, size); });
}

inline Windows::Graphics::Capture::Direct3D11CaptureFramePool Direct3D11CaptureFramePool::CreateFreeThreaded(Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice const& device, Windows::Graphics::DirectX::DirectXPixelFormat const& pixelFormat, int32_t numberOfBuffers, Windows::Graphics::SizeInt32 const& size)
{
    return impl::call_factory<Direct3D11CaptureFramePool, Windows::Graphics::Capture::IDirect3D11CaptureFramePoolStatics2>([&](auto&& f) { return f.CreateFreeThreaded(device, pixelFormat, numberOfBuffers, size); });
}

inline Windows::Graphics::Capture::GraphicsCaptureItem GraphicsCaptureItem::CreateFromVisual(Windows::UI::Composition::Visual const& visual)
{
    return impl::call_factory<GraphicsCaptureItem, Windows::Graphics::Capture::IGraphicsCaptureItemStatics>([&](auto&& f) { return f.CreateFromVisual(visual); });
}

inline GraphicsCapturePicker::GraphicsCapturePicker() :
    GraphicsCapturePicker(impl::call_factory<GraphicsCapturePicker>([](auto&& f) { return f.template ActivateInstance<GraphicsCapturePicker>(); }))
{}

inline bool GraphicsCaptureSession::IsSupported()
{
    return impl::call_factory<GraphicsCaptureSession, Windows::Graphics::Capture::IGraphicsCaptureSessionStatics>([&](auto&& f) { return f.IsSupported(); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Graphics::Capture::IDirect3D11CaptureFrame> : winrt::impl::hash_base<winrt::Windows::Graphics::Capture::IDirect3D11CaptureFrame> {};
template<> struct hash<winrt::Windows::Graphics::Capture::IDirect3D11CaptureFramePool> : winrt::impl::hash_base<winrt::Windows::Graphics::Capture::IDirect3D11CaptureFramePool> {};
template<> struct hash<winrt::Windows::Graphics::Capture::IDirect3D11CaptureFramePoolStatics> : winrt::impl::hash_base<winrt::Windows::Graphics::Capture::IDirect3D11CaptureFramePoolStatics> {};
template<> struct hash<winrt::Windows::Graphics::Capture::IDirect3D11CaptureFramePoolStatics2> : winrt::impl::hash_base<winrt::Windows::Graphics::Capture::IDirect3D11CaptureFramePoolStatics2> {};
template<> struct hash<winrt::Windows::Graphics::Capture::IGraphicsCaptureItem> : winrt::impl::hash_base<winrt::Windows::Graphics::Capture::IGraphicsCaptureItem> {};
template<> struct hash<winrt::Windows::Graphics::Capture::IGraphicsCaptureItemStatics> : winrt::impl::hash_base<winrt::Windows::Graphics::Capture::IGraphicsCaptureItemStatics> {};
template<> struct hash<winrt::Windows::Graphics::Capture::IGraphicsCapturePicker> : winrt::impl::hash_base<winrt::Windows::Graphics::Capture::IGraphicsCapturePicker> {};
template<> struct hash<winrt::Windows::Graphics::Capture::IGraphicsCaptureSession> : winrt::impl::hash_base<winrt::Windows::Graphics::Capture::IGraphicsCaptureSession> {};
template<> struct hash<winrt::Windows::Graphics::Capture::IGraphicsCaptureSessionStatics> : winrt::impl::hash_base<winrt::Windows::Graphics::Capture::IGraphicsCaptureSessionStatics> {};
template<> struct hash<winrt::Windows::Graphics::Capture::Direct3D11CaptureFrame> : winrt::impl::hash_base<winrt::Windows::Graphics::Capture::Direct3D11CaptureFrame> {};
template<> struct hash<winrt::Windows::Graphics::Capture::Direct3D11CaptureFramePool> : winrt::impl::hash_base<winrt::Windows::Graphics::Capture::Direct3D11CaptureFramePool> {};
template<> struct hash<winrt::Windows::Graphics::Capture::GraphicsCaptureItem> : winrt::impl::hash_base<winrt::Windows::Graphics::Capture::GraphicsCaptureItem> {};
template<> struct hash<winrt::Windows::Graphics::Capture::GraphicsCapturePicker> : winrt::impl::hash_base<winrt::Windows::Graphics::Capture::GraphicsCapturePicker> {};
template<> struct hash<winrt::Windows::Graphics::Capture::GraphicsCaptureSession> : winrt::impl::hash_base<winrt::Windows::Graphics::Capture::GraphicsCaptureSession> {};

}
