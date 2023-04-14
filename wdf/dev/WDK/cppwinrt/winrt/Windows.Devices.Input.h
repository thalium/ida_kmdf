// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Devices.Input.2.h"
#include "winrt/Windows.Devices.h"

namespace winrt::impl {

template <typename D> int32_t consume_Windows_Devices_Input_IKeyboardCapabilities<D>::KeyboardPresent() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Input::IKeyboardCapabilities)->get_KeyboardPresent(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Devices_Input_IMouseCapabilities<D>::MousePresent() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Input::IMouseCapabilities)->get_MousePresent(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Devices_Input_IMouseCapabilities<D>::VerticalWheelPresent() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Input::IMouseCapabilities)->get_VerticalWheelPresent(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Devices_Input_IMouseCapabilities<D>::HorizontalWheelPresent() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Input::IMouseCapabilities)->get_HorizontalWheelPresent(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Devices_Input_IMouseCapabilities<D>::SwapButtons() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Input::IMouseCapabilities)->get_SwapButtons(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_Input_IMouseCapabilities<D>::NumberOfButtons() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Input::IMouseCapabilities)->get_NumberOfButtons(&value));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Devices_Input_IMouseDevice<D>::MouseMoved(Windows::Foundation::TypedEventHandler<Windows::Devices::Input::MouseDevice, Windows::Devices::Input::MouseEventArgs> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::Devices::Input::IMouseDevice)->add_MouseMoved(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_Devices_Input_IMouseDevice<D>::MouseMoved_revoker consume_Windows_Devices_Input_IMouseDevice<D>::MouseMoved(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Input::MouseDevice, Windows::Devices::Input::MouseEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, MouseMoved_revoker>(this, MouseMoved(handler));
}

template <typename D> void consume_Windows_Devices_Input_IMouseDevice<D>::MouseMoved(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Input::IMouseDevice)->remove_MouseMoved(get_abi(cookie)));
}

template <typename D> Windows::Devices::Input::MouseDevice consume_Windows_Devices_Input_IMouseDeviceStatics<D>::GetForCurrentView() const
{
    Windows::Devices::Input::MouseDevice mouseDevice{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Input::IMouseDeviceStatics)->GetForCurrentView(put_abi(mouseDevice)));
    return mouseDevice;
}

template <typename D> Windows::Devices::Input::MouseDelta consume_Windows_Devices_Input_IMouseEventArgs<D>::MouseDelta() const
{
    Windows::Devices::Input::MouseDelta value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Input::IMouseEventArgs)->get_MouseDelta(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Devices_Input_IPenDevice<D>::PenId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Input::IPenDevice)->get_PenId(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Input::PenDevice consume_Windows_Devices_Input_IPenDeviceStatics<D>::GetFromPointerId(uint32_t pointerId) const
{
    Windows::Devices::Input::PenDevice result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Input::IPenDeviceStatics)->GetFromPointerId(pointerId, put_abi(result)));
    return result;
}

template <typename D> Windows::Devices::Input::PointerDeviceType consume_Windows_Devices_Input_IPointerDevice<D>::PointerDeviceType() const
{
    Windows::Devices::Input::PointerDeviceType value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Input::IPointerDevice)->get_PointerDeviceType(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Devices_Input_IPointerDevice<D>::IsIntegrated() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Input::IPointerDevice)->get_IsIntegrated(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_Input_IPointerDevice<D>::MaxContacts() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Input::IPointerDevice)->get_MaxContacts(&value));
    return value;
}

template <typename D> Windows::Foundation::Rect consume_Windows_Devices_Input_IPointerDevice<D>::PhysicalDeviceRect() const
{
    Windows::Foundation::Rect value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Input::IPointerDevice)->get_PhysicalDeviceRect(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Rect consume_Windows_Devices_Input_IPointerDevice<D>::ScreenRect() const
{
    Windows::Foundation::Rect value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Input::IPointerDevice)->get_ScreenRect(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::Input::PointerDeviceUsage> consume_Windows_Devices_Input_IPointerDevice<D>::SupportedUsages() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Input::PointerDeviceUsage> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Input::IPointerDevice)->get_SupportedUsages(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_Input_IPointerDevice2<D>::MaxPointersWithZDistance() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Input::IPointerDevice2)->get_MaxPointersWithZDistance(&value));
    return value;
}

template <typename D> Windows::Devices::Input::PointerDevice consume_Windows_Devices_Input_IPointerDeviceStatics<D>::GetPointerDevice(uint32_t pointerId) const
{
    Windows::Devices::Input::PointerDevice pointerDevice{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Input::IPointerDeviceStatics)->GetPointerDevice(pointerId, put_abi(pointerDevice)));
    return pointerDevice;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::Input::PointerDevice> consume_Windows_Devices_Input_IPointerDeviceStatics<D>::GetPointerDevices() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Input::PointerDevice> pointerDevices{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Input::IPointerDeviceStatics)->GetPointerDevices(put_abi(pointerDevices)));
    return pointerDevices;
}

template <typename D> int32_t consume_Windows_Devices_Input_ITouchCapabilities<D>::TouchPresent() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Input::ITouchCapabilities)->get_TouchPresent(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_Input_ITouchCapabilities<D>::Contacts() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Input::ITouchCapabilities)->get_Contacts(&value));
    return value;
}

template <typename D>
struct produce<D, Windows::Devices::Input::IKeyboardCapabilities> : produce_base<D, Windows::Devices::Input::IKeyboardCapabilities>
{
    int32_t WINRT_CALL get_KeyboardPresent(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyboardPresent, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().KeyboardPresent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Input::IMouseCapabilities> : produce_base<D, Windows::Devices::Input::IMouseCapabilities>
{
    int32_t WINRT_CALL get_MousePresent(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MousePresent, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().MousePresent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VerticalWheelPresent(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VerticalWheelPresent, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().VerticalWheelPresent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HorizontalWheelPresent(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HorizontalWheelPresent, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().HorizontalWheelPresent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SwapButtons(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SwapButtons, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().SwapButtons());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NumberOfButtons(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NumberOfButtons, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().NumberOfButtons());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Input::IMouseDevice> : produce_base<D, Windows::Devices::Input::IMouseDevice>
{
    int32_t WINRT_CALL add_MouseMoved(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MouseMoved, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Input::MouseDevice, Windows::Devices::Input::MouseEventArgs> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().MouseMoved(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Input::MouseDevice, Windows::Devices::Input::MouseEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_MouseMoved(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(MouseMoved, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().MouseMoved(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Devices::Input::IMouseDeviceStatics> : produce_base<D, Windows::Devices::Input::IMouseDeviceStatics>
{
    int32_t WINRT_CALL GetForCurrentView(void** mouseDevice) noexcept final
    {
        try
        {
            *mouseDevice = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForCurrentView, WINRT_WRAP(Windows::Devices::Input::MouseDevice));
            *mouseDevice = detach_from<Windows::Devices::Input::MouseDevice>(this->shim().GetForCurrentView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Input::IMouseEventArgs> : produce_base<D, Windows::Devices::Input::IMouseEventArgs>
{
    int32_t WINRT_CALL get_MouseDelta(struct struct_Windows_Devices_Input_MouseDelta* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MouseDelta, WINRT_WRAP(Windows::Devices::Input::MouseDelta));
            *value = detach_from<Windows::Devices::Input::MouseDelta>(this->shim().MouseDelta());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Input::IPenDevice> : produce_base<D, Windows::Devices::Input::IPenDevice>
{
    int32_t WINRT_CALL get_PenId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PenId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().PenId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Input::IPenDeviceStatics> : produce_base<D, Windows::Devices::Input::IPenDeviceStatics>
{
    int32_t WINRT_CALL GetFromPointerId(uint32_t pointerId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetFromPointerId, WINRT_WRAP(Windows::Devices::Input::PenDevice), uint32_t);
            *result = detach_from<Windows::Devices::Input::PenDevice>(this->shim().GetFromPointerId(pointerId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Input::IPointerDevice> : produce_base<D, Windows::Devices::Input::IPointerDevice>
{
    int32_t WINRT_CALL get_PointerDeviceType(Windows::Devices::Input::PointerDeviceType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointerDeviceType, WINRT_WRAP(Windows::Devices::Input::PointerDeviceType));
            *value = detach_from<Windows::Devices::Input::PointerDeviceType>(this->shim().PointerDeviceType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsIntegrated(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsIntegrated, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsIntegrated());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxContacts(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxContacts, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().MaxContacts());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PhysicalDeviceRect(Windows::Foundation::Rect* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PhysicalDeviceRect, WINRT_WRAP(Windows::Foundation::Rect));
            *value = detach_from<Windows::Foundation::Rect>(this->shim().PhysicalDeviceRect());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ScreenRect(Windows::Foundation::Rect* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScreenRect, WINRT_WRAP(Windows::Foundation::Rect));
            *value = detach_from<Windows::Foundation::Rect>(this->shim().ScreenRect());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportedUsages(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedUsages, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::Input::PointerDeviceUsage>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::Input::PointerDeviceUsage>>(this->shim().SupportedUsages());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Input::IPointerDevice2> : produce_base<D, Windows::Devices::Input::IPointerDevice2>
{
    int32_t WINRT_CALL get_MaxPointersWithZDistance(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxPointersWithZDistance, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().MaxPointersWithZDistance());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Input::IPointerDeviceStatics> : produce_base<D, Windows::Devices::Input::IPointerDeviceStatics>
{
    int32_t WINRT_CALL GetPointerDevice(uint32_t pointerId, void** pointerDevice) noexcept final
    {
        try
        {
            *pointerDevice = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetPointerDevice, WINRT_WRAP(Windows::Devices::Input::PointerDevice), uint32_t);
            *pointerDevice = detach_from<Windows::Devices::Input::PointerDevice>(this->shim().GetPointerDevice(pointerId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetPointerDevices(void** pointerDevices) noexcept final
    {
        try
        {
            *pointerDevices = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetPointerDevices, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::Input::PointerDevice>));
            *pointerDevices = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::Input::PointerDevice>>(this->shim().GetPointerDevices());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Input::ITouchCapabilities> : produce_base<D, Windows::Devices::Input::ITouchCapabilities>
{
    int32_t WINRT_CALL get_TouchPresent(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TouchPresent, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().TouchPresent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Contacts(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Contacts, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Contacts());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Devices::Input {

inline KeyboardCapabilities::KeyboardCapabilities() :
    KeyboardCapabilities(impl::call_factory<KeyboardCapabilities>([](auto&& f) { return f.template ActivateInstance<KeyboardCapabilities>(); }))
{}

inline MouseCapabilities::MouseCapabilities() :
    MouseCapabilities(impl::call_factory<MouseCapabilities>([](auto&& f) { return f.template ActivateInstance<MouseCapabilities>(); }))
{}

inline Windows::Devices::Input::MouseDevice MouseDevice::GetForCurrentView()
{
    return impl::call_factory<MouseDevice, Windows::Devices::Input::IMouseDeviceStatics>([&](auto&& f) { return f.GetForCurrentView(); });
}

inline Windows::Devices::Input::PenDevice PenDevice::GetFromPointerId(uint32_t pointerId)
{
    return impl::call_factory<PenDevice, Windows::Devices::Input::IPenDeviceStatics>([&](auto&& f) { return f.GetFromPointerId(pointerId); });
}

inline Windows::Devices::Input::PointerDevice PointerDevice::GetPointerDevice(uint32_t pointerId)
{
    return impl::call_factory<PointerDevice, Windows::Devices::Input::IPointerDeviceStatics>([&](auto&& f) { return f.GetPointerDevice(pointerId); });
}

inline Windows::Foundation::Collections::IVectorView<Windows::Devices::Input::PointerDevice> PointerDevice::GetPointerDevices()
{
    return impl::call_factory<PointerDevice, Windows::Devices::Input::IPointerDeviceStatics>([&](auto&& f) { return f.GetPointerDevices(); });
}

inline TouchCapabilities::TouchCapabilities() :
    TouchCapabilities(impl::call_factory<TouchCapabilities>([](auto&& f) { return f.template ActivateInstance<TouchCapabilities>(); }))
{}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Devices::Input::IKeyboardCapabilities> : winrt::impl::hash_base<winrt::Windows::Devices::Input::IKeyboardCapabilities> {};
template<> struct hash<winrt::Windows::Devices::Input::IMouseCapabilities> : winrt::impl::hash_base<winrt::Windows::Devices::Input::IMouseCapabilities> {};
template<> struct hash<winrt::Windows::Devices::Input::IMouseDevice> : winrt::impl::hash_base<winrt::Windows::Devices::Input::IMouseDevice> {};
template<> struct hash<winrt::Windows::Devices::Input::IMouseDeviceStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Input::IMouseDeviceStatics> {};
template<> struct hash<winrt::Windows::Devices::Input::IMouseEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Input::IMouseEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Input::IPenDevice> : winrt::impl::hash_base<winrt::Windows::Devices::Input::IPenDevice> {};
template<> struct hash<winrt::Windows::Devices::Input::IPenDeviceStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Input::IPenDeviceStatics> {};
template<> struct hash<winrt::Windows::Devices::Input::IPointerDevice> : winrt::impl::hash_base<winrt::Windows::Devices::Input::IPointerDevice> {};
template<> struct hash<winrt::Windows::Devices::Input::IPointerDevice2> : winrt::impl::hash_base<winrt::Windows::Devices::Input::IPointerDevice2> {};
template<> struct hash<winrt::Windows::Devices::Input::IPointerDeviceStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Input::IPointerDeviceStatics> {};
template<> struct hash<winrt::Windows::Devices::Input::ITouchCapabilities> : winrt::impl::hash_base<winrt::Windows::Devices::Input::ITouchCapabilities> {};
template<> struct hash<winrt::Windows::Devices::Input::KeyboardCapabilities> : winrt::impl::hash_base<winrt::Windows::Devices::Input::KeyboardCapabilities> {};
template<> struct hash<winrt::Windows::Devices::Input::MouseCapabilities> : winrt::impl::hash_base<winrt::Windows::Devices::Input::MouseCapabilities> {};
template<> struct hash<winrt::Windows::Devices::Input::MouseDevice> : winrt::impl::hash_base<winrt::Windows::Devices::Input::MouseDevice> {};
template<> struct hash<winrt::Windows::Devices::Input::MouseEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Input::MouseEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Input::PenDevice> : winrt::impl::hash_base<winrt::Windows::Devices::Input::PenDevice> {};
template<> struct hash<winrt::Windows::Devices::Input::PointerDevice> : winrt::impl::hash_base<winrt::Windows::Devices::Input::PointerDevice> {};
template<> struct hash<winrt::Windows::Devices::Input::TouchCapabilities> : winrt::impl::hash_base<winrt::Windows::Devices::Input::TouchCapabilities> {};

}
