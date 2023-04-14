// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.ApplicationModel.Core.2.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.UI.Core.2.h"
#include "winrt/impl/Windows.UI.Input.2.h"
#include "winrt/impl/Windows.UI.Input.Core.2.h"
#include "winrt/Windows.UI.Input.h"

namespace winrt::impl {

template <typename D> Windows::UI::Input::RadialController consume_Windows_UI_Input_Core_IRadialControllerIndependentInputSource<D>::Controller() const
{
    Windows::UI::Input::RadialController value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Core::IRadialControllerIndependentInputSource)->get_Controller(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Core::CoreDispatcher consume_Windows_UI_Input_Core_IRadialControllerIndependentInputSource<D>::Dispatcher() const
{
    Windows::UI::Core::CoreDispatcher value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Core::IRadialControllerIndependentInputSource)->get_Dispatcher(put_abi(value)));
    return value;
}

template <typename D> Windows::System::DispatcherQueue consume_Windows_UI_Input_Core_IRadialControllerIndependentInputSource2<D>::DispatcherQueue() const
{
    Windows::System::DispatcherQueue value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Core::IRadialControllerIndependentInputSource2)->get_DispatcherQueue(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::Core::RadialControllerIndependentInputSource consume_Windows_UI_Input_Core_IRadialControllerIndependentInputSourceStatics<D>::CreateForView(Windows::ApplicationModel::Core::CoreApplicationView const& view) const
{
    Windows::UI::Input::Core::RadialControllerIndependentInputSource result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Core::IRadialControllerIndependentInputSourceStatics)->CreateForView(get_abi(view), put_abi(result)));
    return result;
}

template <typename D>
struct produce<D, Windows::UI::Input::Core::IRadialControllerIndependentInputSource> : produce_base<D, Windows::UI::Input::Core::IRadialControllerIndependentInputSource>
{
    int32_t WINRT_CALL get_Controller(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Controller, WINRT_WRAP(Windows::UI::Input::RadialController));
            *value = detach_from<Windows::UI::Input::RadialController>(this->shim().Controller());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Dispatcher(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Dispatcher, WINRT_WRAP(Windows::UI::Core::CoreDispatcher));
            *value = detach_from<Windows::UI::Core::CoreDispatcher>(this->shim().Dispatcher());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Core::IRadialControllerIndependentInputSource2> : produce_base<D, Windows::UI::Input::Core::IRadialControllerIndependentInputSource2>
{
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
struct produce<D, Windows::UI::Input::Core::IRadialControllerIndependentInputSourceStatics> : produce_base<D, Windows::UI::Input::Core::IRadialControllerIndependentInputSourceStatics>
{
    int32_t WINRT_CALL CreateForView(void* view, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateForView, WINRT_WRAP(Windows::UI::Input::Core::RadialControllerIndependentInputSource), Windows::ApplicationModel::Core::CoreApplicationView const&);
            *result = detach_from<Windows::UI::Input::Core::RadialControllerIndependentInputSource>(this->shim().CreateForView(*reinterpret_cast<Windows::ApplicationModel::Core::CoreApplicationView const*>(&view)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::UI::Input::Core {

inline Windows::UI::Input::Core::RadialControllerIndependentInputSource RadialControllerIndependentInputSource::CreateForView(Windows::ApplicationModel::Core::CoreApplicationView const& view)
{
    return impl::call_factory<RadialControllerIndependentInputSource, Windows::UI::Input::Core::IRadialControllerIndependentInputSourceStatics>([&](auto&& f) { return f.CreateForView(view); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::UI::Input::Core::IRadialControllerIndependentInputSource> : winrt::impl::hash_base<winrt::Windows::UI::Input::Core::IRadialControllerIndependentInputSource> {};
template<> struct hash<winrt::Windows::UI::Input::Core::IRadialControllerIndependentInputSource2> : winrt::impl::hash_base<winrt::Windows::UI::Input::Core::IRadialControllerIndependentInputSource2> {};
template<> struct hash<winrt::Windows::UI::Input::Core::IRadialControllerIndependentInputSourceStatics> : winrt::impl::hash_base<winrt::Windows::UI::Input::Core::IRadialControllerIndependentInputSourceStatics> {};
template<> struct hash<winrt::Windows::UI::Input::Core::RadialControllerIndependentInputSource> : winrt::impl::hash_base<winrt::Windows::UI::Input::Core::RadialControllerIndependentInputSource> {};

}
