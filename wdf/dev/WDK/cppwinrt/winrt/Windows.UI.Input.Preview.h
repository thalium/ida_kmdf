// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.UI.Input.2.h"
#include "winrt/impl/Windows.UI.WindowManagement.2.h"
#include "winrt/impl/Windows.UI.Input.Preview.2.h"
#include "winrt/Windows.UI.Input.h"

namespace winrt::impl {

template <typename D> Windows::UI::Input::InputActivationListener consume_Windows_UI_Input_Preview_IInputActivationListenerPreviewStatics<D>::CreateForApplicationWindow(Windows::UI::WindowManagement::AppWindow const& window) const
{
    Windows::UI::Input::InputActivationListener result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Preview::IInputActivationListenerPreviewStatics)->CreateForApplicationWindow(get_abi(window), put_abi(result)));
    return result;
}

template <typename D>
struct produce<D, Windows::UI::Input::Preview::IInputActivationListenerPreviewStatics> : produce_base<D, Windows::UI::Input::Preview::IInputActivationListenerPreviewStatics>
{
    int32_t WINRT_CALL CreateForApplicationWindow(void* window, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateForApplicationWindow, WINRT_WRAP(Windows::UI::Input::InputActivationListener), Windows::UI::WindowManagement::AppWindow const&);
            *result = detach_from<Windows::UI::Input::InputActivationListener>(this->shim().CreateForApplicationWindow(*reinterpret_cast<Windows::UI::WindowManagement::AppWindow const*>(&window)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::UI::Input::Preview {

inline Windows::UI::Input::InputActivationListener InputActivationListenerPreview::CreateForApplicationWindow(Windows::UI::WindowManagement::AppWindow const& window)
{
    return impl::call_factory<InputActivationListenerPreview, Windows::UI::Input::Preview::IInputActivationListenerPreviewStatics>([&](auto&& f) { return f.CreateForApplicationWindow(window); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::UI::Input::Preview::IInputActivationListenerPreviewStatics> : winrt::impl::hash_base<winrt::Windows::UI::Input::Preview::IInputActivationListenerPreviewStatics> {};
template<> struct hash<winrt::Windows::UI::Input::Preview::InputActivationListenerPreview> : winrt::impl::hash_base<winrt::Windows::UI::Input::Preview::InputActivationListenerPreview> {};

}
