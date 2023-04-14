// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.System.Display.2.h"
#include "winrt/Windows.System.h"

namespace winrt::impl {

template <typename D> void consume_Windows_System_Display_IDisplayRequest<D>::RequestActive() const
{
    check_hresult(WINRT_SHIM(Windows::System::Display::IDisplayRequest)->RequestActive());
}

template <typename D> void consume_Windows_System_Display_IDisplayRequest<D>::RequestRelease() const
{
    check_hresult(WINRT_SHIM(Windows::System::Display::IDisplayRequest)->RequestRelease());
}

template <typename D>
struct produce<D, Windows::System::Display::IDisplayRequest> : produce_base<D, Windows::System::Display::IDisplayRequest>
{
    int32_t WINRT_CALL RequestActive() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestActive, WINRT_WRAP(void));
            this->shim().RequestActive();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestRelease() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestRelease, WINRT_WRAP(void));
            this->shim().RequestRelease();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::System::Display {

inline DisplayRequest::DisplayRequest() :
    DisplayRequest(impl::call_factory<DisplayRequest>([](auto&& f) { return f.template ActivateInstance<DisplayRequest>(); }))
{}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::System::Display::IDisplayRequest> : winrt::impl::hash_base<winrt::Windows::System::Display::IDisplayRequest> {};
template<> struct hash<winrt::Windows::System::Display::DisplayRequest> : winrt::impl::hash_base<winrt::Windows::System::Display::DisplayRequest> {};

}
