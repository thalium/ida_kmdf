// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.UI.Composition.2.h"
#include "winrt/impl/Windows.UI.Composition.Desktop.2.h"
#include "winrt/Windows.UI.Composition.h"

namespace winrt::impl {

template <typename D> bool consume_Windows_UI_Composition_Desktop_IDesktopWindowTarget<D>::IsTopmost() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Desktop::IDesktopWindowTarget)->get_IsTopmost(&value));
    return value;
}

template <typename D>
struct produce<D, Windows::UI::Composition::Desktop::IDesktopWindowTarget> : produce_base<D, Windows::UI::Composition::Desktop::IDesktopWindowTarget>
{
    int32_t WINRT_CALL get_IsTopmost(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsTopmost, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsTopmost());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::UI::Composition::Desktop {

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::UI::Composition::Desktop::IDesktopWindowTarget> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Desktop::IDesktopWindowTarget> {};
template<> struct hash<winrt::Windows::UI::Composition::Desktop::DesktopWindowTarget> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Desktop::DesktopWindowTarget> {};

}
