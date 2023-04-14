// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.UI.WindowManagement.2.h"
#include "winrt/impl/Windows.UI.WindowManagement.Preview.2.h"
#include "winrt/Windows.UI.WindowManagement.h"

namespace winrt::impl {

template <typename D> void consume_Windows_UI_WindowManagement_Preview_IWindowManagementPreviewStatics<D>::SetPreferredMinSize(Windows::UI::WindowManagement::AppWindow const& window, Windows::Foundation::Size const& preferredFrameMinSize) const
{
    check_hresult(WINRT_SHIM(Windows::UI::WindowManagement::Preview::IWindowManagementPreviewStatics)->SetPreferredMinSize(get_abi(window), get_abi(preferredFrameMinSize)));
}

template <typename D>
struct produce<D, Windows::UI::WindowManagement::Preview::IWindowManagementPreview> : produce_base<D, Windows::UI::WindowManagement::Preview::IWindowManagementPreview>
{};

template <typename D>
struct produce<D, Windows::UI::WindowManagement::Preview::IWindowManagementPreviewStatics> : produce_base<D, Windows::UI::WindowManagement::Preview::IWindowManagementPreviewStatics>
{
    int32_t WINRT_CALL SetPreferredMinSize(void* window, Windows::Foundation::Size preferredFrameMinSize) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetPreferredMinSize, WINRT_WRAP(void), Windows::UI::WindowManagement::AppWindow const&, Windows::Foundation::Size const&);
            this->shim().SetPreferredMinSize(*reinterpret_cast<Windows::UI::WindowManagement::AppWindow const*>(&window), *reinterpret_cast<Windows::Foundation::Size const*>(&preferredFrameMinSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::UI::WindowManagement::Preview {

inline void WindowManagementPreview::SetPreferredMinSize(Windows::UI::WindowManagement::AppWindow const& window, Windows::Foundation::Size const& preferredFrameMinSize)
{
    impl::call_factory<WindowManagementPreview, Windows::UI::WindowManagement::Preview::IWindowManagementPreviewStatics>([&](auto&& f) { return f.SetPreferredMinSize(window, preferredFrameMinSize); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::UI::WindowManagement::Preview::IWindowManagementPreview> : winrt::impl::hash_base<winrt::Windows::UI::WindowManagement::Preview::IWindowManagementPreview> {};
template<> struct hash<winrt::Windows::UI::WindowManagement::Preview::IWindowManagementPreviewStatics> : winrt::impl::hash_base<winrt::Windows::UI::WindowManagement::Preview::IWindowManagementPreviewStatics> {};
template<> struct hash<winrt::Windows::UI::WindowManagement::Preview::WindowManagementPreview> : winrt::impl::hash_base<winrt::Windows::UI::WindowManagement::Preview::WindowManagementPreview> {};

}
