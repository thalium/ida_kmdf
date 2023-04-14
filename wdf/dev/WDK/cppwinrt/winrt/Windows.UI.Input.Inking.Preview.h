// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.UI.Composition.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.UI.Input.Inking.Preview.2.h"
#include "winrt/Windows.UI.Input.Inking.h"

namespace winrt::impl {

template <typename D> Windows::UI::Input::Inking::Preview::PalmRejectionDelayZonePreview consume_Windows_UI_Input_Inking_Preview_IPalmRejectionDelayZonePreviewStatics<D>::CreateForVisual(Windows::UI::Composition::Visual const& inputPanelVisual, Windows::Foundation::Rect const& inputPanelRect) const
{
    Windows::UI::Input::Inking::Preview::PalmRejectionDelayZonePreview result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::Preview::IPalmRejectionDelayZonePreviewStatics)->CreateForVisual(get_abi(inputPanelVisual), get_abi(inputPanelRect), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Input::Inking::Preview::PalmRejectionDelayZonePreview consume_Windows_UI_Input_Inking_Preview_IPalmRejectionDelayZonePreviewStatics<D>::CreateForVisual(Windows::UI::Composition::Visual const& inputPanelVisual, Windows::Foundation::Rect const& inputPanelRect, Windows::UI::Composition::Visual const& viewportVisual, Windows::Foundation::Rect const& viewportRect) const
{
    Windows::UI::Input::Inking::Preview::PalmRejectionDelayZonePreview result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::Preview::IPalmRejectionDelayZonePreviewStatics)->CreateForVisualWithViewportClip(get_abi(inputPanelVisual), get_abi(inputPanelRect), get_abi(viewportVisual), get_abi(viewportRect), put_abi(result)));
    return result;
}

template <typename D>
struct produce<D, Windows::UI::Input::Inking::Preview::IPalmRejectionDelayZonePreview> : produce_base<D, Windows::UI::Input::Inking::Preview::IPalmRejectionDelayZonePreview>
{};

template <typename D>
struct produce<D, Windows::UI::Input::Inking::Preview::IPalmRejectionDelayZonePreviewStatics> : produce_base<D, Windows::UI::Input::Inking::Preview::IPalmRejectionDelayZonePreviewStatics>
{
    int32_t WINRT_CALL CreateForVisual(void* inputPanelVisual, Windows::Foundation::Rect inputPanelRect, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateForVisual, WINRT_WRAP(Windows::UI::Input::Inking::Preview::PalmRejectionDelayZonePreview), Windows::UI::Composition::Visual const&, Windows::Foundation::Rect const&);
            *result = detach_from<Windows::UI::Input::Inking::Preview::PalmRejectionDelayZonePreview>(this->shim().CreateForVisual(*reinterpret_cast<Windows::UI::Composition::Visual const*>(&inputPanelVisual), *reinterpret_cast<Windows::Foundation::Rect const*>(&inputPanelRect)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateForVisualWithViewportClip(void* inputPanelVisual, Windows::Foundation::Rect inputPanelRect, void* viewportVisual, Windows::Foundation::Rect viewportRect, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateForVisual, WINRT_WRAP(Windows::UI::Input::Inking::Preview::PalmRejectionDelayZonePreview), Windows::UI::Composition::Visual const&, Windows::Foundation::Rect const&, Windows::UI::Composition::Visual const&, Windows::Foundation::Rect const&);
            *result = detach_from<Windows::UI::Input::Inking::Preview::PalmRejectionDelayZonePreview>(this->shim().CreateForVisual(*reinterpret_cast<Windows::UI::Composition::Visual const*>(&inputPanelVisual), *reinterpret_cast<Windows::Foundation::Rect const*>(&inputPanelRect), *reinterpret_cast<Windows::UI::Composition::Visual const*>(&viewportVisual), *reinterpret_cast<Windows::Foundation::Rect const*>(&viewportRect)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::UI::Input::Inking::Preview {

inline Windows::UI::Input::Inking::Preview::PalmRejectionDelayZonePreview PalmRejectionDelayZonePreview::CreateForVisual(Windows::UI::Composition::Visual const& inputPanelVisual, Windows::Foundation::Rect const& inputPanelRect)
{
    return impl::call_factory<PalmRejectionDelayZonePreview, Windows::UI::Input::Inking::Preview::IPalmRejectionDelayZonePreviewStatics>([&](auto&& f) { return f.CreateForVisual(inputPanelVisual, inputPanelRect); });
}

inline Windows::UI::Input::Inking::Preview::PalmRejectionDelayZonePreview PalmRejectionDelayZonePreview::CreateForVisual(Windows::UI::Composition::Visual const& inputPanelVisual, Windows::Foundation::Rect const& inputPanelRect, Windows::UI::Composition::Visual const& viewportVisual, Windows::Foundation::Rect const& viewportRect)
{
    return impl::call_factory<PalmRejectionDelayZonePreview, Windows::UI::Input::Inking::Preview::IPalmRejectionDelayZonePreviewStatics>([&](auto&& f) { return f.CreateForVisual(inputPanelVisual, inputPanelRect, viewportVisual, viewportRect); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::UI::Input::Inking::Preview::IPalmRejectionDelayZonePreview> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::Preview::IPalmRejectionDelayZonePreview> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::Preview::IPalmRejectionDelayZonePreviewStatics> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::Preview::IPalmRejectionDelayZonePreviewStatics> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::Preview::PalmRejectionDelayZonePreview> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::Preview::PalmRejectionDelayZonePreview> {};

}
