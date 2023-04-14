// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.UI.2.h"
#include "winrt/impl/Windows.UI.ViewManagement.Core.2.h"
#include "winrt/Windows.UI.ViewManagement.h"

namespace winrt::impl {

template <typename D> winrt::event_token consume_Windows_UI_ViewManagement_Core_ICoreInputView<D>::OcclusionsChanged(Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::Core::CoreInputView, Windows::UI::ViewManagement::Core::CoreInputViewOcclusionsChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::Core::ICoreInputView)->add_OcclusionsChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_ViewManagement_Core_ICoreInputView<D>::OcclusionsChanged_revoker consume_Windows_UI_ViewManagement_Core_ICoreInputView<D>::OcclusionsChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::Core::CoreInputView, Windows::UI::ViewManagement::Core::CoreInputViewOcclusionsChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, OcclusionsChanged_revoker>(this, OcclusionsChanged(handler));
}

template <typename D> void consume_Windows_UI_ViewManagement_Core_ICoreInputView<D>::OcclusionsChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::ViewManagement::Core::ICoreInputView)->remove_OcclusionsChanged(get_abi(token)));
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::UI::ViewManagement::Core::CoreInputViewOcclusion> consume_Windows_UI_ViewManagement_Core_ICoreInputView<D>::GetCoreInputViewOcclusions() const
{
    Windows::Foundation::Collections::IVectorView<Windows::UI::ViewManagement::Core::CoreInputViewOcclusion> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::Core::ICoreInputView)->GetCoreInputViewOcclusions(put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_UI_ViewManagement_Core_ICoreInputView<D>::TryShowPrimaryView() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::Core::ICoreInputView)->TryShowPrimaryView(&result));
    return result;
}

template <typename D> bool consume_Windows_UI_ViewManagement_Core_ICoreInputView<D>::TryHidePrimaryView() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::Core::ICoreInputView)->TryHidePrimaryView(&result));
    return result;
}

template <typename D> winrt::event_token consume_Windows_UI_ViewManagement_Core_ICoreInputView2<D>::XYFocusTransferringFromPrimaryView(Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::Core::CoreInputView, Windows::UI::ViewManagement::Core::CoreInputViewTransferringXYFocusEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::Core::ICoreInputView2)->add_XYFocusTransferringFromPrimaryView(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_ViewManagement_Core_ICoreInputView2<D>::XYFocusTransferringFromPrimaryView_revoker consume_Windows_UI_ViewManagement_Core_ICoreInputView2<D>::XYFocusTransferringFromPrimaryView(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::Core::CoreInputView, Windows::UI::ViewManagement::Core::CoreInputViewTransferringXYFocusEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, XYFocusTransferringFromPrimaryView_revoker>(this, XYFocusTransferringFromPrimaryView(handler));
}

template <typename D> void consume_Windows_UI_ViewManagement_Core_ICoreInputView2<D>::XYFocusTransferringFromPrimaryView(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::ViewManagement::Core::ICoreInputView2)->remove_XYFocusTransferringFromPrimaryView(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_ViewManagement_Core_ICoreInputView2<D>::XYFocusTransferredToPrimaryView(Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::Core::CoreInputView, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::Core::ICoreInputView2)->add_XYFocusTransferredToPrimaryView(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_ViewManagement_Core_ICoreInputView2<D>::XYFocusTransferredToPrimaryView_revoker consume_Windows_UI_ViewManagement_Core_ICoreInputView2<D>::XYFocusTransferredToPrimaryView(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::Core::CoreInputView, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, XYFocusTransferredToPrimaryView_revoker>(this, XYFocusTransferredToPrimaryView(handler));
}

template <typename D> void consume_Windows_UI_ViewManagement_Core_ICoreInputView2<D>::XYFocusTransferredToPrimaryView(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::ViewManagement::Core::ICoreInputView2)->remove_XYFocusTransferredToPrimaryView(get_abi(token)));
}

template <typename D> bool consume_Windows_UI_ViewManagement_Core_ICoreInputView2<D>::TryTransferXYFocusToPrimaryView(Windows::Foundation::Rect const& origin, Windows::UI::ViewManagement::Core::CoreInputViewXYFocusTransferDirection const& direction) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::Core::ICoreInputView2)->TryTransferXYFocusToPrimaryView(get_abi(origin), get_abi(direction), &result));
    return result;
}

template <typename D> bool consume_Windows_UI_ViewManagement_Core_ICoreInputView3<D>::TryShow() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::Core::ICoreInputView3)->TryShow(&result));
    return result;
}

template <typename D> bool consume_Windows_UI_ViewManagement_Core_ICoreInputView3<D>::TryShow(Windows::UI::ViewManagement::Core::CoreInputViewKind const& type) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::Core::ICoreInputView3)->TryShowWithKind(get_abi(type), &result));
    return result;
}

template <typename D> bool consume_Windows_UI_ViewManagement_Core_ICoreInputView3<D>::TryHide() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::Core::ICoreInputView3)->TryHide(&result));
    return result;
}

template <typename D> Windows::Foundation::Rect consume_Windows_UI_ViewManagement_Core_ICoreInputViewOcclusion<D>::OccludingRect() const
{
    Windows::Foundation::Rect value{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::Core::ICoreInputViewOcclusion)->get_OccludingRect(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::ViewManagement::Core::CoreInputViewOcclusionKind consume_Windows_UI_ViewManagement_Core_ICoreInputViewOcclusion<D>::OcclusionKind() const
{
    Windows::UI::ViewManagement::Core::CoreInputViewOcclusionKind value{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::Core::ICoreInputViewOcclusion)->get_OcclusionKind(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::UI::ViewManagement::Core::CoreInputViewOcclusion> consume_Windows_UI_ViewManagement_Core_ICoreInputViewOcclusionsChangedEventArgs<D>::Occlusions() const
{
    Windows::Foundation::Collections::IVectorView<Windows::UI::ViewManagement::Core::CoreInputViewOcclusion> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::Core::ICoreInputViewOcclusionsChangedEventArgs)->get_Occlusions(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_ViewManagement_Core_ICoreInputViewOcclusionsChangedEventArgs<D>::Handled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::Core::ICoreInputViewOcclusionsChangedEventArgs)->get_Handled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_ViewManagement_Core_ICoreInputViewOcclusionsChangedEventArgs<D>::Handled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::Core::ICoreInputViewOcclusionsChangedEventArgs)->put_Handled(value));
}

template <typename D> Windows::UI::ViewManagement::Core::CoreInputView consume_Windows_UI_ViewManagement_Core_ICoreInputViewStatics<D>::GetForCurrentView() const
{
    Windows::UI::ViewManagement::Core::CoreInputView result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::Core::ICoreInputViewStatics)->GetForCurrentView(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::ViewManagement::Core::CoreInputView consume_Windows_UI_ViewManagement_Core_ICoreInputViewStatics2<D>::GetForUIContext(Windows::UI::UIContext const& context) const
{
    Windows::UI::ViewManagement::Core::CoreInputView result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::Core::ICoreInputViewStatics2)->GetForUIContext(get_abi(context), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Rect consume_Windows_UI_ViewManagement_Core_ICoreInputViewTransferringXYFocusEventArgs<D>::Origin() const
{
    Windows::Foundation::Rect value{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::Core::ICoreInputViewTransferringXYFocusEventArgs)->get_Origin(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::ViewManagement::Core::CoreInputViewXYFocusTransferDirection consume_Windows_UI_ViewManagement_Core_ICoreInputViewTransferringXYFocusEventArgs<D>::Direction() const
{
    Windows::UI::ViewManagement::Core::CoreInputViewXYFocusTransferDirection value{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::Core::ICoreInputViewTransferringXYFocusEventArgs)->get_Direction(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_ViewManagement_Core_ICoreInputViewTransferringXYFocusEventArgs<D>::TransferHandled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::Core::ICoreInputViewTransferringXYFocusEventArgs)->put_TransferHandled(value));
}

template <typename D> bool consume_Windows_UI_ViewManagement_Core_ICoreInputViewTransferringXYFocusEventArgs<D>::TransferHandled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::Core::ICoreInputViewTransferringXYFocusEventArgs)->get_TransferHandled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_ViewManagement_Core_ICoreInputViewTransferringXYFocusEventArgs<D>::KeepPrimaryViewVisible(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::Core::ICoreInputViewTransferringXYFocusEventArgs)->put_KeepPrimaryViewVisible(value));
}

template <typename D> bool consume_Windows_UI_ViewManagement_Core_ICoreInputViewTransferringXYFocusEventArgs<D>::KeepPrimaryViewVisible() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::ViewManagement::Core::ICoreInputViewTransferringXYFocusEventArgs)->get_KeepPrimaryViewVisible(&value));
    return value;
}

template <typename D>
struct produce<D, Windows::UI::ViewManagement::Core::ICoreInputView> : produce_base<D, Windows::UI::ViewManagement::Core::ICoreInputView>
{
    int32_t WINRT_CALL add_OcclusionsChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OcclusionsChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::Core::CoreInputView, Windows::UI::ViewManagement::Core::CoreInputViewOcclusionsChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().OcclusionsChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::Core::CoreInputView, Windows::UI::ViewManagement::Core::CoreInputViewOcclusionsChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_OcclusionsChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(OcclusionsChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().OcclusionsChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL GetCoreInputViewOcclusions(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCoreInputViewOcclusions, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::UI::ViewManagement::Core::CoreInputViewOcclusion>));
            *result = detach_from<Windows::Foundation::Collections::IVectorView<Windows::UI::ViewManagement::Core::CoreInputViewOcclusion>>(this->shim().GetCoreInputViewOcclusions());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryShowPrimaryView(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryShowPrimaryView, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().TryShowPrimaryView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryHidePrimaryView(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryHidePrimaryView, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().TryHidePrimaryView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::ViewManagement::Core::ICoreInputView2> : produce_base<D, Windows::UI::ViewManagement::Core::ICoreInputView2>
{
    int32_t WINRT_CALL add_XYFocusTransferringFromPrimaryView(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XYFocusTransferringFromPrimaryView, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::Core::CoreInputView, Windows::UI::ViewManagement::Core::CoreInputViewTransferringXYFocusEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().XYFocusTransferringFromPrimaryView(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::Core::CoreInputView, Windows::UI::ViewManagement::Core::CoreInputViewTransferringXYFocusEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_XYFocusTransferringFromPrimaryView(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(XYFocusTransferringFromPrimaryView, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().XYFocusTransferringFromPrimaryView(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_XYFocusTransferredToPrimaryView(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XYFocusTransferredToPrimaryView, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::Core::CoreInputView, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().XYFocusTransferredToPrimaryView(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::ViewManagement::Core::CoreInputView, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_XYFocusTransferredToPrimaryView(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(XYFocusTransferredToPrimaryView, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().XYFocusTransferredToPrimaryView(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL TryTransferXYFocusToPrimaryView(Windows::Foundation::Rect origin, Windows::UI::ViewManagement::Core::CoreInputViewXYFocusTransferDirection direction, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryTransferXYFocusToPrimaryView, WINRT_WRAP(bool), Windows::Foundation::Rect const&, Windows::UI::ViewManagement::Core::CoreInputViewXYFocusTransferDirection const&);
            *result = detach_from<bool>(this->shim().TryTransferXYFocusToPrimaryView(*reinterpret_cast<Windows::Foundation::Rect const*>(&origin), *reinterpret_cast<Windows::UI::ViewManagement::Core::CoreInputViewXYFocusTransferDirection const*>(&direction)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::ViewManagement::Core::ICoreInputView3> : produce_base<D, Windows::UI::ViewManagement::Core::ICoreInputView3>
{
    int32_t WINRT_CALL TryShow(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryShow, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().TryShow());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryShowWithKind(Windows::UI::ViewManagement::Core::CoreInputViewKind type, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryShow, WINRT_WRAP(bool), Windows::UI::ViewManagement::Core::CoreInputViewKind const&);
            *result = detach_from<bool>(this->shim().TryShow(*reinterpret_cast<Windows::UI::ViewManagement::Core::CoreInputViewKind const*>(&type)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryHide(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryHide, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().TryHide());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::ViewManagement::Core::ICoreInputViewOcclusion> : produce_base<D, Windows::UI::ViewManagement::Core::ICoreInputViewOcclusion>
{
    int32_t WINRT_CALL get_OccludingRect(Windows::Foundation::Rect* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OccludingRect, WINRT_WRAP(Windows::Foundation::Rect));
            *value = detach_from<Windows::Foundation::Rect>(this->shim().OccludingRect());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OcclusionKind(Windows::UI::ViewManagement::Core::CoreInputViewOcclusionKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OcclusionKind, WINRT_WRAP(Windows::UI::ViewManagement::Core::CoreInputViewOcclusionKind));
            *value = detach_from<Windows::UI::ViewManagement::Core::CoreInputViewOcclusionKind>(this->shim().OcclusionKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::ViewManagement::Core::ICoreInputViewOcclusionsChangedEventArgs> : produce_base<D, Windows::UI::ViewManagement::Core::ICoreInputViewOcclusionsChangedEventArgs>
{
    int32_t WINRT_CALL get_Occlusions(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Occlusions, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::UI::ViewManagement::Core::CoreInputViewOcclusion>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::UI::ViewManagement::Core::CoreInputViewOcclusion>>(this->shim().Occlusions());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Handled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Handled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Handled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Handled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Handled, WINRT_WRAP(void), bool);
            this->shim().Handled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::ViewManagement::Core::ICoreInputViewStatics> : produce_base<D, Windows::UI::ViewManagement::Core::ICoreInputViewStatics>
{
    int32_t WINRT_CALL GetForCurrentView(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForCurrentView, WINRT_WRAP(Windows::UI::ViewManagement::Core::CoreInputView));
            *result = detach_from<Windows::UI::ViewManagement::Core::CoreInputView>(this->shim().GetForCurrentView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::ViewManagement::Core::ICoreInputViewStatics2> : produce_base<D, Windows::UI::ViewManagement::Core::ICoreInputViewStatics2>
{
    int32_t WINRT_CALL GetForUIContext(void* context, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForUIContext, WINRT_WRAP(Windows::UI::ViewManagement::Core::CoreInputView), Windows::UI::UIContext const&);
            *result = detach_from<Windows::UI::ViewManagement::Core::CoreInputView>(this->shim().GetForUIContext(*reinterpret_cast<Windows::UI::UIContext const*>(&context)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::ViewManagement::Core::ICoreInputViewTransferringXYFocusEventArgs> : produce_base<D, Windows::UI::ViewManagement::Core::ICoreInputViewTransferringXYFocusEventArgs>
{
    int32_t WINRT_CALL get_Origin(Windows::Foundation::Rect* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Origin, WINRT_WRAP(Windows::Foundation::Rect));
            *value = detach_from<Windows::Foundation::Rect>(this->shim().Origin());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Direction(Windows::UI::ViewManagement::Core::CoreInputViewXYFocusTransferDirection* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Direction, WINRT_WRAP(Windows::UI::ViewManagement::Core::CoreInputViewXYFocusTransferDirection));
            *value = detach_from<Windows::UI::ViewManagement::Core::CoreInputViewXYFocusTransferDirection>(this->shim().Direction());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TransferHandled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransferHandled, WINRT_WRAP(void), bool);
            this->shim().TransferHandled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TransferHandled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransferHandled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().TransferHandled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_KeepPrimaryViewVisible(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeepPrimaryViewVisible, WINRT_WRAP(void), bool);
            this->shim().KeepPrimaryViewVisible(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_KeepPrimaryViewVisible(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeepPrimaryViewVisible, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().KeepPrimaryViewVisible());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::UI::ViewManagement::Core {

inline Windows::UI::ViewManagement::Core::CoreInputView CoreInputView::GetForCurrentView()
{
    return impl::call_factory<CoreInputView, Windows::UI::ViewManagement::Core::ICoreInputViewStatics>([&](auto&& f) { return f.GetForCurrentView(); });
}

inline Windows::UI::ViewManagement::Core::CoreInputView CoreInputView::GetForUIContext(Windows::UI::UIContext const& context)
{
    return impl::call_factory<CoreInputView, Windows::UI::ViewManagement::Core::ICoreInputViewStatics2>([&](auto&& f) { return f.GetForUIContext(context); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::UI::ViewManagement::Core::ICoreInputView> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::Core::ICoreInputView> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::Core::ICoreInputView2> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::Core::ICoreInputView2> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::Core::ICoreInputView3> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::Core::ICoreInputView3> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::Core::ICoreInputViewOcclusion> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::Core::ICoreInputViewOcclusion> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::Core::ICoreInputViewOcclusionsChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::Core::ICoreInputViewOcclusionsChangedEventArgs> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::Core::ICoreInputViewStatics> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::Core::ICoreInputViewStatics> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::Core::ICoreInputViewStatics2> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::Core::ICoreInputViewStatics2> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::Core::ICoreInputViewTransferringXYFocusEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::Core::ICoreInputViewTransferringXYFocusEventArgs> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::Core::CoreInputView> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::Core::CoreInputView> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::Core::CoreInputViewOcclusion> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::Core::CoreInputViewOcclusion> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::Core::CoreInputViewOcclusionsChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::Core::CoreInputViewOcclusionsChangedEventArgs> {};
template<> struct hash<winrt::Windows::UI::ViewManagement::Core::CoreInputViewTransferringXYFocusEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::ViewManagement::Core::CoreInputViewTransferringXYFocusEventArgs> {};

}
