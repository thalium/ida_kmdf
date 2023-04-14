// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.UI.WindowManagement.2.h"
#include "winrt/impl/Windows.UI.Core.Preview.2.h"
#include "winrt/Windows.UI.Core.h"

namespace winrt::impl {

template <typename D> int32_t consume_Windows_UI_Core_Preview_ICoreAppWindowPreviewStatics<D>::GetIdFromWindow(Windows::UI::WindowManagement::AppWindow const& window) const
{
    int32_t result{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::Preview::ICoreAppWindowPreviewStatics)->GetIdFromWindow(get_abi(window), &result));
    return result;
}

template <typename D> bool consume_Windows_UI_Core_Preview_ISystemNavigationCloseRequestedPreviewEventArgs<D>::Handled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::Preview::ISystemNavigationCloseRequestedPreviewEventArgs)->get_Handled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Core_Preview_ISystemNavigationCloseRequestedPreviewEventArgs<D>::Handled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Core::Preview::ISystemNavigationCloseRequestedPreviewEventArgs)->put_Handled(value));
}

template <typename D> Windows::Foundation::Deferral consume_Windows_UI_Core_Preview_ISystemNavigationCloseRequestedPreviewEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Core::Preview::ISystemNavigationCloseRequestedPreviewEventArgs)->GetDeferral(put_abi(result)));
    return result;
}

template <typename D> winrt::event_token consume_Windows_UI_Core_Preview_ISystemNavigationManagerPreview<D>::CloseRequested(Windows::Foundation::EventHandler<Windows::UI::Core::Preview::SystemNavigationCloseRequestedPreviewEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Core::Preview::ISystemNavigationManagerPreview)->add_CloseRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Core_Preview_ISystemNavigationManagerPreview<D>::CloseRequested_revoker consume_Windows_UI_Core_Preview_ISystemNavigationManagerPreview<D>::CloseRequested(auto_revoke_t, Windows::Foundation::EventHandler<Windows::UI::Core::Preview::SystemNavigationCloseRequestedPreviewEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, CloseRequested_revoker>(this, CloseRequested(handler));
}

template <typename D> void consume_Windows_UI_Core_Preview_ISystemNavigationManagerPreview<D>::CloseRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Core::Preview::ISystemNavigationManagerPreview)->remove_CloseRequested(get_abi(token)));
}

template <typename D> Windows::UI::Core::Preview::SystemNavigationManagerPreview consume_Windows_UI_Core_Preview_ISystemNavigationManagerPreviewStatics<D>::GetForCurrentView() const
{
    Windows::UI::Core::Preview::SystemNavigationManagerPreview loader{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Core::Preview::ISystemNavigationManagerPreviewStatics)->GetForCurrentView(put_abi(loader)));
    return loader;
}

template <typename D>
struct produce<D, Windows::UI::Core::Preview::ICoreAppWindowPreview> : produce_base<D, Windows::UI::Core::Preview::ICoreAppWindowPreview>
{};

template <typename D>
struct produce<D, Windows::UI::Core::Preview::ICoreAppWindowPreviewStatics> : produce_base<D, Windows::UI::Core::Preview::ICoreAppWindowPreviewStatics>
{
    int32_t WINRT_CALL GetIdFromWindow(void* window, int32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetIdFromWindow, WINRT_WRAP(int32_t), Windows::UI::WindowManagement::AppWindow const&);
            *result = detach_from<int32_t>(this->shim().GetIdFromWindow(*reinterpret_cast<Windows::UI::WindowManagement::AppWindow const*>(&window)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Core::Preview::ISystemNavigationCloseRequestedPreviewEventArgs> : produce_base<D, Windows::UI::Core::Preview::ISystemNavigationCloseRequestedPreviewEventArgs>
{
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

    int32_t WINRT_CALL GetDeferral(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeferral, WINRT_WRAP(Windows::Foundation::Deferral));
            *result = detach_from<Windows::Foundation::Deferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Core::Preview::ISystemNavigationManagerPreview> : produce_base<D, Windows::UI::Core::Preview::ISystemNavigationManagerPreview>
{
    int32_t WINRT_CALL add_CloseRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CloseRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::UI::Core::Preview::SystemNavigationCloseRequestedPreviewEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().CloseRequested(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::UI::Core::Preview::SystemNavigationCloseRequestedPreviewEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_CloseRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(CloseRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().CloseRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::Core::Preview::ISystemNavigationManagerPreviewStatics> : produce_base<D, Windows::UI::Core::Preview::ISystemNavigationManagerPreviewStatics>
{
    int32_t WINRT_CALL GetForCurrentView(void** loader) noexcept final
    {
        try
        {
            *loader = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForCurrentView, WINRT_WRAP(Windows::UI::Core::Preview::SystemNavigationManagerPreview));
            *loader = detach_from<Windows::UI::Core::Preview::SystemNavigationManagerPreview>(this->shim().GetForCurrentView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::UI::Core::Preview {

inline int32_t CoreAppWindowPreview::GetIdFromWindow(Windows::UI::WindowManagement::AppWindow const& window)
{
    return impl::call_factory<CoreAppWindowPreview, Windows::UI::Core::Preview::ICoreAppWindowPreviewStatics>([&](auto&& f) { return f.GetIdFromWindow(window); });
}

inline Windows::UI::Core::Preview::SystemNavigationManagerPreview SystemNavigationManagerPreview::GetForCurrentView()
{
    return impl::call_factory<SystemNavigationManagerPreview, Windows::UI::Core::Preview::ISystemNavigationManagerPreviewStatics>([&](auto&& f) { return f.GetForCurrentView(); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::UI::Core::Preview::ICoreAppWindowPreview> : winrt::impl::hash_base<winrt::Windows::UI::Core::Preview::ICoreAppWindowPreview> {};
template<> struct hash<winrt::Windows::UI::Core::Preview::ICoreAppWindowPreviewStatics> : winrt::impl::hash_base<winrt::Windows::UI::Core::Preview::ICoreAppWindowPreviewStatics> {};
template<> struct hash<winrt::Windows::UI::Core::Preview::ISystemNavigationCloseRequestedPreviewEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Core::Preview::ISystemNavigationCloseRequestedPreviewEventArgs> {};
template<> struct hash<winrt::Windows::UI::Core::Preview::ISystemNavigationManagerPreview> : winrt::impl::hash_base<winrt::Windows::UI::Core::Preview::ISystemNavigationManagerPreview> {};
template<> struct hash<winrt::Windows::UI::Core::Preview::ISystemNavigationManagerPreviewStatics> : winrt::impl::hash_base<winrt::Windows::UI::Core::Preview::ISystemNavigationManagerPreviewStatics> {};
template<> struct hash<winrt::Windows::UI::Core::Preview::CoreAppWindowPreview> : winrt::impl::hash_base<winrt::Windows::UI::Core::Preview::CoreAppWindowPreview> {};
template<> struct hash<winrt::Windows::UI::Core::Preview::SystemNavigationCloseRequestedPreviewEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Core::Preview::SystemNavigationCloseRequestedPreviewEventArgs> {};
template<> struct hash<winrt::Windows::UI::Core::Preview::SystemNavigationManagerPreview> : winrt::impl::hash_base<winrt::Windows::UI::Core::Preview::SystemNavigationManagerPreview> {};

}
