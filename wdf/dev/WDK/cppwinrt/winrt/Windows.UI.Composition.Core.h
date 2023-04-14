// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.UI.Composition.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.UI.Composition.Core.2.h"
#include "winrt/Windows.UI.Composition.h"

namespace winrt::impl {

template <typename D> Windows::UI::Composition::Compositor consume_Windows_UI_Composition_Core_ICompositorController<D>::Compositor() const
{
    Windows::UI::Composition::Compositor value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Core::ICompositorController)->get_Compositor(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Composition_Core_ICompositorController<D>::Commit() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Core::ICompositorController)->Commit());
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_UI_Composition_Core_ICompositorController<D>::EnsurePreviousCommitCompletedAsync() const
{
    Windows::Foundation::IAsyncAction action{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Core::ICompositorController)->EnsurePreviousCommitCompletedAsync(put_abi(action)));
    return action;
}

template <typename D> winrt::event_token consume_Windows_UI_Composition_Core_ICompositorController<D>::CommitNeeded(Windows::Foundation::TypedEventHandler<Windows::UI::Composition::Core::CompositorController, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Composition::Core::ICompositorController)->add_CommitNeeded(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Composition_Core_ICompositorController<D>::CommitNeeded_revoker consume_Windows_UI_Composition_Core_ICompositorController<D>::CommitNeeded(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Composition::Core::CompositorController, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, CommitNeeded_revoker>(this, CommitNeeded(handler));
}

template <typename D> void consume_Windows_UI_Composition_Core_ICompositorController<D>::CommitNeeded(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Composition::Core::ICompositorController)->remove_CommitNeeded(get_abi(token)));
}

template <typename D>
struct produce<D, Windows::UI::Composition::Core::ICompositorController> : produce_base<D, Windows::UI::Composition::Core::ICompositorController>
{
    int32_t WINRT_CALL get_Compositor(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Compositor, WINRT_WRAP(Windows::UI::Composition::Compositor));
            *value = detach_from<Windows::UI::Composition::Compositor>(this->shim().Compositor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Commit() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Commit, WINRT_WRAP(void));
            this->shim().Commit();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL EnsurePreviousCommitCompletedAsync(void** action) noexcept final
    {
        try
        {
            *action = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnsurePreviousCommitCompletedAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *action = detach_from<Windows::Foundation::IAsyncAction>(this->shim().EnsurePreviousCommitCompletedAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_CommitNeeded(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CommitNeeded, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Composition::Core::CompositorController, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().CommitNeeded(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Composition::Core::CompositorController, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_CommitNeeded(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(CommitNeeded, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().CommitNeeded(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

}

WINRT_EXPORT namespace winrt::Windows::UI::Composition::Core {

inline CompositorController::CompositorController() :
    CompositorController(impl::call_factory<CompositorController>([](auto&& f) { return f.template ActivateInstance<CompositorController>(); }))
{}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::UI::Composition::Core::ICompositorController> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Core::ICompositorController> {};
template<> struct hash<winrt::Windows::UI::Composition::Core::CompositorController> : winrt::impl::hash_base<winrt::Windows::UI::Composition::Core::CompositorController> {};

}
