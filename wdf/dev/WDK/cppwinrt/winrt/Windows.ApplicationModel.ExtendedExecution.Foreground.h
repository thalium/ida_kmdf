// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.ApplicationModel.ExtendedExecution.Foreground.2.h"
#include "winrt/Windows.ApplicationModel.ExtendedExecution.h"

namespace winrt::impl {

template <typename D> Windows::ApplicationModel::ExtendedExecution::Foreground::ExtendedExecutionForegroundRevokedReason consume_Windows_ApplicationModel_ExtendedExecution_Foreground_IExtendedExecutionForegroundRevokedEventArgs<D>::Reason() const
{
    Windows::ApplicationModel::ExtendedExecution::Foreground::ExtendedExecutionForegroundRevokedReason value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::ExtendedExecution::Foreground::IExtendedExecutionForegroundRevokedEventArgs)->get_Reason(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_ExtendedExecution_Foreground_IExtendedExecutionForegroundSession<D>::Description() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::ExtendedExecution::Foreground::IExtendedExecutionForegroundSession)->get_Description(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_ExtendedExecution_Foreground_IExtendedExecutionForegroundSession<D>::Description(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::ExtendedExecution::Foreground::IExtendedExecutionForegroundSession)->put_Description(get_abi(value)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_ExtendedExecution_Foreground_IExtendedExecutionForegroundSession<D>::Revoked(Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::ApplicationModel::ExtendedExecution::Foreground::ExtendedExecutionForegroundRevokedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::ExtendedExecution::Foreground::IExtendedExecutionForegroundSession)->add_Revoked(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_ExtendedExecution_Foreground_IExtendedExecutionForegroundSession<D>::Revoked_revoker consume_Windows_ApplicationModel_ExtendedExecution_Foreground_IExtendedExecutionForegroundSession<D>::Revoked(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::ApplicationModel::ExtendedExecution::Foreground::ExtendedExecutionForegroundRevokedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Revoked_revoker>(this, Revoked(handler));
}

template <typename D> void consume_Windows_ApplicationModel_ExtendedExecution_Foreground_IExtendedExecutionForegroundSession<D>::Revoked(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::ExtendedExecution::Foreground::IExtendedExecutionForegroundSession)->remove_Revoked(get_abi(token)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::ExtendedExecution::Foreground::ExtendedExecutionForegroundResult> consume_Windows_ApplicationModel_ExtendedExecution_Foreground_IExtendedExecutionForegroundSession<D>::RequestExtensionAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::ExtendedExecution::Foreground::ExtendedExecutionForegroundResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::ExtendedExecution::Foreground::IExtendedExecutionForegroundSession)->RequestExtensionAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::ApplicationModel::ExtendedExecution::Foreground::ExtendedExecutionForegroundReason consume_Windows_ApplicationModel_ExtendedExecution_Foreground_IExtendedExecutionForegroundSession<D>::Reason() const
{
    Windows::ApplicationModel::ExtendedExecution::Foreground::ExtendedExecutionForegroundReason value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::ExtendedExecution::Foreground::IExtendedExecutionForegroundSession)->get_Reason(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_ExtendedExecution_Foreground_IExtendedExecutionForegroundSession<D>::Reason(Windows::ApplicationModel::ExtendedExecution::Foreground::ExtendedExecutionForegroundReason const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::ExtendedExecution::Foreground::IExtendedExecutionForegroundSession)->put_Reason(get_abi(value)));
}

template <typename D>
struct produce<D, Windows::ApplicationModel::ExtendedExecution::Foreground::IExtendedExecutionForegroundRevokedEventArgs> : produce_base<D, Windows::ApplicationModel::ExtendedExecution::Foreground::IExtendedExecutionForegroundRevokedEventArgs>
{
    int32_t WINRT_CALL get_Reason(Windows::ApplicationModel::ExtendedExecution::Foreground::ExtendedExecutionForegroundRevokedReason* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Reason, WINRT_WRAP(Windows::ApplicationModel::ExtendedExecution::Foreground::ExtendedExecutionForegroundRevokedReason));
            *value = detach_from<Windows::ApplicationModel::ExtendedExecution::Foreground::ExtendedExecutionForegroundRevokedReason>(this->shim().Reason());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::ExtendedExecution::Foreground::IExtendedExecutionForegroundSession> : produce_base<D, Windows::ApplicationModel::ExtendedExecution::Foreground::IExtendedExecutionForegroundSession>
{
    int32_t WINRT_CALL get_Description(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Description, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Description());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Description(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Description, WINRT_WRAP(void), hstring const&);
            this->shim().Description(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_Revoked(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Revoked, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::ApplicationModel::ExtendedExecution::Foreground::ExtendedExecutionForegroundRevokedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Revoked(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::ApplicationModel::ExtendedExecution::Foreground::ExtendedExecutionForegroundRevokedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Revoked(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Revoked, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Revoked(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL RequestExtensionAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestExtensionAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::ExtendedExecution::Foreground::ExtendedExecutionForegroundResult>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::ExtendedExecution::Foreground::ExtendedExecutionForegroundResult>>(this->shim().RequestExtensionAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Reason(Windows::ApplicationModel::ExtendedExecution::Foreground::ExtendedExecutionForegroundReason* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Reason, WINRT_WRAP(Windows::ApplicationModel::ExtendedExecution::Foreground::ExtendedExecutionForegroundReason));
            *value = detach_from<Windows::ApplicationModel::ExtendedExecution::Foreground::ExtendedExecutionForegroundReason>(this->shim().Reason());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Reason(Windows::ApplicationModel::ExtendedExecution::Foreground::ExtendedExecutionForegroundReason value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Reason, WINRT_WRAP(void), Windows::ApplicationModel::ExtendedExecution::Foreground::ExtendedExecutionForegroundReason const&);
            this->shim().Reason(*reinterpret_cast<Windows::ApplicationModel::ExtendedExecution::Foreground::ExtendedExecutionForegroundReason const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::ExtendedExecution::Foreground {

inline ExtendedExecutionForegroundSession::ExtendedExecutionForegroundSession() :
    ExtendedExecutionForegroundSession(impl::call_factory<ExtendedExecutionForegroundSession>([](auto&& f) { return f.template ActivateInstance<ExtendedExecutionForegroundSession>(); }))
{}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::ApplicationModel::ExtendedExecution::Foreground::IExtendedExecutionForegroundRevokedEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::ExtendedExecution::Foreground::IExtendedExecutionForegroundRevokedEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::ExtendedExecution::Foreground::IExtendedExecutionForegroundSession> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::ExtendedExecution::Foreground::IExtendedExecutionForegroundSession> {};
template<> struct hash<winrt::Windows::ApplicationModel::ExtendedExecution::Foreground::ExtendedExecutionForegroundRevokedEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::ExtendedExecution::Foreground::ExtendedExecutionForegroundRevokedEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::ExtendedExecution::Foreground::ExtendedExecutionForegroundSession> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::ExtendedExecution::Foreground::ExtendedExecutionForegroundSession> {};

}
