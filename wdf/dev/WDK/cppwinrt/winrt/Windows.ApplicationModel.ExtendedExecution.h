// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.ApplicationModel.ExtendedExecution.2.h"
#include "winrt/Windows.ApplicationModel.h"

namespace winrt::impl {

template <typename D> Windows::ApplicationModel::ExtendedExecution::ExtendedExecutionRevokedReason consume_Windows_ApplicationModel_ExtendedExecution_IExtendedExecutionRevokedEventArgs<D>::Reason() const
{
    Windows::ApplicationModel::ExtendedExecution::ExtendedExecutionRevokedReason value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::ExtendedExecution::IExtendedExecutionRevokedEventArgs)->get_Reason(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::ExtendedExecution::ExtendedExecutionReason consume_Windows_ApplicationModel_ExtendedExecution_IExtendedExecutionSession<D>::Reason() const
{
    Windows::ApplicationModel::ExtendedExecution::ExtendedExecutionReason value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::ExtendedExecution::IExtendedExecutionSession)->get_Reason(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_ExtendedExecution_IExtendedExecutionSession<D>::Reason(Windows::ApplicationModel::ExtendedExecution::ExtendedExecutionReason const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::ExtendedExecution::IExtendedExecutionSession)->put_Reason(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_ExtendedExecution_IExtendedExecutionSession<D>::Description() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::ExtendedExecution::IExtendedExecutionSession)->get_Description(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_ExtendedExecution_IExtendedExecutionSession<D>::Description(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::ExtendedExecution::IExtendedExecutionSession)->put_Description(get_abi(value)));
}

template <typename D> uint32_t consume_Windows_ApplicationModel_ExtendedExecution_IExtendedExecutionSession<D>::PercentProgress() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::ExtendedExecution::IExtendedExecutionSession)->get_PercentProgress(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_ExtendedExecution_IExtendedExecutionSession<D>::PercentProgress(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::ExtendedExecution::IExtendedExecutionSession)->put_PercentProgress(value));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_ExtendedExecution_IExtendedExecutionSession<D>::Revoked(Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::ApplicationModel::ExtendedExecution::ExtendedExecutionRevokedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::ExtendedExecution::IExtendedExecutionSession)->add_Revoked(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_ExtendedExecution_IExtendedExecutionSession<D>::Revoked_revoker consume_Windows_ApplicationModel_ExtendedExecution_IExtendedExecutionSession<D>::Revoked(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::ApplicationModel::ExtendedExecution::ExtendedExecutionRevokedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Revoked_revoker>(this, Revoked(handler));
}

template <typename D> void consume_Windows_ApplicationModel_ExtendedExecution_IExtendedExecutionSession<D>::Revoked(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::ExtendedExecution::IExtendedExecutionSession)->remove_Revoked(get_abi(token)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::ExtendedExecution::ExtendedExecutionResult> consume_Windows_ApplicationModel_ExtendedExecution_IExtendedExecutionSession<D>::RequestExtensionAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::ExtendedExecution::ExtendedExecutionResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::ExtendedExecution::IExtendedExecutionSession)->RequestExtensionAsync(put_abi(operation)));
    return operation;
}

template <typename D>
struct produce<D, Windows::ApplicationModel::ExtendedExecution::IExtendedExecutionRevokedEventArgs> : produce_base<D, Windows::ApplicationModel::ExtendedExecution::IExtendedExecutionRevokedEventArgs>
{
    int32_t WINRT_CALL get_Reason(Windows::ApplicationModel::ExtendedExecution::ExtendedExecutionRevokedReason* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Reason, WINRT_WRAP(Windows::ApplicationModel::ExtendedExecution::ExtendedExecutionRevokedReason));
            *value = detach_from<Windows::ApplicationModel::ExtendedExecution::ExtendedExecutionRevokedReason>(this->shim().Reason());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::ExtendedExecution::IExtendedExecutionSession> : produce_base<D, Windows::ApplicationModel::ExtendedExecution::IExtendedExecutionSession>
{
    int32_t WINRT_CALL get_Reason(Windows::ApplicationModel::ExtendedExecution::ExtendedExecutionReason* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Reason, WINRT_WRAP(Windows::ApplicationModel::ExtendedExecution::ExtendedExecutionReason));
            *value = detach_from<Windows::ApplicationModel::ExtendedExecution::ExtendedExecutionReason>(this->shim().Reason());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Reason(Windows::ApplicationModel::ExtendedExecution::ExtendedExecutionReason value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Reason, WINRT_WRAP(void), Windows::ApplicationModel::ExtendedExecution::ExtendedExecutionReason const&);
            this->shim().Reason(*reinterpret_cast<Windows::ApplicationModel::ExtendedExecution::ExtendedExecutionReason const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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

    int32_t WINRT_CALL get_PercentProgress(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PercentProgress, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().PercentProgress());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PercentProgress(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PercentProgress, WINRT_WRAP(void), uint32_t);
            this->shim().PercentProgress(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_Revoked(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Revoked, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::ApplicationModel::ExtendedExecution::ExtendedExecutionRevokedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Revoked(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Foundation::IInspectable, Windows::ApplicationModel::ExtendedExecution::ExtendedExecutionRevokedEventArgs> const*>(&handler)));
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
            WINRT_ASSERT_DECLARATION(RequestExtensionAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::ExtendedExecution::ExtendedExecutionResult>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::ExtendedExecution::ExtendedExecutionResult>>(this->shim().RequestExtensionAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::ExtendedExecution {

inline ExtendedExecutionSession::ExtendedExecutionSession() :
    ExtendedExecutionSession(impl::call_factory<ExtendedExecutionSession>([](auto&& f) { return f.template ActivateInstance<ExtendedExecutionSession>(); }))
{}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::ApplicationModel::ExtendedExecution::IExtendedExecutionRevokedEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::ExtendedExecution::IExtendedExecutionRevokedEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::ExtendedExecution::IExtendedExecutionSession> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::ExtendedExecution::IExtendedExecutionSession> {};
template<> struct hash<winrt::Windows::ApplicationModel::ExtendedExecution::ExtendedExecutionRevokedEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::ExtendedExecution::ExtendedExecutionRevokedEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::ExtendedExecution::ExtendedExecutionSession> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::ExtendedExecution::ExtendedExecutionSession> {};

}
