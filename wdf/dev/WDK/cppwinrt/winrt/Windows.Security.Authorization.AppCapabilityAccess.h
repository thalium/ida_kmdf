// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.Security.Authorization.AppCapabilityAccess.2.h"

namespace winrt::impl {

template <typename D> hstring consume_Windows_Security_Authorization_AppCapabilityAccess_IAppCapability<D>::CapabilityName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Authorization::AppCapabilityAccess::IAppCapability)->get_CapabilityName(put_abi(value)));
    return value;
}

template <typename D> Windows::System::User consume_Windows_Security_Authorization_AppCapabilityAccess_IAppCapability<D>::User() const
{
    Windows::System::User value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authorization::AppCapabilityAccess::IAppCapability)->get_User(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::Authorization::AppCapabilityAccess::AppCapabilityAccessStatus> consume_Windows_Security_Authorization_AppCapabilityAccess_IAppCapability<D>::RequestAccessAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::Authorization::AppCapabilityAccess::AppCapabilityAccessStatus> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authorization::AppCapabilityAccess::IAppCapability)->RequestAccessAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Security::Authorization::AppCapabilityAccess::AppCapabilityAccessStatus consume_Windows_Security_Authorization_AppCapabilityAccess_IAppCapability<D>::CheckAccess() const
{
    Windows::Security::Authorization::AppCapabilityAccess::AppCapabilityAccessStatus result{};
    check_hresult(WINRT_SHIM(Windows::Security::Authorization::AppCapabilityAccess::IAppCapability)->CheckAccess(put_abi(result)));
    return result;
}

template <typename D> winrt::event_token consume_Windows_Security_Authorization_AppCapabilityAccess_IAppCapability<D>::AccessChanged(Windows::Foundation::TypedEventHandler<Windows::Security::Authorization::AppCapabilityAccess::AppCapability, Windows::Security::Authorization::AppCapabilityAccess::AppCapabilityAccessChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Security::Authorization::AppCapabilityAccess::IAppCapability)->add_AccessChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Security_Authorization_AppCapabilityAccess_IAppCapability<D>::AccessChanged_revoker consume_Windows_Security_Authorization_AppCapabilityAccess_IAppCapability<D>::AccessChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Security::Authorization::AppCapabilityAccess::AppCapability, Windows::Security::Authorization::AppCapabilityAccess::AppCapabilityAccessChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, AccessChanged_revoker>(this, AccessChanged(handler));
}

template <typename D> void consume_Windows_Security_Authorization_AppCapabilityAccess_IAppCapability<D>::AccessChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Security::Authorization::AppCapabilityAccess::IAppCapability)->remove_AccessChanged(get_abi(token)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IMapView<hstring, Windows::Security::Authorization::AppCapabilityAccess::AppCapabilityAccessStatus>> consume_Windows_Security_Authorization_AppCapabilityAccess_IAppCapabilityStatics<D>::RequestAccessForCapabilitiesAsync(param::async_iterable<hstring> const& capabilityNames) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IMapView<hstring, Windows::Security::Authorization::AppCapabilityAccess::AppCapabilityAccessStatus>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authorization::AppCapabilityAccess::IAppCapabilityStatics)->RequestAccessForCapabilitiesAsync(get_abi(capabilityNames), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IMapView<hstring, Windows::Security::Authorization::AppCapabilityAccess::AppCapabilityAccessStatus>> consume_Windows_Security_Authorization_AppCapabilityAccess_IAppCapabilityStatics<D>::RequestAccessForCapabilitiesForUserAsync(Windows::System::User const& user, param::async_iterable<hstring> const& capabilityNames) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IMapView<hstring, Windows::Security::Authorization::AppCapabilityAccess::AppCapabilityAccessStatus>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authorization::AppCapabilityAccess::IAppCapabilityStatics)->RequestAccessForCapabilitiesForUserAsync(get_abi(user), get_abi(capabilityNames), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Security::Authorization::AppCapabilityAccess::AppCapability consume_Windows_Security_Authorization_AppCapabilityAccess_IAppCapabilityStatics<D>::Create(param::hstring const& capabilityName) const
{
    Windows::Security::Authorization::AppCapabilityAccess::AppCapability result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authorization::AppCapabilityAccess::IAppCapabilityStatics)->Create(get_abi(capabilityName), put_abi(result)));
    return result;
}

template <typename D> Windows::Security::Authorization::AppCapabilityAccess::AppCapability consume_Windows_Security_Authorization_AppCapabilityAccess_IAppCapabilityStatics<D>::CreateWithProcessIdForUser(Windows::System::User const& user, param::hstring const& capabilityName, uint32_t pid) const
{
    Windows::Security::Authorization::AppCapabilityAccess::AppCapability result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authorization::AppCapabilityAccess::IAppCapabilityStatics)->CreateWithProcessIdForUser(get_abi(user), get_abi(capabilityName), pid, put_abi(result)));
    return result;
}

template <typename D>
struct produce<D, Windows::Security::Authorization::AppCapabilityAccess::IAppCapability> : produce_base<D, Windows::Security::Authorization::AppCapabilityAccess::IAppCapability>
{
    int32_t WINRT_CALL get_CapabilityName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CapabilityName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().CapabilityName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_User(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(User, WINRT_WRAP(Windows::System::User));
            *value = detach_from<Windows::System::User>(this->shim().User());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestAccessAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestAccessAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::Authorization::AppCapabilityAccess::AppCapabilityAccessStatus>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::Authorization::AppCapabilityAccess::AppCapabilityAccessStatus>>(this->shim().RequestAccessAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CheckAccess(Windows::Security::Authorization::AppCapabilityAccess::AppCapabilityAccessStatus* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CheckAccess, WINRT_WRAP(Windows::Security::Authorization::AppCapabilityAccess::AppCapabilityAccessStatus));
            *result = detach_from<Windows::Security::Authorization::AppCapabilityAccess::AppCapabilityAccessStatus>(this->shim().CheckAccess());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_AccessChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AccessChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Security::Authorization::AppCapabilityAccess::AppCapability, Windows::Security::Authorization::AppCapabilityAccess::AppCapabilityAccessChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().AccessChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Security::Authorization::AppCapabilityAccess::AppCapability, Windows::Security::Authorization::AppCapabilityAccess::AppCapabilityAccessChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_AccessChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(AccessChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().AccessChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Security::Authorization::AppCapabilityAccess::IAppCapabilityAccessChangedEventArgs> : produce_base<D, Windows::Security::Authorization::AppCapabilityAccess::IAppCapabilityAccessChangedEventArgs>
{};

template <typename D>
struct produce<D, Windows::Security::Authorization::AppCapabilityAccess::IAppCapabilityStatics> : produce_base<D, Windows::Security::Authorization::AppCapabilityAccess::IAppCapabilityStatics>
{
    int32_t WINRT_CALL RequestAccessForCapabilitiesAsync(void* capabilityNames, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestAccessForCapabilitiesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IMapView<hstring, Windows::Security::Authorization::AppCapabilityAccess::AppCapabilityAccessStatus>>), Windows::Foundation::Collections::IIterable<hstring> const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IMapView<hstring, Windows::Security::Authorization::AppCapabilityAccess::AppCapabilityAccessStatus>>>(this->shim().RequestAccessForCapabilitiesAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&capabilityNames)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestAccessForCapabilitiesForUserAsync(void* user, void* capabilityNames, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestAccessForCapabilitiesForUserAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IMapView<hstring, Windows::Security::Authorization::AppCapabilityAccess::AppCapabilityAccessStatus>>), Windows::System::User const, Windows::Foundation::Collections::IIterable<hstring> const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IMapView<hstring, Windows::Security::Authorization::AppCapabilityAccess::AppCapabilityAccessStatus>>>(this->shim().RequestAccessForCapabilitiesForUserAsync(*reinterpret_cast<Windows::System::User const*>(&user), *reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&capabilityNames)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Create(void* capabilityName, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Security::Authorization::AppCapabilityAccess::AppCapability), hstring const&);
            *result = detach_from<Windows::Security::Authorization::AppCapabilityAccess::AppCapability>(this->shim().Create(*reinterpret_cast<hstring const*>(&capabilityName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithProcessIdForUser(void* user, void* capabilityName, uint32_t pid, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithProcessIdForUser, WINRT_WRAP(Windows::Security::Authorization::AppCapabilityAccess::AppCapability), Windows::System::User const&, hstring const&, uint32_t);
            *result = detach_from<Windows::Security::Authorization::AppCapabilityAccess::AppCapability>(this->shim().CreateWithProcessIdForUser(*reinterpret_cast<Windows::System::User const*>(&user), *reinterpret_cast<hstring const*>(&capabilityName), pid));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Security::Authorization::AppCapabilityAccess {

inline Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IMapView<hstring, Windows::Security::Authorization::AppCapabilityAccess::AppCapabilityAccessStatus>> AppCapability::RequestAccessForCapabilitiesAsync(param::async_iterable<hstring> const& capabilityNames)
{
    return impl::call_factory<AppCapability, Windows::Security::Authorization::AppCapabilityAccess::IAppCapabilityStatics>([&](auto&& f) { return f.RequestAccessForCapabilitiesAsync(capabilityNames); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IMapView<hstring, Windows::Security::Authorization::AppCapabilityAccess::AppCapabilityAccessStatus>> AppCapability::RequestAccessForCapabilitiesForUserAsync(Windows::System::User const& user, param::async_iterable<hstring> const& capabilityNames)
{
    return impl::call_factory<AppCapability, Windows::Security::Authorization::AppCapabilityAccess::IAppCapabilityStatics>([&](auto&& f) { return f.RequestAccessForCapabilitiesForUserAsync(user, capabilityNames); });
}

inline Windows::Security::Authorization::AppCapabilityAccess::AppCapability AppCapability::Create(param::hstring const& capabilityName)
{
    return impl::call_factory<AppCapability, Windows::Security::Authorization::AppCapabilityAccess::IAppCapabilityStatics>([&](auto&& f) { return f.Create(capabilityName); });
}

inline Windows::Security::Authorization::AppCapabilityAccess::AppCapability AppCapability::CreateWithProcessIdForUser(Windows::System::User const& user, param::hstring const& capabilityName, uint32_t pid)
{
    return impl::call_factory<AppCapability, Windows::Security::Authorization::AppCapabilityAccess::IAppCapabilityStatics>([&](auto&& f) { return f.CreateWithProcessIdForUser(user, capabilityName, pid); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Security::Authorization::AppCapabilityAccess::IAppCapability> : winrt::impl::hash_base<winrt::Windows::Security::Authorization::AppCapabilityAccess::IAppCapability> {};
template<> struct hash<winrt::Windows::Security::Authorization::AppCapabilityAccess::IAppCapabilityAccessChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Security::Authorization::AppCapabilityAccess::IAppCapabilityAccessChangedEventArgs> {};
template<> struct hash<winrt::Windows::Security::Authorization::AppCapabilityAccess::IAppCapabilityStatics> : winrt::impl::hash_base<winrt::Windows::Security::Authorization::AppCapabilityAccess::IAppCapabilityStatics> {};
template<> struct hash<winrt::Windows::Security::Authorization::AppCapabilityAccess::AppCapability> : winrt::impl::hash_base<winrt::Windows::Security::Authorization::AppCapabilityAccess::AppCapability> {};
template<> struct hash<winrt::Windows::Security::Authorization::AppCapabilityAccess::AppCapabilityAccessChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Security::Authorization::AppCapabilityAccess::AppCapabilityAccessChangedEventArgs> {};

}
