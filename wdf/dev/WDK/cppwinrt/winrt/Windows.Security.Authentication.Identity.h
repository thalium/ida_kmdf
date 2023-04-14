// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Security.Authentication.Identity.2.h"

namespace winrt::impl {

template <typename D> hstring consume_Windows_Security_Authentication_Identity_IEnterpriseKeyCredentialRegistrationInfo<D>::TenantId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Identity::IEnterpriseKeyCredentialRegistrationInfo)->get_TenantId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Authentication_Identity_IEnterpriseKeyCredentialRegistrationInfo<D>::TenantName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Identity::IEnterpriseKeyCredentialRegistrationInfo)->get_TenantName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Authentication_Identity_IEnterpriseKeyCredentialRegistrationInfo<D>::Subject() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Identity::IEnterpriseKeyCredentialRegistrationInfo)->get_Subject(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Authentication_Identity_IEnterpriseKeyCredentialRegistrationInfo<D>::KeyId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Identity::IEnterpriseKeyCredentialRegistrationInfo)->get_KeyId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Authentication_Identity_IEnterpriseKeyCredentialRegistrationInfo<D>::KeyName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Identity::IEnterpriseKeyCredentialRegistrationInfo)->get_KeyName(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Security::Authentication::Identity::EnterpriseKeyCredentialRegistrationInfo>> consume_Windows_Security_Authentication_Identity_IEnterpriseKeyCredentialRegistrationManager<D>::GetRegistrationsAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Security::Authentication::Identity::EnterpriseKeyCredentialRegistrationInfo>> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Identity::IEnterpriseKeyCredentialRegistrationManager)->GetRegistrationsAsync(put_abi(value)));
    return value;
}

template <typename D> Windows::Security::Authentication::Identity::EnterpriseKeyCredentialRegistrationManager consume_Windows_Security_Authentication_Identity_IEnterpriseKeyCredentialRegistrationManagerStatics<D>::Current() const
{
    Windows::Security::Authentication::Identity::EnterpriseKeyCredentialRegistrationManager value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Identity::IEnterpriseKeyCredentialRegistrationManagerStatics)->get_Current(put_abi(value)));
    return value;
}

template <typename D>
struct produce<D, Windows::Security::Authentication::Identity::IEnterpriseKeyCredentialRegistrationInfo> : produce_base<D, Windows::Security::Authentication::Identity::IEnterpriseKeyCredentialRegistrationInfo>
{
    int32_t WINRT_CALL get_TenantId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TenantId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().TenantId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TenantName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TenantName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().TenantName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Subject(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Subject, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Subject());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_KeyId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().KeyId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_KeyName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().KeyName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Authentication::Identity::IEnterpriseKeyCredentialRegistrationManager> : produce_base<D, Windows::Security::Authentication::Identity::IEnterpriseKeyCredentialRegistrationManager>
{
    int32_t WINRT_CALL GetRegistrationsAsync(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetRegistrationsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Security::Authentication::Identity::EnterpriseKeyCredentialRegistrationInfo>>));
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Security::Authentication::Identity::EnterpriseKeyCredentialRegistrationInfo>>>(this->shim().GetRegistrationsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Authentication::Identity::IEnterpriseKeyCredentialRegistrationManagerStatics> : produce_base<D, Windows::Security::Authentication::Identity::IEnterpriseKeyCredentialRegistrationManagerStatics>
{
    int32_t WINRT_CALL get_Current(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Current, WINRT_WRAP(Windows::Security::Authentication::Identity::EnterpriseKeyCredentialRegistrationManager));
            *value = detach_from<Windows::Security::Authentication::Identity::EnterpriseKeyCredentialRegistrationManager>(this->shim().Current());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Security::Authentication::Identity {

inline Windows::Security::Authentication::Identity::EnterpriseKeyCredentialRegistrationManager EnterpriseKeyCredentialRegistrationManager::Current()
{
    return impl::call_factory<EnterpriseKeyCredentialRegistrationManager, Windows::Security::Authentication::Identity::IEnterpriseKeyCredentialRegistrationManagerStatics>([&](auto&& f) { return f.Current(); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Security::Authentication::Identity::IEnterpriseKeyCredentialRegistrationInfo> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Identity::IEnterpriseKeyCredentialRegistrationInfo> {};
template<> struct hash<winrt::Windows::Security::Authentication::Identity::IEnterpriseKeyCredentialRegistrationManager> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Identity::IEnterpriseKeyCredentialRegistrationManager> {};
template<> struct hash<winrt::Windows::Security::Authentication::Identity::IEnterpriseKeyCredentialRegistrationManagerStatics> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Identity::IEnterpriseKeyCredentialRegistrationManagerStatics> {};
template<> struct hash<winrt::Windows::Security::Authentication::Identity::EnterpriseKeyCredentialRegistrationInfo> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Identity::EnterpriseKeyCredentialRegistrationInfo> {};
template<> struct hash<winrt::Windows::Security::Authentication::Identity::EnterpriseKeyCredentialRegistrationManager> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Identity::EnterpriseKeyCredentialRegistrationManager> {};

}
