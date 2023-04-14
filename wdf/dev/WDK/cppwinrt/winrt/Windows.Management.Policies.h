// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.Management.Policies.2.h"
#include "winrt/Windows.Management.h"

namespace winrt::impl {

template <typename D> hstring consume_Windows_Management_Policies_INamedPolicyData<D>::Area() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Management::Policies::INamedPolicyData)->get_Area(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Management_Policies_INamedPolicyData<D>::Name() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Management::Policies::INamedPolicyData)->get_Name(put_abi(value)));
    return value;
}

template <typename D> Windows::Management::Policies::NamedPolicyKind consume_Windows_Management_Policies_INamedPolicyData<D>::Kind() const
{
    Windows::Management::Policies::NamedPolicyKind value{};
    check_hresult(WINRT_SHIM(Windows::Management::Policies::INamedPolicyData)->get_Kind(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Management_Policies_INamedPolicyData<D>::IsManaged() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Management::Policies::INamedPolicyData)->get_IsManaged(&value));
    return value;
}

template <typename D> bool consume_Windows_Management_Policies_INamedPolicyData<D>::IsUserPolicy() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Management::Policies::INamedPolicyData)->get_IsUserPolicy(&value));
    return value;
}

template <typename D> Windows::System::User consume_Windows_Management_Policies_INamedPolicyData<D>::User() const
{
    Windows::System::User value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Policies::INamedPolicyData)->get_User(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Management_Policies_INamedPolicyData<D>::GetBoolean() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::Management::Policies::INamedPolicyData)->GetBoolean(&result));
    return result;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Management_Policies_INamedPolicyData<D>::GetBinary() const
{
    Windows::Storage::Streams::IBuffer result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Policies::INamedPolicyData)->GetBinary(put_abi(result)));
    return result;
}

template <typename D> int32_t consume_Windows_Management_Policies_INamedPolicyData<D>::GetInt32() const
{
    int32_t result{};
    check_hresult(WINRT_SHIM(Windows::Management::Policies::INamedPolicyData)->GetInt32(&result));
    return result;
}

template <typename D> int64_t consume_Windows_Management_Policies_INamedPolicyData<D>::GetInt64() const
{
    int64_t result{};
    check_hresult(WINRT_SHIM(Windows::Management::Policies::INamedPolicyData)->GetInt64(&result));
    return result;
}

template <typename D> hstring consume_Windows_Management_Policies_INamedPolicyData<D>::GetString() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::Management::Policies::INamedPolicyData)->GetString(put_abi(result)));
    return result;
}

template <typename D> winrt::event_token consume_Windows_Management_Policies_INamedPolicyData<D>::Changed(Windows::Foundation::TypedEventHandler<Windows::Management::Policies::NamedPolicyData, Windows::Foundation::IInspectable> const& changedHandler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::Management::Policies::INamedPolicyData)->add_Changed(get_abi(changedHandler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_Management_Policies_INamedPolicyData<D>::Changed_revoker consume_Windows_Management_Policies_INamedPolicyData<D>::Changed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Management::Policies::NamedPolicyData, Windows::Foundation::IInspectable> const& changedHandler) const
{
    return impl::make_event_revoker<D, Changed_revoker>(this, Changed(changedHandler));
}

template <typename D> void consume_Windows_Management_Policies_INamedPolicyData<D>::Changed(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Management::Policies::INamedPolicyData)->remove_Changed(get_abi(cookie)));
}

template <typename D> Windows::Management::Policies::NamedPolicyData consume_Windows_Management_Policies_INamedPolicyStatics<D>::GetPolicyFromPath(param::hstring const& area, param::hstring const& name) const
{
    Windows::Management::Policies::NamedPolicyData result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Policies::INamedPolicyStatics)->GetPolicyFromPath(get_abi(area), get_abi(name), put_abi(result)));
    return result;
}

template <typename D> Windows::Management::Policies::NamedPolicyData consume_Windows_Management_Policies_INamedPolicyStatics<D>::GetPolicyFromPathForUser(Windows::System::User const& user, param::hstring const& area, param::hstring const& name) const
{
    Windows::Management::Policies::NamedPolicyData result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Policies::INamedPolicyStatics)->GetPolicyFromPathForUser(get_abi(user), get_abi(area), get_abi(name), put_abi(result)));
    return result;
}

template <typename D>
struct produce<D, Windows::Management::Policies::INamedPolicyData> : produce_base<D, Windows::Management::Policies::INamedPolicyData>
{
    int32_t WINRT_CALL get_Area(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Area, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Area());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Name(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Name, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Kind(Windows::Management::Policies::NamedPolicyKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Kind, WINRT_WRAP(Windows::Management::Policies::NamedPolicyKind));
            *value = detach_from<Windows::Management::Policies::NamedPolicyKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsManaged(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsManaged, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsManaged());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsUserPolicy(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsUserPolicy, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsUserPolicy());
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

    int32_t WINRT_CALL GetBoolean(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetBoolean, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().GetBoolean());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetBinary(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetBinary, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *result = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().GetBinary());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetInt32(int32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetInt32, WINRT_WRAP(int32_t));
            *result = detach_from<int32_t>(this->shim().GetInt32());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetInt64(int64_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetInt64, WINRT_WRAP(int64_t));
            *result = detach_from<int64_t>(this->shim().GetInt64());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetString(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetString, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().GetString());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_Changed(void* changedHandler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Changed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Management::Policies::NamedPolicyData, Windows::Foundation::IInspectable> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().Changed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Management::Policies::NamedPolicyData, Windows::Foundation::IInspectable> const*>(&changedHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Changed(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Changed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Changed(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Management::Policies::INamedPolicyStatics> : produce_base<D, Windows::Management::Policies::INamedPolicyStatics>
{
    int32_t WINRT_CALL GetPolicyFromPath(void* area, void* name, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetPolicyFromPath, WINRT_WRAP(Windows::Management::Policies::NamedPolicyData), hstring const&, hstring const&);
            *result = detach_from<Windows::Management::Policies::NamedPolicyData>(this->shim().GetPolicyFromPath(*reinterpret_cast<hstring const*>(&area), *reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetPolicyFromPathForUser(void* user, void* area, void* name, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetPolicyFromPathForUser, WINRT_WRAP(Windows::Management::Policies::NamedPolicyData), Windows::System::User const&, hstring const&, hstring const&);
            *result = detach_from<Windows::Management::Policies::NamedPolicyData>(this->shim().GetPolicyFromPathForUser(*reinterpret_cast<Windows::System::User const*>(&user), *reinterpret_cast<hstring const*>(&area), *reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Management::Policies {

inline Windows::Management::Policies::NamedPolicyData NamedPolicy::GetPolicyFromPath(param::hstring const& area, param::hstring const& name)
{
    return impl::call_factory<NamedPolicy, Windows::Management::Policies::INamedPolicyStatics>([&](auto&& f) { return f.GetPolicyFromPath(area, name); });
}

inline Windows::Management::Policies::NamedPolicyData NamedPolicy::GetPolicyFromPathForUser(Windows::System::User const& user, param::hstring const& area, param::hstring const& name)
{
    return impl::call_factory<NamedPolicy, Windows::Management::Policies::INamedPolicyStatics>([&](auto&& f) { return f.GetPolicyFromPathForUser(user, area, name); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Management::Policies::INamedPolicyData> : winrt::impl::hash_base<winrt::Windows::Management::Policies::INamedPolicyData> {};
template<> struct hash<winrt::Windows::Management::Policies::INamedPolicyStatics> : winrt::impl::hash_base<winrt::Windows::Management::Policies::INamedPolicyStatics> {};
template<> struct hash<winrt::Windows::Management::Policies::NamedPolicy> : winrt::impl::hash_base<winrt::Windows::Management::Policies::NamedPolicy> {};
template<> struct hash<winrt::Windows::Management::Policies::NamedPolicyData> : winrt::impl::hash_base<winrt::Windows::Management::Policies::NamedPolicyData> {};

}
