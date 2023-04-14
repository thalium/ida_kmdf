// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Management.Workplace.2.h"
#include "winrt/Windows.Management.h"

namespace winrt::impl {

template <typename D> bool consume_Windows_Management_Workplace_IMdmAllowPolicyStatics<D>::IsBrowserAllowed() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Management::Workplace::IMdmAllowPolicyStatics)->IsBrowserAllowed(&value));
    return value;
}

template <typename D> bool consume_Windows_Management_Workplace_IMdmAllowPolicyStatics<D>::IsCameraAllowed() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Management::Workplace::IMdmAllowPolicyStatics)->IsCameraAllowed(&value));
    return value;
}

template <typename D> bool consume_Windows_Management_Workplace_IMdmAllowPolicyStatics<D>::IsMicrosoftAccountAllowed() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Management::Workplace::IMdmAllowPolicyStatics)->IsMicrosoftAccountAllowed(&value));
    return value;
}

template <typename D> bool consume_Windows_Management_Workplace_IMdmAllowPolicyStatics<D>::IsStoreAllowed() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Management::Workplace::IMdmAllowPolicyStatics)->IsStoreAllowed(&value));
    return value;
}

template <typename D> Windows::Management::Workplace::MessagingSyncPolicy consume_Windows_Management_Workplace_IMdmPolicyStatics2<D>::GetMessagingSyncPolicy() const
{
    Windows::Management::Workplace::MessagingSyncPolicy value{};
    check_hresult(WINRT_SHIM(Windows::Management::Workplace::IMdmPolicyStatics2)->GetMessagingSyncPolicy(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Management_Workplace_IWorkplaceSettingsStatics<D>::IsMicrosoftAccountOptional() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Management::Workplace::IWorkplaceSettingsStatics)->get_IsMicrosoftAccountOptional(&value));
    return value;
}

template <typename D>
struct produce<D, Windows::Management::Workplace::IMdmAllowPolicyStatics> : produce_base<D, Windows::Management::Workplace::IMdmAllowPolicyStatics>
{
    int32_t WINRT_CALL IsBrowserAllowed(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsBrowserAllowed, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsBrowserAllowed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsCameraAllowed(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsCameraAllowed, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsCameraAllowed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsMicrosoftAccountAllowed(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsMicrosoftAccountAllowed, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsMicrosoftAccountAllowed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsStoreAllowed(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsStoreAllowed, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsStoreAllowed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Management::Workplace::IMdmPolicyStatics2> : produce_base<D, Windows::Management::Workplace::IMdmPolicyStatics2>
{
    int32_t WINRT_CALL GetMessagingSyncPolicy(Windows::Management::Workplace::MessagingSyncPolicy* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetMessagingSyncPolicy, WINRT_WRAP(Windows::Management::Workplace::MessagingSyncPolicy));
            *value = detach_from<Windows::Management::Workplace::MessagingSyncPolicy>(this->shim().GetMessagingSyncPolicy());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Management::Workplace::IWorkplaceSettingsStatics> : produce_base<D, Windows::Management::Workplace::IWorkplaceSettingsStatics>
{
    int32_t WINRT_CALL get_IsMicrosoftAccountOptional(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsMicrosoftAccountOptional, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsMicrosoftAccountOptional());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Management::Workplace {

inline bool MdmPolicy::IsBrowserAllowed()
{
    return impl::call_factory<MdmPolicy, Windows::Management::Workplace::IMdmAllowPolicyStatics>([&](auto&& f) { return f.IsBrowserAllowed(); });
}

inline bool MdmPolicy::IsCameraAllowed()
{
    return impl::call_factory<MdmPolicy, Windows::Management::Workplace::IMdmAllowPolicyStatics>([&](auto&& f) { return f.IsCameraAllowed(); });
}

inline bool MdmPolicy::IsMicrosoftAccountAllowed()
{
    return impl::call_factory<MdmPolicy, Windows::Management::Workplace::IMdmAllowPolicyStatics>([&](auto&& f) { return f.IsMicrosoftAccountAllowed(); });
}

inline bool MdmPolicy::IsStoreAllowed()
{
    return impl::call_factory<MdmPolicy, Windows::Management::Workplace::IMdmAllowPolicyStatics>([&](auto&& f) { return f.IsStoreAllowed(); });
}

inline Windows::Management::Workplace::MessagingSyncPolicy MdmPolicy::GetMessagingSyncPolicy()
{
    return impl::call_factory<MdmPolicy, Windows::Management::Workplace::IMdmPolicyStatics2>([&](auto&& f) { return f.GetMessagingSyncPolicy(); });
}

inline bool WorkplaceSettings::IsMicrosoftAccountOptional()
{
    return impl::call_factory<WorkplaceSettings, Windows::Management::Workplace::IWorkplaceSettingsStatics>([&](auto&& f) { return f.IsMicrosoftAccountOptional(); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Management::Workplace::IMdmAllowPolicyStatics> : winrt::impl::hash_base<winrt::Windows::Management::Workplace::IMdmAllowPolicyStatics> {};
template<> struct hash<winrt::Windows::Management::Workplace::IMdmPolicyStatics2> : winrt::impl::hash_base<winrt::Windows::Management::Workplace::IMdmPolicyStatics2> {};
template<> struct hash<winrt::Windows::Management::Workplace::IWorkplaceSettingsStatics> : winrt::impl::hash_base<winrt::Windows::Management::Workplace::IWorkplaceSettingsStatics> {};
template<> struct hash<winrt::Windows::Management::Workplace::MdmPolicy> : winrt::impl::hash_base<winrt::Windows::Management::Workplace::MdmPolicy> {};
template<> struct hash<winrt::Windows::Management::Workplace::WorkplaceSettings> : winrt::impl::hash_base<winrt::Windows::Management::Workplace::WorkplaceSettings> {};

}
