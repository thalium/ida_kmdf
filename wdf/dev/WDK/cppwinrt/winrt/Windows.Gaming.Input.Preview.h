// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Gaming.Input.Custom.2.h"
#include "winrt/impl/Windows.Gaming.Input.Preview.2.h"
#include "winrt/Windows.Gaming.Input.h"

namespace winrt::impl {

template <typename D> hstring consume_Windows_Gaming_Input_Preview_IGameControllerProviderInfoStatics<D>::GetParentProviderId(Windows::Gaming::Input::Custom::IGameControllerProvider const& provider) const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::Preview::IGameControllerProviderInfoStatics)->GetParentProviderId(get_abi(provider), put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Gaming_Input_Preview_IGameControllerProviderInfoStatics<D>::GetProviderId(Windows::Gaming::Input::Custom::IGameControllerProvider const& provider) const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::Preview::IGameControllerProviderInfoStatics)->GetProviderId(get_abi(provider), put_abi(value)));
    return value;
}

template <typename D>
struct produce<D, Windows::Gaming::Input::Preview::IGameControllerProviderInfoStatics> : produce_base<D, Windows::Gaming::Input::Preview::IGameControllerProviderInfoStatics>
{
    int32_t WINRT_CALL GetParentProviderId(void* provider, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetParentProviderId, WINRT_WRAP(hstring), Windows::Gaming::Input::Custom::IGameControllerProvider const&);
            *value = detach_from<hstring>(this->shim().GetParentProviderId(*reinterpret_cast<Windows::Gaming::Input::Custom::IGameControllerProvider const*>(&provider)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetProviderId(void* provider, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetProviderId, WINRT_WRAP(hstring), Windows::Gaming::Input::Custom::IGameControllerProvider const&);
            *value = detach_from<hstring>(this->shim().GetProviderId(*reinterpret_cast<Windows::Gaming::Input::Custom::IGameControllerProvider const*>(&provider)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Gaming::Input::Preview {

inline hstring GameControllerProviderInfo::GetParentProviderId(Windows::Gaming::Input::Custom::IGameControllerProvider const& provider)
{
    return impl::call_factory<GameControllerProviderInfo, Windows::Gaming::Input::Preview::IGameControllerProviderInfoStatics>([&](auto&& f) { return f.GetParentProviderId(provider); });
}

inline hstring GameControllerProviderInfo::GetProviderId(Windows::Gaming::Input::Custom::IGameControllerProvider const& provider)
{
    return impl::call_factory<GameControllerProviderInfo, Windows::Gaming::Input::Preview::IGameControllerProviderInfoStatics>([&](auto&& f) { return f.GetProviderId(provider); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Gaming::Input::Preview::IGameControllerProviderInfoStatics> : winrt::impl::hash_base<winrt::Windows::Gaming::Input::Preview::IGameControllerProviderInfoStatics> {};
template<> struct hash<winrt::Windows::Gaming::Input::Preview::GameControllerProviderInfo> : winrt::impl::hash_base<winrt::Windows::Gaming::Input::Preview::GameControllerProviderInfo> {};

}
