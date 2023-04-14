// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Management.Deployment.Preview.2.h"
#include "winrt/Windows.Management.Deployment.h"

namespace winrt::impl {

template <typename D> Windows::Management::Deployment::Preview::InstalledClassicAppInfo consume_Windows_Management_Deployment_Preview_IClassicAppManagerStatics<D>::FindInstalledApp(param::hstring const& appUninstallKey) const
{
    Windows::Management::Deployment::Preview::InstalledClassicAppInfo result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::Preview::IClassicAppManagerStatics)->FindInstalledApp(get_abi(appUninstallKey), put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Management_Deployment_Preview_IInstalledClassicAppInfo<D>::DisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::Preview::IInstalledClassicAppInfo)->get_DisplayName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Management_Deployment_Preview_IInstalledClassicAppInfo<D>::DisplayVersion() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Management::Deployment::Preview::IInstalledClassicAppInfo)->get_DisplayVersion(put_abi(value)));
    return value;
}

template <typename D>
struct produce<D, Windows::Management::Deployment::Preview::IClassicAppManagerStatics> : produce_base<D, Windows::Management::Deployment::Preview::IClassicAppManagerStatics>
{
    int32_t WINRT_CALL FindInstalledApp(void* appUninstallKey, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindInstalledApp, WINRT_WRAP(Windows::Management::Deployment::Preview::InstalledClassicAppInfo), hstring const&);
            *result = detach_from<Windows::Management::Deployment::Preview::InstalledClassicAppInfo>(this->shim().FindInstalledApp(*reinterpret_cast<hstring const*>(&appUninstallKey)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Management::Deployment::Preview::IInstalledClassicAppInfo> : produce_base<D, Windows::Management::Deployment::Preview::IInstalledClassicAppInfo>
{
    int32_t WINRT_CALL get_DisplayName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DisplayName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DisplayVersion(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayVersion, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DisplayVersion());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Management::Deployment::Preview {

inline Windows::Management::Deployment::Preview::InstalledClassicAppInfo ClassicAppManager::FindInstalledApp(param::hstring const& appUninstallKey)
{
    return impl::call_factory<ClassicAppManager, Windows::Management::Deployment::Preview::IClassicAppManagerStatics>([&](auto&& f) { return f.FindInstalledApp(appUninstallKey); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Management::Deployment::Preview::IClassicAppManagerStatics> : winrt::impl::hash_base<winrt::Windows::Management::Deployment::Preview::IClassicAppManagerStatics> {};
template<> struct hash<winrt::Windows::Management::Deployment::Preview::IInstalledClassicAppInfo> : winrt::impl::hash_base<winrt::Windows::Management::Deployment::Preview::IInstalledClassicAppInfo> {};
template<> struct hash<winrt::Windows::Management::Deployment::Preview::ClassicAppManager> : winrt::impl::hash_base<winrt::Windows::Management::Deployment::Preview::ClassicAppManager> {};
template<> struct hash<winrt::Windows::Management::Deployment::Preview::InstalledClassicAppInfo> : winrt::impl::hash_base<winrt::Windows::Management::Deployment::Preview::InstalledClassicAppInfo> {};

}
