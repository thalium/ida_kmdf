// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Storage.2.h"
#include "winrt/impl/Windows.Management.Core.2.h"
#include "winrt/Windows.Management.h"

namespace winrt::impl {

template <typename D> Windows::Storage::ApplicationData consume_Windows_Management_Core_IApplicationDataManagerStatics<D>::CreateForPackageFamily(param::hstring const& packageFamilyName) const
{
    Windows::Storage::ApplicationData applicationData{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Management::Core::IApplicationDataManagerStatics)->CreateForPackageFamily(get_abi(packageFamilyName), put_abi(applicationData)));
    return applicationData;
}

template <typename D>
struct produce<D, Windows::Management::Core::IApplicationDataManager> : produce_base<D, Windows::Management::Core::IApplicationDataManager>
{};

template <typename D>
struct produce<D, Windows::Management::Core::IApplicationDataManagerStatics> : produce_base<D, Windows::Management::Core::IApplicationDataManagerStatics>
{
    int32_t WINRT_CALL CreateForPackageFamily(void* packageFamilyName, void** applicationData) noexcept final
    {
        try
        {
            *applicationData = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateForPackageFamily, WINRT_WRAP(Windows::Storage::ApplicationData), hstring const&);
            *applicationData = detach_from<Windows::Storage::ApplicationData>(this->shim().CreateForPackageFamily(*reinterpret_cast<hstring const*>(&packageFamilyName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Management::Core {

inline Windows::Storage::ApplicationData ApplicationDataManager::CreateForPackageFamily(param::hstring const& packageFamilyName)
{
    return impl::call_factory<ApplicationDataManager, Windows::Management::Core::IApplicationDataManagerStatics>([&](auto&& f) { return f.CreateForPackageFamily(packageFamilyName); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Management::Core::IApplicationDataManager> : winrt::impl::hash_base<winrt::Windows::Management::Core::IApplicationDataManager> {};
template<> struct hash<winrt::Windows::Management::Core::IApplicationDataManagerStatics> : winrt::impl::hash_base<winrt::Windows::Management::Core::IApplicationDataManagerStatics> {};
template<> struct hash<winrt::Windows::Management::Core::ApplicationDataManager> : winrt::impl::hash_base<winrt::Windows::Management::Core::ApplicationDataManager> {};

}
