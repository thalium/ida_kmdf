// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.System.Inventory.2.h"
#include "winrt/Windows.System.h"

namespace winrt::impl {

template <typename D> hstring consume_Windows_System_Inventory_IInstalledDesktopApp<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::Inventory::IInstalledDesktopApp)->get_Id(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_Inventory_IInstalledDesktopApp<D>::DisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::Inventory::IInstalledDesktopApp)->get_DisplayName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_Inventory_IInstalledDesktopApp<D>::Publisher() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::Inventory::IInstalledDesktopApp)->get_Publisher(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_Inventory_IInstalledDesktopApp<D>::DisplayVersion() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::Inventory::IInstalledDesktopApp)->get_DisplayVersion(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::System::Inventory::InstalledDesktopApp>> consume_Windows_System_Inventory_IInstalledDesktopAppStatics<D>::GetInventoryAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::System::Inventory::InstalledDesktopApp>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Inventory::IInstalledDesktopAppStatics)->GetInventoryAsync(put_abi(operation)));
    return operation;
}

template <typename D>
struct produce<D, Windows::System::Inventory::IInstalledDesktopApp> : produce_base<D, Windows::System::Inventory::IInstalledDesktopApp>
{
    int32_t WINRT_CALL get_Id(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Id, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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

    int32_t WINRT_CALL get_Publisher(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Publisher, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Publisher());
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

template <typename D>
struct produce<D, Windows::System::Inventory::IInstalledDesktopAppStatics> : produce_base<D, Windows::System::Inventory::IInstalledDesktopAppStatics>
{
    int32_t WINRT_CALL GetInventoryAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetInventoryAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::System::Inventory::InstalledDesktopApp>>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::System::Inventory::InstalledDesktopApp>>>(this->shim().GetInventoryAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::System::Inventory {

inline Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::System::Inventory::InstalledDesktopApp>> InstalledDesktopApp::GetInventoryAsync()
{
    return impl::call_factory<InstalledDesktopApp, Windows::System::Inventory::IInstalledDesktopAppStatics>([&](auto&& f) { return f.GetInventoryAsync(); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::System::Inventory::IInstalledDesktopApp> : winrt::impl::hash_base<winrt::Windows::System::Inventory::IInstalledDesktopApp> {};
template<> struct hash<winrt::Windows::System::Inventory::IInstalledDesktopAppStatics> : winrt::impl::hash_base<winrt::Windows::System::Inventory::IInstalledDesktopAppStatics> {};
template<> struct hash<winrt::Windows::System::Inventory::InstalledDesktopApp> : winrt::impl::hash_base<winrt::Windows::System::Inventory::InstalledDesktopApp> {};

}
