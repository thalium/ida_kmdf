// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.ApplicationModel.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Storage.2.h"
#include "winrt/impl/Windows.ApplicationModel.AppExtensions.2.h"
#include "winrt/Windows.ApplicationModel.h"

namespace winrt::impl {

template <typename D> hstring consume_Windows_ApplicationModel_AppExtensions_IAppExtension<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::AppExtensions::IAppExtension)->get_Id(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_AppExtensions_IAppExtension<D>::DisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::AppExtensions::IAppExtension)->get_DisplayName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_AppExtensions_IAppExtension<D>::Description() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::AppExtensions::IAppExtension)->get_Description(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Package consume_Windows_ApplicationModel_AppExtensions_IAppExtension<D>::Package() const
{
    Windows::ApplicationModel::Package value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::AppExtensions::IAppExtension)->get_Package(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::AppInfo consume_Windows_ApplicationModel_AppExtensions_IAppExtension<D>::AppInfo() const
{
    Windows::ApplicationModel::AppInfo value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::AppExtensions::IAppExtension)->get_AppInfo(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IPropertySet> consume_Windows_ApplicationModel_AppExtensions_IAppExtension<D>::GetExtensionPropertiesAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IPropertySet> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::AppExtensions::IAppExtension)->GetExtensionPropertiesAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFolder> consume_Windows_ApplicationModel_AppExtensions_IAppExtension<D>::GetPublicFolderAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFolder> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::AppExtensions::IAppExtension)->GetPublicFolderAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::AppExtensions::AppExtension>> consume_Windows_ApplicationModel_AppExtensions_IAppExtensionCatalog<D>::FindAllAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::AppExtensions::AppExtension>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::AppExtensions::IAppExtensionCatalog)->FindAllAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_ApplicationModel_AppExtensions_IAppExtensionCatalog<D>::RequestRemovePackageAsync(param::hstring const& packageFullName) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::AppExtensions::IAppExtensionCatalog)->RequestRemovePackageAsync(get_abi(packageFullName), put_abi(operation)));
    return operation;
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_AppExtensions_IAppExtensionCatalog<D>::PackageInstalled(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::AppExtensions::AppExtensionCatalog, Windows::ApplicationModel::AppExtensions::AppExtensionPackageInstalledEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::AppExtensions::IAppExtensionCatalog)->add_PackageInstalled(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_AppExtensions_IAppExtensionCatalog<D>::PackageInstalled_revoker consume_Windows_ApplicationModel_AppExtensions_IAppExtensionCatalog<D>::PackageInstalled(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::AppExtensions::AppExtensionCatalog, Windows::ApplicationModel::AppExtensions::AppExtensionPackageInstalledEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, PackageInstalled_revoker>(this, PackageInstalled(handler));
}

template <typename D> void consume_Windows_ApplicationModel_AppExtensions_IAppExtensionCatalog<D>::PackageInstalled(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::AppExtensions::IAppExtensionCatalog)->remove_PackageInstalled(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_AppExtensions_IAppExtensionCatalog<D>::PackageUpdating(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::AppExtensions::AppExtensionCatalog, Windows::ApplicationModel::AppExtensions::AppExtensionPackageUpdatingEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::AppExtensions::IAppExtensionCatalog)->add_PackageUpdating(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_AppExtensions_IAppExtensionCatalog<D>::PackageUpdating_revoker consume_Windows_ApplicationModel_AppExtensions_IAppExtensionCatalog<D>::PackageUpdating(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::AppExtensions::AppExtensionCatalog, Windows::ApplicationModel::AppExtensions::AppExtensionPackageUpdatingEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, PackageUpdating_revoker>(this, PackageUpdating(handler));
}

template <typename D> void consume_Windows_ApplicationModel_AppExtensions_IAppExtensionCatalog<D>::PackageUpdating(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::AppExtensions::IAppExtensionCatalog)->remove_PackageUpdating(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_AppExtensions_IAppExtensionCatalog<D>::PackageUpdated(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::AppExtensions::AppExtensionCatalog, Windows::ApplicationModel::AppExtensions::AppExtensionPackageUpdatedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::AppExtensions::IAppExtensionCatalog)->add_PackageUpdated(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_AppExtensions_IAppExtensionCatalog<D>::PackageUpdated_revoker consume_Windows_ApplicationModel_AppExtensions_IAppExtensionCatalog<D>::PackageUpdated(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::AppExtensions::AppExtensionCatalog, Windows::ApplicationModel::AppExtensions::AppExtensionPackageUpdatedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, PackageUpdated_revoker>(this, PackageUpdated(handler));
}

template <typename D> void consume_Windows_ApplicationModel_AppExtensions_IAppExtensionCatalog<D>::PackageUpdated(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::AppExtensions::IAppExtensionCatalog)->remove_PackageUpdated(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_AppExtensions_IAppExtensionCatalog<D>::PackageUninstalling(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::AppExtensions::AppExtensionCatalog, Windows::ApplicationModel::AppExtensions::AppExtensionPackageUninstallingEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::AppExtensions::IAppExtensionCatalog)->add_PackageUninstalling(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_AppExtensions_IAppExtensionCatalog<D>::PackageUninstalling_revoker consume_Windows_ApplicationModel_AppExtensions_IAppExtensionCatalog<D>::PackageUninstalling(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::AppExtensions::AppExtensionCatalog, Windows::ApplicationModel::AppExtensions::AppExtensionPackageUninstallingEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, PackageUninstalling_revoker>(this, PackageUninstalling(handler));
}

template <typename D> void consume_Windows_ApplicationModel_AppExtensions_IAppExtensionCatalog<D>::PackageUninstalling(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::AppExtensions::IAppExtensionCatalog)->remove_PackageUninstalling(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_AppExtensions_IAppExtensionCatalog<D>::PackageStatusChanged(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::AppExtensions::AppExtensionCatalog, Windows::ApplicationModel::AppExtensions::AppExtensionPackageStatusChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::AppExtensions::IAppExtensionCatalog)->add_PackageStatusChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_AppExtensions_IAppExtensionCatalog<D>::PackageStatusChanged_revoker consume_Windows_ApplicationModel_AppExtensions_IAppExtensionCatalog<D>::PackageStatusChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::AppExtensions::AppExtensionCatalog, Windows::ApplicationModel::AppExtensions::AppExtensionPackageStatusChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, PackageStatusChanged_revoker>(this, PackageStatusChanged(handler));
}

template <typename D> void consume_Windows_ApplicationModel_AppExtensions_IAppExtensionCatalog<D>::PackageStatusChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::AppExtensions::IAppExtensionCatalog)->remove_PackageStatusChanged(get_abi(token)));
}

template <typename D> Windows::ApplicationModel::AppExtensions::AppExtensionCatalog consume_Windows_ApplicationModel_AppExtensions_IAppExtensionCatalogStatics<D>::Open(param::hstring const& appExtensionName) const
{
    Windows::ApplicationModel::AppExtensions::AppExtensionCatalog value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::AppExtensions::IAppExtensionCatalogStatics)->Open(get_abi(appExtensionName), put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_AppExtensions_IAppExtensionPackageInstalledEventArgs<D>::AppExtensionName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::AppExtensions::IAppExtensionPackageInstalledEventArgs)->get_AppExtensionName(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Package consume_Windows_ApplicationModel_AppExtensions_IAppExtensionPackageInstalledEventArgs<D>::Package() const
{
    Windows::ApplicationModel::Package value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::AppExtensions::IAppExtensionPackageInstalledEventArgs)->get_Package(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::AppExtensions::AppExtension> consume_Windows_ApplicationModel_AppExtensions_IAppExtensionPackageInstalledEventArgs<D>::Extensions() const
{
    Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::AppExtensions::AppExtension> values{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::AppExtensions::IAppExtensionPackageInstalledEventArgs)->get_Extensions(put_abi(values)));
    return values;
}

template <typename D> hstring consume_Windows_ApplicationModel_AppExtensions_IAppExtensionPackageStatusChangedEventArgs<D>::AppExtensionName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::AppExtensions::IAppExtensionPackageStatusChangedEventArgs)->get_AppExtensionName(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Package consume_Windows_ApplicationModel_AppExtensions_IAppExtensionPackageStatusChangedEventArgs<D>::Package() const
{
    Windows::ApplicationModel::Package value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::AppExtensions::IAppExtensionPackageStatusChangedEventArgs)->get_Package(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_AppExtensions_IAppExtensionPackageUninstallingEventArgs<D>::AppExtensionName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::AppExtensions::IAppExtensionPackageUninstallingEventArgs)->get_AppExtensionName(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Package consume_Windows_ApplicationModel_AppExtensions_IAppExtensionPackageUninstallingEventArgs<D>::Package() const
{
    Windows::ApplicationModel::Package value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::AppExtensions::IAppExtensionPackageUninstallingEventArgs)->get_Package(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_AppExtensions_IAppExtensionPackageUpdatedEventArgs<D>::AppExtensionName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::AppExtensions::IAppExtensionPackageUpdatedEventArgs)->get_AppExtensionName(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Package consume_Windows_ApplicationModel_AppExtensions_IAppExtensionPackageUpdatedEventArgs<D>::Package() const
{
    Windows::ApplicationModel::Package value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::AppExtensions::IAppExtensionPackageUpdatedEventArgs)->get_Package(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::AppExtensions::AppExtension> consume_Windows_ApplicationModel_AppExtensions_IAppExtensionPackageUpdatedEventArgs<D>::Extensions() const
{
    Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::AppExtensions::AppExtension> values{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::AppExtensions::IAppExtensionPackageUpdatedEventArgs)->get_Extensions(put_abi(values)));
    return values;
}

template <typename D> hstring consume_Windows_ApplicationModel_AppExtensions_IAppExtensionPackageUpdatingEventArgs<D>::AppExtensionName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::AppExtensions::IAppExtensionPackageUpdatingEventArgs)->get_AppExtensionName(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Package consume_Windows_ApplicationModel_AppExtensions_IAppExtensionPackageUpdatingEventArgs<D>::Package() const
{
    Windows::ApplicationModel::Package value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::AppExtensions::IAppExtensionPackageUpdatingEventArgs)->get_Package(put_abi(value)));
    return value;
}

template <typename D>
struct produce<D, Windows::ApplicationModel::AppExtensions::IAppExtension> : produce_base<D, Windows::ApplicationModel::AppExtensions::IAppExtension>
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

    int32_t WINRT_CALL get_Package(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Package, WINRT_WRAP(Windows::ApplicationModel::Package));
            *value = detach_from<Windows::ApplicationModel::Package>(this->shim().Package());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AppInfo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppInfo, WINRT_WRAP(Windows::ApplicationModel::AppInfo));
            *value = detach_from<Windows::ApplicationModel::AppInfo>(this->shim().AppInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetExtensionPropertiesAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetExtensionPropertiesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IPropertySet>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IPropertySet>>(this->shim().GetExtensionPropertiesAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetPublicFolderAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetPublicFolderAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFolder>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFolder>>(this->shim().GetPublicFolderAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::AppExtensions::IAppExtensionCatalog> : produce_base<D, Windows::ApplicationModel::AppExtensions::IAppExtensionCatalog>
{
    int32_t WINRT_CALL FindAllAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindAllAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::AppExtensions::AppExtension>>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::AppExtensions::AppExtension>>>(this->shim().FindAllAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestRemovePackageAsync(void* packageFullName, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestRemovePackageAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().RequestRemovePackageAsync(*reinterpret_cast<hstring const*>(&packageFullName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_PackageInstalled(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PackageInstalled, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::AppExtensions::AppExtensionCatalog, Windows::ApplicationModel::AppExtensions::AppExtensionPackageInstalledEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().PackageInstalled(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::AppExtensions::AppExtensionCatalog, Windows::ApplicationModel::AppExtensions::AppExtensionPackageInstalledEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PackageInstalled(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PackageInstalled, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PackageInstalled(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_PackageUpdating(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PackageUpdating, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::AppExtensions::AppExtensionCatalog, Windows::ApplicationModel::AppExtensions::AppExtensionPackageUpdatingEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().PackageUpdating(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::AppExtensions::AppExtensionCatalog, Windows::ApplicationModel::AppExtensions::AppExtensionPackageUpdatingEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PackageUpdating(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PackageUpdating, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PackageUpdating(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_PackageUpdated(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PackageUpdated, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::AppExtensions::AppExtensionCatalog, Windows::ApplicationModel::AppExtensions::AppExtensionPackageUpdatedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().PackageUpdated(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::AppExtensions::AppExtensionCatalog, Windows::ApplicationModel::AppExtensions::AppExtensionPackageUpdatedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PackageUpdated(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PackageUpdated, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PackageUpdated(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_PackageUninstalling(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PackageUninstalling, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::AppExtensions::AppExtensionCatalog, Windows::ApplicationModel::AppExtensions::AppExtensionPackageUninstallingEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().PackageUninstalling(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::AppExtensions::AppExtensionCatalog, Windows::ApplicationModel::AppExtensions::AppExtensionPackageUninstallingEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PackageUninstalling(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PackageUninstalling, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PackageUninstalling(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_PackageStatusChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PackageStatusChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::AppExtensions::AppExtensionCatalog, Windows::ApplicationModel::AppExtensions::AppExtensionPackageStatusChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().PackageStatusChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::AppExtensions::AppExtensionCatalog, Windows::ApplicationModel::AppExtensions::AppExtensionPackageStatusChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PackageStatusChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PackageStatusChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PackageStatusChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::AppExtensions::IAppExtensionCatalogStatics> : produce_base<D, Windows::ApplicationModel::AppExtensions::IAppExtensionCatalogStatics>
{
    int32_t WINRT_CALL Open(void* appExtensionName, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Open, WINRT_WRAP(Windows::ApplicationModel::AppExtensions::AppExtensionCatalog), hstring const&);
            *value = detach_from<Windows::ApplicationModel::AppExtensions::AppExtensionCatalog>(this->shim().Open(*reinterpret_cast<hstring const*>(&appExtensionName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::AppExtensions::IAppExtensionPackageInstalledEventArgs> : produce_base<D, Windows::ApplicationModel::AppExtensions::IAppExtensionPackageInstalledEventArgs>
{
    int32_t WINRT_CALL get_AppExtensionName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppExtensionName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AppExtensionName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Package(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Package, WINRT_WRAP(Windows::ApplicationModel::Package));
            *value = detach_from<Windows::ApplicationModel::Package>(this->shim().Package());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Extensions(void** values) noexcept final
    {
        try
        {
            *values = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Extensions, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::AppExtensions::AppExtension>));
            *values = detach_from<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::AppExtensions::AppExtension>>(this->shim().Extensions());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::AppExtensions::IAppExtensionPackageStatusChangedEventArgs> : produce_base<D, Windows::ApplicationModel::AppExtensions::IAppExtensionPackageStatusChangedEventArgs>
{
    int32_t WINRT_CALL get_AppExtensionName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppExtensionName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AppExtensionName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Package(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Package, WINRT_WRAP(Windows::ApplicationModel::Package));
            *value = detach_from<Windows::ApplicationModel::Package>(this->shim().Package());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::AppExtensions::IAppExtensionPackageUninstallingEventArgs> : produce_base<D, Windows::ApplicationModel::AppExtensions::IAppExtensionPackageUninstallingEventArgs>
{
    int32_t WINRT_CALL get_AppExtensionName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppExtensionName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AppExtensionName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Package(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Package, WINRT_WRAP(Windows::ApplicationModel::Package));
            *value = detach_from<Windows::ApplicationModel::Package>(this->shim().Package());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::AppExtensions::IAppExtensionPackageUpdatedEventArgs> : produce_base<D, Windows::ApplicationModel::AppExtensions::IAppExtensionPackageUpdatedEventArgs>
{
    int32_t WINRT_CALL get_AppExtensionName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppExtensionName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AppExtensionName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Package(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Package, WINRT_WRAP(Windows::ApplicationModel::Package));
            *value = detach_from<Windows::ApplicationModel::Package>(this->shim().Package());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Extensions(void** values) noexcept final
    {
        try
        {
            *values = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Extensions, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::AppExtensions::AppExtension>));
            *values = detach_from<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::AppExtensions::AppExtension>>(this->shim().Extensions());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::AppExtensions::IAppExtensionPackageUpdatingEventArgs> : produce_base<D, Windows::ApplicationModel::AppExtensions::IAppExtensionPackageUpdatingEventArgs>
{
    int32_t WINRT_CALL get_AppExtensionName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppExtensionName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AppExtensionName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Package(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Package, WINRT_WRAP(Windows::ApplicationModel::Package));
            *value = detach_from<Windows::ApplicationModel::Package>(this->shim().Package());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::AppExtensions {

inline Windows::ApplicationModel::AppExtensions::AppExtensionCatalog AppExtensionCatalog::Open(param::hstring const& appExtensionName)
{
    return impl::call_factory<AppExtensionCatalog, Windows::ApplicationModel::AppExtensions::IAppExtensionCatalogStatics>([&](auto&& f) { return f.Open(appExtensionName); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::ApplicationModel::AppExtensions::IAppExtension> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::AppExtensions::IAppExtension> {};
template<> struct hash<winrt::Windows::ApplicationModel::AppExtensions::IAppExtensionCatalog> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::AppExtensions::IAppExtensionCatalog> {};
template<> struct hash<winrt::Windows::ApplicationModel::AppExtensions::IAppExtensionCatalogStatics> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::AppExtensions::IAppExtensionCatalogStatics> {};
template<> struct hash<winrt::Windows::ApplicationModel::AppExtensions::IAppExtensionPackageInstalledEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::AppExtensions::IAppExtensionPackageInstalledEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::AppExtensions::IAppExtensionPackageStatusChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::AppExtensions::IAppExtensionPackageStatusChangedEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::AppExtensions::IAppExtensionPackageUninstallingEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::AppExtensions::IAppExtensionPackageUninstallingEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::AppExtensions::IAppExtensionPackageUpdatedEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::AppExtensions::IAppExtensionPackageUpdatedEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::AppExtensions::IAppExtensionPackageUpdatingEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::AppExtensions::IAppExtensionPackageUpdatingEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::AppExtensions::AppExtension> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::AppExtensions::AppExtension> {};
template<> struct hash<winrt::Windows::ApplicationModel::AppExtensions::AppExtensionCatalog> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::AppExtensions::AppExtensionCatalog> {};
template<> struct hash<winrt::Windows::ApplicationModel::AppExtensions::AppExtensionPackageInstalledEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::AppExtensions::AppExtensionPackageInstalledEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::AppExtensions::AppExtensionPackageStatusChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::AppExtensions::AppExtensionPackageStatusChangedEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::AppExtensions::AppExtensionPackageUninstallingEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::AppExtensions::AppExtensionPackageUninstallingEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::AppExtensions::AppExtensionPackageUpdatedEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::AppExtensions::AppExtensionPackageUpdatedEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::AppExtensions::AppExtensionPackageUpdatingEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::AppExtensions::AppExtensionPackageUpdatingEventArgs> {};

}
