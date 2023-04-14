// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.ApplicationModel.UserDataAccounts.2.h"
#include "winrt/impl/Windows.ApplicationModel.UserDataAccounts.Provider.2.h"
#include "winrt/Windows.ApplicationModel.UserDataAccounts.h"

namespace winrt::impl {

template <typename D> hstring consume_Windows_ApplicationModel_UserDataAccounts_Provider_IUserDataAccountPartnerAccountInfo<D>::DisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::Provider::IUserDataAccountPartnerAccountInfo)->get_DisplayName(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_ApplicationModel_UserDataAccounts_Provider_IUserDataAccountPartnerAccountInfo<D>::Priority() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::Provider::IUserDataAccountPartnerAccountInfo)->get_Priority(&value));
    return value;
}

template <typename D> Windows::ApplicationModel::UserDataAccounts::Provider::UserDataAccountProviderPartnerAccountKind consume_Windows_ApplicationModel_UserDataAccounts_Provider_IUserDataAccountPartnerAccountInfo<D>::AccountKind() const
{
    Windows::ApplicationModel::UserDataAccounts::Provider::UserDataAccountProviderPartnerAccountKind value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::Provider::IUserDataAccountPartnerAccountInfo)->get_AccountKind(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::UserDataAccounts::UserDataAccountContentKinds consume_Windows_ApplicationModel_UserDataAccounts_Provider_IUserDataAccountProviderAddAccountOperation<D>::ContentKinds() const
{
    Windows::ApplicationModel::UserDataAccounts::UserDataAccountContentKinds value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::Provider::IUserDataAccountProviderAddAccountOperation)->get_ContentKinds(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::UserDataAccounts::Provider::UserDataAccountPartnerAccountInfo> consume_Windows_ApplicationModel_UserDataAccounts_Provider_IUserDataAccountProviderAddAccountOperation<D>::PartnerAccountInfos() const
{
    Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::UserDataAccounts::Provider::UserDataAccountPartnerAccountInfo> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::Provider::IUserDataAccountProviderAddAccountOperation)->get_PartnerAccountInfos(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataAccounts_Provider_IUserDataAccountProviderAddAccountOperation<D>::ReportCompleted(param::hstring const& userDataAccountId) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::Provider::IUserDataAccountProviderAddAccountOperation)->ReportCompleted(get_abi(userDataAccountId)));
}

template <typename D> Windows::ApplicationModel::UserDataAccounts::Provider::UserDataAccountProviderOperationKind consume_Windows_ApplicationModel_UserDataAccounts_Provider_IUserDataAccountProviderOperation<D>::Kind() const
{
    Windows::ApplicationModel::UserDataAccounts::Provider::UserDataAccountProviderOperationKind value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::Provider::IUserDataAccountProviderOperation)->get_Kind(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_UserDataAccounts_Provider_IUserDataAccountProviderResolveErrorsOperation<D>::UserDataAccountId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::Provider::IUserDataAccountProviderResolveErrorsOperation)->get_UserDataAccountId(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataAccounts_Provider_IUserDataAccountProviderResolveErrorsOperation<D>::ReportCompleted() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::Provider::IUserDataAccountProviderResolveErrorsOperation)->ReportCompleted());
}

template <typename D> hstring consume_Windows_ApplicationModel_UserDataAccounts_Provider_IUserDataAccountProviderSettingsOperation<D>::UserDataAccountId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::Provider::IUserDataAccountProviderSettingsOperation)->get_UserDataAccountId(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataAccounts_Provider_IUserDataAccountProviderSettingsOperation<D>::ReportCompleted() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::Provider::IUserDataAccountProviderSettingsOperation)->ReportCompleted());
}

template <typename D>
struct produce<D, Windows::ApplicationModel::UserDataAccounts::Provider::IUserDataAccountPartnerAccountInfo> : produce_base<D, Windows::ApplicationModel::UserDataAccounts::Provider::IUserDataAccountPartnerAccountInfo>
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

    int32_t WINRT_CALL get_Priority(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Priority, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Priority());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AccountKind(Windows::ApplicationModel::UserDataAccounts::Provider::UserDataAccountProviderPartnerAccountKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AccountKind, WINRT_WRAP(Windows::ApplicationModel::UserDataAccounts::Provider::UserDataAccountProviderPartnerAccountKind));
            *value = detach_from<Windows::ApplicationModel::UserDataAccounts::Provider::UserDataAccountProviderPartnerAccountKind>(this->shim().AccountKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::UserDataAccounts::Provider::IUserDataAccountProviderAddAccountOperation> : produce_base<D, Windows::ApplicationModel::UserDataAccounts::Provider::IUserDataAccountProviderAddAccountOperation>
{
    int32_t WINRT_CALL get_ContentKinds(Windows::ApplicationModel::UserDataAccounts::UserDataAccountContentKinds* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentKinds, WINRT_WRAP(Windows::ApplicationModel::UserDataAccounts::UserDataAccountContentKinds));
            *value = detach_from<Windows::ApplicationModel::UserDataAccounts::UserDataAccountContentKinds>(this->shim().ContentKinds());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PartnerAccountInfos(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PartnerAccountInfos, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::UserDataAccounts::Provider::UserDataAccountPartnerAccountInfo>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::UserDataAccounts::Provider::UserDataAccountPartnerAccountInfo>>(this->shim().PartnerAccountInfos());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReportCompleted(void* userDataAccountId) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportCompleted, WINRT_WRAP(void), hstring const&);
            this->shim().ReportCompleted(*reinterpret_cast<hstring const*>(&userDataAccountId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::UserDataAccounts::Provider::IUserDataAccountProviderOperation> : produce_base<D, Windows::ApplicationModel::UserDataAccounts::Provider::IUserDataAccountProviderOperation>
{
    int32_t WINRT_CALL get_Kind(Windows::ApplicationModel::UserDataAccounts::Provider::UserDataAccountProviderOperationKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Kind, WINRT_WRAP(Windows::ApplicationModel::UserDataAccounts::Provider::UserDataAccountProviderOperationKind));
            *value = detach_from<Windows::ApplicationModel::UserDataAccounts::Provider::UserDataAccountProviderOperationKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::UserDataAccounts::Provider::IUserDataAccountProviderResolveErrorsOperation> : produce_base<D, Windows::ApplicationModel::UserDataAccounts::Provider::IUserDataAccountProviderResolveErrorsOperation>
{
    int32_t WINRT_CALL get_UserDataAccountId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UserDataAccountId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().UserDataAccountId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReportCompleted() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportCompleted, WINRT_WRAP(void));
            this->shim().ReportCompleted();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::UserDataAccounts::Provider::IUserDataAccountProviderSettingsOperation> : produce_base<D, Windows::ApplicationModel::UserDataAccounts::Provider::IUserDataAccountProviderSettingsOperation>
{
    int32_t WINRT_CALL get_UserDataAccountId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UserDataAccountId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().UserDataAccountId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReportCompleted() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportCompleted, WINRT_WRAP(void));
            this->shim().ReportCompleted();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::UserDataAccounts::Provider {

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::ApplicationModel::UserDataAccounts::Provider::IUserDataAccountPartnerAccountInfo> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataAccounts::Provider::IUserDataAccountPartnerAccountInfo> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataAccounts::Provider::IUserDataAccountProviderAddAccountOperation> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataAccounts::Provider::IUserDataAccountProviderAddAccountOperation> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataAccounts::Provider::IUserDataAccountProviderOperation> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataAccounts::Provider::IUserDataAccountProviderOperation> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataAccounts::Provider::IUserDataAccountProviderResolveErrorsOperation> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataAccounts::Provider::IUserDataAccountProviderResolveErrorsOperation> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataAccounts::Provider::IUserDataAccountProviderSettingsOperation> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataAccounts::Provider::IUserDataAccountProviderSettingsOperation> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataAccounts::Provider::UserDataAccountPartnerAccountInfo> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataAccounts::Provider::UserDataAccountPartnerAccountInfo> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataAccounts::Provider::UserDataAccountProviderAddAccountOperation> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataAccounts::Provider::UserDataAccountProviderAddAccountOperation> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataAccounts::Provider::UserDataAccountProviderResolveErrorsOperation> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataAccounts::Provider::UserDataAccountProviderResolveErrorsOperation> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataAccounts::Provider::UserDataAccountProviderSettingsOperation> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataAccounts::Provider::UserDataAccountProviderSettingsOperation> {};

}
