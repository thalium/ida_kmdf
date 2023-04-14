// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.ApplicationModel.Appointments.2.h"
#include "winrt/impl/Windows.ApplicationModel.Contacts.2.h"
#include "winrt/impl/Windows.ApplicationModel.Email.2.h"
#include "winrt/impl/Windows.ApplicationModel.UserDataTasks.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.ApplicationModel.UserDataAccounts.2.h"
#include "winrt/Windows.ApplicationModel.h"

namespace winrt::impl {

template <typename D> hstring consume_Windows_ApplicationModel_UserDataAccounts_IUserDataAccount<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::IUserDataAccount)->get_Id(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_UserDataAccounts_IUserDataAccount<D>::UserDisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::IUserDataAccount)->get_UserDisplayName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataAccounts_IUserDataAccount<D>::UserDisplayName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::IUserDataAccount)->put_UserDisplayName(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::UserDataAccounts::UserDataAccountOtherAppReadAccess consume_Windows_ApplicationModel_UserDataAccounts_IUserDataAccount<D>::OtherAppReadAccess() const
{
    Windows::ApplicationModel::UserDataAccounts::UserDataAccountOtherAppReadAccess value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::IUserDataAccount)->get_OtherAppReadAccess(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataAccounts_IUserDataAccount<D>::OtherAppReadAccess(Windows::ApplicationModel::UserDataAccounts::UserDataAccountOtherAppReadAccess const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::IUserDataAccount)->put_OtherAppReadAccess(get_abi(value)));
}

template <typename D> Windows::Storage::Streams::IRandomAccessStreamReference consume_Windows_ApplicationModel_UserDataAccounts_IUserDataAccount<D>::Icon() const
{
    Windows::Storage::Streams::IRandomAccessStreamReference value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::IUserDataAccount)->get_Icon(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_UserDataAccounts_IUserDataAccount<D>::DeviceAccountTypeId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::IUserDataAccount)->get_DeviceAccountTypeId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_UserDataAccounts_IUserDataAccount<D>::PackageFamilyName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::IUserDataAccount)->get_PackageFamilyName(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_UserDataAccounts_IUserDataAccount<D>::SaveAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::IUserDataAccount)->SaveAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_UserDataAccounts_IUserDataAccount<D>::DeleteAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::IUserDataAccount)->DeleteAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Appointments::AppointmentCalendar>> consume_Windows_ApplicationModel_UserDataAccounts_IUserDataAccount<D>::FindAppointmentCalendarsAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Appointments::AppointmentCalendar>> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::IUserDataAccount)->FindAppointmentCalendarsAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Email::EmailMailbox>> consume_Windows_ApplicationModel_UserDataAccounts_IUserDataAccount<D>::FindEmailMailboxesAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Email::EmailMailbox>> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::IUserDataAccount)->FindEmailMailboxesAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactList>> consume_Windows_ApplicationModel_UserDataAccounts_IUserDataAccount<D>::FindContactListsAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactList>> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::IUserDataAccount)->FindContactListsAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactAnnotationList>> consume_Windows_ApplicationModel_UserDataAccounts_IUserDataAccount<D>::FindContactAnnotationListsAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactAnnotationList>> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::IUserDataAccount)->FindContactAnnotationListsAsync(put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_ApplicationModel_UserDataAccounts_IUserDataAccount2<D>::EnterpriseId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::IUserDataAccount2)->get_EnterpriseId(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_UserDataAccounts_IUserDataAccount2<D>::IsProtectedUnderLock() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::IUserDataAccount2)->get_IsProtectedUnderLock(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<hstring> consume_Windows_ApplicationModel_UserDataAccounts_IUserDataAccount3<D>::ExplictReadAccessPackageFamilyNames() const
{
    Windows::Foundation::Collections::IVector<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::IUserDataAccount3)->get_ExplictReadAccessPackageFamilyNames(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_UserDataAccounts_IUserDataAccount3<D>::DisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::IUserDataAccount3)->get_DisplayName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataAccounts_IUserDataAccount3<D>::DisplayName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::IUserDataAccount3)->put_DisplayName(get_abi(value)));
}

template <typename D> bool consume_Windows_ApplicationModel_UserDataAccounts_IUserDataAccount4<D>::CanShowCreateContactGroup() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::IUserDataAccount4)->get_CanShowCreateContactGroup(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataAccounts_IUserDataAccount4<D>::CanShowCreateContactGroup(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::IUserDataAccount4)->put_CanShowCreateContactGroup(value));
}

template <typename D> Windows::Foundation::Collections::IPropertySet consume_Windows_ApplicationModel_UserDataAccounts_IUserDataAccount4<D>::ProviderProperties() const
{
    Windows::Foundation::Collections::IPropertySet value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::IUserDataAccount4)->get_ProviderProperties(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::UserDataTasks::UserDataTaskList>> consume_Windows_ApplicationModel_UserDataAccounts_IUserDataAccount4<D>::FindUserDataTaskListsAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::UserDataTasks::UserDataTaskList>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::IUserDataAccount4)->FindUserDataTaskListsAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactGroup>> consume_Windows_ApplicationModel_UserDataAccounts_IUserDataAccount4<D>::FindContactGroupsAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactGroup>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::IUserDataAccount4)->FindContactGroupsAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<hstring> consume_Windows_ApplicationModel_UserDataAccounts_IUserDataAccount4<D>::TryShowCreateContactGroupAsync() const
{
    Windows::Foundation::IAsyncOperation<hstring> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::IUserDataAccount4)->TryShowCreateContactGroupAsync(put_abi(operation)));
    return operation;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataAccounts_IUserDataAccount4<D>::IsProtectedUnderLock(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::IUserDataAccount4)->put_IsProtectedUnderLock(value));
}

template <typename D> void consume_Windows_ApplicationModel_UserDataAccounts_IUserDataAccount4<D>::Icon(Windows::Storage::Streams::IRandomAccessStreamReference const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::IUserDataAccount4)->put_Icon(get_abi(value)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::UserDataAccounts::UserDataAccountStore> consume_Windows_ApplicationModel_UserDataAccounts_IUserDataAccountManagerForUser<D>::RequestStoreAsync(Windows::ApplicationModel::UserDataAccounts::UserDataAccountStoreAccessType const& storeAccessType) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::UserDataAccounts::UserDataAccountStore> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::IUserDataAccountManagerForUser)->RequestStoreAsync(get_abi(storeAccessType), put_abi(result)));
    return result;
}

template <typename D> Windows::System::User consume_Windows_ApplicationModel_UserDataAccounts_IUserDataAccountManagerForUser<D>::User() const
{
    Windows::System::User value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::IUserDataAccountManagerForUser)->get_User(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::UserDataAccounts::UserDataAccountStore> consume_Windows_ApplicationModel_UserDataAccounts_IUserDataAccountManagerStatics<D>::RequestStoreAsync(Windows::ApplicationModel::UserDataAccounts::UserDataAccountStoreAccessType const& storeAccessType) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::UserDataAccounts::UserDataAccountStore> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::IUserDataAccountManagerStatics)->RequestStoreAsync(get_abi(storeAccessType), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<hstring> consume_Windows_ApplicationModel_UserDataAccounts_IUserDataAccountManagerStatics<D>::ShowAddAccountAsync(Windows::ApplicationModel::UserDataAccounts::UserDataAccountContentKinds const& contentKinds) const
{
    Windows::Foundation::IAsyncOperation<hstring> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::IUserDataAccountManagerStatics)->ShowAddAccountAsync(get_abi(contentKinds), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_UserDataAccounts_IUserDataAccountManagerStatics<D>::ShowAccountSettingsAsync(param::hstring const& id) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::IUserDataAccountManagerStatics)->ShowAccountSettingsAsync(get_abi(id), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_UserDataAccounts_IUserDataAccountManagerStatics<D>::ShowAccountErrorResolverAsync(param::hstring const& id) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::IUserDataAccountManagerStatics)->ShowAccountErrorResolverAsync(get_abi(id), put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::UserDataAccounts::UserDataAccountManagerForUser consume_Windows_ApplicationModel_UserDataAccounts_IUserDataAccountManagerStatics2<D>::GetForUser(Windows::System::User const& user) const
{
    Windows::ApplicationModel::UserDataAccounts::UserDataAccountManagerForUser result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::IUserDataAccountManagerStatics2)->GetForUser(get_abi(user), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::UserDataAccounts::UserDataAccount>> consume_Windows_ApplicationModel_UserDataAccounts_IUserDataAccountStore<D>::FindAccountsAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::UserDataAccounts::UserDataAccount>> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::IUserDataAccountStore)->FindAccountsAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::UserDataAccounts::UserDataAccount> consume_Windows_ApplicationModel_UserDataAccounts_IUserDataAccountStore<D>::GetAccountAsync(param::hstring const& id) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::UserDataAccounts::UserDataAccount> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::IUserDataAccountStore)->GetAccountAsync(get_abi(id), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::UserDataAccounts::UserDataAccount> consume_Windows_ApplicationModel_UserDataAccounts_IUserDataAccountStore<D>::CreateAccountAsync(param::hstring const& userDisplayName) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::UserDataAccounts::UserDataAccount> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::IUserDataAccountStore)->CreateAccountAsync(get_abi(userDisplayName), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::UserDataAccounts::UserDataAccount> consume_Windows_ApplicationModel_UserDataAccounts_IUserDataAccountStore2<D>::CreateAccountAsync(param::hstring const& userDisplayName, param::hstring const& packageRelativeAppId) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::UserDataAccounts::UserDataAccount> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::IUserDataAccountStore2)->CreateAccountWithPackageRelativeAppIdAsync(get_abi(userDisplayName), get_abi(packageRelativeAppId), put_abi(result)));
    return result;
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_UserDataAccounts_IUserDataAccountStore2<D>::StoreChanged(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::UserDataAccounts::UserDataAccountStore, Windows::ApplicationModel::UserDataAccounts::UserDataAccountStoreChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::IUserDataAccountStore2)->add_StoreChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_UserDataAccounts_IUserDataAccountStore2<D>::StoreChanged_revoker consume_Windows_ApplicationModel_UserDataAccounts_IUserDataAccountStore2<D>::StoreChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::UserDataAccounts::UserDataAccountStore, Windows::ApplicationModel::UserDataAccounts::UserDataAccountStoreChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, StoreChanged_revoker>(this, StoreChanged(handler));
}

template <typename D> void consume_Windows_ApplicationModel_UserDataAccounts_IUserDataAccountStore2<D>::StoreChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::IUserDataAccountStore2)->remove_StoreChanged(get_abi(token)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::UserDataAccounts::UserDataAccount> consume_Windows_ApplicationModel_UserDataAccounts_IUserDataAccountStore3<D>::CreateAccountAsync(param::hstring const& userDisplayName, param::hstring const& packageRelativeAppId, param::hstring const& enterpriseId) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::UserDataAccounts::UserDataAccount> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::IUserDataAccountStore3)->CreateAccountWithPackageRelativeAppIdAndEnterpriseIdAsync(get_abi(userDisplayName), get_abi(packageRelativeAppId), get_abi(enterpriseId), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Deferral consume_Windows_ApplicationModel_UserDataAccounts_IUserDataAccountStoreChangedEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::IUserDataAccountStoreChangedEventArgs)->GetDeferral(put_abi(result)));
    return result;
}

template <typename D>
struct produce<D, Windows::ApplicationModel::UserDataAccounts::IUserDataAccount> : produce_base<D, Windows::ApplicationModel::UserDataAccounts::IUserDataAccount>
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

    int32_t WINRT_CALL get_UserDisplayName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UserDisplayName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().UserDisplayName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_UserDisplayName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UserDisplayName, WINRT_WRAP(void), hstring const&);
            this->shim().UserDisplayName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OtherAppReadAccess(Windows::ApplicationModel::UserDataAccounts::UserDataAccountOtherAppReadAccess* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OtherAppReadAccess, WINRT_WRAP(Windows::ApplicationModel::UserDataAccounts::UserDataAccountOtherAppReadAccess));
            *value = detach_from<Windows::ApplicationModel::UserDataAccounts::UserDataAccountOtherAppReadAccess>(this->shim().OtherAppReadAccess());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_OtherAppReadAccess(Windows::ApplicationModel::UserDataAccounts::UserDataAccountOtherAppReadAccess value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OtherAppReadAccess, WINRT_WRAP(void), Windows::ApplicationModel::UserDataAccounts::UserDataAccountOtherAppReadAccess const&);
            this->shim().OtherAppReadAccess(*reinterpret_cast<Windows::ApplicationModel::UserDataAccounts::UserDataAccountOtherAppReadAccess const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Icon(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Icon, WINRT_WRAP(Windows::Storage::Streams::IRandomAccessStreamReference));
            *value = detach_from<Windows::Storage::Streams::IRandomAccessStreamReference>(this->shim().Icon());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DeviceAccountTypeId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceAccountTypeId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DeviceAccountTypeId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PackageFamilyName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PackageFamilyName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().PackageFamilyName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SaveAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SaveAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SaveAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DeleteAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeleteAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().DeleteAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindAppointmentCalendarsAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindAppointmentCalendarsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Appointments::AppointmentCalendar>>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Appointments::AppointmentCalendar>>>(this->shim().FindAppointmentCalendarsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindEmailMailboxesAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindEmailMailboxesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Email::EmailMailbox>>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Email::EmailMailbox>>>(this->shim().FindEmailMailboxesAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindContactListsAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindContactListsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactList>>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactList>>>(this->shim().FindContactListsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindContactAnnotationListsAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindContactAnnotationListsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactAnnotationList>>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactAnnotationList>>>(this->shim().FindContactAnnotationListsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::UserDataAccounts::IUserDataAccount2> : produce_base<D, Windows::ApplicationModel::UserDataAccounts::IUserDataAccount2>
{
    int32_t WINRT_CALL get_EnterpriseId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnterpriseId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().EnterpriseId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsProtectedUnderLock(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsProtectedUnderLock, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsProtectedUnderLock());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::UserDataAccounts::IUserDataAccount3> : produce_base<D, Windows::ApplicationModel::UserDataAccounts::IUserDataAccount3>
{
    int32_t WINRT_CALL get_ExplictReadAccessPackageFamilyNames(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExplictReadAccessPackageFamilyNames, WINRT_WRAP(Windows::Foundation::Collections::IVector<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVector<hstring>>(this->shim().ExplictReadAccessPackageFamilyNames());
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

    int32_t WINRT_CALL put_DisplayName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayName, WINRT_WRAP(void), hstring const&);
            this->shim().DisplayName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::UserDataAccounts::IUserDataAccount4> : produce_base<D, Windows::ApplicationModel::UserDataAccounts::IUserDataAccount4>
{
    int32_t WINRT_CALL get_CanShowCreateContactGroup(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanShowCreateContactGroup, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanShowCreateContactGroup());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CanShowCreateContactGroup(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanShowCreateContactGroup, WINRT_WRAP(void), bool);
            this->shim().CanShowCreateContactGroup(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProviderProperties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProviderProperties, WINRT_WRAP(Windows::Foundation::Collections::IPropertySet));
            *value = detach_from<Windows::Foundation::Collections::IPropertySet>(this->shim().ProviderProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindUserDataTaskListsAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindUserDataTaskListsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::UserDataTasks::UserDataTaskList>>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::UserDataTasks::UserDataTaskList>>>(this->shim().FindUserDataTaskListsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindContactGroupsAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindContactGroupsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactGroup>>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Contacts::ContactGroup>>>(this->shim().FindContactGroupsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryShowCreateContactGroupAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryShowCreateContactGroupAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<hstring>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<hstring>>(this->shim().TryShowCreateContactGroupAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsProtectedUnderLock(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsProtectedUnderLock, WINRT_WRAP(void), bool);
            this->shim().IsProtectedUnderLock(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Icon(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Icon, WINRT_WRAP(void), Windows::Storage::Streams::IRandomAccessStreamReference const&);
            this->shim().Icon(*reinterpret_cast<Windows::Storage::Streams::IRandomAccessStreamReference const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::UserDataAccounts::IUserDataAccountManagerForUser> : produce_base<D, Windows::ApplicationModel::UserDataAccounts::IUserDataAccountManagerForUser>
{
    int32_t WINRT_CALL RequestStoreAsync(Windows::ApplicationModel::UserDataAccounts::UserDataAccountStoreAccessType storeAccessType, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestStoreAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::UserDataAccounts::UserDataAccountStore>), Windows::ApplicationModel::UserDataAccounts::UserDataAccountStoreAccessType const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::UserDataAccounts::UserDataAccountStore>>(this->shim().RequestStoreAsync(*reinterpret_cast<Windows::ApplicationModel::UserDataAccounts::UserDataAccountStoreAccessType const*>(&storeAccessType)));
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
};

template <typename D>
struct produce<D, Windows::ApplicationModel::UserDataAccounts::IUserDataAccountManagerStatics> : produce_base<D, Windows::ApplicationModel::UserDataAccounts::IUserDataAccountManagerStatics>
{
    int32_t WINRT_CALL RequestStoreAsync(Windows::ApplicationModel::UserDataAccounts::UserDataAccountStoreAccessType storeAccessType, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestStoreAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::UserDataAccounts::UserDataAccountStore>), Windows::ApplicationModel::UserDataAccounts::UserDataAccountStoreAccessType const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::UserDataAccounts::UserDataAccountStore>>(this->shim().RequestStoreAsync(*reinterpret_cast<Windows::ApplicationModel::UserDataAccounts::UserDataAccountStoreAccessType const*>(&storeAccessType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ShowAddAccountAsync(Windows::ApplicationModel::UserDataAccounts::UserDataAccountContentKinds contentKinds, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowAddAccountAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<hstring>), Windows::ApplicationModel::UserDataAccounts::UserDataAccountContentKinds const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<hstring>>(this->shim().ShowAddAccountAsync(*reinterpret_cast<Windows::ApplicationModel::UserDataAccounts::UserDataAccountContentKinds const*>(&contentKinds)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ShowAccountSettingsAsync(void* id, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowAccountSettingsAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), hstring const);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ShowAccountSettingsAsync(*reinterpret_cast<hstring const*>(&id)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ShowAccountErrorResolverAsync(void* id, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowAccountErrorResolverAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), hstring const);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ShowAccountErrorResolverAsync(*reinterpret_cast<hstring const*>(&id)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::UserDataAccounts::IUserDataAccountManagerStatics2> : produce_base<D, Windows::ApplicationModel::UserDataAccounts::IUserDataAccountManagerStatics2>
{
    int32_t WINRT_CALL GetForUser(void* user, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForUser, WINRT_WRAP(Windows::ApplicationModel::UserDataAccounts::UserDataAccountManagerForUser), Windows::System::User const&);
            *result = detach_from<Windows::ApplicationModel::UserDataAccounts::UserDataAccountManagerForUser>(this->shim().GetForUser(*reinterpret_cast<Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::UserDataAccounts::IUserDataAccountStore> : produce_base<D, Windows::ApplicationModel::UserDataAccounts::IUserDataAccountStore>
{
    int32_t WINRT_CALL FindAccountsAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindAccountsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::UserDataAccounts::UserDataAccount>>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::UserDataAccounts::UserDataAccount>>>(this->shim().FindAccountsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetAccountAsync(void* id, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAccountAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::UserDataAccounts::UserDataAccount>), hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::UserDataAccounts::UserDataAccount>>(this->shim().GetAccountAsync(*reinterpret_cast<hstring const*>(&id)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateAccountAsync(void* userDisplayName, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateAccountAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::UserDataAccounts::UserDataAccount>), hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::UserDataAccounts::UserDataAccount>>(this->shim().CreateAccountAsync(*reinterpret_cast<hstring const*>(&userDisplayName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::UserDataAccounts::IUserDataAccountStore2> : produce_base<D, Windows::ApplicationModel::UserDataAccounts::IUserDataAccountStore2>
{
    int32_t WINRT_CALL CreateAccountWithPackageRelativeAppIdAsync(void* userDisplayName, void* packageRelativeAppId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateAccountAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::UserDataAccounts::UserDataAccount>), hstring const, hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::UserDataAccounts::UserDataAccount>>(this->shim().CreateAccountAsync(*reinterpret_cast<hstring const*>(&userDisplayName), *reinterpret_cast<hstring const*>(&packageRelativeAppId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_StoreChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StoreChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::UserDataAccounts::UserDataAccountStore, Windows::ApplicationModel::UserDataAccounts::UserDataAccountStoreChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().StoreChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::UserDataAccounts::UserDataAccountStore, Windows::ApplicationModel::UserDataAccounts::UserDataAccountStoreChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_StoreChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(StoreChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().StoreChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::UserDataAccounts::IUserDataAccountStore3> : produce_base<D, Windows::ApplicationModel::UserDataAccounts::IUserDataAccountStore3>
{
    int32_t WINRT_CALL CreateAccountWithPackageRelativeAppIdAndEnterpriseIdAsync(void* userDisplayName, void* packageRelativeAppId, void* enterpriseId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateAccountAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::UserDataAccounts::UserDataAccount>), hstring const, hstring const, hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::UserDataAccounts::UserDataAccount>>(this->shim().CreateAccountAsync(*reinterpret_cast<hstring const*>(&userDisplayName), *reinterpret_cast<hstring const*>(&packageRelativeAppId), *reinterpret_cast<hstring const*>(&enterpriseId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::UserDataAccounts::IUserDataAccountStoreChangedEventArgs> : produce_base<D, Windows::ApplicationModel::UserDataAccounts::IUserDataAccountStoreChangedEventArgs>
{
    int32_t WINRT_CALL GetDeferral(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeferral, WINRT_WRAP(Windows::Foundation::Deferral));
            *result = detach_from<Windows::Foundation::Deferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::UserDataAccounts {

inline Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::UserDataAccounts::UserDataAccountStore> UserDataAccountManager::RequestStoreAsync(Windows::ApplicationModel::UserDataAccounts::UserDataAccountStoreAccessType const& storeAccessType)
{
    return impl::call_factory<UserDataAccountManager, Windows::ApplicationModel::UserDataAccounts::IUserDataAccountManagerStatics>([&](auto&& f) { return f.RequestStoreAsync(storeAccessType); });
}

inline Windows::Foundation::IAsyncOperation<hstring> UserDataAccountManager::ShowAddAccountAsync(Windows::ApplicationModel::UserDataAccounts::UserDataAccountContentKinds const& contentKinds)
{
    return impl::call_factory<UserDataAccountManager, Windows::ApplicationModel::UserDataAccounts::IUserDataAccountManagerStatics>([&](auto&& f) { return f.ShowAddAccountAsync(contentKinds); });
}

inline Windows::Foundation::IAsyncAction UserDataAccountManager::ShowAccountSettingsAsync(param::hstring const& id)
{
    return impl::call_factory<UserDataAccountManager, Windows::ApplicationModel::UserDataAccounts::IUserDataAccountManagerStatics>([&](auto&& f) { return f.ShowAccountSettingsAsync(id); });
}

inline Windows::Foundation::IAsyncAction UserDataAccountManager::ShowAccountErrorResolverAsync(param::hstring const& id)
{
    return impl::call_factory<UserDataAccountManager, Windows::ApplicationModel::UserDataAccounts::IUserDataAccountManagerStatics>([&](auto&& f) { return f.ShowAccountErrorResolverAsync(id); });
}

inline Windows::ApplicationModel::UserDataAccounts::UserDataAccountManagerForUser UserDataAccountManager::GetForUser(Windows::System::User const& user)
{
    return impl::call_factory<UserDataAccountManager, Windows::ApplicationModel::UserDataAccounts::IUserDataAccountManagerStatics2>([&](auto&& f) { return f.GetForUser(user); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::ApplicationModel::UserDataAccounts::IUserDataAccount> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataAccounts::IUserDataAccount> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataAccounts::IUserDataAccount2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataAccounts::IUserDataAccount2> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataAccounts::IUserDataAccount3> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataAccounts::IUserDataAccount3> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataAccounts::IUserDataAccount4> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataAccounts::IUserDataAccount4> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataAccounts::IUserDataAccountManagerForUser> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataAccounts::IUserDataAccountManagerForUser> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataAccounts::IUserDataAccountManagerStatics> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataAccounts::IUserDataAccountManagerStatics> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataAccounts::IUserDataAccountManagerStatics2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataAccounts::IUserDataAccountManagerStatics2> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataAccounts::IUserDataAccountStore> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataAccounts::IUserDataAccountStore> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataAccounts::IUserDataAccountStore2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataAccounts::IUserDataAccountStore2> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataAccounts::IUserDataAccountStore3> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataAccounts::IUserDataAccountStore3> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataAccounts::IUserDataAccountStoreChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataAccounts::IUserDataAccountStoreChangedEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataAccounts::UserDataAccount> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataAccounts::UserDataAccount> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataAccounts::UserDataAccountManager> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataAccounts::UserDataAccountManager> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataAccounts::UserDataAccountManagerForUser> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataAccounts::UserDataAccountManagerForUser> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataAccounts::UserDataAccountStore> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataAccounts::UserDataAccountStore> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataAccounts::UserDataAccountStoreChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataAccounts::UserDataAccountStoreChangedEventArgs> {};

}
