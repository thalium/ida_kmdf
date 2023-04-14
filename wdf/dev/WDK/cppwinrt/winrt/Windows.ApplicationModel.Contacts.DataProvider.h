// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.ApplicationModel.Contacts.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.ApplicationModel.Contacts.DataProvider.2.h"
#include "winrt/Windows.ApplicationModel.Contacts.h"

namespace winrt::impl {

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Contacts_DataProvider_IContactDataProviderConnection<D>::SyncRequested(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Contacts::DataProvider::ContactDataProviderConnection, Windows::ApplicationModel::Contacts::DataProvider::ContactListSyncManagerSyncRequestEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::DataProvider::IContactDataProviderConnection)->add_SyncRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Contacts_DataProvider_IContactDataProviderConnection<D>::SyncRequested_revoker consume_Windows_ApplicationModel_Contacts_DataProvider_IContactDataProviderConnection<D>::SyncRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Contacts::DataProvider::ContactDataProviderConnection, Windows::ApplicationModel::Contacts::DataProvider::ContactListSyncManagerSyncRequestEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, SyncRequested_revoker>(this, SyncRequested(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_DataProvider_IContactDataProviderConnection<D>::SyncRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Contacts::DataProvider::IContactDataProviderConnection)->remove_SyncRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Contacts_DataProvider_IContactDataProviderConnection<D>::ServerSearchReadBatchRequested(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Contacts::DataProvider::ContactDataProviderConnection, Windows::ApplicationModel::Contacts::DataProvider::ContactListServerSearchReadBatchRequestEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::DataProvider::IContactDataProviderConnection)->add_ServerSearchReadBatchRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Contacts_DataProvider_IContactDataProviderConnection<D>::ServerSearchReadBatchRequested_revoker consume_Windows_ApplicationModel_Contacts_DataProvider_IContactDataProviderConnection<D>::ServerSearchReadBatchRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Contacts::DataProvider::ContactDataProviderConnection, Windows::ApplicationModel::Contacts::DataProvider::ContactListServerSearchReadBatchRequestEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ServerSearchReadBatchRequested_revoker>(this, ServerSearchReadBatchRequested(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_DataProvider_IContactDataProviderConnection<D>::ServerSearchReadBatchRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Contacts::DataProvider::IContactDataProviderConnection)->remove_ServerSearchReadBatchRequested(get_abi(token)));
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_DataProvider_IContactDataProviderConnection<D>::Start() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::DataProvider::IContactDataProviderConnection)->Start());
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Contacts_DataProvider_IContactDataProviderConnection2<D>::CreateOrUpdateContactRequested(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Contacts::DataProvider::ContactDataProviderConnection, Windows::ApplicationModel::Contacts::DataProvider::ContactListCreateOrUpdateContactRequestEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::DataProvider::IContactDataProviderConnection2)->add_CreateOrUpdateContactRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Contacts_DataProvider_IContactDataProviderConnection2<D>::CreateOrUpdateContactRequested_revoker consume_Windows_ApplicationModel_Contacts_DataProvider_IContactDataProviderConnection2<D>::CreateOrUpdateContactRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Contacts::DataProvider::ContactDataProviderConnection, Windows::ApplicationModel::Contacts::DataProvider::ContactListCreateOrUpdateContactRequestEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, CreateOrUpdateContactRequested_revoker>(this, CreateOrUpdateContactRequested(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_DataProvider_IContactDataProviderConnection2<D>::CreateOrUpdateContactRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Contacts::DataProvider::IContactDataProviderConnection2)->remove_CreateOrUpdateContactRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Contacts_DataProvider_IContactDataProviderConnection2<D>::DeleteContactRequested(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Contacts::DataProvider::ContactDataProviderConnection, Windows::ApplicationModel::Contacts::DataProvider::ContactListDeleteContactRequestEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::DataProvider::IContactDataProviderConnection2)->add_DeleteContactRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Contacts_DataProvider_IContactDataProviderConnection2<D>::DeleteContactRequested_revoker consume_Windows_ApplicationModel_Contacts_DataProvider_IContactDataProviderConnection2<D>::DeleteContactRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Contacts::DataProvider::ContactDataProviderConnection, Windows::ApplicationModel::Contacts::DataProvider::ContactListDeleteContactRequestEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, DeleteContactRequested_revoker>(this, DeleteContactRequested(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Contacts_DataProvider_IContactDataProviderConnection2<D>::DeleteContactRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Contacts::DataProvider::IContactDataProviderConnection2)->remove_DeleteContactRequested(get_abi(token)));
}

template <typename D> Windows::ApplicationModel::Contacts::DataProvider::ContactDataProviderConnection consume_Windows_ApplicationModel_Contacts_DataProvider_IContactDataProviderTriggerDetails<D>::Connection() const
{
    Windows::ApplicationModel::Contacts::DataProvider::ContactDataProviderConnection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::DataProvider::IContactDataProviderTriggerDetails)->get_Connection(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_DataProvider_IContactListCreateOrUpdateContactRequest<D>::ContactListId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::DataProvider::IContactListCreateOrUpdateContactRequest)->get_ContactListId(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Contacts::Contact consume_Windows_ApplicationModel_Contacts_DataProvider_IContactListCreateOrUpdateContactRequest<D>::Contact() const
{
    Windows::ApplicationModel::Contacts::Contact value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::DataProvider::IContactListCreateOrUpdateContactRequest)->get_Contact(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Contacts_DataProvider_IContactListCreateOrUpdateContactRequest<D>::ReportCompletedAsync(Windows::ApplicationModel::Contacts::Contact const& createdOrUpdatedContact) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::DataProvider::IContactListCreateOrUpdateContactRequest)->ReportCompletedAsync(get_abi(createdOrUpdatedContact), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Contacts_DataProvider_IContactListCreateOrUpdateContactRequest<D>::ReportFailedAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::DataProvider::IContactListCreateOrUpdateContactRequest)->ReportFailedAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Contacts::DataProvider::ContactListCreateOrUpdateContactRequest consume_Windows_ApplicationModel_Contacts_DataProvider_IContactListCreateOrUpdateContactRequestEventArgs<D>::Request() const
{
    Windows::ApplicationModel::Contacts::DataProvider::ContactListCreateOrUpdateContactRequest value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::DataProvider::IContactListCreateOrUpdateContactRequestEventArgs)->get_Request(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Deferral consume_Windows_ApplicationModel_Contacts_DataProvider_IContactListCreateOrUpdateContactRequestEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::DataProvider::IContactListCreateOrUpdateContactRequestEventArgs)->GetDeferral(put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_DataProvider_IContactListDeleteContactRequest<D>::ContactListId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::DataProvider::IContactListDeleteContactRequest)->get_ContactListId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_DataProvider_IContactListDeleteContactRequest<D>::ContactId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::DataProvider::IContactListDeleteContactRequest)->get_ContactId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Contacts_DataProvider_IContactListDeleteContactRequest<D>::ReportCompletedAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::DataProvider::IContactListDeleteContactRequest)->ReportCompletedAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Contacts_DataProvider_IContactListDeleteContactRequest<D>::ReportFailedAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::DataProvider::IContactListDeleteContactRequest)->ReportFailedAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Contacts::DataProvider::ContactListDeleteContactRequest consume_Windows_ApplicationModel_Contacts_DataProvider_IContactListDeleteContactRequestEventArgs<D>::Request() const
{
    Windows::ApplicationModel::Contacts::DataProvider::ContactListDeleteContactRequest value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::DataProvider::IContactListDeleteContactRequestEventArgs)->get_Request(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Deferral consume_Windows_ApplicationModel_Contacts_DataProvider_IContactListDeleteContactRequestEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::DataProvider::IContactListDeleteContactRequestEventArgs)->GetDeferral(put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_DataProvider_IContactListServerSearchReadBatchRequest<D>::SessionId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::DataProvider::IContactListServerSearchReadBatchRequest)->get_SessionId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_DataProvider_IContactListServerSearchReadBatchRequest<D>::ContactListId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::DataProvider::IContactListServerSearchReadBatchRequest)->get_ContactListId(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Contacts::ContactQueryOptions consume_Windows_ApplicationModel_Contacts_DataProvider_IContactListServerSearchReadBatchRequest<D>::Options() const
{
    Windows::ApplicationModel::Contacts::ContactQueryOptions value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::DataProvider::IContactListServerSearchReadBatchRequest)->get_Options(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_ApplicationModel_Contacts_DataProvider_IContactListServerSearchReadBatchRequest<D>::SuggestedBatchSize() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::DataProvider::IContactListServerSearchReadBatchRequest)->get_SuggestedBatchSize(&value));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Contacts_DataProvider_IContactListServerSearchReadBatchRequest<D>::SaveContactAsync(Windows::ApplicationModel::Contacts::Contact const& contact) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::DataProvider::IContactListServerSearchReadBatchRequest)->SaveContactAsync(get_abi(contact), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Contacts_DataProvider_IContactListServerSearchReadBatchRequest<D>::ReportCompletedAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::DataProvider::IContactListServerSearchReadBatchRequest)->ReportCompletedAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Contacts_DataProvider_IContactListServerSearchReadBatchRequest<D>::ReportFailedAsync(Windows::ApplicationModel::Contacts::ContactBatchStatus const& batchStatus) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::DataProvider::IContactListServerSearchReadBatchRequest)->ReportFailedAsync(get_abi(batchStatus), put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Contacts::DataProvider::ContactListServerSearchReadBatchRequest consume_Windows_ApplicationModel_Contacts_DataProvider_IContactListServerSearchReadBatchRequestEventArgs<D>::Request() const
{
    Windows::ApplicationModel::Contacts::DataProvider::ContactListServerSearchReadBatchRequest value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::DataProvider::IContactListServerSearchReadBatchRequestEventArgs)->get_Request(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Deferral consume_Windows_ApplicationModel_Contacts_DataProvider_IContactListServerSearchReadBatchRequestEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::DataProvider::IContactListServerSearchReadBatchRequestEventArgs)->GetDeferral(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Contacts_DataProvider_IContactListSyncManagerSyncRequest<D>::ContactListId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::DataProvider::IContactListSyncManagerSyncRequest)->get_ContactListId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Contacts_DataProvider_IContactListSyncManagerSyncRequest<D>::ReportCompletedAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::DataProvider::IContactListSyncManagerSyncRequest)->ReportCompletedAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Contacts_DataProvider_IContactListSyncManagerSyncRequest<D>::ReportFailedAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::DataProvider::IContactListSyncManagerSyncRequest)->ReportFailedAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Contacts::DataProvider::ContactListSyncManagerSyncRequest consume_Windows_ApplicationModel_Contacts_DataProvider_IContactListSyncManagerSyncRequestEventArgs<D>::Request() const
{
    Windows::ApplicationModel::Contacts::DataProvider::ContactListSyncManagerSyncRequest value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::DataProvider::IContactListSyncManagerSyncRequestEventArgs)->get_Request(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Deferral consume_Windows_ApplicationModel_Contacts_DataProvider_IContactListSyncManagerSyncRequestEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Contacts::DataProvider::IContactListSyncManagerSyncRequestEventArgs)->GetDeferral(put_abi(value)));
    return value;
}

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::DataProvider::IContactDataProviderConnection> : produce_base<D, Windows::ApplicationModel::Contacts::DataProvider::IContactDataProviderConnection>
{
    int32_t WINRT_CALL add_SyncRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SyncRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Contacts::DataProvider::ContactDataProviderConnection, Windows::ApplicationModel::Contacts::DataProvider::ContactListSyncManagerSyncRequestEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().SyncRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Contacts::DataProvider::ContactDataProviderConnection, Windows::ApplicationModel::Contacts::DataProvider::ContactListSyncManagerSyncRequestEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_SyncRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(SyncRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().SyncRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_ServerSearchReadBatchRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServerSearchReadBatchRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Contacts::DataProvider::ContactDataProviderConnection, Windows::ApplicationModel::Contacts::DataProvider::ContactListServerSearchReadBatchRequestEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ServerSearchReadBatchRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Contacts::DataProvider::ContactDataProviderConnection, Windows::ApplicationModel::Contacts::DataProvider::ContactListServerSearchReadBatchRequestEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ServerSearchReadBatchRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ServerSearchReadBatchRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ServerSearchReadBatchRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL Start() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Start, WINRT_WRAP(void));
            this->shim().Start();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::DataProvider::IContactDataProviderConnection2> : produce_base<D, Windows::ApplicationModel::Contacts::DataProvider::IContactDataProviderConnection2>
{
    int32_t WINRT_CALL add_CreateOrUpdateContactRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateOrUpdateContactRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Contacts::DataProvider::ContactDataProviderConnection, Windows::ApplicationModel::Contacts::DataProvider::ContactListCreateOrUpdateContactRequestEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().CreateOrUpdateContactRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Contacts::DataProvider::ContactDataProviderConnection, Windows::ApplicationModel::Contacts::DataProvider::ContactListCreateOrUpdateContactRequestEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_CreateOrUpdateContactRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(CreateOrUpdateContactRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().CreateOrUpdateContactRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_DeleteContactRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeleteContactRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Contacts::DataProvider::ContactDataProviderConnection, Windows::ApplicationModel::Contacts::DataProvider::ContactListDeleteContactRequestEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().DeleteContactRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Contacts::DataProvider::ContactDataProviderConnection, Windows::ApplicationModel::Contacts::DataProvider::ContactListDeleteContactRequestEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_DeleteContactRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(DeleteContactRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().DeleteContactRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::DataProvider::IContactDataProviderTriggerDetails> : produce_base<D, Windows::ApplicationModel::Contacts::DataProvider::IContactDataProviderTriggerDetails>
{
    int32_t WINRT_CALL get_Connection(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Connection, WINRT_WRAP(Windows::ApplicationModel::Contacts::DataProvider::ContactDataProviderConnection));
            *value = detach_from<Windows::ApplicationModel::Contacts::DataProvider::ContactDataProviderConnection>(this->shim().Connection());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::DataProvider::IContactListCreateOrUpdateContactRequest> : produce_base<D, Windows::ApplicationModel::Contacts::DataProvider::IContactListCreateOrUpdateContactRequest>
{
    int32_t WINRT_CALL get_ContactListId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContactListId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ContactListId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Contact(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Contact, WINRT_WRAP(Windows::ApplicationModel::Contacts::Contact));
            *value = detach_from<Windows::ApplicationModel::Contacts::Contact>(this->shim().Contact());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReportCompletedAsync(void* createdOrUpdatedContact, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportCompletedAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::ApplicationModel::Contacts::Contact const);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ReportCompletedAsync(*reinterpret_cast<Windows::ApplicationModel::Contacts::Contact const*>(&createdOrUpdatedContact)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReportFailedAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportFailedAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ReportFailedAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::DataProvider::IContactListCreateOrUpdateContactRequestEventArgs> : produce_base<D, Windows::ApplicationModel::Contacts::DataProvider::IContactListCreateOrUpdateContactRequestEventArgs>
{
    int32_t WINRT_CALL get_Request(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Request, WINRT_WRAP(Windows::ApplicationModel::Contacts::DataProvider::ContactListCreateOrUpdateContactRequest));
            *value = detach_from<Windows::ApplicationModel::Contacts::DataProvider::ContactListCreateOrUpdateContactRequest>(this->shim().Request());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::DataProvider::IContactListDeleteContactRequest> : produce_base<D, Windows::ApplicationModel::Contacts::DataProvider::IContactListDeleteContactRequest>
{
    int32_t WINRT_CALL get_ContactListId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContactListId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ContactListId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ContactId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContactId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ContactId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReportCompletedAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportCompletedAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ReportCompletedAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReportFailedAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportFailedAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ReportFailedAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::DataProvider::IContactListDeleteContactRequestEventArgs> : produce_base<D, Windows::ApplicationModel::Contacts::DataProvider::IContactListDeleteContactRequestEventArgs>
{
    int32_t WINRT_CALL get_Request(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Request, WINRT_WRAP(Windows::ApplicationModel::Contacts::DataProvider::ContactListDeleteContactRequest));
            *value = detach_from<Windows::ApplicationModel::Contacts::DataProvider::ContactListDeleteContactRequest>(this->shim().Request());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::DataProvider::IContactListServerSearchReadBatchRequest> : produce_base<D, Windows::ApplicationModel::Contacts::DataProvider::IContactListServerSearchReadBatchRequest>
{
    int32_t WINRT_CALL get_SessionId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SessionId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SessionId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ContactListId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContactListId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ContactListId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Options(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Options, WINRT_WRAP(Windows::ApplicationModel::Contacts::ContactQueryOptions));
            *value = detach_from<Windows::ApplicationModel::Contacts::ContactQueryOptions>(this->shim().Options());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SuggestedBatchSize(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SuggestedBatchSize, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().SuggestedBatchSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SaveContactAsync(void* contact, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SaveContactAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::ApplicationModel::Contacts::Contact const);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SaveContactAsync(*reinterpret_cast<Windows::ApplicationModel::Contacts::Contact const*>(&contact)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReportCompletedAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportCompletedAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ReportCompletedAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReportFailedAsync(Windows::ApplicationModel::Contacts::ContactBatchStatus batchStatus, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportFailedAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::ApplicationModel::Contacts::ContactBatchStatus const);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ReportFailedAsync(*reinterpret_cast<Windows::ApplicationModel::Contacts::ContactBatchStatus const*>(&batchStatus)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::DataProvider::IContactListServerSearchReadBatchRequestEventArgs> : produce_base<D, Windows::ApplicationModel::Contacts::DataProvider::IContactListServerSearchReadBatchRequestEventArgs>
{
    int32_t WINRT_CALL get_Request(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Request, WINRT_WRAP(Windows::ApplicationModel::Contacts::DataProvider::ContactListServerSearchReadBatchRequest));
            *value = detach_from<Windows::ApplicationModel::Contacts::DataProvider::ContactListServerSearchReadBatchRequest>(this->shim().Request());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeferral(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeferral, WINRT_WRAP(Windows::Foundation::Deferral));
            *value = detach_from<Windows::Foundation::Deferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::DataProvider::IContactListSyncManagerSyncRequest> : produce_base<D, Windows::ApplicationModel::Contacts::DataProvider::IContactListSyncManagerSyncRequest>
{
    int32_t WINRT_CALL get_ContactListId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContactListId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ContactListId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReportCompletedAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportCompletedAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ReportCompletedAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReportFailedAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportFailedAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ReportFailedAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Contacts::DataProvider::IContactListSyncManagerSyncRequestEventArgs> : produce_base<D, Windows::ApplicationModel::Contacts::DataProvider::IContactListSyncManagerSyncRequestEventArgs>
{
    int32_t WINRT_CALL get_Request(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Request, WINRT_WRAP(Windows::ApplicationModel::Contacts::DataProvider::ContactListSyncManagerSyncRequest));
            *value = detach_from<Windows::ApplicationModel::Contacts::DataProvider::ContactListSyncManagerSyncRequest>(this->shim().Request());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeferral(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeferral, WINRT_WRAP(Windows::Foundation::Deferral));
            *value = detach_from<Windows::Foundation::Deferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Contacts::DataProvider {

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::ApplicationModel::Contacts::DataProvider::IContactDataProviderConnection> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::DataProvider::IContactDataProviderConnection> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::DataProvider::IContactDataProviderConnection2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::DataProvider::IContactDataProviderConnection2> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::DataProvider::IContactDataProviderTriggerDetails> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::DataProvider::IContactDataProviderTriggerDetails> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::DataProvider::IContactListCreateOrUpdateContactRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::DataProvider::IContactListCreateOrUpdateContactRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::DataProvider::IContactListCreateOrUpdateContactRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::DataProvider::IContactListCreateOrUpdateContactRequestEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::DataProvider::IContactListDeleteContactRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::DataProvider::IContactListDeleteContactRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::DataProvider::IContactListDeleteContactRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::DataProvider::IContactListDeleteContactRequestEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::DataProvider::IContactListServerSearchReadBatchRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::DataProvider::IContactListServerSearchReadBatchRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::DataProvider::IContactListServerSearchReadBatchRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::DataProvider::IContactListServerSearchReadBatchRequestEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::DataProvider::IContactListSyncManagerSyncRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::DataProvider::IContactListSyncManagerSyncRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::DataProvider::IContactListSyncManagerSyncRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::DataProvider::IContactListSyncManagerSyncRequestEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::DataProvider::ContactDataProviderConnection> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::DataProvider::ContactDataProviderConnection> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::DataProvider::ContactDataProviderTriggerDetails> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::DataProvider::ContactDataProviderTriggerDetails> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::DataProvider::ContactListCreateOrUpdateContactRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::DataProvider::ContactListCreateOrUpdateContactRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::DataProvider::ContactListCreateOrUpdateContactRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::DataProvider::ContactListCreateOrUpdateContactRequestEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::DataProvider::ContactListDeleteContactRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::DataProvider::ContactListDeleteContactRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::DataProvider::ContactListDeleteContactRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::DataProvider::ContactListDeleteContactRequestEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::DataProvider::ContactListServerSearchReadBatchRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::DataProvider::ContactListServerSearchReadBatchRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::DataProvider::ContactListServerSearchReadBatchRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::DataProvider::ContactListServerSearchReadBatchRequestEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::DataProvider::ContactListSyncManagerSyncRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::DataProvider::ContactListSyncManagerSyncRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::Contacts::DataProvider::ContactListSyncManagerSyncRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Contacts::DataProvider::ContactListSyncManagerSyncRequestEventArgs> {};

}
