// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.ApplicationModel.UserDataTasks.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.ApplicationModel.UserDataTasks.DataProvider.2.h"
#include "winrt/Windows.ApplicationModel.UserDataTasks.h"

namespace winrt::impl {

template <typename D> winrt::event_token consume_Windows_ApplicationModel_UserDataTasks_DataProvider_IUserDataTaskDataProviderConnection<D>::CreateOrUpdateTaskRequested(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskDataProviderConnection, Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskListCreateOrUpdateTaskRequestEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskDataProviderConnection)->add_CreateOrUpdateTaskRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_UserDataTasks_DataProvider_IUserDataTaskDataProviderConnection<D>::CreateOrUpdateTaskRequested_revoker consume_Windows_ApplicationModel_UserDataTasks_DataProvider_IUserDataTaskDataProviderConnection<D>::CreateOrUpdateTaskRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskDataProviderConnection, Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskListCreateOrUpdateTaskRequestEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, CreateOrUpdateTaskRequested_revoker>(this, CreateOrUpdateTaskRequested(handler));
}

template <typename D> void consume_Windows_ApplicationModel_UserDataTasks_DataProvider_IUserDataTaskDataProviderConnection<D>::CreateOrUpdateTaskRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskDataProviderConnection)->remove_CreateOrUpdateTaskRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_UserDataTasks_DataProvider_IUserDataTaskDataProviderConnection<D>::SyncRequested(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskDataProviderConnection, Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskListSyncManagerSyncRequestEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskDataProviderConnection)->add_SyncRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_UserDataTasks_DataProvider_IUserDataTaskDataProviderConnection<D>::SyncRequested_revoker consume_Windows_ApplicationModel_UserDataTasks_DataProvider_IUserDataTaskDataProviderConnection<D>::SyncRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskDataProviderConnection, Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskListSyncManagerSyncRequestEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, SyncRequested_revoker>(this, SyncRequested(handler));
}

template <typename D> void consume_Windows_ApplicationModel_UserDataTasks_DataProvider_IUserDataTaskDataProviderConnection<D>::SyncRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskDataProviderConnection)->remove_SyncRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_UserDataTasks_DataProvider_IUserDataTaskDataProviderConnection<D>::SkipOccurrenceRequested(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskDataProviderConnection, Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskListSkipOccurrenceRequestEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskDataProviderConnection)->add_SkipOccurrenceRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_UserDataTasks_DataProvider_IUserDataTaskDataProviderConnection<D>::SkipOccurrenceRequested_revoker consume_Windows_ApplicationModel_UserDataTasks_DataProvider_IUserDataTaskDataProviderConnection<D>::SkipOccurrenceRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskDataProviderConnection, Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskListSkipOccurrenceRequestEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, SkipOccurrenceRequested_revoker>(this, SkipOccurrenceRequested(handler));
}

template <typename D> void consume_Windows_ApplicationModel_UserDataTasks_DataProvider_IUserDataTaskDataProviderConnection<D>::SkipOccurrenceRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskDataProviderConnection)->remove_SkipOccurrenceRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_UserDataTasks_DataProvider_IUserDataTaskDataProviderConnection<D>::CompleteTaskRequested(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskDataProviderConnection, Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskListCompleteTaskRequestEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskDataProviderConnection)->add_CompleteTaskRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_UserDataTasks_DataProvider_IUserDataTaskDataProviderConnection<D>::CompleteTaskRequested_revoker consume_Windows_ApplicationModel_UserDataTasks_DataProvider_IUserDataTaskDataProviderConnection<D>::CompleteTaskRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskDataProviderConnection, Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskListCompleteTaskRequestEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, CompleteTaskRequested_revoker>(this, CompleteTaskRequested(handler));
}

template <typename D> void consume_Windows_ApplicationModel_UserDataTasks_DataProvider_IUserDataTaskDataProviderConnection<D>::CompleteTaskRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskDataProviderConnection)->remove_CompleteTaskRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_UserDataTasks_DataProvider_IUserDataTaskDataProviderConnection<D>::DeleteTaskRequested(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskDataProviderConnection, Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskListDeleteTaskRequestEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskDataProviderConnection)->add_DeleteTaskRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_UserDataTasks_DataProvider_IUserDataTaskDataProviderConnection<D>::DeleteTaskRequested_revoker consume_Windows_ApplicationModel_UserDataTasks_DataProvider_IUserDataTaskDataProviderConnection<D>::DeleteTaskRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskDataProviderConnection, Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskListDeleteTaskRequestEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, DeleteTaskRequested_revoker>(this, DeleteTaskRequested(handler));
}

template <typename D> void consume_Windows_ApplicationModel_UserDataTasks_DataProvider_IUserDataTaskDataProviderConnection<D>::DeleteTaskRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskDataProviderConnection)->remove_DeleteTaskRequested(get_abi(token)));
}

template <typename D> void consume_Windows_ApplicationModel_UserDataTasks_DataProvider_IUserDataTaskDataProviderConnection<D>::Start() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskDataProviderConnection)->Start());
}

template <typename D> Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskDataProviderConnection consume_Windows_ApplicationModel_UserDataTasks_DataProvider_IUserDataTaskDataProviderTriggerDetails<D>::Connection() const
{
    Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskDataProviderConnection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskDataProviderTriggerDetails)->get_Connection(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_UserDataTasks_DataProvider_IUserDataTaskListCompleteTaskRequest<D>::TaskListId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskListCompleteTaskRequest)->get_TaskListId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_UserDataTasks_DataProvider_IUserDataTaskListCompleteTaskRequest<D>::TaskId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskListCompleteTaskRequest)->get_TaskId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_UserDataTasks_DataProvider_IUserDataTaskListCompleteTaskRequest<D>::ReportCompletedAsync(param::hstring const& completedTaskId) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskListCompleteTaskRequest)->ReportCompletedAsync(get_abi(completedTaskId), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_UserDataTasks_DataProvider_IUserDataTaskListCompleteTaskRequest<D>::ReportFailedAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskListCompleteTaskRequest)->ReportFailedAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskListCompleteTaskRequest consume_Windows_ApplicationModel_UserDataTasks_DataProvider_IUserDataTaskListCompleteTaskRequestEventArgs<D>::Request() const
{
    Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskListCompleteTaskRequest value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskListCompleteTaskRequestEventArgs)->get_Request(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Deferral consume_Windows_ApplicationModel_UserDataTasks_DataProvider_IUserDataTaskListCompleteTaskRequestEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskListCompleteTaskRequestEventArgs)->GetDeferral(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_UserDataTasks_DataProvider_IUserDataTaskListCreateOrUpdateTaskRequest<D>::TaskListId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskListCreateOrUpdateTaskRequest)->get_TaskListId(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::UserDataTasks::UserDataTask consume_Windows_ApplicationModel_UserDataTasks_DataProvider_IUserDataTaskListCreateOrUpdateTaskRequest<D>::Task() const
{
    Windows::ApplicationModel::UserDataTasks::UserDataTask value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskListCreateOrUpdateTaskRequest)->get_Task(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_UserDataTasks_DataProvider_IUserDataTaskListCreateOrUpdateTaskRequest<D>::ReportCompletedAsync(Windows::ApplicationModel::UserDataTasks::UserDataTask const& createdOrUpdatedUserDataTask) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskListCreateOrUpdateTaskRequest)->ReportCompletedAsync(get_abi(createdOrUpdatedUserDataTask), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_UserDataTasks_DataProvider_IUserDataTaskListCreateOrUpdateTaskRequest<D>::ReportFailedAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskListCreateOrUpdateTaskRequest)->ReportFailedAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskListCreateOrUpdateTaskRequest consume_Windows_ApplicationModel_UserDataTasks_DataProvider_IUserDataTaskListCreateOrUpdateTaskRequestEventArgs<D>::Request() const
{
    Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskListCreateOrUpdateTaskRequest value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskListCreateOrUpdateTaskRequestEventArgs)->get_Request(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Deferral consume_Windows_ApplicationModel_UserDataTasks_DataProvider_IUserDataTaskListCreateOrUpdateTaskRequestEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskListCreateOrUpdateTaskRequestEventArgs)->GetDeferral(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_UserDataTasks_DataProvider_IUserDataTaskListDeleteTaskRequest<D>::TaskListId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskListDeleteTaskRequest)->get_TaskListId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_UserDataTasks_DataProvider_IUserDataTaskListDeleteTaskRequest<D>::TaskId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskListDeleteTaskRequest)->get_TaskId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_UserDataTasks_DataProvider_IUserDataTaskListDeleteTaskRequest<D>::ReportCompletedAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskListDeleteTaskRequest)->ReportCompletedAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_UserDataTasks_DataProvider_IUserDataTaskListDeleteTaskRequest<D>::ReportFailedAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskListDeleteTaskRequest)->ReportFailedAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskListDeleteTaskRequest consume_Windows_ApplicationModel_UserDataTasks_DataProvider_IUserDataTaskListDeleteTaskRequestEventArgs<D>::Request() const
{
    Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskListDeleteTaskRequest value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskListDeleteTaskRequestEventArgs)->get_Request(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Deferral consume_Windows_ApplicationModel_UserDataTasks_DataProvider_IUserDataTaskListDeleteTaskRequestEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskListDeleteTaskRequestEventArgs)->GetDeferral(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_UserDataTasks_DataProvider_IUserDataTaskListSkipOccurrenceRequest<D>::TaskListId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskListSkipOccurrenceRequest)->get_TaskListId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_UserDataTasks_DataProvider_IUserDataTaskListSkipOccurrenceRequest<D>::TaskId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskListSkipOccurrenceRequest)->get_TaskId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_UserDataTasks_DataProvider_IUserDataTaskListSkipOccurrenceRequest<D>::ReportCompletedAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskListSkipOccurrenceRequest)->ReportCompletedAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_UserDataTasks_DataProvider_IUserDataTaskListSkipOccurrenceRequest<D>::ReportFailedAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskListSkipOccurrenceRequest)->ReportFailedAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskListSkipOccurrenceRequest consume_Windows_ApplicationModel_UserDataTasks_DataProvider_IUserDataTaskListSkipOccurrenceRequestEventArgs<D>::Request() const
{
    Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskListSkipOccurrenceRequest value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskListSkipOccurrenceRequestEventArgs)->get_Request(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Deferral consume_Windows_ApplicationModel_UserDataTasks_DataProvider_IUserDataTaskListSkipOccurrenceRequestEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskListSkipOccurrenceRequestEventArgs)->GetDeferral(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_UserDataTasks_DataProvider_IUserDataTaskListSyncManagerSyncRequest<D>::TaskListId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskListSyncManagerSyncRequest)->get_TaskListId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_UserDataTasks_DataProvider_IUserDataTaskListSyncManagerSyncRequest<D>::ReportCompletedAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskListSyncManagerSyncRequest)->ReportCompletedAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_UserDataTasks_DataProvider_IUserDataTaskListSyncManagerSyncRequest<D>::ReportFailedAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskListSyncManagerSyncRequest)->ReportFailedAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskListSyncManagerSyncRequest consume_Windows_ApplicationModel_UserDataTasks_DataProvider_IUserDataTaskListSyncManagerSyncRequestEventArgs<D>::Request() const
{
    Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskListSyncManagerSyncRequest value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskListSyncManagerSyncRequestEventArgs)->get_Request(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Deferral consume_Windows_ApplicationModel_UserDataTasks_DataProvider_IUserDataTaskListSyncManagerSyncRequestEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskListSyncManagerSyncRequestEventArgs)->GetDeferral(put_abi(value)));
    return value;
}

template <typename D>
struct produce<D, Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskDataProviderConnection> : produce_base<D, Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskDataProviderConnection>
{
    int32_t WINRT_CALL add_CreateOrUpdateTaskRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateOrUpdateTaskRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskDataProviderConnection, Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskListCreateOrUpdateTaskRequestEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().CreateOrUpdateTaskRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskDataProviderConnection, Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskListCreateOrUpdateTaskRequestEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_CreateOrUpdateTaskRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(CreateOrUpdateTaskRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().CreateOrUpdateTaskRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_SyncRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SyncRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskDataProviderConnection, Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskListSyncManagerSyncRequestEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().SyncRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskDataProviderConnection, Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskListSyncManagerSyncRequestEventArgs> const*>(&handler)));
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

    int32_t WINRT_CALL add_SkipOccurrenceRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SkipOccurrenceRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskDataProviderConnection, Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskListSkipOccurrenceRequestEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().SkipOccurrenceRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskDataProviderConnection, Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskListSkipOccurrenceRequestEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_SkipOccurrenceRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(SkipOccurrenceRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().SkipOccurrenceRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_CompleteTaskRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CompleteTaskRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskDataProviderConnection, Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskListCompleteTaskRequestEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().CompleteTaskRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskDataProviderConnection, Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskListCompleteTaskRequestEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_CompleteTaskRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(CompleteTaskRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().CompleteTaskRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_DeleteTaskRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeleteTaskRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskDataProviderConnection, Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskListDeleteTaskRequestEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().DeleteTaskRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskDataProviderConnection, Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskListDeleteTaskRequestEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_DeleteTaskRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(DeleteTaskRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().DeleteTaskRequested(*reinterpret_cast<winrt::event_token const*>(&token));
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
struct produce<D, Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskDataProviderTriggerDetails> : produce_base<D, Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskDataProviderTriggerDetails>
{
    int32_t WINRT_CALL get_Connection(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Connection, WINRT_WRAP(Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskDataProviderConnection));
            *value = detach_from<Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskDataProviderConnection>(this->shim().Connection());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskListCompleteTaskRequest> : produce_base<D, Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskListCompleteTaskRequest>
{
    int32_t WINRT_CALL get_TaskListId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TaskListId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().TaskListId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TaskId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TaskId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().TaskId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReportCompletedAsync(void* completedTaskId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportCompletedAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), hstring const);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ReportCompletedAsync(*reinterpret_cast<hstring const*>(&completedTaskId)));
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
struct produce<D, Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskListCompleteTaskRequestEventArgs> : produce_base<D, Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskListCompleteTaskRequestEventArgs>
{
    int32_t WINRT_CALL get_Request(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Request, WINRT_WRAP(Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskListCompleteTaskRequest));
            *value = detach_from<Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskListCompleteTaskRequest>(this->shim().Request());
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
struct produce<D, Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskListCreateOrUpdateTaskRequest> : produce_base<D, Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskListCreateOrUpdateTaskRequest>
{
    int32_t WINRT_CALL get_TaskListId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TaskListId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().TaskListId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Task(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Task, WINRT_WRAP(Windows::ApplicationModel::UserDataTasks::UserDataTask));
            *value = detach_from<Windows::ApplicationModel::UserDataTasks::UserDataTask>(this->shim().Task());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReportCompletedAsync(void* createdOrUpdatedUserDataTask, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportCompletedAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::ApplicationModel::UserDataTasks::UserDataTask const);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ReportCompletedAsync(*reinterpret_cast<Windows::ApplicationModel::UserDataTasks::UserDataTask const*>(&createdOrUpdatedUserDataTask)));
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
struct produce<D, Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskListCreateOrUpdateTaskRequestEventArgs> : produce_base<D, Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskListCreateOrUpdateTaskRequestEventArgs>
{
    int32_t WINRT_CALL get_Request(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Request, WINRT_WRAP(Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskListCreateOrUpdateTaskRequest));
            *value = detach_from<Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskListCreateOrUpdateTaskRequest>(this->shim().Request());
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
struct produce<D, Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskListDeleteTaskRequest> : produce_base<D, Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskListDeleteTaskRequest>
{
    int32_t WINRT_CALL get_TaskListId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TaskListId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().TaskListId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TaskId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TaskId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().TaskId());
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
struct produce<D, Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskListDeleteTaskRequestEventArgs> : produce_base<D, Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskListDeleteTaskRequestEventArgs>
{
    int32_t WINRT_CALL get_Request(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Request, WINRT_WRAP(Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskListDeleteTaskRequest));
            *value = detach_from<Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskListDeleteTaskRequest>(this->shim().Request());
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
struct produce<D, Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskListSkipOccurrenceRequest> : produce_base<D, Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskListSkipOccurrenceRequest>
{
    int32_t WINRT_CALL get_TaskListId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TaskListId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().TaskListId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TaskId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TaskId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().TaskId());
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
struct produce<D, Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskListSkipOccurrenceRequestEventArgs> : produce_base<D, Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskListSkipOccurrenceRequestEventArgs>
{
    int32_t WINRT_CALL get_Request(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Request, WINRT_WRAP(Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskListSkipOccurrenceRequest));
            *value = detach_from<Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskListSkipOccurrenceRequest>(this->shim().Request());
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
struct produce<D, Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskListSyncManagerSyncRequest> : produce_base<D, Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskListSyncManagerSyncRequest>
{
    int32_t WINRT_CALL get_TaskListId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TaskListId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().TaskListId());
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
struct produce<D, Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskListSyncManagerSyncRequestEventArgs> : produce_base<D, Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskListSyncManagerSyncRequestEventArgs>
{
    int32_t WINRT_CALL get_Request(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Request, WINRT_WRAP(Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskListSyncManagerSyncRequest));
            *value = detach_from<Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskListSyncManagerSyncRequest>(this->shim().Request());
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

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::UserDataTasks::DataProvider {

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskDataProviderConnection> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskDataProviderConnection> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskDataProviderTriggerDetails> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskDataProviderTriggerDetails> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskListCompleteTaskRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskListCompleteTaskRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskListCompleteTaskRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskListCompleteTaskRequestEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskListCreateOrUpdateTaskRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskListCreateOrUpdateTaskRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskListCreateOrUpdateTaskRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskListCreateOrUpdateTaskRequestEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskListDeleteTaskRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskListDeleteTaskRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskListDeleteTaskRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskListDeleteTaskRequestEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskListSkipOccurrenceRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskListSkipOccurrenceRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskListSkipOccurrenceRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskListSkipOccurrenceRequestEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskListSyncManagerSyncRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskListSyncManagerSyncRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskListSyncManagerSyncRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataTasks::DataProvider::IUserDataTaskListSyncManagerSyncRequestEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskDataProviderConnection> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskDataProviderConnection> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskDataProviderTriggerDetails> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskDataProviderTriggerDetails> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskListCompleteTaskRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskListCompleteTaskRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskListCompleteTaskRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskListCompleteTaskRequestEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskListCreateOrUpdateTaskRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskListCreateOrUpdateTaskRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskListCreateOrUpdateTaskRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskListCreateOrUpdateTaskRequestEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskListDeleteTaskRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskListDeleteTaskRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskListDeleteTaskRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskListDeleteTaskRequestEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskListSkipOccurrenceRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskListSkipOccurrenceRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskListSkipOccurrenceRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskListSkipOccurrenceRequestEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskListSyncManagerSyncRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskListSyncManagerSyncRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskListSyncManagerSyncRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataTasks::DataProvider::UserDataTaskListSyncManagerSyncRequestEventArgs> {};

}
