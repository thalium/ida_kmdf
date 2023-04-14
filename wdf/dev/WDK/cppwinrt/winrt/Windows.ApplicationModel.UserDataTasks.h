// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.ApplicationModel.UserDataTasks.2.h"
#include "winrt/Windows.ApplicationModel.h"

namespace winrt::impl {

template <typename D> hstring consume_Windows_ApplicationModel_UserDataTasks_IUserDataTask<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTask)->get_Id(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_UserDataTasks_IUserDataTask<D>::ListId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTask)->get_ListId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_UserDataTasks_IUserDataTask<D>::RemoteId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTask)->get_RemoteId(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataTasks_IUserDataTask<D>::RemoteId(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTask)->put_RemoteId(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::DateTime> consume_Windows_ApplicationModel_UserDataTasks_IUserDataTask<D>::CompletedDate() const
{
    Windows::Foundation::IReference<Windows::Foundation::DateTime> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTask)->get_CompletedDate(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataTasks_IUserDataTask<D>::CompletedDate(optional<Windows::Foundation::DateTime> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTask)->put_CompletedDate(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_UserDataTasks_IUserDataTask<D>::Details() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTask)->get_Details(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataTasks_IUserDataTask<D>::Details(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTask)->put_Details(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::UserDataTasks::UserDataTaskDetailsKind consume_Windows_ApplicationModel_UserDataTasks_IUserDataTask<D>::DetailsKind() const
{
    Windows::ApplicationModel::UserDataTasks::UserDataTaskDetailsKind value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTask)->get_DetailsKind(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataTasks_IUserDataTask<D>::DetailsKind(Windows::ApplicationModel::UserDataTasks::UserDataTaskDetailsKind const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTask)->put_DetailsKind(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::DateTime> consume_Windows_ApplicationModel_UserDataTasks_IUserDataTask<D>::DueDate() const
{
    Windows::Foundation::IReference<Windows::Foundation::DateTime> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTask)->get_DueDate(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataTasks_IUserDataTask<D>::DueDate(optional<Windows::Foundation::DateTime> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTask)->put_DueDate(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::UserDataTasks::UserDataTaskKind consume_Windows_ApplicationModel_UserDataTasks_IUserDataTask<D>::Kind() const
{
    Windows::ApplicationModel::UserDataTasks::UserDataTaskKind value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTask)->get_Kind(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::UserDataTasks::UserDataTaskPriority consume_Windows_ApplicationModel_UserDataTasks_IUserDataTask<D>::Priority() const
{
    Windows::ApplicationModel::UserDataTasks::UserDataTaskPriority value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTask)->get_Priority(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataTasks_IUserDataTask<D>::Priority(Windows::ApplicationModel::UserDataTasks::UserDataTaskPriority const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTask)->put_Priority(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::UserDataTasks::UserDataTaskRecurrenceProperties consume_Windows_ApplicationModel_UserDataTasks_IUserDataTask<D>::RecurrenceProperties() const
{
    Windows::ApplicationModel::UserDataTasks::UserDataTaskRecurrenceProperties value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTask)->get_RecurrenceProperties(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataTasks_IUserDataTask<D>::RecurrenceProperties(Windows::ApplicationModel::UserDataTasks::UserDataTaskRecurrenceProperties const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTask)->put_RecurrenceProperties(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::UserDataTasks::UserDataTaskRegenerationProperties consume_Windows_ApplicationModel_UserDataTasks_IUserDataTask<D>::RegenerationProperties() const
{
    Windows::ApplicationModel::UserDataTasks::UserDataTaskRegenerationProperties value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTask)->get_RegenerationProperties(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataTasks_IUserDataTask<D>::RegenerationProperties(Windows::ApplicationModel::UserDataTasks::UserDataTaskRegenerationProperties const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTask)->put_RegenerationProperties(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::DateTime> consume_Windows_ApplicationModel_UserDataTasks_IUserDataTask<D>::Reminder() const
{
    Windows::Foundation::IReference<Windows::Foundation::DateTime> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTask)->get_Reminder(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataTasks_IUserDataTask<D>::Reminder(optional<Windows::Foundation::DateTime> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTask)->put_Reminder(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::UserDataTasks::UserDataTaskSensitivity consume_Windows_ApplicationModel_UserDataTasks_IUserDataTask<D>::Sensitivity() const
{
    Windows::ApplicationModel::UserDataTasks::UserDataTaskSensitivity value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTask)->get_Sensitivity(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataTasks_IUserDataTask<D>::Sensitivity(Windows::ApplicationModel::UserDataTasks::UserDataTaskSensitivity const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTask)->put_Sensitivity(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_UserDataTasks_IUserDataTask<D>::Subject() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTask)->get_Subject(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataTasks_IUserDataTask<D>::Subject(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTask)->put_Subject(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::DateTime> consume_Windows_ApplicationModel_UserDataTasks_IUserDataTask<D>::StartDate() const
{
    Windows::Foundation::IReference<Windows::Foundation::DateTime> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTask)->get_StartDate(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataTasks_IUserDataTask<D>::StartDate(optional<Windows::Foundation::DateTime> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTask)->put_StartDate(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::UserDataTasks::UserDataTask> consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskBatch<D>::Tasks() const
{
    Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::UserDataTasks::UserDataTask> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTaskBatch)->get_Tasks(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskList<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTaskList)->get_Id(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskList<D>::UserDataAccountId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTaskList)->get_UserDataAccountId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskList<D>::DisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTaskList)->get_DisplayName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskList<D>::DisplayName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTaskList)->put_DisplayName(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskList<D>::SourceDisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTaskList)->get_SourceDisplayName(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::UserDataTasks::UserDataTaskListOtherAppReadAccess consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskList<D>::OtherAppReadAccess() const
{
    Windows::ApplicationModel::UserDataTasks::UserDataTaskListOtherAppReadAccess value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTaskList)->get_OtherAppReadAccess(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskList<D>::OtherAppReadAccess(Windows::ApplicationModel::UserDataTasks::UserDataTaskListOtherAppReadAccess const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTaskList)->put_OtherAppReadAccess(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::UserDataTasks::UserDataTaskListOtherAppWriteAccess consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskList<D>::OtherAppWriteAccess() const
{
    Windows::ApplicationModel::UserDataTasks::UserDataTaskListOtherAppWriteAccess value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTaskList)->get_OtherAppWriteAccess(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskList<D>::OtherAppWriteAccess(Windows::ApplicationModel::UserDataTasks::UserDataTaskListOtherAppWriteAccess const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTaskList)->put_OtherAppWriteAccess(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::UserDataTasks::UserDataTaskListLimitedWriteOperations consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskList<D>::LimitedWriteOperations() const
{
    Windows::ApplicationModel::UserDataTasks::UserDataTaskListLimitedWriteOperations value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTaskList)->get_LimitedWriteOperations(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::UserDataTasks::UserDataTaskListSyncManager consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskList<D>::SyncManager() const
{
    Windows::ApplicationModel::UserDataTasks::UserDataTaskListSyncManager value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTaskList)->get_SyncManager(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskList<D>::RegisterSyncManagerAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTaskList)->RegisterSyncManagerAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::UserDataTasks::UserDataTaskReader consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskList<D>::GetTaskReader() const
{
    Windows::ApplicationModel::UserDataTasks::UserDataTaskReader result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTaskList)->GetTaskReader(put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::UserDataTasks::UserDataTaskReader consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskList<D>::GetTaskReader(Windows::ApplicationModel::UserDataTasks::UserDataTaskQueryOptions const& options) const
{
    Windows::ApplicationModel::UserDataTasks::UserDataTaskReader value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTaskList)->GetTaskReaderWithOptions(get_abi(options), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::UserDataTasks::UserDataTask> consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskList<D>::GetTaskAsync(param::hstring const& userDataTask) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::UserDataTasks::UserDataTask> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTaskList)->GetTaskAsync(get_abi(userDataTask), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskList<D>::SaveTaskAsync(Windows::ApplicationModel::UserDataTasks::UserDataTask const& userDataTask) const
{
    Windows::Foundation::IAsyncAction action{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTaskList)->SaveTaskAsync(get_abi(userDataTask), put_abi(action)));
    return action;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskList<D>::DeleteTaskAsync(param::hstring const& userDataTaskId) const
{
    Windows::Foundation::IAsyncAction action{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTaskList)->DeleteTaskAsync(get_abi(userDataTaskId), put_abi(action)));
    return action;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskList<D>::DeleteAsync() const
{
    Windows::Foundation::IAsyncAction asyncAction{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTaskList)->DeleteAsync(put_abi(asyncAction)));
    return asyncAction;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskList<D>::SaveAsync() const
{
    Windows::Foundation::IAsyncAction asyncAction{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTaskList)->SaveAsync(put_abi(asyncAction)));
    return asyncAction;
}

template <typename D> Windows::Foundation::IAsyncOperation<hstring> consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskListLimitedWriteOperations<D>::TryCompleteTaskAsync(param::hstring const& userDataTaskId) const
{
    Windows::Foundation::IAsyncOperation<hstring> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTaskListLimitedWriteOperations)->TryCompleteTaskAsync(get_abi(userDataTaskId), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskListLimitedWriteOperations<D>::TryCreateOrUpdateTaskAsync(Windows::ApplicationModel::UserDataTasks::UserDataTask const& userDataTask) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTaskListLimitedWriteOperations)->TryCreateOrUpdateTaskAsync(get_abi(userDataTask), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskListLimitedWriteOperations<D>::TryDeleteTaskAsync(param::hstring const& userDataTaskId) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTaskListLimitedWriteOperations)->TryDeleteTaskAsync(get_abi(userDataTaskId), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskListLimitedWriteOperations<D>::TrySkipOccurrenceAsync(param::hstring const& userDataTaskId) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTaskListLimitedWriteOperations)->TrySkipOccurrenceAsync(get_abi(userDataTaskId), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskListSyncManager<D>::LastAttemptedSyncTime() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTaskListSyncManager)->get_LastAttemptedSyncTime(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskListSyncManager<D>::LastAttemptedSyncTime(Windows::Foundation::DateTime const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTaskListSyncManager)->put_LastAttemptedSyncTime(get_abi(value)));
}

template <typename D> Windows::Foundation::DateTime consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskListSyncManager<D>::LastSuccessfulSyncTime() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTaskListSyncManager)->get_LastSuccessfulSyncTime(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskListSyncManager<D>::LastSuccessfulSyncTime(Windows::Foundation::DateTime const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTaskListSyncManager)->put_LastSuccessfulSyncTime(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::UserDataTasks::UserDataTaskListSyncStatus consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskListSyncManager<D>::Status() const
{
    Windows::ApplicationModel::UserDataTasks::UserDataTaskListSyncStatus value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTaskListSyncManager)->get_Status(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskListSyncManager<D>::Status(Windows::ApplicationModel::UserDataTasks::UserDataTaskListSyncStatus const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTaskListSyncManager)->put_Status(get_abi(value)));
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskListSyncManager<D>::SyncAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTaskListSyncManager)->SyncAsync(put_abi(result)));
    return result;
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskListSyncManager<D>::SyncStatusChanged(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::UserDataTasks::UserDataTaskListSyncManager, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTaskListSyncManager)->add_SyncStatusChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskListSyncManager<D>::SyncStatusChanged_revoker consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskListSyncManager<D>::SyncStatusChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::UserDataTasks::UserDataTaskListSyncManager, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, SyncStatusChanged_revoker>(this, SyncStatusChanged(handler));
}

template <typename D> void consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskListSyncManager<D>::SyncStatusChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTaskListSyncManager)->remove_SyncStatusChanged(get_abi(token)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::UserDataTasks::UserDataTaskStore> consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskManager<D>::RequestStoreAsync(Windows::ApplicationModel::UserDataTasks::UserDataTaskStoreAccessType const& accessType) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::UserDataTasks::UserDataTaskStore> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTaskManager)->RequestStoreAsync(get_abi(accessType), put_abi(operation)));
    return operation;
}

template <typename D> Windows::System::User consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskManager<D>::User() const
{
    Windows::System::User value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTaskManager)->get_User(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::UserDataTasks::UserDataTaskManager consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskManagerStatics<D>::GetDefault() const
{
    Windows::ApplicationModel::UserDataTasks::UserDataTaskManager result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTaskManagerStatics)->GetDefault(put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::UserDataTasks::UserDataTaskManager consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskManagerStatics<D>::GetForUser(Windows::System::User const& user) const
{
    Windows::ApplicationModel::UserDataTasks::UserDataTaskManager result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTaskManagerStatics)->GetForUser(get_abi(user), put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::UserDataTasks::UserDataTaskQuerySortProperty consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskQueryOptions<D>::SortProperty() const
{
    Windows::ApplicationModel::UserDataTasks::UserDataTaskQuerySortProperty value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTaskQueryOptions)->get_SortProperty(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskQueryOptions<D>::SortProperty(Windows::ApplicationModel::UserDataTasks::UserDataTaskQuerySortProperty const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTaskQueryOptions)->put_SortProperty(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::UserDataTasks::UserDataTaskQueryKind consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskQueryOptions<D>::Kind() const
{
    Windows::ApplicationModel::UserDataTasks::UserDataTaskQueryKind value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTaskQueryOptions)->get_Kind(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskQueryOptions<D>::Kind(Windows::ApplicationModel::UserDataTasks::UserDataTaskQueryKind const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTaskQueryOptions)->put_Kind(get_abi(value)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::UserDataTasks::UserDataTaskBatch> consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskReader<D>::ReadBatchAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::UserDataTasks::UserDataTaskBatch> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTaskReader)->ReadBatchAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::UserDataTasks::UserDataTaskRecurrenceUnit consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskRecurrenceProperties<D>::Unit() const
{
    Windows::ApplicationModel::UserDataTasks::UserDataTaskRecurrenceUnit value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTaskRecurrenceProperties)->get_Unit(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskRecurrenceProperties<D>::Unit(Windows::ApplicationModel::UserDataTasks::UserDataTaskRecurrenceUnit const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTaskRecurrenceProperties)->put_Unit(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskRecurrenceProperties<D>::Occurrences() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTaskRecurrenceProperties)->get_Occurrences(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskRecurrenceProperties<D>::Occurrences(optional<int32_t> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTaskRecurrenceProperties)->put_Occurrences(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::DateTime> consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskRecurrenceProperties<D>::Until() const
{
    Windows::Foundation::IReference<Windows::Foundation::DateTime> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTaskRecurrenceProperties)->get_Until(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskRecurrenceProperties<D>::Until(optional<Windows::Foundation::DateTime> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTaskRecurrenceProperties)->put_Until(get_abi(value)));
}

template <typename D> int32_t consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskRecurrenceProperties<D>::Interval() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTaskRecurrenceProperties)->get_Interval(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskRecurrenceProperties<D>::Interval(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTaskRecurrenceProperties)->put_Interval(value));
}

template <typename D> Windows::Foundation::IReference<Windows::ApplicationModel::UserDataTasks::UserDataTaskDaysOfWeek> consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskRecurrenceProperties<D>::DaysOfWeek() const
{
    Windows::Foundation::IReference<Windows::ApplicationModel::UserDataTasks::UserDataTaskDaysOfWeek> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTaskRecurrenceProperties)->get_DaysOfWeek(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskRecurrenceProperties<D>::DaysOfWeek(optional<Windows::ApplicationModel::UserDataTasks::UserDataTaskDaysOfWeek> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTaskRecurrenceProperties)->put_DaysOfWeek(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::ApplicationModel::UserDataTasks::UserDataTaskWeekOfMonth> consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskRecurrenceProperties<D>::WeekOfMonth() const
{
    Windows::Foundation::IReference<Windows::ApplicationModel::UserDataTasks::UserDataTaskWeekOfMonth> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTaskRecurrenceProperties)->get_WeekOfMonth(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskRecurrenceProperties<D>::WeekOfMonth(optional<Windows::ApplicationModel::UserDataTasks::UserDataTaskWeekOfMonth> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTaskRecurrenceProperties)->put_WeekOfMonth(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskRecurrenceProperties<D>::Month() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTaskRecurrenceProperties)->get_Month(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskRecurrenceProperties<D>::Month(optional<int32_t> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTaskRecurrenceProperties)->put_Month(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskRecurrenceProperties<D>::Day() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTaskRecurrenceProperties)->get_Day(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskRecurrenceProperties<D>::Day(optional<int32_t> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTaskRecurrenceProperties)->put_Day(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::UserDataTasks::UserDataTaskRegenerationUnit consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskRegenerationProperties<D>::Unit() const
{
    Windows::ApplicationModel::UserDataTasks::UserDataTaskRegenerationUnit value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTaskRegenerationProperties)->get_Unit(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskRegenerationProperties<D>::Unit(Windows::ApplicationModel::UserDataTasks::UserDataTaskRegenerationUnit const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTaskRegenerationProperties)->put_Unit(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskRegenerationProperties<D>::Occurrences() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTaskRegenerationProperties)->get_Occurrences(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskRegenerationProperties<D>::Occurrences(optional<int32_t> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTaskRegenerationProperties)->put_Occurrences(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::DateTime> consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskRegenerationProperties<D>::Until() const
{
    Windows::Foundation::IReference<Windows::Foundation::DateTime> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTaskRegenerationProperties)->get_Until(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskRegenerationProperties<D>::Until(optional<Windows::Foundation::DateTime> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTaskRegenerationProperties)->put_Until(get_abi(value)));
}

template <typename D> int32_t consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskRegenerationProperties<D>::Interval() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTaskRegenerationProperties)->get_Interval(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskRegenerationProperties<D>::Interval(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTaskRegenerationProperties)->put_Interval(value));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::UserDataTasks::UserDataTaskList> consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskStore<D>::CreateListAsync(param::hstring const& name) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::UserDataTasks::UserDataTaskList> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTaskStore)->CreateListAsync(get_abi(name), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::UserDataTasks::UserDataTaskList> consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskStore<D>::CreateListAsync(param::hstring const& name, param::hstring const& userDataAccountId) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::UserDataTasks::UserDataTaskList> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTaskStore)->CreateListInAccountAsync(get_abi(name), get_abi(userDataAccountId), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::UserDataTasks::UserDataTaskList>> consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskStore<D>::FindListsAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::UserDataTasks::UserDataTaskList>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTaskStore)->FindListsAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::UserDataTasks::UserDataTaskList> consume_Windows_ApplicationModel_UserDataTasks_IUserDataTaskStore<D>::GetListAsync(param::hstring const& taskListId) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::UserDataTasks::UserDataTaskList> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataTasks::IUserDataTaskStore)->GetListAsync(get_abi(taskListId), put_abi(operation)));
    return operation;
}

template <typename D>
struct produce<D, Windows::ApplicationModel::UserDataTasks::IUserDataTask> : produce_base<D, Windows::ApplicationModel::UserDataTasks::IUserDataTask>
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

    int32_t WINRT_CALL get_ListId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ListId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ListId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RemoteId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoteId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().RemoteId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RemoteId(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoteId, WINRT_WRAP(void), hstring const&);
            this->shim().RemoteId(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CompletedDate(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CompletedDate, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::DateTime>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::DateTime>>(this->shim().CompletedDate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CompletedDate(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CompletedDate, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Foundation::DateTime> const&);
            this->shim().CompletedDate(*reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::DateTime> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Details(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Details, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Details());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Details(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Details, WINRT_WRAP(void), hstring const&);
            this->shim().Details(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DetailsKind(Windows::ApplicationModel::UserDataTasks::UserDataTaskDetailsKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DetailsKind, WINRT_WRAP(Windows::ApplicationModel::UserDataTasks::UserDataTaskDetailsKind));
            *value = detach_from<Windows::ApplicationModel::UserDataTasks::UserDataTaskDetailsKind>(this->shim().DetailsKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DetailsKind(Windows::ApplicationModel::UserDataTasks::UserDataTaskDetailsKind value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DetailsKind, WINRT_WRAP(void), Windows::ApplicationModel::UserDataTasks::UserDataTaskDetailsKind const&);
            this->shim().DetailsKind(*reinterpret_cast<Windows::ApplicationModel::UserDataTasks::UserDataTaskDetailsKind const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DueDate(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DueDate, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::DateTime>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::DateTime>>(this->shim().DueDate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DueDate(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DueDate, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Foundation::DateTime> const&);
            this->shim().DueDate(*reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::DateTime> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Kind(Windows::ApplicationModel::UserDataTasks::UserDataTaskKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Kind, WINRT_WRAP(Windows::ApplicationModel::UserDataTasks::UserDataTaskKind));
            *value = detach_from<Windows::ApplicationModel::UserDataTasks::UserDataTaskKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Priority(Windows::ApplicationModel::UserDataTasks::UserDataTaskPriority* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Priority, WINRT_WRAP(Windows::ApplicationModel::UserDataTasks::UserDataTaskPriority));
            *value = detach_from<Windows::ApplicationModel::UserDataTasks::UserDataTaskPriority>(this->shim().Priority());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Priority(Windows::ApplicationModel::UserDataTasks::UserDataTaskPriority value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Priority, WINRT_WRAP(void), Windows::ApplicationModel::UserDataTasks::UserDataTaskPriority const&);
            this->shim().Priority(*reinterpret_cast<Windows::ApplicationModel::UserDataTasks::UserDataTaskPriority const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RecurrenceProperties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RecurrenceProperties, WINRT_WRAP(Windows::ApplicationModel::UserDataTasks::UserDataTaskRecurrenceProperties));
            *value = detach_from<Windows::ApplicationModel::UserDataTasks::UserDataTaskRecurrenceProperties>(this->shim().RecurrenceProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RecurrenceProperties(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RecurrenceProperties, WINRT_WRAP(void), Windows::ApplicationModel::UserDataTasks::UserDataTaskRecurrenceProperties const&);
            this->shim().RecurrenceProperties(*reinterpret_cast<Windows::ApplicationModel::UserDataTasks::UserDataTaskRecurrenceProperties const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RegenerationProperties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RegenerationProperties, WINRT_WRAP(Windows::ApplicationModel::UserDataTasks::UserDataTaskRegenerationProperties));
            *value = detach_from<Windows::ApplicationModel::UserDataTasks::UserDataTaskRegenerationProperties>(this->shim().RegenerationProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RegenerationProperties(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RegenerationProperties, WINRT_WRAP(void), Windows::ApplicationModel::UserDataTasks::UserDataTaskRegenerationProperties const&);
            this->shim().RegenerationProperties(*reinterpret_cast<Windows::ApplicationModel::UserDataTasks::UserDataTaskRegenerationProperties const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Reminder(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Reminder, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::DateTime>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::DateTime>>(this->shim().Reminder());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Reminder(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Reminder, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Foundation::DateTime> const&);
            this->shim().Reminder(*reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::DateTime> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Sensitivity(Windows::ApplicationModel::UserDataTasks::UserDataTaskSensitivity* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Sensitivity, WINRT_WRAP(Windows::ApplicationModel::UserDataTasks::UserDataTaskSensitivity));
            *value = detach_from<Windows::ApplicationModel::UserDataTasks::UserDataTaskSensitivity>(this->shim().Sensitivity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Sensitivity(Windows::ApplicationModel::UserDataTasks::UserDataTaskSensitivity value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Sensitivity, WINRT_WRAP(void), Windows::ApplicationModel::UserDataTasks::UserDataTaskSensitivity const&);
            this->shim().Sensitivity(*reinterpret_cast<Windows::ApplicationModel::UserDataTasks::UserDataTaskSensitivity const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Subject(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Subject, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Subject());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Subject(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Subject, WINRT_WRAP(void), hstring const&);
            this->shim().Subject(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StartDate(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartDate, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::DateTime>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::DateTime>>(this->shim().StartDate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_StartDate(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartDate, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Foundation::DateTime> const&);
            this->shim().StartDate(*reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::DateTime> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::UserDataTasks::IUserDataTaskBatch> : produce_base<D, Windows::ApplicationModel::UserDataTasks::IUserDataTaskBatch>
{
    int32_t WINRT_CALL get_Tasks(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Tasks, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::UserDataTasks::UserDataTask>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::UserDataTasks::UserDataTask>>(this->shim().Tasks());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::UserDataTasks::IUserDataTaskList> : produce_base<D, Windows::ApplicationModel::UserDataTasks::IUserDataTaskList>
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

    int32_t WINRT_CALL get_SourceDisplayName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourceDisplayName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SourceDisplayName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OtherAppReadAccess(Windows::ApplicationModel::UserDataTasks::UserDataTaskListOtherAppReadAccess* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OtherAppReadAccess, WINRT_WRAP(Windows::ApplicationModel::UserDataTasks::UserDataTaskListOtherAppReadAccess));
            *value = detach_from<Windows::ApplicationModel::UserDataTasks::UserDataTaskListOtherAppReadAccess>(this->shim().OtherAppReadAccess());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_OtherAppReadAccess(Windows::ApplicationModel::UserDataTasks::UserDataTaskListOtherAppReadAccess value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OtherAppReadAccess, WINRT_WRAP(void), Windows::ApplicationModel::UserDataTasks::UserDataTaskListOtherAppReadAccess const&);
            this->shim().OtherAppReadAccess(*reinterpret_cast<Windows::ApplicationModel::UserDataTasks::UserDataTaskListOtherAppReadAccess const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OtherAppWriteAccess(Windows::ApplicationModel::UserDataTasks::UserDataTaskListOtherAppWriteAccess* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OtherAppWriteAccess, WINRT_WRAP(Windows::ApplicationModel::UserDataTasks::UserDataTaskListOtherAppWriteAccess));
            *value = detach_from<Windows::ApplicationModel::UserDataTasks::UserDataTaskListOtherAppWriteAccess>(this->shim().OtherAppWriteAccess());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_OtherAppWriteAccess(Windows::ApplicationModel::UserDataTasks::UserDataTaskListOtherAppWriteAccess value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OtherAppWriteAccess, WINRT_WRAP(void), Windows::ApplicationModel::UserDataTasks::UserDataTaskListOtherAppWriteAccess const&);
            this->shim().OtherAppWriteAccess(*reinterpret_cast<Windows::ApplicationModel::UserDataTasks::UserDataTaskListOtherAppWriteAccess const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LimitedWriteOperations(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LimitedWriteOperations, WINRT_WRAP(Windows::ApplicationModel::UserDataTasks::UserDataTaskListLimitedWriteOperations));
            *value = detach_from<Windows::ApplicationModel::UserDataTasks::UserDataTaskListLimitedWriteOperations>(this->shim().LimitedWriteOperations());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SyncManager(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SyncManager, WINRT_WRAP(Windows::ApplicationModel::UserDataTasks::UserDataTaskListSyncManager));
            *value = detach_from<Windows::ApplicationModel::UserDataTasks::UserDataTaskListSyncManager>(this->shim().SyncManager());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RegisterSyncManagerAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RegisterSyncManagerAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().RegisterSyncManagerAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetTaskReader(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetTaskReader, WINRT_WRAP(Windows::ApplicationModel::UserDataTasks::UserDataTaskReader));
            *result = detach_from<Windows::ApplicationModel::UserDataTasks::UserDataTaskReader>(this->shim().GetTaskReader());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetTaskReaderWithOptions(void* options, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetTaskReader, WINRT_WRAP(Windows::ApplicationModel::UserDataTasks::UserDataTaskReader), Windows::ApplicationModel::UserDataTasks::UserDataTaskQueryOptions const&);
            *value = detach_from<Windows::ApplicationModel::UserDataTasks::UserDataTaskReader>(this->shim().GetTaskReader(*reinterpret_cast<Windows::ApplicationModel::UserDataTasks::UserDataTaskQueryOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetTaskAsync(void* userDataTask, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetTaskAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::UserDataTasks::UserDataTask>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::UserDataTasks::UserDataTask>>(this->shim().GetTaskAsync(*reinterpret_cast<hstring const*>(&userDataTask)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SaveTaskAsync(void* userDataTask, void** action) noexcept final
    {
        try
        {
            *action = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SaveTaskAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::ApplicationModel::UserDataTasks::UserDataTask const);
            *action = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SaveTaskAsync(*reinterpret_cast<Windows::ApplicationModel::UserDataTasks::UserDataTask const*>(&userDataTask)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DeleteTaskAsync(void* userDataTaskId, void** action) noexcept final
    {
        try
        {
            *action = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeleteTaskAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), hstring const);
            *action = detach_from<Windows::Foundation::IAsyncAction>(this->shim().DeleteTaskAsync(*reinterpret_cast<hstring const*>(&userDataTaskId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DeleteAsync(void** asyncAction) noexcept final
    {
        try
        {
            *asyncAction = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeleteAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *asyncAction = detach_from<Windows::Foundation::IAsyncAction>(this->shim().DeleteAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SaveAsync(void** asyncAction) noexcept final
    {
        try
        {
            *asyncAction = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SaveAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *asyncAction = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SaveAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::UserDataTasks::IUserDataTaskListLimitedWriteOperations> : produce_base<D, Windows::ApplicationModel::UserDataTasks::IUserDataTaskListLimitedWriteOperations>
{
    int32_t WINRT_CALL TryCompleteTaskAsync(void* userDataTaskId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryCompleteTaskAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<hstring>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<hstring>>(this->shim().TryCompleteTaskAsync(*reinterpret_cast<hstring const*>(&userDataTaskId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryCreateOrUpdateTaskAsync(void* userDataTask, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryCreateOrUpdateTaskAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::ApplicationModel::UserDataTasks::UserDataTask const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryCreateOrUpdateTaskAsync(*reinterpret_cast<Windows::ApplicationModel::UserDataTasks::UserDataTask const*>(&userDataTask)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryDeleteTaskAsync(void* userDataTaskId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryDeleteTaskAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryDeleteTaskAsync(*reinterpret_cast<hstring const*>(&userDataTaskId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TrySkipOccurrenceAsync(void* userDataTaskId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrySkipOccurrenceAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TrySkipOccurrenceAsync(*reinterpret_cast<hstring const*>(&userDataTaskId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::UserDataTasks::IUserDataTaskListSyncManager> : produce_base<D, Windows::ApplicationModel::UserDataTasks::IUserDataTaskListSyncManager>
{
    int32_t WINRT_CALL get_LastAttemptedSyncTime(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LastAttemptedSyncTime, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().LastAttemptedSyncTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_LastAttemptedSyncTime(Windows::Foundation::DateTime value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LastAttemptedSyncTime, WINRT_WRAP(void), Windows::Foundation::DateTime const&);
            this->shim().LastAttemptedSyncTime(*reinterpret_cast<Windows::Foundation::DateTime const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LastSuccessfulSyncTime(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LastSuccessfulSyncTime, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().LastSuccessfulSyncTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_LastSuccessfulSyncTime(Windows::Foundation::DateTime value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LastSuccessfulSyncTime, WINRT_WRAP(void), Windows::Foundation::DateTime const&);
            this->shim().LastSuccessfulSyncTime(*reinterpret_cast<Windows::Foundation::DateTime const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Status(Windows::ApplicationModel::UserDataTasks::UserDataTaskListSyncStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::ApplicationModel::UserDataTasks::UserDataTaskListSyncStatus));
            *value = detach_from<Windows::ApplicationModel::UserDataTasks::UserDataTaskListSyncStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Status(Windows::ApplicationModel::UserDataTasks::UserDataTaskListSyncStatus value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(void), Windows::ApplicationModel::UserDataTasks::UserDataTaskListSyncStatus const&);
            this->shim().Status(*reinterpret_cast<Windows::ApplicationModel::UserDataTasks::UserDataTaskListSyncStatus const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SyncAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SyncAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().SyncAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_SyncStatusChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SyncStatusChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::UserDataTasks::UserDataTaskListSyncManager, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().SyncStatusChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::UserDataTasks::UserDataTaskListSyncManager, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_SyncStatusChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(SyncStatusChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().SyncStatusChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::UserDataTasks::IUserDataTaskManager> : produce_base<D, Windows::ApplicationModel::UserDataTasks::IUserDataTaskManager>
{
    int32_t WINRT_CALL RequestStoreAsync(Windows::ApplicationModel::UserDataTasks::UserDataTaskStoreAccessType accessType, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestStoreAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::UserDataTasks::UserDataTaskStore>), Windows::ApplicationModel::UserDataTasks::UserDataTaskStoreAccessType const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::UserDataTasks::UserDataTaskStore>>(this->shim().RequestStoreAsync(*reinterpret_cast<Windows::ApplicationModel::UserDataTasks::UserDataTaskStoreAccessType const*>(&accessType)));
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
struct produce<D, Windows::ApplicationModel::UserDataTasks::IUserDataTaskManagerStatics> : produce_base<D, Windows::ApplicationModel::UserDataTasks::IUserDataTaskManagerStatics>
{
    int32_t WINRT_CALL GetDefault(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefault, WINRT_WRAP(Windows::ApplicationModel::UserDataTasks::UserDataTaskManager));
            *result = detach_from<Windows::ApplicationModel::UserDataTasks::UserDataTaskManager>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetForUser(void* user, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForUser, WINRT_WRAP(Windows::ApplicationModel::UserDataTasks::UserDataTaskManager), Windows::System::User const&);
            *result = detach_from<Windows::ApplicationModel::UserDataTasks::UserDataTaskManager>(this->shim().GetForUser(*reinterpret_cast<Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::UserDataTasks::IUserDataTaskQueryOptions> : produce_base<D, Windows::ApplicationModel::UserDataTasks::IUserDataTaskQueryOptions>
{
    int32_t WINRT_CALL get_SortProperty(Windows::ApplicationModel::UserDataTasks::UserDataTaskQuerySortProperty* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SortProperty, WINRT_WRAP(Windows::ApplicationModel::UserDataTasks::UserDataTaskQuerySortProperty));
            *value = detach_from<Windows::ApplicationModel::UserDataTasks::UserDataTaskQuerySortProperty>(this->shim().SortProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SortProperty(Windows::ApplicationModel::UserDataTasks::UserDataTaskQuerySortProperty value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SortProperty, WINRT_WRAP(void), Windows::ApplicationModel::UserDataTasks::UserDataTaskQuerySortProperty const&);
            this->shim().SortProperty(*reinterpret_cast<Windows::ApplicationModel::UserDataTasks::UserDataTaskQuerySortProperty const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Kind(Windows::ApplicationModel::UserDataTasks::UserDataTaskQueryKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Kind, WINRT_WRAP(Windows::ApplicationModel::UserDataTasks::UserDataTaskQueryKind));
            *value = detach_from<Windows::ApplicationModel::UserDataTasks::UserDataTaskQueryKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Kind(Windows::ApplicationModel::UserDataTasks::UserDataTaskQueryKind value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Kind, WINRT_WRAP(void), Windows::ApplicationModel::UserDataTasks::UserDataTaskQueryKind const&);
            this->shim().Kind(*reinterpret_cast<Windows::ApplicationModel::UserDataTasks::UserDataTaskQueryKind const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::UserDataTasks::IUserDataTaskReader> : produce_base<D, Windows::ApplicationModel::UserDataTasks::IUserDataTaskReader>
{
    int32_t WINRT_CALL ReadBatchAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadBatchAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::UserDataTasks::UserDataTaskBatch>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::UserDataTasks::UserDataTaskBatch>>(this->shim().ReadBatchAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::UserDataTasks::IUserDataTaskRecurrenceProperties> : produce_base<D, Windows::ApplicationModel::UserDataTasks::IUserDataTaskRecurrenceProperties>
{
    int32_t WINRT_CALL get_Unit(Windows::ApplicationModel::UserDataTasks::UserDataTaskRecurrenceUnit* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Unit, WINRT_WRAP(Windows::ApplicationModel::UserDataTasks::UserDataTaskRecurrenceUnit));
            *value = detach_from<Windows::ApplicationModel::UserDataTasks::UserDataTaskRecurrenceUnit>(this->shim().Unit());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Unit(Windows::ApplicationModel::UserDataTasks::UserDataTaskRecurrenceUnit value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Unit, WINRT_WRAP(void), Windows::ApplicationModel::UserDataTasks::UserDataTaskRecurrenceUnit const&);
            this->shim().Unit(*reinterpret_cast<Windows::ApplicationModel::UserDataTasks::UserDataTaskRecurrenceUnit const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Occurrences(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Occurrences, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().Occurrences());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Occurrences(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Occurrences, WINRT_WRAP(void), Windows::Foundation::IReference<int32_t> const&);
            this->shim().Occurrences(*reinterpret_cast<Windows::Foundation::IReference<int32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Until(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Until, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::DateTime>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::DateTime>>(this->shim().Until());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Until(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Until, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Foundation::DateTime> const&);
            this->shim().Until(*reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::DateTime> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Interval(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Interval, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().Interval());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Interval(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Interval, WINRT_WRAP(void), int32_t);
            this->shim().Interval(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DaysOfWeek(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DaysOfWeek, WINRT_WRAP(Windows::Foundation::IReference<Windows::ApplicationModel::UserDataTasks::UserDataTaskDaysOfWeek>));
            *value = detach_from<Windows::Foundation::IReference<Windows::ApplicationModel::UserDataTasks::UserDataTaskDaysOfWeek>>(this->shim().DaysOfWeek());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DaysOfWeek(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DaysOfWeek, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::ApplicationModel::UserDataTasks::UserDataTaskDaysOfWeek> const&);
            this->shim().DaysOfWeek(*reinterpret_cast<Windows::Foundation::IReference<Windows::ApplicationModel::UserDataTasks::UserDataTaskDaysOfWeek> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WeekOfMonth(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WeekOfMonth, WINRT_WRAP(Windows::Foundation::IReference<Windows::ApplicationModel::UserDataTasks::UserDataTaskWeekOfMonth>));
            *value = detach_from<Windows::Foundation::IReference<Windows::ApplicationModel::UserDataTasks::UserDataTaskWeekOfMonth>>(this->shim().WeekOfMonth());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_WeekOfMonth(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WeekOfMonth, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::ApplicationModel::UserDataTasks::UserDataTaskWeekOfMonth> const&);
            this->shim().WeekOfMonth(*reinterpret_cast<Windows::Foundation::IReference<Windows::ApplicationModel::UserDataTasks::UserDataTaskWeekOfMonth> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Month(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Month, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().Month());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Month(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Month, WINRT_WRAP(void), Windows::Foundation::IReference<int32_t> const&);
            this->shim().Month(*reinterpret_cast<Windows::Foundation::IReference<int32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Day(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Day, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().Day());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Day(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Day, WINRT_WRAP(void), Windows::Foundation::IReference<int32_t> const&);
            this->shim().Day(*reinterpret_cast<Windows::Foundation::IReference<int32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::UserDataTasks::IUserDataTaskRegenerationProperties> : produce_base<D, Windows::ApplicationModel::UserDataTasks::IUserDataTaskRegenerationProperties>
{
    int32_t WINRT_CALL get_Unit(Windows::ApplicationModel::UserDataTasks::UserDataTaskRegenerationUnit* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Unit, WINRT_WRAP(Windows::ApplicationModel::UserDataTasks::UserDataTaskRegenerationUnit));
            *value = detach_from<Windows::ApplicationModel::UserDataTasks::UserDataTaskRegenerationUnit>(this->shim().Unit());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Unit(Windows::ApplicationModel::UserDataTasks::UserDataTaskRegenerationUnit value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Unit, WINRT_WRAP(void), Windows::ApplicationModel::UserDataTasks::UserDataTaskRegenerationUnit const&);
            this->shim().Unit(*reinterpret_cast<Windows::ApplicationModel::UserDataTasks::UserDataTaskRegenerationUnit const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Occurrences(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Occurrences, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().Occurrences());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Occurrences(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Occurrences, WINRT_WRAP(void), Windows::Foundation::IReference<int32_t> const&);
            this->shim().Occurrences(*reinterpret_cast<Windows::Foundation::IReference<int32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Until(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Until, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::DateTime>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::DateTime>>(this->shim().Until());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Until(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Until, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Foundation::DateTime> const&);
            this->shim().Until(*reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::DateTime> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Interval(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Interval, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().Interval());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Interval(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Interval, WINRT_WRAP(void), int32_t);
            this->shim().Interval(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::UserDataTasks::IUserDataTaskStore> : produce_base<D, Windows::ApplicationModel::UserDataTasks::IUserDataTaskStore>
{
    int32_t WINRT_CALL CreateListAsync(void* name, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateListAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::UserDataTasks::UserDataTaskList>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::UserDataTasks::UserDataTaskList>>(this->shim().CreateListAsync(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateListInAccountAsync(void* name, void* userDataAccountId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateListAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::UserDataTasks::UserDataTaskList>), hstring const, hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::UserDataTasks::UserDataTaskList>>(this->shim().CreateListAsync(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<hstring const*>(&userDataAccountId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindListsAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindListsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::UserDataTasks::UserDataTaskList>>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::UserDataTasks::UserDataTaskList>>>(this->shim().FindListsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetListAsync(void* taskListId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetListAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::UserDataTasks::UserDataTaskList>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::UserDataTasks::UserDataTaskList>>(this->shim().GetListAsync(*reinterpret_cast<hstring const*>(&taskListId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::UserDataTasks {

inline UserDataTask::UserDataTask() :
    UserDataTask(impl::call_factory<UserDataTask>([](auto&& f) { return f.template ActivateInstance<UserDataTask>(); }))
{}

inline Windows::ApplicationModel::UserDataTasks::UserDataTaskManager UserDataTaskManager::GetDefault()
{
    return impl::call_factory<UserDataTaskManager, Windows::ApplicationModel::UserDataTasks::IUserDataTaskManagerStatics>([&](auto&& f) { return f.GetDefault(); });
}

inline Windows::ApplicationModel::UserDataTasks::UserDataTaskManager UserDataTaskManager::GetForUser(Windows::System::User const& user)
{
    return impl::call_factory<UserDataTaskManager, Windows::ApplicationModel::UserDataTasks::IUserDataTaskManagerStatics>([&](auto&& f) { return f.GetForUser(user); });
}

inline UserDataTaskQueryOptions::UserDataTaskQueryOptions() :
    UserDataTaskQueryOptions(impl::call_factory<UserDataTaskQueryOptions>([](auto&& f) { return f.template ActivateInstance<UserDataTaskQueryOptions>(); }))
{}

inline UserDataTaskRecurrenceProperties::UserDataTaskRecurrenceProperties() :
    UserDataTaskRecurrenceProperties(impl::call_factory<UserDataTaskRecurrenceProperties>([](auto&& f) { return f.template ActivateInstance<UserDataTaskRecurrenceProperties>(); }))
{}

inline UserDataTaskRegenerationProperties::UserDataTaskRegenerationProperties() :
    UserDataTaskRegenerationProperties(impl::call_factory<UserDataTaskRegenerationProperties>([](auto&& f) { return f.template ActivateInstance<UserDataTaskRegenerationProperties>(); }))
{}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::ApplicationModel::UserDataTasks::IUserDataTask> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataTasks::IUserDataTask> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataTasks::IUserDataTaskBatch> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataTasks::IUserDataTaskBatch> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataTasks::IUserDataTaskList> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataTasks::IUserDataTaskList> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataTasks::IUserDataTaskListLimitedWriteOperations> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataTasks::IUserDataTaskListLimitedWriteOperations> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataTasks::IUserDataTaskListSyncManager> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataTasks::IUserDataTaskListSyncManager> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataTasks::IUserDataTaskManager> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataTasks::IUserDataTaskManager> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataTasks::IUserDataTaskManagerStatics> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataTasks::IUserDataTaskManagerStatics> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataTasks::IUserDataTaskQueryOptions> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataTasks::IUserDataTaskQueryOptions> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataTasks::IUserDataTaskReader> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataTasks::IUserDataTaskReader> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataTasks::IUserDataTaskRecurrenceProperties> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataTasks::IUserDataTaskRecurrenceProperties> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataTasks::IUserDataTaskRegenerationProperties> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataTasks::IUserDataTaskRegenerationProperties> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataTasks::IUserDataTaskStore> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataTasks::IUserDataTaskStore> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataTasks::UserDataTask> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataTasks::UserDataTask> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataTasks::UserDataTaskBatch> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataTasks::UserDataTaskBatch> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataTasks::UserDataTaskList> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataTasks::UserDataTaskList> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataTasks::UserDataTaskListLimitedWriteOperations> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataTasks::UserDataTaskListLimitedWriteOperations> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataTasks::UserDataTaskListSyncManager> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataTasks::UserDataTaskListSyncManager> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataTasks::UserDataTaskManager> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataTasks::UserDataTaskManager> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataTasks::UserDataTaskQueryOptions> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataTasks::UserDataTaskQueryOptions> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataTasks::UserDataTaskReader> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataTasks::UserDataTaskReader> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataTasks::UserDataTaskRecurrenceProperties> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataTasks::UserDataTaskRecurrenceProperties> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataTasks::UserDataTaskRegenerationProperties> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataTasks::UserDataTaskRegenerationProperties> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataTasks::UserDataTaskStore> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataTasks::UserDataTaskStore> {};

}
