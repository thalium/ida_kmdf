// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.ApplicationModel.Appointments.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.ApplicationModel.Appointments.DataProvider.2.h"
#include "winrt/Windows.ApplicationModel.Appointments.h"

namespace winrt::impl {

template <typename D> hstring consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentCalendarCancelMeetingRequest<D>::AppointmentCalendarLocalId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarCancelMeetingRequest)->get_AppointmentCalendarLocalId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentCalendarCancelMeetingRequest<D>::AppointmentLocalId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarCancelMeetingRequest)->get_AppointmentLocalId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::DateTime> consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentCalendarCancelMeetingRequest<D>::AppointmentOriginalStartTime() const
{
    Windows::Foundation::IReference<Windows::Foundation::DateTime> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarCancelMeetingRequest)->get_AppointmentOriginalStartTime(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentCalendarCancelMeetingRequest<D>::Subject() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarCancelMeetingRequest)->get_Subject(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentCalendarCancelMeetingRequest<D>::Comment() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarCancelMeetingRequest)->get_Comment(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentCalendarCancelMeetingRequest<D>::NotifyInvitees() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarCancelMeetingRequest)->get_NotifyInvitees(&value));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentCalendarCancelMeetingRequest<D>::ReportCompletedAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarCancelMeetingRequest)->ReportCompletedAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentCalendarCancelMeetingRequest<D>::ReportFailedAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarCancelMeetingRequest)->ReportFailedAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarCancelMeetingRequest consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentCalendarCancelMeetingRequestEventArgs<D>::Request() const
{
    Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarCancelMeetingRequest value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarCancelMeetingRequestEventArgs)->get_Request(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Deferral consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentCalendarCancelMeetingRequestEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarCancelMeetingRequestEventArgs)->GetDeferral(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentCalendarCreateOrUpdateAppointmentRequest<D>::AppointmentCalendarLocalId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarCreateOrUpdateAppointmentRequest)->get_AppointmentCalendarLocalId(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Appointments::Appointment consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentCalendarCreateOrUpdateAppointmentRequest<D>::Appointment() const
{
    Windows::ApplicationModel::Appointments::Appointment value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarCreateOrUpdateAppointmentRequest)->get_Appointment(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentCalendarCreateOrUpdateAppointmentRequest<D>::NotifyInvitees() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarCreateOrUpdateAppointmentRequest)->get_NotifyInvitees(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<hstring> consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentCalendarCreateOrUpdateAppointmentRequest<D>::ChangedProperties() const
{
    Windows::Foundation::Collections::IVectorView<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarCreateOrUpdateAppointmentRequest)->get_ChangedProperties(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentCalendarCreateOrUpdateAppointmentRequest<D>::ReportCompletedAsync(Windows::ApplicationModel::Appointments::Appointment const& createdOrUpdatedAppointment) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarCreateOrUpdateAppointmentRequest)->ReportCompletedAsync(get_abi(createdOrUpdatedAppointment), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentCalendarCreateOrUpdateAppointmentRequest<D>::ReportFailedAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarCreateOrUpdateAppointmentRequest)->ReportFailedAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarCreateOrUpdateAppointmentRequest consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentCalendarCreateOrUpdateAppointmentRequestEventArgs<D>::Request() const
{
    Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarCreateOrUpdateAppointmentRequest value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarCreateOrUpdateAppointmentRequestEventArgs)->get_Request(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Deferral consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentCalendarCreateOrUpdateAppointmentRequestEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarCreateOrUpdateAppointmentRequestEventArgs)->GetDeferral(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentCalendarForwardMeetingRequest<D>::AppointmentCalendarLocalId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarForwardMeetingRequest)->get_AppointmentCalendarLocalId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentCalendarForwardMeetingRequest<D>::AppointmentLocalId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarForwardMeetingRequest)->get_AppointmentLocalId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::DateTime> consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentCalendarForwardMeetingRequest<D>::AppointmentOriginalStartTime() const
{
    Windows::Foundation::IReference<Windows::Foundation::DateTime> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarForwardMeetingRequest)->get_AppointmentOriginalStartTime(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Appointments::AppointmentInvitee> consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentCalendarForwardMeetingRequest<D>::Invitees() const
{
    Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Appointments::AppointmentInvitee> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarForwardMeetingRequest)->get_Invitees(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentCalendarForwardMeetingRequest<D>::Subject() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarForwardMeetingRequest)->get_Subject(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentCalendarForwardMeetingRequest<D>::ForwardHeader() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarForwardMeetingRequest)->get_ForwardHeader(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentCalendarForwardMeetingRequest<D>::Comment() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarForwardMeetingRequest)->get_Comment(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentCalendarForwardMeetingRequest<D>::ReportCompletedAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarForwardMeetingRequest)->ReportCompletedAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentCalendarForwardMeetingRequest<D>::ReportFailedAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarForwardMeetingRequest)->ReportFailedAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarForwardMeetingRequest consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentCalendarForwardMeetingRequestEventArgs<D>::Request() const
{
    Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarForwardMeetingRequest value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarForwardMeetingRequestEventArgs)->get_Request(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Deferral consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentCalendarForwardMeetingRequestEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarForwardMeetingRequestEventArgs)->GetDeferral(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentCalendarProposeNewTimeForMeetingRequest<D>::AppointmentCalendarLocalId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarProposeNewTimeForMeetingRequest)->get_AppointmentCalendarLocalId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentCalendarProposeNewTimeForMeetingRequest<D>::AppointmentLocalId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarProposeNewTimeForMeetingRequest)->get_AppointmentLocalId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::DateTime> consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentCalendarProposeNewTimeForMeetingRequest<D>::AppointmentOriginalStartTime() const
{
    Windows::Foundation::IReference<Windows::Foundation::DateTime> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarProposeNewTimeForMeetingRequest)->get_AppointmentOriginalStartTime(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentCalendarProposeNewTimeForMeetingRequest<D>::NewStartTime() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarProposeNewTimeForMeetingRequest)->get_NewStartTime(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentCalendarProposeNewTimeForMeetingRequest<D>::NewDuration() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarProposeNewTimeForMeetingRequest)->get_NewDuration(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentCalendarProposeNewTimeForMeetingRequest<D>::Subject() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarProposeNewTimeForMeetingRequest)->get_Subject(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentCalendarProposeNewTimeForMeetingRequest<D>::Comment() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarProposeNewTimeForMeetingRequest)->get_Comment(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentCalendarProposeNewTimeForMeetingRequest<D>::ReportCompletedAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarProposeNewTimeForMeetingRequest)->ReportCompletedAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentCalendarProposeNewTimeForMeetingRequest<D>::ReportFailedAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarProposeNewTimeForMeetingRequest)->ReportFailedAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarProposeNewTimeForMeetingRequest consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentCalendarProposeNewTimeForMeetingRequestEventArgs<D>::Request() const
{
    Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarProposeNewTimeForMeetingRequest value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarProposeNewTimeForMeetingRequestEventArgs)->get_Request(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Deferral consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentCalendarProposeNewTimeForMeetingRequestEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarProposeNewTimeForMeetingRequestEventArgs)->GetDeferral(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentCalendarSyncManagerSyncRequest<D>::AppointmentCalendarLocalId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarSyncManagerSyncRequest)->get_AppointmentCalendarLocalId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentCalendarSyncManagerSyncRequest<D>::ReportCompletedAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarSyncManagerSyncRequest)->ReportCompletedAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentCalendarSyncManagerSyncRequest<D>::ReportFailedAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarSyncManagerSyncRequest)->ReportFailedAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarSyncManagerSyncRequest consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentCalendarSyncManagerSyncRequestEventArgs<D>::Request() const
{
    Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarSyncManagerSyncRequest value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarSyncManagerSyncRequestEventArgs)->get_Request(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Deferral consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentCalendarSyncManagerSyncRequestEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarSyncManagerSyncRequestEventArgs)->GetDeferral(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentCalendarUpdateMeetingResponseRequest<D>::AppointmentCalendarLocalId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarUpdateMeetingResponseRequest)->get_AppointmentCalendarLocalId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentCalendarUpdateMeetingResponseRequest<D>::AppointmentLocalId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarUpdateMeetingResponseRequest)->get_AppointmentLocalId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::DateTime> consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentCalendarUpdateMeetingResponseRequest<D>::AppointmentOriginalStartTime() const
{
    Windows::Foundation::IReference<Windows::Foundation::DateTime> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarUpdateMeetingResponseRequest)->get_AppointmentOriginalStartTime(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Appointments::AppointmentParticipantResponse consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentCalendarUpdateMeetingResponseRequest<D>::Response() const
{
    Windows::ApplicationModel::Appointments::AppointmentParticipantResponse response{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarUpdateMeetingResponseRequest)->get_Response(put_abi(response)));
    return response;
}

template <typename D> hstring consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentCalendarUpdateMeetingResponseRequest<D>::Subject() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarUpdateMeetingResponseRequest)->get_Subject(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentCalendarUpdateMeetingResponseRequest<D>::Comment() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarUpdateMeetingResponseRequest)->get_Comment(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentCalendarUpdateMeetingResponseRequest<D>::SendUpdate() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarUpdateMeetingResponseRequest)->get_SendUpdate(&value));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentCalendarUpdateMeetingResponseRequest<D>::ReportCompletedAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarUpdateMeetingResponseRequest)->ReportCompletedAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentCalendarUpdateMeetingResponseRequest<D>::ReportFailedAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarUpdateMeetingResponseRequest)->ReportFailedAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarUpdateMeetingResponseRequest consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentCalendarUpdateMeetingResponseRequestEventArgs<D>::Request() const
{
    Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarUpdateMeetingResponseRequest value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarUpdateMeetingResponseRequestEventArgs)->get_Request(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Deferral consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentCalendarUpdateMeetingResponseRequestEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarUpdateMeetingResponseRequestEventArgs)->GetDeferral(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentDataProviderConnection<D>::SyncRequested(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Appointments::DataProvider::AppointmentDataProviderConnection, Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarSyncManagerSyncRequestEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::DataProvider::IAppointmentDataProviderConnection)->add_SyncRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentDataProviderConnection<D>::SyncRequested_revoker consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentDataProviderConnection<D>::SyncRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Appointments::DataProvider::AppointmentDataProviderConnection, Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarSyncManagerSyncRequestEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, SyncRequested_revoker>(this, SyncRequested(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentDataProviderConnection<D>::SyncRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Appointments::DataProvider::IAppointmentDataProviderConnection)->remove_SyncRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentDataProviderConnection<D>::CreateOrUpdateAppointmentRequested(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Appointments::DataProvider::AppointmentDataProviderConnection, Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarCreateOrUpdateAppointmentRequestEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::DataProvider::IAppointmentDataProviderConnection)->add_CreateOrUpdateAppointmentRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentDataProviderConnection<D>::CreateOrUpdateAppointmentRequested_revoker consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentDataProviderConnection<D>::CreateOrUpdateAppointmentRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Appointments::DataProvider::AppointmentDataProviderConnection, Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarCreateOrUpdateAppointmentRequestEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, CreateOrUpdateAppointmentRequested_revoker>(this, CreateOrUpdateAppointmentRequested(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentDataProviderConnection<D>::CreateOrUpdateAppointmentRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Appointments::DataProvider::IAppointmentDataProviderConnection)->remove_CreateOrUpdateAppointmentRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentDataProviderConnection<D>::CancelMeetingRequested(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Appointments::DataProvider::AppointmentDataProviderConnection, Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarCancelMeetingRequestEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::DataProvider::IAppointmentDataProviderConnection)->add_CancelMeetingRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentDataProviderConnection<D>::CancelMeetingRequested_revoker consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentDataProviderConnection<D>::CancelMeetingRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Appointments::DataProvider::AppointmentDataProviderConnection, Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarCancelMeetingRequestEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, CancelMeetingRequested_revoker>(this, CancelMeetingRequested(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentDataProviderConnection<D>::CancelMeetingRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Appointments::DataProvider::IAppointmentDataProviderConnection)->remove_CancelMeetingRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentDataProviderConnection<D>::ForwardMeetingRequested(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Appointments::DataProvider::AppointmentDataProviderConnection, Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarForwardMeetingRequestEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::DataProvider::IAppointmentDataProviderConnection)->add_ForwardMeetingRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentDataProviderConnection<D>::ForwardMeetingRequested_revoker consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentDataProviderConnection<D>::ForwardMeetingRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Appointments::DataProvider::AppointmentDataProviderConnection, Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarForwardMeetingRequestEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ForwardMeetingRequested_revoker>(this, ForwardMeetingRequested(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentDataProviderConnection<D>::ForwardMeetingRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Appointments::DataProvider::IAppointmentDataProviderConnection)->remove_ForwardMeetingRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentDataProviderConnection<D>::ProposeNewTimeForMeetingRequested(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Appointments::DataProvider::AppointmentDataProviderConnection, Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarProposeNewTimeForMeetingRequestEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::DataProvider::IAppointmentDataProviderConnection)->add_ProposeNewTimeForMeetingRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentDataProviderConnection<D>::ProposeNewTimeForMeetingRequested_revoker consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentDataProviderConnection<D>::ProposeNewTimeForMeetingRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Appointments::DataProvider::AppointmentDataProviderConnection, Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarProposeNewTimeForMeetingRequestEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ProposeNewTimeForMeetingRequested_revoker>(this, ProposeNewTimeForMeetingRequested(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentDataProviderConnection<D>::ProposeNewTimeForMeetingRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Appointments::DataProvider::IAppointmentDataProviderConnection)->remove_ProposeNewTimeForMeetingRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentDataProviderConnection<D>::UpdateMeetingResponseRequested(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Appointments::DataProvider::AppointmentDataProviderConnection, Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarUpdateMeetingResponseRequestEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::DataProvider::IAppointmentDataProviderConnection)->add_UpdateMeetingResponseRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentDataProviderConnection<D>::UpdateMeetingResponseRequested_revoker consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentDataProviderConnection<D>::UpdateMeetingResponseRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Appointments::DataProvider::AppointmentDataProviderConnection, Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarUpdateMeetingResponseRequestEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, UpdateMeetingResponseRequested_revoker>(this, UpdateMeetingResponseRequested(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentDataProviderConnection<D>::UpdateMeetingResponseRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Appointments::DataProvider::IAppointmentDataProviderConnection)->remove_UpdateMeetingResponseRequested(get_abi(token)));
}

template <typename D> void consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentDataProviderConnection<D>::Start() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::DataProvider::IAppointmentDataProviderConnection)->Start());
}

template <typename D> Windows::ApplicationModel::Appointments::DataProvider::AppointmentDataProviderConnection consume_Windows_ApplicationModel_Appointments_DataProvider_IAppointmentDataProviderTriggerDetails<D>::Connection() const
{
    Windows::ApplicationModel::Appointments::DataProvider::AppointmentDataProviderConnection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::DataProvider::IAppointmentDataProviderTriggerDetails)->get_Connection(put_abi(value)));
    return value;
}

template <typename D>
struct produce<D, Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarCancelMeetingRequest> : produce_base<D, Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarCancelMeetingRequest>
{
    int32_t WINRT_CALL get_AppointmentCalendarLocalId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppointmentCalendarLocalId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AppointmentCalendarLocalId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AppointmentLocalId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppointmentLocalId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AppointmentLocalId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AppointmentOriginalStartTime(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppointmentOriginalStartTime, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::DateTime>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::DateTime>>(this->shim().AppointmentOriginalStartTime());
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

    int32_t WINRT_CALL get_Comment(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Comment, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Comment());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NotifyInvitees(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NotifyInvitees, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().NotifyInvitees());
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
struct produce<D, Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarCancelMeetingRequestEventArgs> : produce_base<D, Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarCancelMeetingRequestEventArgs>
{
    int32_t WINRT_CALL get_Request(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Request, WINRT_WRAP(Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarCancelMeetingRequest));
            *value = detach_from<Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarCancelMeetingRequest>(this->shim().Request());
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
struct produce<D, Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarCreateOrUpdateAppointmentRequest> : produce_base<D, Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarCreateOrUpdateAppointmentRequest>
{
    int32_t WINRT_CALL get_AppointmentCalendarLocalId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppointmentCalendarLocalId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AppointmentCalendarLocalId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Appointment(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Appointment, WINRT_WRAP(Windows::ApplicationModel::Appointments::Appointment));
            *value = detach_from<Windows::ApplicationModel::Appointments::Appointment>(this->shim().Appointment());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NotifyInvitees(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NotifyInvitees, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().NotifyInvitees());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ChangedProperties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChangedProperties, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().ChangedProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReportCompletedAsync(void* createdOrUpdatedAppointment, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportCompletedAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::ApplicationModel::Appointments::Appointment const);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ReportCompletedAsync(*reinterpret_cast<Windows::ApplicationModel::Appointments::Appointment const*>(&createdOrUpdatedAppointment)));
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
struct produce<D, Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarCreateOrUpdateAppointmentRequestEventArgs> : produce_base<D, Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarCreateOrUpdateAppointmentRequestEventArgs>
{
    int32_t WINRT_CALL get_Request(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Request, WINRT_WRAP(Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarCreateOrUpdateAppointmentRequest));
            *value = detach_from<Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarCreateOrUpdateAppointmentRequest>(this->shim().Request());
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
struct produce<D, Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarForwardMeetingRequest> : produce_base<D, Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarForwardMeetingRequest>
{
    int32_t WINRT_CALL get_AppointmentCalendarLocalId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppointmentCalendarLocalId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AppointmentCalendarLocalId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AppointmentLocalId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppointmentLocalId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AppointmentLocalId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AppointmentOriginalStartTime(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppointmentOriginalStartTime, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::DateTime>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::DateTime>>(this->shim().AppointmentOriginalStartTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Invitees(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Invitees, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Appointments::AppointmentInvitee>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Appointments::AppointmentInvitee>>(this->shim().Invitees());
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

    int32_t WINRT_CALL get_ForwardHeader(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ForwardHeader, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ForwardHeader());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Comment(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Comment, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Comment());
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
struct produce<D, Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarForwardMeetingRequestEventArgs> : produce_base<D, Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarForwardMeetingRequestEventArgs>
{
    int32_t WINRT_CALL get_Request(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Request, WINRT_WRAP(Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarForwardMeetingRequest));
            *value = detach_from<Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarForwardMeetingRequest>(this->shim().Request());
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
struct produce<D, Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarProposeNewTimeForMeetingRequest> : produce_base<D, Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarProposeNewTimeForMeetingRequest>
{
    int32_t WINRT_CALL get_AppointmentCalendarLocalId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppointmentCalendarLocalId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AppointmentCalendarLocalId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AppointmentLocalId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppointmentLocalId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AppointmentLocalId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AppointmentOriginalStartTime(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppointmentOriginalStartTime, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::DateTime>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::DateTime>>(this->shim().AppointmentOriginalStartTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NewStartTime(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NewStartTime, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().NewStartTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NewDuration(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NewDuration, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().NewDuration());
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

    int32_t WINRT_CALL get_Comment(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Comment, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Comment());
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
struct produce<D, Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarProposeNewTimeForMeetingRequestEventArgs> : produce_base<D, Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarProposeNewTimeForMeetingRequestEventArgs>
{
    int32_t WINRT_CALL get_Request(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Request, WINRT_WRAP(Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarProposeNewTimeForMeetingRequest));
            *value = detach_from<Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarProposeNewTimeForMeetingRequest>(this->shim().Request());
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
struct produce<D, Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarSyncManagerSyncRequest> : produce_base<D, Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarSyncManagerSyncRequest>
{
    int32_t WINRT_CALL get_AppointmentCalendarLocalId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppointmentCalendarLocalId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AppointmentCalendarLocalId());
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
struct produce<D, Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarSyncManagerSyncRequestEventArgs> : produce_base<D, Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarSyncManagerSyncRequestEventArgs>
{
    int32_t WINRT_CALL get_Request(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Request, WINRT_WRAP(Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarSyncManagerSyncRequest));
            *value = detach_from<Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarSyncManagerSyncRequest>(this->shim().Request());
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
struct produce<D, Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarUpdateMeetingResponseRequest> : produce_base<D, Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarUpdateMeetingResponseRequest>
{
    int32_t WINRT_CALL get_AppointmentCalendarLocalId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppointmentCalendarLocalId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AppointmentCalendarLocalId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AppointmentLocalId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppointmentLocalId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AppointmentLocalId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AppointmentOriginalStartTime(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppointmentOriginalStartTime, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::DateTime>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::DateTime>>(this->shim().AppointmentOriginalStartTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Response(Windows::ApplicationModel::Appointments::AppointmentParticipantResponse* response) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Response, WINRT_WRAP(Windows::ApplicationModel::Appointments::AppointmentParticipantResponse));
            *response = detach_from<Windows::ApplicationModel::Appointments::AppointmentParticipantResponse>(this->shim().Response());
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

    int32_t WINRT_CALL get_Comment(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Comment, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Comment());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SendUpdate(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SendUpdate, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().SendUpdate());
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
struct produce<D, Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarUpdateMeetingResponseRequestEventArgs> : produce_base<D, Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarUpdateMeetingResponseRequestEventArgs>
{
    int32_t WINRT_CALL get_Request(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Request, WINRT_WRAP(Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarUpdateMeetingResponseRequest));
            *value = detach_from<Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarUpdateMeetingResponseRequest>(this->shim().Request());
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
struct produce<D, Windows::ApplicationModel::Appointments::DataProvider::IAppointmentDataProviderConnection> : produce_base<D, Windows::ApplicationModel::Appointments::DataProvider::IAppointmentDataProviderConnection>
{
    int32_t WINRT_CALL add_SyncRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SyncRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Appointments::DataProvider::AppointmentDataProviderConnection, Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarSyncManagerSyncRequestEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().SyncRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Appointments::DataProvider::AppointmentDataProviderConnection, Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarSyncManagerSyncRequestEventArgs> const*>(&handler)));
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

    int32_t WINRT_CALL add_CreateOrUpdateAppointmentRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateOrUpdateAppointmentRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Appointments::DataProvider::AppointmentDataProviderConnection, Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarCreateOrUpdateAppointmentRequestEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().CreateOrUpdateAppointmentRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Appointments::DataProvider::AppointmentDataProviderConnection, Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarCreateOrUpdateAppointmentRequestEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_CreateOrUpdateAppointmentRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(CreateOrUpdateAppointmentRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().CreateOrUpdateAppointmentRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_CancelMeetingRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CancelMeetingRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Appointments::DataProvider::AppointmentDataProviderConnection, Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarCancelMeetingRequestEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().CancelMeetingRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Appointments::DataProvider::AppointmentDataProviderConnection, Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarCancelMeetingRequestEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_CancelMeetingRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(CancelMeetingRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().CancelMeetingRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_ForwardMeetingRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ForwardMeetingRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Appointments::DataProvider::AppointmentDataProviderConnection, Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarForwardMeetingRequestEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ForwardMeetingRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Appointments::DataProvider::AppointmentDataProviderConnection, Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarForwardMeetingRequestEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ForwardMeetingRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ForwardMeetingRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ForwardMeetingRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_ProposeNewTimeForMeetingRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProposeNewTimeForMeetingRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Appointments::DataProvider::AppointmentDataProviderConnection, Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarProposeNewTimeForMeetingRequestEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ProposeNewTimeForMeetingRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Appointments::DataProvider::AppointmentDataProviderConnection, Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarProposeNewTimeForMeetingRequestEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ProposeNewTimeForMeetingRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ProposeNewTimeForMeetingRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ProposeNewTimeForMeetingRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_UpdateMeetingResponseRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpdateMeetingResponseRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Appointments::DataProvider::AppointmentDataProviderConnection, Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarUpdateMeetingResponseRequestEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().UpdateMeetingResponseRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Appointments::DataProvider::AppointmentDataProviderConnection, Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarUpdateMeetingResponseRequestEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_UpdateMeetingResponseRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(UpdateMeetingResponseRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().UpdateMeetingResponseRequested(*reinterpret_cast<winrt::event_token const*>(&token));
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
struct produce<D, Windows::ApplicationModel::Appointments::DataProvider::IAppointmentDataProviderTriggerDetails> : produce_base<D, Windows::ApplicationModel::Appointments::DataProvider::IAppointmentDataProviderTriggerDetails>
{
    int32_t WINRT_CALL get_Connection(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Connection, WINRT_WRAP(Windows::ApplicationModel::Appointments::DataProvider::AppointmentDataProviderConnection));
            *value = detach_from<Windows::ApplicationModel::Appointments::DataProvider::AppointmentDataProviderConnection>(this->shim().Connection());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Appointments::DataProvider {

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarCancelMeetingRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarCancelMeetingRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarCancelMeetingRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarCancelMeetingRequestEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarCreateOrUpdateAppointmentRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarCreateOrUpdateAppointmentRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarCreateOrUpdateAppointmentRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarCreateOrUpdateAppointmentRequestEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarForwardMeetingRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarForwardMeetingRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarForwardMeetingRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarForwardMeetingRequestEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarProposeNewTimeForMeetingRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarProposeNewTimeForMeetingRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarProposeNewTimeForMeetingRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarProposeNewTimeForMeetingRequestEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarSyncManagerSyncRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarSyncManagerSyncRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarSyncManagerSyncRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarSyncManagerSyncRequestEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarUpdateMeetingResponseRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarUpdateMeetingResponseRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarUpdateMeetingResponseRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Appointments::DataProvider::IAppointmentCalendarUpdateMeetingResponseRequestEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Appointments::DataProvider::IAppointmentDataProviderConnection> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Appointments::DataProvider::IAppointmentDataProviderConnection> {};
template<> struct hash<winrt::Windows::ApplicationModel::Appointments::DataProvider::IAppointmentDataProviderTriggerDetails> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Appointments::DataProvider::IAppointmentDataProviderTriggerDetails> {};
template<> struct hash<winrt::Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarCancelMeetingRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarCancelMeetingRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarCancelMeetingRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarCancelMeetingRequestEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarCreateOrUpdateAppointmentRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarCreateOrUpdateAppointmentRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarCreateOrUpdateAppointmentRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarCreateOrUpdateAppointmentRequestEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarForwardMeetingRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarForwardMeetingRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarForwardMeetingRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarForwardMeetingRequestEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarProposeNewTimeForMeetingRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarProposeNewTimeForMeetingRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarProposeNewTimeForMeetingRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarProposeNewTimeForMeetingRequestEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarSyncManagerSyncRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarSyncManagerSyncRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarSyncManagerSyncRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarSyncManagerSyncRequestEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarUpdateMeetingResponseRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarUpdateMeetingResponseRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarUpdateMeetingResponseRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Appointments::DataProvider::AppointmentCalendarUpdateMeetingResponseRequestEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Appointments::DataProvider::AppointmentDataProviderConnection> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Appointments::DataProvider::AppointmentDataProviderConnection> {};
template<> struct hash<winrt::Windows::ApplicationModel::Appointments::DataProvider::AppointmentDataProviderTriggerDetails> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Appointments::DataProvider::AppointmentDataProviderTriggerDetails> {};

}
