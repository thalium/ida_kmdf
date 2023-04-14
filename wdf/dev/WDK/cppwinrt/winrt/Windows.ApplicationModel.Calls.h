// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.ApplicationModel.Contacts.2.h"
#include "winrt/impl/Windows.Devices.Enumeration.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.UI.2.h"
#include "winrt/impl/Windows.ApplicationModel.Calls.2.h"
#include "winrt/Windows.ApplicationModel.h"

namespace winrt::impl {

template <typename D> Windows::ApplicationModel::Calls::VoipPhoneCallMedia consume_Windows_ApplicationModel_Calls_ICallAnswerEventArgs<D>::AcceptedMedia() const
{
    Windows::ApplicationModel::Calls::VoipPhoneCallMedia value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::ICallAnswerEventArgs)->get_AcceptedMedia(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Calls::VoipPhoneCallRejectReason consume_Windows_ApplicationModel_Calls_ICallRejectEventArgs<D>::RejectReason() const
{
    Windows::ApplicationModel::Calls::VoipPhoneCallRejectReason value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::ICallRejectEventArgs)->get_RejectReason(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Calls::VoipPhoneCallState consume_Windows_ApplicationModel_Calls_ICallStateChangeEventArgs<D>::State() const
{
    Windows::ApplicationModel::Calls::VoipPhoneCallState value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::ICallStateChangeEventArgs)->get_State(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Calls_ILockScreenCallEndCallDeferral<D>::Complete() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::ILockScreenCallEndCallDeferral)->Complete());
}

template <typename D> Windows::ApplicationModel::Calls::LockScreenCallEndCallDeferral consume_Windows_ApplicationModel_Calls_ILockScreenCallEndRequestedEventArgs<D>::GetDeferral() const
{
    Windows::ApplicationModel::Calls::LockScreenCallEndCallDeferral value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::ILockScreenCallEndRequestedEventArgs)->GetDeferral(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_ApplicationModel_Calls_ILockScreenCallEndRequestedEventArgs<D>::Deadline() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::ILockScreenCallEndRequestedEventArgs)->get_Deadline(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Calls_ILockScreenCallUI<D>::Dismiss() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::ILockScreenCallUI)->Dismiss());
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Calls_ILockScreenCallUI<D>::EndRequested(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Calls::LockScreenCallUI, Windows::ApplicationModel::Calls::LockScreenCallEndRequestedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::ILockScreenCallUI)->add_EndRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Calls_ILockScreenCallUI<D>::EndRequested_revoker consume_Windows_ApplicationModel_Calls_ILockScreenCallUI<D>::EndRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Calls::LockScreenCallUI, Windows::ApplicationModel::Calls::LockScreenCallEndRequestedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, EndRequested_revoker>(this, EndRequested(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Calls_ILockScreenCallUI<D>::EndRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Calls::ILockScreenCallUI)->remove_EndRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Calls_ILockScreenCallUI<D>::Closed(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Calls::LockScreenCallUI, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::ILockScreenCallUI)->add_Closed(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Calls_ILockScreenCallUI<D>::Closed_revoker consume_Windows_ApplicationModel_Calls_ILockScreenCallUI<D>::Closed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Calls::LockScreenCallUI, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, Closed_revoker>(this, Closed(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Calls_ILockScreenCallUI<D>::Closed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Calls::ILockScreenCallUI)->remove_Closed(get_abi(token)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Calls_ILockScreenCallUI<D>::CallTitle() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::ILockScreenCallUI)->get_CallTitle(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Calls_ILockScreenCallUI<D>::CallTitle(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::ILockScreenCallUI)->put_CallTitle(get_abi(value)));
}

template <typename D> bool consume_Windows_ApplicationModel_Calls_IMuteChangeEventArgs<D>::Muted() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IMuteChangeEventArgs)->get_Muted(&value));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Calls_IPhoneCallBlockingStatics<D>::BlockUnknownNumbers() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallBlockingStatics)->get_BlockUnknownNumbers(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Calls_IPhoneCallBlockingStatics<D>::BlockUnknownNumbers(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallBlockingStatics)->put_BlockUnknownNumbers(value));
}

template <typename D> bool consume_Windows_ApplicationModel_Calls_IPhoneCallBlockingStatics<D>::BlockPrivateNumbers() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallBlockingStatics)->get_BlockPrivateNumbers(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Calls_IPhoneCallBlockingStatics<D>::BlockPrivateNumbers(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallBlockingStatics)->put_BlockPrivateNumbers(value));
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_ApplicationModel_Calls_IPhoneCallBlockingStatics<D>::SetCallBlockingListAsync(param::async_iterable<hstring> const& phoneNumberList) const
{
    Windows::Foundation::IAsyncOperation<bool> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallBlockingStatics)->SetCallBlockingListAsync(get_abi(phoneNumberList), put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_ApplicationModel_Calls_IPhoneCallHistoryEntry<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallHistoryEntry)->get_Id(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Calls::PhoneCallHistoryEntryAddress consume_Windows_ApplicationModel_Calls_IPhoneCallHistoryEntry<D>::Address() const
{
    Windows::ApplicationModel::Calls::PhoneCallHistoryEntryAddress value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallHistoryEntry)->get_Address(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Calls_IPhoneCallHistoryEntry<D>::Address(Windows::ApplicationModel::Calls::PhoneCallHistoryEntryAddress const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallHistoryEntry)->put_Address(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::TimeSpan> consume_Windows_ApplicationModel_Calls_IPhoneCallHistoryEntry<D>::Duration() const
{
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallHistoryEntry)->get_Duration(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Calls_IPhoneCallHistoryEntry<D>::Duration(optional<Windows::Foundation::TimeSpan> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallHistoryEntry)->put_Duration(get_abi(value)));
}

template <typename D> bool consume_Windows_ApplicationModel_Calls_IPhoneCallHistoryEntry<D>::IsCallerIdBlocked() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallHistoryEntry)->get_IsCallerIdBlocked(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Calls_IPhoneCallHistoryEntry<D>::IsCallerIdBlocked(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallHistoryEntry)->put_IsCallerIdBlocked(value));
}

template <typename D> bool consume_Windows_ApplicationModel_Calls_IPhoneCallHistoryEntry<D>::IsEmergency() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallHistoryEntry)->get_IsEmergency(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Calls_IPhoneCallHistoryEntry<D>::IsEmergency(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallHistoryEntry)->put_IsEmergency(value));
}

template <typename D> bool consume_Windows_ApplicationModel_Calls_IPhoneCallHistoryEntry<D>::IsIncoming() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallHistoryEntry)->get_IsIncoming(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Calls_IPhoneCallHistoryEntry<D>::IsIncoming(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallHistoryEntry)->put_IsIncoming(value));
}

template <typename D> bool consume_Windows_ApplicationModel_Calls_IPhoneCallHistoryEntry<D>::IsMissed() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallHistoryEntry)->get_IsMissed(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Calls_IPhoneCallHistoryEntry<D>::IsMissed(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallHistoryEntry)->put_IsMissed(value));
}

template <typename D> bool consume_Windows_ApplicationModel_Calls_IPhoneCallHistoryEntry<D>::IsRinging() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallHistoryEntry)->get_IsRinging(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Calls_IPhoneCallHistoryEntry<D>::IsRinging(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallHistoryEntry)->put_IsRinging(value));
}

template <typename D> bool consume_Windows_ApplicationModel_Calls_IPhoneCallHistoryEntry<D>::IsSeen() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallHistoryEntry)->get_IsSeen(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Calls_IPhoneCallHistoryEntry<D>::IsSeen(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallHistoryEntry)->put_IsSeen(value));
}

template <typename D> bool consume_Windows_ApplicationModel_Calls_IPhoneCallHistoryEntry<D>::IsSuppressed() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallHistoryEntry)->get_IsSuppressed(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Calls_IPhoneCallHistoryEntry<D>::IsSuppressed(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallHistoryEntry)->put_IsSuppressed(value));
}

template <typename D> bool consume_Windows_ApplicationModel_Calls_IPhoneCallHistoryEntry<D>::IsVoicemail() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallHistoryEntry)->get_IsVoicemail(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Calls_IPhoneCallHistoryEntry<D>::IsVoicemail(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallHistoryEntry)->put_IsVoicemail(value));
}

template <typename D> Windows::ApplicationModel::Calls::PhoneCallHistoryEntryMedia consume_Windows_ApplicationModel_Calls_IPhoneCallHistoryEntry<D>::Media() const
{
    Windows::ApplicationModel::Calls::PhoneCallHistoryEntryMedia value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallHistoryEntry)->get_Media(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Calls_IPhoneCallHistoryEntry<D>::Media(Windows::ApplicationModel::Calls::PhoneCallHistoryEntryMedia const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallHistoryEntry)->put_Media(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::Calls::PhoneCallHistoryEntryOtherAppReadAccess consume_Windows_ApplicationModel_Calls_IPhoneCallHistoryEntry<D>::OtherAppReadAccess() const
{
    Windows::ApplicationModel::Calls::PhoneCallHistoryEntryOtherAppReadAccess value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallHistoryEntry)->get_OtherAppReadAccess(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Calls_IPhoneCallHistoryEntry<D>::OtherAppReadAccess(Windows::ApplicationModel::Calls::PhoneCallHistoryEntryOtherAppReadAccess const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallHistoryEntry)->put_OtherAppReadAccess(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Calls_IPhoneCallHistoryEntry<D>::RemoteId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallHistoryEntry)->get_RemoteId(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Calls_IPhoneCallHistoryEntry<D>::RemoteId(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallHistoryEntry)->put_RemoteId(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Calls_IPhoneCallHistoryEntry<D>::SourceDisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallHistoryEntry)->get_SourceDisplayName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Calls_IPhoneCallHistoryEntry<D>::SourceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallHistoryEntry)->get_SourceId(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Calls_IPhoneCallHistoryEntry<D>::SourceId(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallHistoryEntry)->put_SourceId(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::Calls::PhoneCallHistorySourceIdKind consume_Windows_ApplicationModel_Calls_IPhoneCallHistoryEntry<D>::SourceIdKind() const
{
    Windows::ApplicationModel::Calls::PhoneCallHistorySourceIdKind value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallHistoryEntry)->get_SourceIdKind(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Calls_IPhoneCallHistoryEntry<D>::SourceIdKind(Windows::ApplicationModel::Calls::PhoneCallHistorySourceIdKind const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallHistoryEntry)->put_SourceIdKind(get_abi(value)));
}

template <typename D> Windows::Foundation::DateTime consume_Windows_ApplicationModel_Calls_IPhoneCallHistoryEntry<D>::StartTime() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallHistoryEntry)->get_StartTime(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Calls_IPhoneCallHistoryEntry<D>::StartTime(Windows::Foundation::DateTime const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallHistoryEntry)->put_StartTime(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Calls_IPhoneCallHistoryEntryAddress<D>::ContactId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallHistoryEntryAddress)->get_ContactId(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Calls_IPhoneCallHistoryEntryAddress<D>::ContactId(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallHistoryEntryAddress)->put_ContactId(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Calls_IPhoneCallHistoryEntryAddress<D>::DisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallHistoryEntryAddress)->get_DisplayName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Calls_IPhoneCallHistoryEntryAddress<D>::DisplayName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallHistoryEntryAddress)->put_DisplayName(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Calls_IPhoneCallHistoryEntryAddress<D>::RawAddress() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallHistoryEntryAddress)->get_RawAddress(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Calls_IPhoneCallHistoryEntryAddress<D>::RawAddress(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallHistoryEntryAddress)->put_RawAddress(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::Calls::PhoneCallHistoryEntryRawAddressKind consume_Windows_ApplicationModel_Calls_IPhoneCallHistoryEntryAddress<D>::RawAddressKind() const
{
    Windows::ApplicationModel::Calls::PhoneCallHistoryEntryRawAddressKind value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallHistoryEntryAddress)->get_RawAddressKind(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Calls_IPhoneCallHistoryEntryAddress<D>::RawAddressKind(Windows::ApplicationModel::Calls::PhoneCallHistoryEntryRawAddressKind const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallHistoryEntryAddress)->put_RawAddressKind(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::Calls::PhoneCallHistoryEntryAddress consume_Windows_ApplicationModel_Calls_IPhoneCallHistoryEntryAddressFactory<D>::Create(param::hstring const& rawAddress, Windows::ApplicationModel::Calls::PhoneCallHistoryEntryRawAddressKind const& rawAddressKind) const
{
    Windows::ApplicationModel::Calls::PhoneCallHistoryEntryAddress result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallHistoryEntryAddressFactory)->Create(get_abi(rawAddress), get_abi(rawAddressKind), put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Calls::PhoneCallHistoryEntryQueryDesiredMedia consume_Windows_ApplicationModel_Calls_IPhoneCallHistoryEntryQueryOptions<D>::DesiredMedia() const
{
    Windows::ApplicationModel::Calls::PhoneCallHistoryEntryQueryDesiredMedia value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallHistoryEntryQueryOptions)->get_DesiredMedia(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Calls_IPhoneCallHistoryEntryQueryOptions<D>::DesiredMedia(Windows::ApplicationModel::Calls::PhoneCallHistoryEntryQueryDesiredMedia const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallHistoryEntryQueryOptions)->put_DesiredMedia(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVector<hstring> consume_Windows_ApplicationModel_Calls_IPhoneCallHistoryEntryQueryOptions<D>::SourceIds() const
{
    Windows::Foundation::Collections::IVector<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallHistoryEntryQueryOptions)->get_SourceIds(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Calls::PhoneCallHistoryEntry>> consume_Windows_ApplicationModel_Calls_IPhoneCallHistoryEntryReader<D>::ReadBatchAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Calls::PhoneCallHistoryEntry>> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallHistoryEntryReader)->ReadBatchAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Calls::PhoneCallHistoryStore> consume_Windows_ApplicationModel_Calls_IPhoneCallHistoryManagerForUser<D>::RequestStoreAsync(Windows::ApplicationModel::Calls::PhoneCallHistoryStoreAccessType const& accessType) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Calls::PhoneCallHistoryStore> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallHistoryManagerForUser)->RequestStoreAsync(get_abi(accessType), put_abi(result)));
    return result;
}

template <typename D> Windows::System::User consume_Windows_ApplicationModel_Calls_IPhoneCallHistoryManagerForUser<D>::User() const
{
    Windows::System::User value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallHistoryManagerForUser)->get_User(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Calls::PhoneCallHistoryStore> consume_Windows_ApplicationModel_Calls_IPhoneCallHistoryManagerStatics<D>::RequestStoreAsync(Windows::ApplicationModel::Calls::PhoneCallHistoryStoreAccessType const& accessType) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Calls::PhoneCallHistoryStore> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallHistoryManagerStatics)->RequestStoreAsync(get_abi(accessType), put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Calls::PhoneCallHistoryManagerForUser consume_Windows_ApplicationModel_Calls_IPhoneCallHistoryManagerStatics2<D>::GetForUser(Windows::System::User const& user) const
{
    Windows::ApplicationModel::Calls::PhoneCallHistoryManagerForUser result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallHistoryManagerStatics2)->GetForUser(get_abi(user), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Calls::PhoneCallHistoryEntry> consume_Windows_ApplicationModel_Calls_IPhoneCallHistoryStore<D>::GetEntryAsync(param::hstring const& callHistoryEntryId) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Calls::PhoneCallHistoryEntry> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallHistoryStore)->GetEntryAsync(get_abi(callHistoryEntryId), put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Calls::PhoneCallHistoryEntryReader consume_Windows_ApplicationModel_Calls_IPhoneCallHistoryStore<D>::GetEntryReader() const
{
    Windows::ApplicationModel::Calls::PhoneCallHistoryEntryReader result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallHistoryStore)->GetEntryReader(put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Calls::PhoneCallHistoryEntryReader consume_Windows_ApplicationModel_Calls_IPhoneCallHistoryStore<D>::GetEntryReader(Windows::ApplicationModel::Calls::PhoneCallHistoryEntryQueryOptions const& queryOptions) const
{
    Windows::ApplicationModel::Calls::PhoneCallHistoryEntryReader result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallHistoryStore)->GetEntryReaderWithOptions(get_abi(queryOptions), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Calls_IPhoneCallHistoryStore<D>::SaveEntryAsync(Windows::ApplicationModel::Calls::PhoneCallHistoryEntry const& callHistoryEntry) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallHistoryStore)->SaveEntryAsync(get_abi(callHistoryEntry), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Calls_IPhoneCallHistoryStore<D>::DeleteEntryAsync(Windows::ApplicationModel::Calls::PhoneCallHistoryEntry const& callHistoryEntry) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallHistoryStore)->DeleteEntryAsync(get_abi(callHistoryEntry), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Calls_IPhoneCallHistoryStore<D>::DeleteEntriesAsync(param::async_iterable<Windows::ApplicationModel::Calls::PhoneCallHistoryEntry> const& callHistoryEntries) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallHistoryStore)->DeleteEntriesAsync(get_abi(callHistoryEntries), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Calls_IPhoneCallHistoryStore<D>::MarkEntryAsSeenAsync(Windows::ApplicationModel::Calls::PhoneCallHistoryEntry const& callHistoryEntry) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallHistoryStore)->MarkEntryAsSeenAsync(get_abi(callHistoryEntry), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Calls_IPhoneCallHistoryStore<D>::MarkEntriesAsSeenAsync(param::async_iterable<Windows::ApplicationModel::Calls::PhoneCallHistoryEntry> const& callHistoryEntries) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallHistoryStore)->MarkEntriesAsSeenAsync(get_abi(callHistoryEntries), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<uint32_t> consume_Windows_ApplicationModel_Calls_IPhoneCallHistoryStore<D>::GetUnseenCountAsync() const
{
    Windows::Foundation::IAsyncOperation<uint32_t> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallHistoryStore)->GetUnseenCountAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Calls_IPhoneCallHistoryStore<D>::MarkAllAsSeenAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallHistoryStore)->MarkAllAsSeenAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<uint32_t> consume_Windows_ApplicationModel_Calls_IPhoneCallHistoryStore<D>::GetSourcesUnseenCountAsync(param::async_iterable<hstring> const& sourceIds) const
{
    Windows::Foundation::IAsyncOperation<uint32_t> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallHistoryStore)->GetSourcesUnseenCountAsync(get_abi(sourceIds), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Calls_IPhoneCallHistoryStore<D>::MarkSourcesAsSeenAsync(param::async_iterable<hstring> const& sourceIds) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallHistoryStore)->MarkSourcesAsSeenAsync(get_abi(sourceIds), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_ApplicationModel_Calls_IPhoneCallManagerStatics<D>::ShowPhoneCallUI(param::hstring const& phoneNumber, param::hstring const& displayName) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallManagerStatics)->ShowPhoneCallUI(get_abi(phoneNumber), get_abi(displayName)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Calls_IPhoneCallManagerStatics2<D>::CallStateChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallManagerStatics2)->add_CallStateChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Calls_IPhoneCallManagerStatics2<D>::CallStateChanged_revoker consume_Windows_ApplicationModel_Calls_IPhoneCallManagerStatics2<D>::CallStateChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, CallStateChanged_revoker>(this, CallStateChanged(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Calls_IPhoneCallManagerStatics2<D>::CallStateChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallManagerStatics2)->remove_CallStateChanged(get_abi(token)));
}

template <typename D> bool consume_Windows_ApplicationModel_Calls_IPhoneCallManagerStatics2<D>::IsCallActive() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallManagerStatics2)->get_IsCallActive(&value));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Calls_IPhoneCallManagerStatics2<D>::IsCallIncoming() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallManagerStatics2)->get_IsCallIncoming(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Calls_IPhoneCallManagerStatics2<D>::ShowPhoneCallSettingsUI() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallManagerStatics2)->ShowPhoneCallSettingsUI());
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Calls::PhoneCallStore> consume_Windows_ApplicationModel_Calls_IPhoneCallManagerStatics2<D>::RequestStoreAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Calls::PhoneCallStore> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallManagerStatics2)->RequestStoreAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_ApplicationModel_Calls_IPhoneCallStore<D>::IsEmergencyPhoneNumberAsync(param::hstring const& number) const
{
    Windows::Foundation::IAsyncOperation<bool> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallStore)->IsEmergencyPhoneNumberAsync(get_abi(number), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<winrt::guid> consume_Windows_ApplicationModel_Calls_IPhoneCallStore<D>::GetDefaultLineAsync() const
{
    Windows::Foundation::IAsyncOperation<winrt::guid> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallStore)->GetDefaultLineAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Calls::PhoneLineWatcher consume_Windows_ApplicationModel_Calls_IPhoneCallStore<D>::RequestLineWatcher() const
{
    Windows::ApplicationModel::Calls::PhoneLineWatcher result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallStore)->RequestLineWatcher(put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_ApplicationModel_Calls_IPhoneCallVideoCapabilities<D>::IsVideoCallingCapable() const
{
    bool pValue{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallVideoCapabilities)->get_IsVideoCallingCapable(&pValue));
    return pValue;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Calls::PhoneCallVideoCapabilities> consume_Windows_ApplicationModel_Calls_IPhoneCallVideoCapabilitiesManagerStatics<D>::GetCapabilitiesAsync(param::hstring const& phoneNumber) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Calls::PhoneCallVideoCapabilities> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneCallVideoCapabilitiesManagerStatics)->GetCapabilitiesAsync(get_abi(phoneNumber), put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_ApplicationModel_Calls_IPhoneDialOptions<D>::Number() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneDialOptions)->get_Number(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Calls_IPhoneDialOptions<D>::Number(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneDialOptions)->put_Number(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Calls_IPhoneDialOptions<D>::DisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneDialOptions)->get_DisplayName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Calls_IPhoneDialOptions<D>::DisplayName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneDialOptions)->put_DisplayName(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::Contacts::Contact consume_Windows_ApplicationModel_Calls_IPhoneDialOptions<D>::Contact() const
{
    Windows::ApplicationModel::Contacts::Contact value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneDialOptions)->get_Contact(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Calls_IPhoneDialOptions<D>::Contact(Windows::ApplicationModel::Contacts::Contact const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneDialOptions)->put_Contact(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::Contacts::ContactPhone consume_Windows_ApplicationModel_Calls_IPhoneDialOptions<D>::ContactPhone() const
{
    Windows::ApplicationModel::Contacts::ContactPhone value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneDialOptions)->get_ContactPhone(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Calls_IPhoneDialOptions<D>::ContactPhone(Windows::ApplicationModel::Contacts::ContactPhone const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneDialOptions)->put_ContactPhone(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::Calls::PhoneCallMedia consume_Windows_ApplicationModel_Calls_IPhoneDialOptions<D>::Media() const
{
    Windows::ApplicationModel::Calls::PhoneCallMedia value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneDialOptions)->get_Media(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Calls_IPhoneDialOptions<D>::Media(Windows::ApplicationModel::Calls::PhoneCallMedia const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneDialOptions)->put_Media(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::Calls::PhoneAudioRoutingEndpoint consume_Windows_ApplicationModel_Calls_IPhoneDialOptions<D>::AudioEndpoint() const
{
    Windows::ApplicationModel::Calls::PhoneAudioRoutingEndpoint value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneDialOptions)->get_AudioEndpoint(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Calls_IPhoneDialOptions<D>::AudioEndpoint(Windows::ApplicationModel::Calls::PhoneAudioRoutingEndpoint const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneDialOptions)->put_AudioEndpoint(get_abi(value)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Calls_IPhoneLine<D>::LineChanged(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Calls::PhoneLine, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneLine)->add_LineChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Calls_IPhoneLine<D>::LineChanged_revoker consume_Windows_ApplicationModel_Calls_IPhoneLine<D>::LineChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Calls::PhoneLine, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, LineChanged_revoker>(this, LineChanged(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Calls_IPhoneLine<D>::LineChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneLine)->remove_LineChanged(get_abi(token)));
}

template <typename D> winrt::guid consume_Windows_ApplicationModel_Calls_IPhoneLine<D>::Id() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneLine)->get_Id(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_ApplicationModel_Calls_IPhoneLine<D>::DisplayColor() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneLine)->get_DisplayColor(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Calls::PhoneNetworkState consume_Windows_ApplicationModel_Calls_IPhoneLine<D>::NetworkState() const
{
    Windows::ApplicationModel::Calls::PhoneNetworkState value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneLine)->get_NetworkState(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Calls_IPhoneLine<D>::DisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneLine)->get_DisplayName(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Calls::PhoneVoicemail consume_Windows_ApplicationModel_Calls_IPhoneLine<D>::Voicemail() const
{
    Windows::ApplicationModel::Calls::PhoneVoicemail value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneLine)->get_Voicemail(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Calls_IPhoneLine<D>::NetworkName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneLine)->get_NetworkName(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Calls::PhoneLineCellularDetails consume_Windows_ApplicationModel_Calls_IPhoneLine<D>::CellularDetails() const
{
    Windows::ApplicationModel::Calls::PhoneLineCellularDetails value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneLine)->get_CellularDetails(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Calls::PhoneLineTransport consume_Windows_ApplicationModel_Calls_IPhoneLine<D>::Transport() const
{
    Windows::ApplicationModel::Calls::PhoneLineTransport value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneLine)->get_Transport(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Calls_IPhoneLine<D>::CanDial() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneLine)->get_CanDial(&value));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Calls_IPhoneLine<D>::SupportsTile() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneLine)->get_SupportsTile(&value));
    return value;
}

template <typename D> Windows::ApplicationModel::Calls::PhoneCallVideoCapabilities consume_Windows_ApplicationModel_Calls_IPhoneLine<D>::VideoCallingCapabilities() const
{
    Windows::ApplicationModel::Calls::PhoneCallVideoCapabilities value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneLine)->get_VideoCallingCapabilities(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Calls::PhoneLineConfiguration consume_Windows_ApplicationModel_Calls_IPhoneLine<D>::LineConfiguration() const
{
    Windows::ApplicationModel::Calls::PhoneLineConfiguration value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneLine)->get_LineConfiguration(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_ApplicationModel_Calls_IPhoneLine<D>::IsImmediateDialNumberAsync(param::hstring const& number) const
{
    Windows::Foundation::IAsyncOperation<bool> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneLine)->IsImmediateDialNumberAsync(get_abi(number), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_ApplicationModel_Calls_IPhoneLine<D>::Dial(param::hstring const& number, param::hstring const& displayName) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneLine)->Dial(get_abi(number), get_abi(displayName)));
}

template <typename D> void consume_Windows_ApplicationModel_Calls_IPhoneLine<D>::DialWithOptions(Windows::ApplicationModel::Calls::PhoneDialOptions const& options) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneLine)->DialWithOptions(get_abi(options)));
}

template <typename D> void consume_Windows_ApplicationModel_Calls_IPhoneLine2<D>::EnableTextReply(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneLine2)->EnableTextReply(value));
}

template <typename D> hstring consume_Windows_ApplicationModel_Calls_IPhoneLine2<D>::TransportDeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneLine2)->get_TransportDeviceId(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Calls::PhoneSimState consume_Windows_ApplicationModel_Calls_IPhoneLineCellularDetails<D>::SimState() const
{
    Windows::ApplicationModel::Calls::PhoneSimState value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneLineCellularDetails)->get_SimState(put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_ApplicationModel_Calls_IPhoneLineCellularDetails<D>::SimSlotIndex() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneLineCellularDetails)->get_SimSlotIndex(&value));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Calls_IPhoneLineCellularDetails<D>::IsModemOn() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneLineCellularDetails)->get_IsModemOn(&value));
    return value;
}

template <typename D> int32_t consume_Windows_ApplicationModel_Calls_IPhoneLineCellularDetails<D>::RegistrationRejectCode() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneLineCellularDetails)->get_RegistrationRejectCode(&value));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Calls_IPhoneLineCellularDetails<D>::GetNetworkOperatorDisplayText(Windows::ApplicationModel::Calls::PhoneLineNetworkOperatorDisplayTextLocation const& location) const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneLineCellularDetails)->GetNetworkOperatorDisplayText(get_abi(location), put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Calls_IPhoneLineConfiguration<D>::IsVideoCallingEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneLineConfiguration)->get_IsVideoCallingEnabled(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable> consume_Windows_ApplicationModel_Calls_IPhoneLineConfiguration<D>::ExtendedProperties() const
{
    Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneLineConfiguration)->get_ExtendedProperties(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Calls::PhoneLine> consume_Windows_ApplicationModel_Calls_IPhoneLineStatics<D>::FromIdAsync(winrt::guid const& lineId) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Calls::PhoneLine> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneLineStatics)->FromIdAsync(get_abi(lineId), put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_ApplicationModel_Calls_IPhoneLineTransportDevice<D>::DeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneLineTransportDevice)->get_DeviceId(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Calls::PhoneLineTransport consume_Windows_ApplicationModel_Calls_IPhoneLineTransportDevice<D>::Transport() const
{
    Windows::ApplicationModel::Calls::PhoneLineTransport value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneLineTransportDevice)->get_Transport(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceAccessStatus> consume_Windows_ApplicationModel_Calls_IPhoneLineTransportDevice<D>::RequestAccessAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceAccessStatus> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneLineTransportDevice)->RequestAccessAsync(put_abi(operation)));
    return operation;
}

template <typename D> void consume_Windows_ApplicationModel_Calls_IPhoneLineTransportDevice<D>::RegisterApp() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneLineTransportDevice)->RegisterApp());
}

template <typename D> void consume_Windows_ApplicationModel_Calls_IPhoneLineTransportDevice<D>::RegisterAppForUser(Windows::System::User const& user) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneLineTransportDevice)->RegisterAppForUser(get_abi(user)));
}

template <typename D> void consume_Windows_ApplicationModel_Calls_IPhoneLineTransportDevice<D>::UnregisterApp() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneLineTransportDevice)->UnregisterApp());
}

template <typename D> void consume_Windows_ApplicationModel_Calls_IPhoneLineTransportDevice<D>::UnregisterAppForUser(Windows::System::User const& user) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneLineTransportDevice)->UnregisterAppForUser(get_abi(user)));
}

template <typename D> bool consume_Windows_ApplicationModel_Calls_IPhoneLineTransportDevice<D>::IsRegistered() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneLineTransportDevice)->IsRegistered(&result));
    return result;
}

template <typename D> bool consume_Windows_ApplicationModel_Calls_IPhoneLineTransportDevice<D>::Connect() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneLineTransportDevice)->Connect(&result));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_ApplicationModel_Calls_IPhoneLineTransportDevice<D>::ConnectAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneLineTransportDevice)->ConnectAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::ApplicationModel::Calls::PhoneLineTransportDevice consume_Windows_ApplicationModel_Calls_IPhoneLineTransportDeviceStatics<D>::FromId(param::hstring const& id) const
{
    Windows::ApplicationModel::Calls::PhoneLineTransportDevice result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneLineTransportDeviceStatics)->FromId(get_abi(id), put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_ApplicationModel_Calls_IPhoneLineTransportDeviceStatics<D>::GetDeviceSelector() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneLineTransportDeviceStatics)->GetDeviceSelector(put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_ApplicationModel_Calls_IPhoneLineTransportDeviceStatics<D>::GetDeviceSelector(Windows::ApplicationModel::Calls::PhoneLineTransport const& transport) const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneLineTransportDeviceStatics)->GetDeviceSelectorForPhoneLineTransport(get_abi(transport), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_ApplicationModel_Calls_IPhoneLineWatcher<D>::Start() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneLineWatcher)->Start());
}

template <typename D> void consume_Windows_ApplicationModel_Calls_IPhoneLineWatcher<D>::Stop() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneLineWatcher)->Stop());
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Calls_IPhoneLineWatcher<D>::LineAdded(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Calls::PhoneLineWatcher, Windows::ApplicationModel::Calls::PhoneLineWatcherEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneLineWatcher)->add_LineAdded(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Calls_IPhoneLineWatcher<D>::LineAdded_revoker consume_Windows_ApplicationModel_Calls_IPhoneLineWatcher<D>::LineAdded(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Calls::PhoneLineWatcher, Windows::ApplicationModel::Calls::PhoneLineWatcherEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, LineAdded_revoker>(this, LineAdded(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Calls_IPhoneLineWatcher<D>::LineAdded(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneLineWatcher)->remove_LineAdded(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Calls_IPhoneLineWatcher<D>::LineRemoved(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Calls::PhoneLineWatcher, Windows::ApplicationModel::Calls::PhoneLineWatcherEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneLineWatcher)->add_LineRemoved(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Calls_IPhoneLineWatcher<D>::LineRemoved_revoker consume_Windows_ApplicationModel_Calls_IPhoneLineWatcher<D>::LineRemoved(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Calls::PhoneLineWatcher, Windows::ApplicationModel::Calls::PhoneLineWatcherEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, LineRemoved_revoker>(this, LineRemoved(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Calls_IPhoneLineWatcher<D>::LineRemoved(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneLineWatcher)->remove_LineRemoved(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Calls_IPhoneLineWatcher<D>::LineUpdated(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Calls::PhoneLineWatcher, Windows::ApplicationModel::Calls::PhoneLineWatcherEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneLineWatcher)->add_LineUpdated(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Calls_IPhoneLineWatcher<D>::LineUpdated_revoker consume_Windows_ApplicationModel_Calls_IPhoneLineWatcher<D>::LineUpdated(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Calls::PhoneLineWatcher, Windows::ApplicationModel::Calls::PhoneLineWatcherEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, LineUpdated_revoker>(this, LineUpdated(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Calls_IPhoneLineWatcher<D>::LineUpdated(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneLineWatcher)->remove_LineUpdated(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Calls_IPhoneLineWatcher<D>::EnumerationCompleted(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Calls::PhoneLineWatcher, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneLineWatcher)->add_EnumerationCompleted(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Calls_IPhoneLineWatcher<D>::EnumerationCompleted_revoker consume_Windows_ApplicationModel_Calls_IPhoneLineWatcher<D>::EnumerationCompleted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Calls::PhoneLineWatcher, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, EnumerationCompleted_revoker>(this, EnumerationCompleted(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Calls_IPhoneLineWatcher<D>::EnumerationCompleted(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneLineWatcher)->remove_EnumerationCompleted(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Calls_IPhoneLineWatcher<D>::Stopped(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Calls::PhoneLineWatcher, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneLineWatcher)->add_Stopped(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Calls_IPhoneLineWatcher<D>::Stopped_revoker consume_Windows_ApplicationModel_Calls_IPhoneLineWatcher<D>::Stopped(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Calls::PhoneLineWatcher, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, Stopped_revoker>(this, Stopped(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Calls_IPhoneLineWatcher<D>::Stopped(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneLineWatcher)->remove_Stopped(get_abi(token)));
}

template <typename D> Windows::ApplicationModel::Calls::PhoneLineWatcherStatus consume_Windows_ApplicationModel_Calls_IPhoneLineWatcher<D>::Status() const
{
    Windows::ApplicationModel::Calls::PhoneLineWatcherStatus status{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneLineWatcher)->get_Status(put_abi(status)));
    return status;
}

template <typename D> winrt::guid consume_Windows_ApplicationModel_Calls_IPhoneLineWatcherEventArgs<D>::LineId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneLineWatcherEventArgs)->get_LineId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Calls_IPhoneVoicemail<D>::Number() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneVoicemail)->get_Number(put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_ApplicationModel_Calls_IPhoneVoicemail<D>::MessageCount() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneVoicemail)->get_MessageCount(&value));
    return value;
}

template <typename D> Windows::ApplicationModel::Calls::PhoneVoicemailType consume_Windows_ApplicationModel_Calls_IPhoneVoicemail<D>::Type() const
{
    Windows::ApplicationModel::Calls::PhoneVoicemailType value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneVoicemail)->get_Type(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Calls_IPhoneVoicemail<D>::DialVoicemailAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IPhoneVoicemail)->DialVoicemailAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Calls::VoipPhoneCallResourceReservationStatus> consume_Windows_ApplicationModel_Calls_IVoipCallCoordinator<D>::ReserveCallResourcesAsync(param::hstring const& taskEntryPoint) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Calls::VoipPhoneCallResourceReservationStatus> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IVoipCallCoordinator)->ReserveCallResourcesAsync(get_abi(taskEntryPoint), put_abi(operation)));
    return operation;
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Calls_IVoipCallCoordinator<D>::MuteStateChanged(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Calls::VoipCallCoordinator, Windows::ApplicationModel::Calls::MuteChangeEventArgs> const& muteChangeHandler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IVoipCallCoordinator)->add_MuteStateChanged(get_abi(muteChangeHandler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Calls_IVoipCallCoordinator<D>::MuteStateChanged_revoker consume_Windows_ApplicationModel_Calls_IVoipCallCoordinator<D>::MuteStateChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Calls::VoipCallCoordinator, Windows::ApplicationModel::Calls::MuteChangeEventArgs> const& muteChangeHandler) const
{
    return impl::make_event_revoker<D, MuteStateChanged_revoker>(this, MuteStateChanged(muteChangeHandler));
}

template <typename D> void consume_Windows_ApplicationModel_Calls_IVoipCallCoordinator<D>::MuteStateChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Calls::IVoipCallCoordinator)->remove_MuteStateChanged(get_abi(token)));
}

template <typename D> Windows::ApplicationModel::Calls::VoipPhoneCall consume_Windows_ApplicationModel_Calls_IVoipCallCoordinator<D>::RequestNewIncomingCall(param::hstring const& context, param::hstring const& contactName, param::hstring const& contactNumber, Windows::Foundation::Uri const& contactImage, param::hstring const& serviceName, Windows::Foundation::Uri const& brandingImage, param::hstring const& callDetails, Windows::Foundation::Uri const& ringtone, Windows::ApplicationModel::Calls::VoipPhoneCallMedia const& media, Windows::Foundation::TimeSpan const& ringTimeout) const
{
    Windows::ApplicationModel::Calls::VoipPhoneCall call{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IVoipCallCoordinator)->RequestNewIncomingCall(get_abi(context), get_abi(contactName), get_abi(contactNumber), get_abi(contactImage), get_abi(serviceName), get_abi(brandingImage), get_abi(callDetails), get_abi(ringtone), get_abi(media), get_abi(ringTimeout), put_abi(call)));
    return call;
}

template <typename D> Windows::ApplicationModel::Calls::VoipPhoneCall consume_Windows_ApplicationModel_Calls_IVoipCallCoordinator<D>::RequestNewOutgoingCall(param::hstring const& context, param::hstring const& contactName, param::hstring const& serviceName, Windows::ApplicationModel::Calls::VoipPhoneCallMedia const& media) const
{
    Windows::ApplicationModel::Calls::VoipPhoneCall call{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IVoipCallCoordinator)->RequestNewOutgoingCall(get_abi(context), get_abi(contactName), get_abi(serviceName), get_abi(media), put_abi(call)));
    return call;
}

template <typename D> void consume_Windows_ApplicationModel_Calls_IVoipCallCoordinator<D>::NotifyMuted() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IVoipCallCoordinator)->NotifyMuted());
}

template <typename D> void consume_Windows_ApplicationModel_Calls_IVoipCallCoordinator<D>::NotifyUnmuted() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IVoipCallCoordinator)->NotifyUnmuted());
}

template <typename D> Windows::ApplicationModel::Calls::VoipPhoneCall consume_Windows_ApplicationModel_Calls_IVoipCallCoordinator<D>::RequestOutgoingUpgradeToVideoCall(winrt::guid const& callUpgradeGuid, param::hstring const& context, param::hstring const& contactName, param::hstring const& serviceName) const
{
    Windows::ApplicationModel::Calls::VoipPhoneCall call{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IVoipCallCoordinator)->RequestOutgoingUpgradeToVideoCall(get_abi(callUpgradeGuid), get_abi(context), get_abi(contactName), get_abi(serviceName), put_abi(call)));
    return call;
}

template <typename D> Windows::ApplicationModel::Calls::VoipPhoneCall consume_Windows_ApplicationModel_Calls_IVoipCallCoordinator<D>::RequestIncomingUpgradeToVideoCall(param::hstring const& context, param::hstring const& contactName, param::hstring const& contactNumber, Windows::Foundation::Uri const& contactImage, param::hstring const& serviceName, Windows::Foundation::Uri const& brandingImage, param::hstring const& callDetails, Windows::Foundation::Uri const& ringtone, Windows::Foundation::TimeSpan const& ringTimeout) const
{
    Windows::ApplicationModel::Calls::VoipPhoneCall call{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IVoipCallCoordinator)->RequestIncomingUpgradeToVideoCall(get_abi(context), get_abi(contactName), get_abi(contactNumber), get_abi(contactImage), get_abi(serviceName), get_abi(brandingImage), get_abi(callDetails), get_abi(ringtone), get_abi(ringTimeout), put_abi(call)));
    return call;
}

template <typename D> void consume_Windows_ApplicationModel_Calls_IVoipCallCoordinator<D>::TerminateCellularCall(winrt::guid const& callUpgradeGuid) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IVoipCallCoordinator)->TerminateCellularCall(get_abi(callUpgradeGuid)));
}

template <typename D> void consume_Windows_ApplicationModel_Calls_IVoipCallCoordinator<D>::CancelUpgrade(winrt::guid const& callUpgradeGuid) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IVoipCallCoordinator)->CancelUpgrade(get_abi(callUpgradeGuid)));
}

template <typename D> Windows::ApplicationModel::Calls::VoipPhoneCall consume_Windows_ApplicationModel_Calls_IVoipCallCoordinator2<D>::SetupNewAcceptedCall(param::hstring const& context, param::hstring const& contactName, param::hstring const& contactNumber, param::hstring const& serviceName, Windows::ApplicationModel::Calls::VoipPhoneCallMedia const& media) const
{
    Windows::ApplicationModel::Calls::VoipPhoneCall call{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IVoipCallCoordinator2)->SetupNewAcceptedCall(get_abi(context), get_abi(contactName), get_abi(contactNumber), get_abi(serviceName), get_abi(media), put_abi(call)));
    return call;
}

template <typename D> Windows::ApplicationModel::Calls::VoipPhoneCall consume_Windows_ApplicationModel_Calls_IVoipCallCoordinator3<D>::RequestNewAppInitiatedCall(param::hstring const& context, param::hstring const& contactName, param::hstring const& contactNumber, param::hstring const& serviceName, Windows::ApplicationModel::Calls::VoipPhoneCallMedia const& media) const
{
    Windows::ApplicationModel::Calls::VoipPhoneCall call{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IVoipCallCoordinator3)->RequestNewAppInitiatedCall(get_abi(context), get_abi(contactName), get_abi(contactNumber), get_abi(serviceName), get_abi(media), put_abi(call)));
    return call;
}

template <typename D> Windows::ApplicationModel::Calls::VoipPhoneCall consume_Windows_ApplicationModel_Calls_IVoipCallCoordinator3<D>::RequestNewIncomingCall(param::hstring const& context, param::hstring const& contactName, param::hstring const& contactNumber, Windows::Foundation::Uri const& contactImage, param::hstring const& serviceName, Windows::Foundation::Uri const& brandingImage, param::hstring const& callDetails, Windows::Foundation::Uri const& ringtone, Windows::ApplicationModel::Calls::VoipPhoneCallMedia const& media, Windows::Foundation::TimeSpan const& ringTimeout, param::hstring const& contactRemoteId) const
{
    Windows::ApplicationModel::Calls::VoipPhoneCall call{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IVoipCallCoordinator3)->RequestNewIncomingCallWithContactRemoteId(get_abi(context), get_abi(contactName), get_abi(contactNumber), get_abi(contactImage), get_abi(serviceName), get_abi(brandingImage), get_abi(callDetails), get_abi(ringtone), get_abi(media), get_abi(ringTimeout), get_abi(contactRemoteId), put_abi(call)));
    return call;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Calls::VoipPhoneCallResourceReservationStatus> consume_Windows_ApplicationModel_Calls_IVoipCallCoordinator4<D>::ReserveCallResourcesAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Calls::VoipPhoneCallResourceReservationStatus> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IVoipCallCoordinator4)->ReserveOneProcessCallResourcesAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::ApplicationModel::Calls::VoipCallCoordinator consume_Windows_ApplicationModel_Calls_IVoipCallCoordinatorStatics<D>::GetDefault() const
{
    Windows::ApplicationModel::Calls::VoipCallCoordinator coordinator{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IVoipCallCoordinatorStatics)->GetDefault(put_abi(coordinator)));
    return coordinator;
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Calls_IVoipPhoneCall<D>::EndRequested(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Calls::VoipPhoneCall, Windows::ApplicationModel::Calls::CallStateChangeEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IVoipPhoneCall)->add_EndRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Calls_IVoipPhoneCall<D>::EndRequested_revoker consume_Windows_ApplicationModel_Calls_IVoipPhoneCall<D>::EndRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Calls::VoipPhoneCall, Windows::ApplicationModel::Calls::CallStateChangeEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, EndRequested_revoker>(this, EndRequested(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Calls_IVoipPhoneCall<D>::EndRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Calls::IVoipPhoneCall)->remove_EndRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Calls_IVoipPhoneCall<D>::HoldRequested(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Calls::VoipPhoneCall, Windows::ApplicationModel::Calls::CallStateChangeEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IVoipPhoneCall)->add_HoldRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Calls_IVoipPhoneCall<D>::HoldRequested_revoker consume_Windows_ApplicationModel_Calls_IVoipPhoneCall<D>::HoldRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Calls::VoipPhoneCall, Windows::ApplicationModel::Calls::CallStateChangeEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, HoldRequested_revoker>(this, HoldRequested(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Calls_IVoipPhoneCall<D>::HoldRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Calls::IVoipPhoneCall)->remove_HoldRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Calls_IVoipPhoneCall<D>::ResumeRequested(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Calls::VoipPhoneCall, Windows::ApplicationModel::Calls::CallStateChangeEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IVoipPhoneCall)->add_ResumeRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Calls_IVoipPhoneCall<D>::ResumeRequested_revoker consume_Windows_ApplicationModel_Calls_IVoipPhoneCall<D>::ResumeRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Calls::VoipPhoneCall, Windows::ApplicationModel::Calls::CallStateChangeEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ResumeRequested_revoker>(this, ResumeRequested(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Calls_IVoipPhoneCall<D>::ResumeRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Calls::IVoipPhoneCall)->remove_ResumeRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Calls_IVoipPhoneCall<D>::AnswerRequested(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Calls::VoipPhoneCall, Windows::ApplicationModel::Calls::CallAnswerEventArgs> const& acceptHandler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IVoipPhoneCall)->add_AnswerRequested(get_abi(acceptHandler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Calls_IVoipPhoneCall<D>::AnswerRequested_revoker consume_Windows_ApplicationModel_Calls_IVoipPhoneCall<D>::AnswerRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Calls::VoipPhoneCall, Windows::ApplicationModel::Calls::CallAnswerEventArgs> const& acceptHandler) const
{
    return impl::make_event_revoker<D, AnswerRequested_revoker>(this, AnswerRequested(acceptHandler));
}

template <typename D> void consume_Windows_ApplicationModel_Calls_IVoipPhoneCall<D>::AnswerRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Calls::IVoipPhoneCall)->remove_AnswerRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Calls_IVoipPhoneCall<D>::RejectRequested(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Calls::VoipPhoneCall, Windows::ApplicationModel::Calls::CallRejectEventArgs> const& rejectHandler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IVoipPhoneCall)->add_RejectRequested(get_abi(rejectHandler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Calls_IVoipPhoneCall<D>::RejectRequested_revoker consume_Windows_ApplicationModel_Calls_IVoipPhoneCall<D>::RejectRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Calls::VoipPhoneCall, Windows::ApplicationModel::Calls::CallRejectEventArgs> const& rejectHandler) const
{
    return impl::make_event_revoker<D, RejectRequested_revoker>(this, RejectRequested(rejectHandler));
}

template <typename D> void consume_Windows_ApplicationModel_Calls_IVoipPhoneCall<D>::RejectRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Calls::IVoipPhoneCall)->remove_RejectRequested(get_abi(token)));
}

template <typename D> void consume_Windows_ApplicationModel_Calls_IVoipPhoneCall<D>::NotifyCallHeld() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IVoipPhoneCall)->NotifyCallHeld());
}

template <typename D> void consume_Windows_ApplicationModel_Calls_IVoipPhoneCall<D>::NotifyCallActive() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IVoipPhoneCall)->NotifyCallActive());
}

template <typename D> void consume_Windows_ApplicationModel_Calls_IVoipPhoneCall<D>::NotifyCallEnded() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IVoipPhoneCall)->NotifyCallEnded());
}

template <typename D> hstring consume_Windows_ApplicationModel_Calls_IVoipPhoneCall<D>::ContactName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IVoipPhoneCall)->get_ContactName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Calls_IVoipPhoneCall<D>::ContactName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IVoipPhoneCall)->put_ContactName(get_abi(value)));
}

template <typename D> Windows::Foundation::DateTime consume_Windows_ApplicationModel_Calls_IVoipPhoneCall<D>::StartTime() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IVoipPhoneCall)->get_StartTime(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Calls_IVoipPhoneCall<D>::StartTime(Windows::Foundation::DateTime const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IVoipPhoneCall)->put_StartTime(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::Calls::VoipPhoneCallMedia consume_Windows_ApplicationModel_Calls_IVoipPhoneCall<D>::CallMedia() const
{
    Windows::ApplicationModel::Calls::VoipPhoneCallMedia value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IVoipPhoneCall)->get_CallMedia(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Calls_IVoipPhoneCall<D>::CallMedia(Windows::ApplicationModel::Calls::VoipPhoneCallMedia const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IVoipPhoneCall)->put_CallMedia(get_abi(value)));
}

template <typename D> void consume_Windows_ApplicationModel_Calls_IVoipPhoneCall<D>::NotifyCallReady() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IVoipPhoneCall)->NotifyCallReady());
}

template <typename D> void consume_Windows_ApplicationModel_Calls_IVoipPhoneCall2<D>::TryShowAppUI() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IVoipPhoneCall2)->TryShowAppUI());
}

template <typename D> void consume_Windows_ApplicationModel_Calls_IVoipPhoneCall3<D>::NotifyCallAccepted(Windows::ApplicationModel::Calls::VoipPhoneCallMedia const& media) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Calls::IVoipPhoneCall3)->NotifyCallAccepted(get_abi(media)));
}

template <typename D>
struct produce<D, Windows::ApplicationModel::Calls::ICallAnswerEventArgs> : produce_base<D, Windows::ApplicationModel::Calls::ICallAnswerEventArgs>
{
    int32_t WINRT_CALL get_AcceptedMedia(Windows::ApplicationModel::Calls::VoipPhoneCallMedia* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AcceptedMedia, WINRT_WRAP(Windows::ApplicationModel::Calls::VoipPhoneCallMedia));
            *value = detach_from<Windows::ApplicationModel::Calls::VoipPhoneCallMedia>(this->shim().AcceptedMedia());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Calls::ICallRejectEventArgs> : produce_base<D, Windows::ApplicationModel::Calls::ICallRejectEventArgs>
{
    int32_t WINRT_CALL get_RejectReason(Windows::ApplicationModel::Calls::VoipPhoneCallRejectReason* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RejectReason, WINRT_WRAP(Windows::ApplicationModel::Calls::VoipPhoneCallRejectReason));
            *value = detach_from<Windows::ApplicationModel::Calls::VoipPhoneCallRejectReason>(this->shim().RejectReason());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Calls::ICallStateChangeEventArgs> : produce_base<D, Windows::ApplicationModel::Calls::ICallStateChangeEventArgs>
{
    int32_t WINRT_CALL get_State(Windows::ApplicationModel::Calls::VoipPhoneCallState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(State, WINRT_WRAP(Windows::ApplicationModel::Calls::VoipPhoneCallState));
            *value = detach_from<Windows::ApplicationModel::Calls::VoipPhoneCallState>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Calls::ILockScreenCallEndCallDeferral> : produce_base<D, Windows::ApplicationModel::Calls::ILockScreenCallEndCallDeferral>
{
    int32_t WINRT_CALL Complete() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Complete, WINRT_WRAP(void));
            this->shim().Complete();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Calls::ILockScreenCallEndRequestedEventArgs> : produce_base<D, Windows::ApplicationModel::Calls::ILockScreenCallEndRequestedEventArgs>
{
    int32_t WINRT_CALL GetDeferral(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeferral, WINRT_WRAP(Windows::ApplicationModel::Calls::LockScreenCallEndCallDeferral));
            *value = detach_from<Windows::ApplicationModel::Calls::LockScreenCallEndCallDeferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Deadline(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Deadline, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().Deadline());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Calls::ILockScreenCallUI> : produce_base<D, Windows::ApplicationModel::Calls::ILockScreenCallUI>
{
    int32_t WINRT_CALL Dismiss() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Dismiss, WINRT_WRAP(void));
            this->shim().Dismiss();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_EndRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EndRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Calls::LockScreenCallUI, Windows::ApplicationModel::Calls::LockScreenCallEndRequestedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().EndRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Calls::LockScreenCallUI, Windows::ApplicationModel::Calls::LockScreenCallEndRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_EndRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(EndRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().EndRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_Closed(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Closed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Calls::LockScreenCallUI, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().Closed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Calls::LockScreenCallUI, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Closed(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Closed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Closed(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL get_CallTitle(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CallTitle, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().CallTitle());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CallTitle(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CallTitle, WINRT_WRAP(void), hstring const&);
            this->shim().CallTitle(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Calls::IMuteChangeEventArgs> : produce_base<D, Windows::ApplicationModel::Calls::IMuteChangeEventArgs>
{
    int32_t WINRT_CALL get_Muted(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Muted, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Muted());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Calls::IPhoneCallBlockingStatics> : produce_base<D, Windows::ApplicationModel::Calls::IPhoneCallBlockingStatics>
{
    int32_t WINRT_CALL get_BlockUnknownNumbers(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BlockUnknownNumbers, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().BlockUnknownNumbers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_BlockUnknownNumbers(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BlockUnknownNumbers, WINRT_WRAP(void), bool);
            this->shim().BlockUnknownNumbers(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BlockPrivateNumbers(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BlockPrivateNumbers, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().BlockPrivateNumbers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_BlockPrivateNumbers(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BlockPrivateNumbers, WINRT_WRAP(void), bool);
            this->shim().BlockPrivateNumbers(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetCallBlockingListAsync(void* phoneNumberList, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetCallBlockingListAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::Foundation::Collections::IIterable<hstring> const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().SetCallBlockingListAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&phoneNumberList)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Calls::IPhoneCallHistoryEntry> : produce_base<D, Windows::ApplicationModel::Calls::IPhoneCallHistoryEntry>
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

    int32_t WINRT_CALL get_Address(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Address, WINRT_WRAP(Windows::ApplicationModel::Calls::PhoneCallHistoryEntryAddress));
            *value = detach_from<Windows::ApplicationModel::Calls::PhoneCallHistoryEntryAddress>(this->shim().Address());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Address(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Address, WINRT_WRAP(void), Windows::ApplicationModel::Calls::PhoneCallHistoryEntryAddress const&);
            this->shim().Address(*reinterpret_cast<Windows::ApplicationModel::Calls::PhoneCallHistoryEntryAddress const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Duration(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Duration, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::TimeSpan>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::TimeSpan>>(this->shim().Duration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Duration(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Duration, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Foundation::TimeSpan> const&);
            this->shim().Duration(*reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::TimeSpan> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsCallerIdBlocked(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsCallerIdBlocked, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsCallerIdBlocked());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsCallerIdBlocked(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsCallerIdBlocked, WINRT_WRAP(void), bool);
            this->shim().IsCallerIdBlocked(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsEmergency(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsEmergency, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsEmergency());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsEmergency(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsEmergency, WINRT_WRAP(void), bool);
            this->shim().IsEmergency(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsIncoming(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsIncoming, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsIncoming());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsIncoming(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsIncoming, WINRT_WRAP(void), bool);
            this->shim().IsIncoming(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsMissed(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsMissed, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsMissed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsMissed(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsMissed, WINRT_WRAP(void), bool);
            this->shim().IsMissed(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsRinging(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsRinging, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsRinging());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsRinging(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsRinging, WINRT_WRAP(void), bool);
            this->shim().IsRinging(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsSeen(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSeen, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsSeen());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsSeen(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSeen, WINRT_WRAP(void), bool);
            this->shim().IsSeen(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsSuppressed(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSuppressed, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsSuppressed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsSuppressed(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSuppressed, WINRT_WRAP(void), bool);
            this->shim().IsSuppressed(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsVoicemail(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsVoicemail, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsVoicemail());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsVoicemail(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsVoicemail, WINRT_WRAP(void), bool);
            this->shim().IsVoicemail(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Media(Windows::ApplicationModel::Calls::PhoneCallHistoryEntryMedia* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Media, WINRT_WRAP(Windows::ApplicationModel::Calls::PhoneCallHistoryEntryMedia));
            *value = detach_from<Windows::ApplicationModel::Calls::PhoneCallHistoryEntryMedia>(this->shim().Media());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Media(Windows::ApplicationModel::Calls::PhoneCallHistoryEntryMedia value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Media, WINRT_WRAP(void), Windows::ApplicationModel::Calls::PhoneCallHistoryEntryMedia const&);
            this->shim().Media(*reinterpret_cast<Windows::ApplicationModel::Calls::PhoneCallHistoryEntryMedia const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OtherAppReadAccess(Windows::ApplicationModel::Calls::PhoneCallHistoryEntryOtherAppReadAccess* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OtherAppReadAccess, WINRT_WRAP(Windows::ApplicationModel::Calls::PhoneCallHistoryEntryOtherAppReadAccess));
            *value = detach_from<Windows::ApplicationModel::Calls::PhoneCallHistoryEntryOtherAppReadAccess>(this->shim().OtherAppReadAccess());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_OtherAppReadAccess(Windows::ApplicationModel::Calls::PhoneCallHistoryEntryOtherAppReadAccess value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OtherAppReadAccess, WINRT_WRAP(void), Windows::ApplicationModel::Calls::PhoneCallHistoryEntryOtherAppReadAccess const&);
            this->shim().OtherAppReadAccess(*reinterpret_cast<Windows::ApplicationModel::Calls::PhoneCallHistoryEntryOtherAppReadAccess const*>(&value));
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

    int32_t WINRT_CALL get_SourceId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourceId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SourceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SourceId(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourceId, WINRT_WRAP(void), hstring const&);
            this->shim().SourceId(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SourceIdKind(Windows::ApplicationModel::Calls::PhoneCallHistorySourceIdKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourceIdKind, WINRT_WRAP(Windows::ApplicationModel::Calls::PhoneCallHistorySourceIdKind));
            *value = detach_from<Windows::ApplicationModel::Calls::PhoneCallHistorySourceIdKind>(this->shim().SourceIdKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SourceIdKind(Windows::ApplicationModel::Calls::PhoneCallHistorySourceIdKind value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourceIdKind, WINRT_WRAP(void), Windows::ApplicationModel::Calls::PhoneCallHistorySourceIdKind const&);
            this->shim().SourceIdKind(*reinterpret_cast<Windows::ApplicationModel::Calls::PhoneCallHistorySourceIdKind const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StartTime(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartTime, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().StartTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_StartTime(Windows::Foundation::DateTime value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartTime, WINRT_WRAP(void), Windows::Foundation::DateTime const&);
            this->shim().StartTime(*reinterpret_cast<Windows::Foundation::DateTime const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Calls::IPhoneCallHistoryEntryAddress> : produce_base<D, Windows::ApplicationModel::Calls::IPhoneCallHistoryEntryAddress>
{
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

    int32_t WINRT_CALL put_ContactId(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContactId, WINRT_WRAP(void), hstring const&);
            this->shim().ContactId(*reinterpret_cast<hstring const*>(&value));
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

    int32_t WINRT_CALL get_RawAddress(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RawAddress, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().RawAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RawAddress(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RawAddress, WINRT_WRAP(void), hstring const&);
            this->shim().RawAddress(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RawAddressKind(Windows::ApplicationModel::Calls::PhoneCallHistoryEntryRawAddressKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RawAddressKind, WINRT_WRAP(Windows::ApplicationModel::Calls::PhoneCallHistoryEntryRawAddressKind));
            *value = detach_from<Windows::ApplicationModel::Calls::PhoneCallHistoryEntryRawAddressKind>(this->shim().RawAddressKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RawAddressKind(Windows::ApplicationModel::Calls::PhoneCallHistoryEntryRawAddressKind value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RawAddressKind, WINRT_WRAP(void), Windows::ApplicationModel::Calls::PhoneCallHistoryEntryRawAddressKind const&);
            this->shim().RawAddressKind(*reinterpret_cast<Windows::ApplicationModel::Calls::PhoneCallHistoryEntryRawAddressKind const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Calls::IPhoneCallHistoryEntryAddressFactory> : produce_base<D, Windows::ApplicationModel::Calls::IPhoneCallHistoryEntryAddressFactory>
{
    int32_t WINRT_CALL Create(void* rawAddress, Windows::ApplicationModel::Calls::PhoneCallHistoryEntryRawAddressKind rawAddressKind, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::ApplicationModel::Calls::PhoneCallHistoryEntryAddress), hstring const&, Windows::ApplicationModel::Calls::PhoneCallHistoryEntryRawAddressKind const&);
            *result = detach_from<Windows::ApplicationModel::Calls::PhoneCallHistoryEntryAddress>(this->shim().Create(*reinterpret_cast<hstring const*>(&rawAddress), *reinterpret_cast<Windows::ApplicationModel::Calls::PhoneCallHistoryEntryRawAddressKind const*>(&rawAddressKind)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Calls::IPhoneCallHistoryEntryQueryOptions> : produce_base<D, Windows::ApplicationModel::Calls::IPhoneCallHistoryEntryQueryOptions>
{
    int32_t WINRT_CALL get_DesiredMedia(Windows::ApplicationModel::Calls::PhoneCallHistoryEntryQueryDesiredMedia* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesiredMedia, WINRT_WRAP(Windows::ApplicationModel::Calls::PhoneCallHistoryEntryQueryDesiredMedia));
            *value = detach_from<Windows::ApplicationModel::Calls::PhoneCallHistoryEntryQueryDesiredMedia>(this->shim().DesiredMedia());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DesiredMedia(Windows::ApplicationModel::Calls::PhoneCallHistoryEntryQueryDesiredMedia value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesiredMedia, WINRT_WRAP(void), Windows::ApplicationModel::Calls::PhoneCallHistoryEntryQueryDesiredMedia const&);
            this->shim().DesiredMedia(*reinterpret_cast<Windows::ApplicationModel::Calls::PhoneCallHistoryEntryQueryDesiredMedia const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SourceIds(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourceIds, WINRT_WRAP(Windows::Foundation::Collections::IVector<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVector<hstring>>(this->shim().SourceIds());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Calls::IPhoneCallHistoryEntryReader> : produce_base<D, Windows::ApplicationModel::Calls::IPhoneCallHistoryEntryReader>
{
    int32_t WINRT_CALL ReadBatchAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadBatchAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Calls::PhoneCallHistoryEntry>>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Calls::PhoneCallHistoryEntry>>>(this->shim().ReadBatchAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Calls::IPhoneCallHistoryManagerForUser> : produce_base<D, Windows::ApplicationModel::Calls::IPhoneCallHistoryManagerForUser>
{
    int32_t WINRT_CALL RequestStoreAsync(Windows::ApplicationModel::Calls::PhoneCallHistoryStoreAccessType accessType, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestStoreAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Calls::PhoneCallHistoryStore>), Windows::ApplicationModel::Calls::PhoneCallHistoryStoreAccessType const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Calls::PhoneCallHistoryStore>>(this->shim().RequestStoreAsync(*reinterpret_cast<Windows::ApplicationModel::Calls::PhoneCallHistoryStoreAccessType const*>(&accessType)));
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
struct produce<D, Windows::ApplicationModel::Calls::IPhoneCallHistoryManagerStatics> : produce_base<D, Windows::ApplicationModel::Calls::IPhoneCallHistoryManagerStatics>
{
    int32_t WINRT_CALL RequestStoreAsync(Windows::ApplicationModel::Calls::PhoneCallHistoryStoreAccessType accessType, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestStoreAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Calls::PhoneCallHistoryStore>), Windows::ApplicationModel::Calls::PhoneCallHistoryStoreAccessType const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Calls::PhoneCallHistoryStore>>(this->shim().RequestStoreAsync(*reinterpret_cast<Windows::ApplicationModel::Calls::PhoneCallHistoryStoreAccessType const*>(&accessType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Calls::IPhoneCallHistoryManagerStatics2> : produce_base<D, Windows::ApplicationModel::Calls::IPhoneCallHistoryManagerStatics2>
{
    int32_t WINRT_CALL GetForUser(void* user, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForUser, WINRT_WRAP(Windows::ApplicationModel::Calls::PhoneCallHistoryManagerForUser), Windows::System::User const&);
            *result = detach_from<Windows::ApplicationModel::Calls::PhoneCallHistoryManagerForUser>(this->shim().GetForUser(*reinterpret_cast<Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Calls::IPhoneCallHistoryStore> : produce_base<D, Windows::ApplicationModel::Calls::IPhoneCallHistoryStore>
{
    int32_t WINRT_CALL GetEntryAsync(void* callHistoryEntryId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetEntryAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Calls::PhoneCallHistoryEntry>), hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Calls::PhoneCallHistoryEntry>>(this->shim().GetEntryAsync(*reinterpret_cast<hstring const*>(&callHistoryEntryId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetEntryReader(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetEntryReader, WINRT_WRAP(Windows::ApplicationModel::Calls::PhoneCallHistoryEntryReader));
            *result = detach_from<Windows::ApplicationModel::Calls::PhoneCallHistoryEntryReader>(this->shim().GetEntryReader());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetEntryReaderWithOptions(void* queryOptions, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetEntryReader, WINRT_WRAP(Windows::ApplicationModel::Calls::PhoneCallHistoryEntryReader), Windows::ApplicationModel::Calls::PhoneCallHistoryEntryQueryOptions const&);
            *result = detach_from<Windows::ApplicationModel::Calls::PhoneCallHistoryEntryReader>(this->shim().GetEntryReader(*reinterpret_cast<Windows::ApplicationModel::Calls::PhoneCallHistoryEntryQueryOptions const*>(&queryOptions)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SaveEntryAsync(void* callHistoryEntry, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SaveEntryAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::ApplicationModel::Calls::PhoneCallHistoryEntry const);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SaveEntryAsync(*reinterpret_cast<Windows::ApplicationModel::Calls::PhoneCallHistoryEntry const*>(&callHistoryEntry)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DeleteEntryAsync(void* callHistoryEntry, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeleteEntryAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::ApplicationModel::Calls::PhoneCallHistoryEntry const);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().DeleteEntryAsync(*reinterpret_cast<Windows::ApplicationModel::Calls::PhoneCallHistoryEntry const*>(&callHistoryEntry)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DeleteEntriesAsync(void* callHistoryEntries, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeleteEntriesAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Calls::PhoneCallHistoryEntry> const);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().DeleteEntriesAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Calls::PhoneCallHistoryEntry> const*>(&callHistoryEntries)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL MarkEntryAsSeenAsync(void* callHistoryEntry, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MarkEntryAsSeenAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::ApplicationModel::Calls::PhoneCallHistoryEntry const);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().MarkEntryAsSeenAsync(*reinterpret_cast<Windows::ApplicationModel::Calls::PhoneCallHistoryEntry const*>(&callHistoryEntry)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL MarkEntriesAsSeenAsync(void* callHistoryEntries, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MarkEntriesAsSeenAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Calls::PhoneCallHistoryEntry> const);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().MarkEntriesAsSeenAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Calls::PhoneCallHistoryEntry> const*>(&callHistoryEntries)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetUnseenCountAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetUnseenCountAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<uint32_t>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<uint32_t>>(this->shim().GetUnseenCountAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL MarkAllAsSeenAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MarkAllAsSeenAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().MarkAllAsSeenAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetSourcesUnseenCountAsync(void* sourceIds, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetSourcesUnseenCountAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<uint32_t>), Windows::Foundation::Collections::IIterable<hstring> const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<uint32_t>>(this->shim().GetSourcesUnseenCountAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&sourceIds)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL MarkSourcesAsSeenAsync(void* sourceIds, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MarkSourcesAsSeenAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Foundation::Collections::IIterable<hstring> const);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().MarkSourcesAsSeenAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&sourceIds)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Calls::IPhoneCallManagerStatics> : produce_base<D, Windows::ApplicationModel::Calls::IPhoneCallManagerStatics>
{
    int32_t WINRT_CALL ShowPhoneCallUI(void* phoneNumber, void* displayName) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowPhoneCallUI, WINRT_WRAP(void), hstring const&, hstring const&);
            this->shim().ShowPhoneCallUI(*reinterpret_cast<hstring const*>(&phoneNumber), *reinterpret_cast<hstring const*>(&displayName));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Calls::IPhoneCallManagerStatics2> : produce_base<D, Windows::ApplicationModel::Calls::IPhoneCallManagerStatics2>
{
    int32_t WINRT_CALL add_CallStateChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CallStateChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().CallStateChanged(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_CallStateChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(CallStateChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().CallStateChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL get_IsCallActive(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsCallActive, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsCallActive());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsCallIncoming(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsCallIncoming, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsCallIncoming());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ShowPhoneCallSettingsUI() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowPhoneCallSettingsUI, WINRT_WRAP(void));
            this->shim().ShowPhoneCallSettingsUI();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestStoreAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestStoreAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Calls::PhoneCallStore>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Calls::PhoneCallStore>>(this->shim().RequestStoreAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Calls::IPhoneCallStore> : produce_base<D, Windows::ApplicationModel::Calls::IPhoneCallStore>
{
    int32_t WINRT_CALL IsEmergencyPhoneNumberAsync(void* number, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsEmergencyPhoneNumberAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().IsEmergencyPhoneNumberAsync(*reinterpret_cast<hstring const*>(&number)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDefaultLineAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefaultLineAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<winrt::guid>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<winrt::guid>>(this->shim().GetDefaultLineAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestLineWatcher(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestLineWatcher, WINRT_WRAP(Windows::ApplicationModel::Calls::PhoneLineWatcher));
            *result = detach_from<Windows::ApplicationModel::Calls::PhoneLineWatcher>(this->shim().RequestLineWatcher());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Calls::IPhoneCallVideoCapabilities> : produce_base<D, Windows::ApplicationModel::Calls::IPhoneCallVideoCapabilities>
{
    int32_t WINRT_CALL get_IsVideoCallingCapable(bool* pValue) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsVideoCallingCapable, WINRT_WRAP(bool));
            *pValue = detach_from<bool>(this->shim().IsVideoCallingCapable());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Calls::IPhoneCallVideoCapabilitiesManagerStatics> : produce_base<D, Windows::ApplicationModel::Calls::IPhoneCallVideoCapabilitiesManagerStatics>
{
    int32_t WINRT_CALL GetCapabilitiesAsync(void* phoneNumber, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCapabilitiesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Calls::PhoneCallVideoCapabilities>), hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Calls::PhoneCallVideoCapabilities>>(this->shim().GetCapabilitiesAsync(*reinterpret_cast<hstring const*>(&phoneNumber)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Calls::IPhoneDialOptions> : produce_base<D, Windows::ApplicationModel::Calls::IPhoneDialOptions>
{
    int32_t WINRT_CALL get_Number(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Number, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Number());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Number(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Number, WINRT_WRAP(void), hstring const&);
            this->shim().Number(*reinterpret_cast<hstring const*>(&value));
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

    int32_t WINRT_CALL put_Contact(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Contact, WINRT_WRAP(void), Windows::ApplicationModel::Contacts::Contact const&);
            this->shim().Contact(*reinterpret_cast<Windows::ApplicationModel::Contacts::Contact const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ContactPhone(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContactPhone, WINRT_WRAP(Windows::ApplicationModel::Contacts::ContactPhone));
            *value = detach_from<Windows::ApplicationModel::Contacts::ContactPhone>(this->shim().ContactPhone());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ContactPhone(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContactPhone, WINRT_WRAP(void), Windows::ApplicationModel::Contacts::ContactPhone const&);
            this->shim().ContactPhone(*reinterpret_cast<Windows::ApplicationModel::Contacts::ContactPhone const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Media(Windows::ApplicationModel::Calls::PhoneCallMedia* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Media, WINRT_WRAP(Windows::ApplicationModel::Calls::PhoneCallMedia));
            *value = detach_from<Windows::ApplicationModel::Calls::PhoneCallMedia>(this->shim().Media());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Media(Windows::ApplicationModel::Calls::PhoneCallMedia value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Media, WINRT_WRAP(void), Windows::ApplicationModel::Calls::PhoneCallMedia const&);
            this->shim().Media(*reinterpret_cast<Windows::ApplicationModel::Calls::PhoneCallMedia const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AudioEndpoint(Windows::ApplicationModel::Calls::PhoneAudioRoutingEndpoint* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioEndpoint, WINRT_WRAP(Windows::ApplicationModel::Calls::PhoneAudioRoutingEndpoint));
            *value = detach_from<Windows::ApplicationModel::Calls::PhoneAudioRoutingEndpoint>(this->shim().AudioEndpoint());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AudioEndpoint(Windows::ApplicationModel::Calls::PhoneAudioRoutingEndpoint value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioEndpoint, WINRT_WRAP(void), Windows::ApplicationModel::Calls::PhoneAudioRoutingEndpoint const&);
            this->shim().AudioEndpoint(*reinterpret_cast<Windows::ApplicationModel::Calls::PhoneAudioRoutingEndpoint const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Calls::IPhoneLine> : produce_base<D, Windows::ApplicationModel::Calls::IPhoneLine>
{
    int32_t WINRT_CALL add_LineChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LineChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Calls::PhoneLine, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().LineChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Calls::PhoneLine, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_LineChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(LineChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().LineChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL get_Id(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Id, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DisplayColor(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayColor, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().DisplayColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NetworkState(Windows::ApplicationModel::Calls::PhoneNetworkState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NetworkState, WINRT_WRAP(Windows::ApplicationModel::Calls::PhoneNetworkState));
            *value = detach_from<Windows::ApplicationModel::Calls::PhoneNetworkState>(this->shim().NetworkState());
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

    int32_t WINRT_CALL get_Voicemail(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Voicemail, WINRT_WRAP(Windows::ApplicationModel::Calls::PhoneVoicemail));
            *value = detach_from<Windows::ApplicationModel::Calls::PhoneVoicemail>(this->shim().Voicemail());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NetworkName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NetworkName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().NetworkName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CellularDetails(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CellularDetails, WINRT_WRAP(Windows::ApplicationModel::Calls::PhoneLineCellularDetails));
            *value = detach_from<Windows::ApplicationModel::Calls::PhoneLineCellularDetails>(this->shim().CellularDetails());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Transport(Windows::ApplicationModel::Calls::PhoneLineTransport* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Transport, WINRT_WRAP(Windows::ApplicationModel::Calls::PhoneLineTransport));
            *value = detach_from<Windows::ApplicationModel::Calls::PhoneLineTransport>(this->shim().Transport());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanDial(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanDial, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanDial());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportsTile(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportsTile, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().SupportsTile());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VideoCallingCapabilities(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoCallingCapabilities, WINRT_WRAP(Windows::ApplicationModel::Calls::PhoneCallVideoCapabilities));
            *value = detach_from<Windows::ApplicationModel::Calls::PhoneCallVideoCapabilities>(this->shim().VideoCallingCapabilities());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LineConfiguration(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LineConfiguration, WINRT_WRAP(Windows::ApplicationModel::Calls::PhoneLineConfiguration));
            *value = detach_from<Windows::ApplicationModel::Calls::PhoneLineConfiguration>(this->shim().LineConfiguration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsImmediateDialNumberAsync(void* number, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsImmediateDialNumberAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().IsImmediateDialNumberAsync(*reinterpret_cast<hstring const*>(&number)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Dial(void* number, void* displayName) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Dial, WINRT_WRAP(void), hstring const&, hstring const&);
            this->shim().Dial(*reinterpret_cast<hstring const*>(&number), *reinterpret_cast<hstring const*>(&displayName));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DialWithOptions(void* options) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DialWithOptions, WINRT_WRAP(void), Windows::ApplicationModel::Calls::PhoneDialOptions const&);
            this->shim().DialWithOptions(*reinterpret_cast<Windows::ApplicationModel::Calls::PhoneDialOptions const*>(&options));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Calls::IPhoneLine2> : produce_base<D, Windows::ApplicationModel::Calls::IPhoneLine2>
{
    int32_t WINRT_CALL EnableTextReply(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnableTextReply, WINRT_WRAP(void), bool);
            this->shim().EnableTextReply(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TransportDeviceId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransportDeviceId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().TransportDeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Calls::IPhoneLineCellularDetails> : produce_base<D, Windows::ApplicationModel::Calls::IPhoneLineCellularDetails>
{
    int32_t WINRT_CALL get_SimState(Windows::ApplicationModel::Calls::PhoneSimState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SimState, WINRT_WRAP(Windows::ApplicationModel::Calls::PhoneSimState));
            *value = detach_from<Windows::ApplicationModel::Calls::PhoneSimState>(this->shim().SimState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SimSlotIndex(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SimSlotIndex, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().SimSlotIndex());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsModemOn(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsModemOn, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsModemOn());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RegistrationRejectCode(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RegistrationRejectCode, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().RegistrationRejectCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetNetworkOperatorDisplayText(Windows::ApplicationModel::Calls::PhoneLineNetworkOperatorDisplayTextLocation location, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetNetworkOperatorDisplayText, WINRT_WRAP(hstring), Windows::ApplicationModel::Calls::PhoneLineNetworkOperatorDisplayTextLocation const&);
            *value = detach_from<hstring>(this->shim().GetNetworkOperatorDisplayText(*reinterpret_cast<Windows::ApplicationModel::Calls::PhoneLineNetworkOperatorDisplayTextLocation const*>(&location)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Calls::IPhoneLineConfiguration> : produce_base<D, Windows::ApplicationModel::Calls::IPhoneLineConfiguration>
{
    int32_t WINRT_CALL get_IsVideoCallingEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsVideoCallingEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsVideoCallingEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExtendedProperties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExtendedProperties, WINRT_WRAP(Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable>));
            *value = detach_from<Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable>>(this->shim().ExtendedProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Calls::IPhoneLineStatics> : produce_base<D, Windows::ApplicationModel::Calls::IPhoneLineStatics>
{
    int32_t WINRT_CALL FromIdAsync(winrt::guid lineId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Calls::PhoneLine>), winrt::guid const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Calls::PhoneLine>>(this->shim().FromIdAsync(*reinterpret_cast<winrt::guid const*>(&lineId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Calls::IPhoneLineTransportDevice> : produce_base<D, Windows::ApplicationModel::Calls::IPhoneLineTransportDevice>
{
    int32_t WINRT_CALL get_DeviceId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Transport(Windows::ApplicationModel::Calls::PhoneLineTransport* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Transport, WINRT_WRAP(Windows::ApplicationModel::Calls::PhoneLineTransport));
            *value = detach_from<Windows::ApplicationModel::Calls::PhoneLineTransport>(this->shim().Transport());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestAccessAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestAccessAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceAccessStatus>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceAccessStatus>>(this->shim().RequestAccessAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RegisterApp() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RegisterApp, WINRT_WRAP(void));
            this->shim().RegisterApp();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RegisterAppForUser(void* user) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RegisterAppForUser, WINRT_WRAP(void), Windows::System::User const&);
            this->shim().RegisterAppForUser(*reinterpret_cast<Windows::System::User const*>(&user));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UnregisterApp() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UnregisterApp, WINRT_WRAP(void));
            this->shim().UnregisterApp();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UnregisterAppForUser(void* user) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UnregisterAppForUser, WINRT_WRAP(void), Windows::System::User const&);
            this->shim().UnregisterAppForUser(*reinterpret_cast<Windows::System::User const*>(&user));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsRegistered(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsRegistered, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().IsRegistered());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Connect(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Connect, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().Connect());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ConnectAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConnectAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().ConnectAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Calls::IPhoneLineTransportDeviceStatics> : produce_base<D, Windows::ApplicationModel::Calls::IPhoneLineTransportDeviceStatics>
{
    int32_t WINRT_CALL FromId(void* id, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromId, WINRT_WRAP(Windows::ApplicationModel::Calls::PhoneLineTransportDevice), hstring const&);
            *result = detach_from<Windows::ApplicationModel::Calls::PhoneLineTransportDevice>(this->shim().FromId(*reinterpret_cast<hstring const*>(&id)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeviceSelector(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelector, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().GetDeviceSelector());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeviceSelectorForPhoneLineTransport(Windows::ApplicationModel::Calls::PhoneLineTransport transport, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelector, WINRT_WRAP(hstring), Windows::ApplicationModel::Calls::PhoneLineTransport const&);
            *result = detach_from<hstring>(this->shim().GetDeviceSelector(*reinterpret_cast<Windows::ApplicationModel::Calls::PhoneLineTransport const*>(&transport)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Calls::IPhoneLineWatcher> : produce_base<D, Windows::ApplicationModel::Calls::IPhoneLineWatcher>
{
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

    int32_t WINRT_CALL Stop() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Stop, WINRT_WRAP(void));
            this->shim().Stop();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_LineAdded(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LineAdded, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Calls::PhoneLineWatcher, Windows::ApplicationModel::Calls::PhoneLineWatcherEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().LineAdded(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Calls::PhoneLineWatcher, Windows::ApplicationModel::Calls::PhoneLineWatcherEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_LineAdded(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(LineAdded, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().LineAdded(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_LineRemoved(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LineRemoved, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Calls::PhoneLineWatcher, Windows::ApplicationModel::Calls::PhoneLineWatcherEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().LineRemoved(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Calls::PhoneLineWatcher, Windows::ApplicationModel::Calls::PhoneLineWatcherEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_LineRemoved(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(LineRemoved, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().LineRemoved(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_LineUpdated(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LineUpdated, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Calls::PhoneLineWatcher, Windows::ApplicationModel::Calls::PhoneLineWatcherEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().LineUpdated(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Calls::PhoneLineWatcher, Windows::ApplicationModel::Calls::PhoneLineWatcherEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_LineUpdated(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(LineUpdated, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().LineUpdated(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_EnumerationCompleted(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnumerationCompleted, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Calls::PhoneLineWatcher, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().EnumerationCompleted(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Calls::PhoneLineWatcher, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_EnumerationCompleted(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(EnumerationCompleted, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().EnumerationCompleted(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_Stopped(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Stopped, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Calls::PhoneLineWatcher, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().Stopped(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Calls::PhoneLineWatcher, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Stopped(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Stopped, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Stopped(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL get_Status(Windows::ApplicationModel::Calls::PhoneLineWatcherStatus* status) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::ApplicationModel::Calls::PhoneLineWatcherStatus));
            *status = detach_from<Windows::ApplicationModel::Calls::PhoneLineWatcherStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Calls::IPhoneLineWatcherEventArgs> : produce_base<D, Windows::ApplicationModel::Calls::IPhoneLineWatcherEventArgs>
{
    int32_t WINRT_CALL get_LineId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LineId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().LineId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Calls::IPhoneVoicemail> : produce_base<D, Windows::ApplicationModel::Calls::IPhoneVoicemail>
{
    int32_t WINRT_CALL get_Number(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Number, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Number());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MessageCount(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MessageCount, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().MessageCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Type(Windows::ApplicationModel::Calls::PhoneVoicemailType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Type, WINRT_WRAP(Windows::ApplicationModel::Calls::PhoneVoicemailType));
            *value = detach_from<Windows::ApplicationModel::Calls::PhoneVoicemailType>(this->shim().Type());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DialVoicemailAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DialVoicemailAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().DialVoicemailAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Calls::IVoipCallCoordinator> : produce_base<D, Windows::ApplicationModel::Calls::IVoipCallCoordinator>
{
    int32_t WINRT_CALL ReserveCallResourcesAsync(void* taskEntryPoint, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReserveCallResourcesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Calls::VoipPhoneCallResourceReservationStatus>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Calls::VoipPhoneCallResourceReservationStatus>>(this->shim().ReserveCallResourcesAsync(*reinterpret_cast<hstring const*>(&taskEntryPoint)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_MuteStateChanged(void* muteChangeHandler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MuteStateChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Calls::VoipCallCoordinator, Windows::ApplicationModel::Calls::MuteChangeEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().MuteStateChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Calls::VoipCallCoordinator, Windows::ApplicationModel::Calls::MuteChangeEventArgs> const*>(&muteChangeHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_MuteStateChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(MuteStateChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().MuteStateChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL RequestNewIncomingCall(void* context, void* contactName, void* contactNumber, void* contactImage, void* serviceName, void* brandingImage, void* callDetails, void* ringtone, Windows::ApplicationModel::Calls::VoipPhoneCallMedia media, Windows::Foundation::TimeSpan ringTimeout, void** call) noexcept final
    {
        try
        {
            *call = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestNewIncomingCall, WINRT_WRAP(Windows::ApplicationModel::Calls::VoipPhoneCall), hstring const&, hstring const&, hstring const&, Windows::Foundation::Uri const&, hstring const&, Windows::Foundation::Uri const&, hstring const&, Windows::Foundation::Uri const&, Windows::ApplicationModel::Calls::VoipPhoneCallMedia const&, Windows::Foundation::TimeSpan const&);
            *call = detach_from<Windows::ApplicationModel::Calls::VoipPhoneCall>(this->shim().RequestNewIncomingCall(*reinterpret_cast<hstring const*>(&context), *reinterpret_cast<hstring const*>(&contactName), *reinterpret_cast<hstring const*>(&contactNumber), *reinterpret_cast<Windows::Foundation::Uri const*>(&contactImage), *reinterpret_cast<hstring const*>(&serviceName), *reinterpret_cast<Windows::Foundation::Uri const*>(&brandingImage), *reinterpret_cast<hstring const*>(&callDetails), *reinterpret_cast<Windows::Foundation::Uri const*>(&ringtone), *reinterpret_cast<Windows::ApplicationModel::Calls::VoipPhoneCallMedia const*>(&media), *reinterpret_cast<Windows::Foundation::TimeSpan const*>(&ringTimeout)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestNewOutgoingCall(void* context, void* contactName, void* serviceName, Windows::ApplicationModel::Calls::VoipPhoneCallMedia media, void** call) noexcept final
    {
        try
        {
            *call = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestNewOutgoingCall, WINRT_WRAP(Windows::ApplicationModel::Calls::VoipPhoneCall), hstring const&, hstring const&, hstring const&, Windows::ApplicationModel::Calls::VoipPhoneCallMedia const&);
            *call = detach_from<Windows::ApplicationModel::Calls::VoipPhoneCall>(this->shim().RequestNewOutgoingCall(*reinterpret_cast<hstring const*>(&context), *reinterpret_cast<hstring const*>(&contactName), *reinterpret_cast<hstring const*>(&serviceName), *reinterpret_cast<Windows::ApplicationModel::Calls::VoipPhoneCallMedia const*>(&media)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL NotifyMuted() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NotifyMuted, WINRT_WRAP(void));
            this->shim().NotifyMuted();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL NotifyUnmuted() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NotifyUnmuted, WINRT_WRAP(void));
            this->shim().NotifyUnmuted();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestOutgoingUpgradeToVideoCall(winrt::guid callUpgradeGuid, void* context, void* contactName, void* serviceName, void** call) noexcept final
    {
        try
        {
            *call = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestOutgoingUpgradeToVideoCall, WINRT_WRAP(Windows::ApplicationModel::Calls::VoipPhoneCall), winrt::guid const&, hstring const&, hstring const&, hstring const&);
            *call = detach_from<Windows::ApplicationModel::Calls::VoipPhoneCall>(this->shim().RequestOutgoingUpgradeToVideoCall(*reinterpret_cast<winrt::guid const*>(&callUpgradeGuid), *reinterpret_cast<hstring const*>(&context), *reinterpret_cast<hstring const*>(&contactName), *reinterpret_cast<hstring const*>(&serviceName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestIncomingUpgradeToVideoCall(void* context, void* contactName, void* contactNumber, void* contactImage, void* serviceName, void* brandingImage, void* callDetails, void* ringtone, Windows::Foundation::TimeSpan ringTimeout, void** call) noexcept final
    {
        try
        {
            *call = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestIncomingUpgradeToVideoCall, WINRT_WRAP(Windows::ApplicationModel::Calls::VoipPhoneCall), hstring const&, hstring const&, hstring const&, Windows::Foundation::Uri const&, hstring const&, Windows::Foundation::Uri const&, hstring const&, Windows::Foundation::Uri const&, Windows::Foundation::TimeSpan const&);
            *call = detach_from<Windows::ApplicationModel::Calls::VoipPhoneCall>(this->shim().RequestIncomingUpgradeToVideoCall(*reinterpret_cast<hstring const*>(&context), *reinterpret_cast<hstring const*>(&contactName), *reinterpret_cast<hstring const*>(&contactNumber), *reinterpret_cast<Windows::Foundation::Uri const*>(&contactImage), *reinterpret_cast<hstring const*>(&serviceName), *reinterpret_cast<Windows::Foundation::Uri const*>(&brandingImage), *reinterpret_cast<hstring const*>(&callDetails), *reinterpret_cast<Windows::Foundation::Uri const*>(&ringtone), *reinterpret_cast<Windows::Foundation::TimeSpan const*>(&ringTimeout)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TerminateCellularCall(winrt::guid callUpgradeGuid) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TerminateCellularCall, WINRT_WRAP(void), winrt::guid const&);
            this->shim().TerminateCellularCall(*reinterpret_cast<winrt::guid const*>(&callUpgradeGuid));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CancelUpgrade(winrt::guid callUpgradeGuid) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CancelUpgrade, WINRT_WRAP(void), winrt::guid const&);
            this->shim().CancelUpgrade(*reinterpret_cast<winrt::guid const*>(&callUpgradeGuid));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Calls::IVoipCallCoordinator2> : produce_base<D, Windows::ApplicationModel::Calls::IVoipCallCoordinator2>
{
    int32_t WINRT_CALL SetupNewAcceptedCall(void* context, void* contactName, void* contactNumber, void* serviceName, Windows::ApplicationModel::Calls::VoipPhoneCallMedia media, void** call) noexcept final
    {
        try
        {
            *call = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetupNewAcceptedCall, WINRT_WRAP(Windows::ApplicationModel::Calls::VoipPhoneCall), hstring const&, hstring const&, hstring const&, hstring const&, Windows::ApplicationModel::Calls::VoipPhoneCallMedia const&);
            *call = detach_from<Windows::ApplicationModel::Calls::VoipPhoneCall>(this->shim().SetupNewAcceptedCall(*reinterpret_cast<hstring const*>(&context), *reinterpret_cast<hstring const*>(&contactName), *reinterpret_cast<hstring const*>(&contactNumber), *reinterpret_cast<hstring const*>(&serviceName), *reinterpret_cast<Windows::ApplicationModel::Calls::VoipPhoneCallMedia const*>(&media)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Calls::IVoipCallCoordinator3> : produce_base<D, Windows::ApplicationModel::Calls::IVoipCallCoordinator3>
{
    int32_t WINRT_CALL RequestNewAppInitiatedCall(void* context, void* contactName, void* contactNumber, void* serviceName, Windows::ApplicationModel::Calls::VoipPhoneCallMedia media, void** call) noexcept final
    {
        try
        {
            *call = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestNewAppInitiatedCall, WINRT_WRAP(Windows::ApplicationModel::Calls::VoipPhoneCall), hstring const&, hstring const&, hstring const&, hstring const&, Windows::ApplicationModel::Calls::VoipPhoneCallMedia const&);
            *call = detach_from<Windows::ApplicationModel::Calls::VoipPhoneCall>(this->shim().RequestNewAppInitiatedCall(*reinterpret_cast<hstring const*>(&context), *reinterpret_cast<hstring const*>(&contactName), *reinterpret_cast<hstring const*>(&contactNumber), *reinterpret_cast<hstring const*>(&serviceName), *reinterpret_cast<Windows::ApplicationModel::Calls::VoipPhoneCallMedia const*>(&media)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestNewIncomingCallWithContactRemoteId(void* context, void* contactName, void* contactNumber, void* contactImage, void* serviceName, void* brandingImage, void* callDetails, void* ringtone, Windows::ApplicationModel::Calls::VoipPhoneCallMedia media, Windows::Foundation::TimeSpan ringTimeout, void* contactRemoteId, void** call) noexcept final
    {
        try
        {
            *call = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestNewIncomingCall, WINRT_WRAP(Windows::ApplicationModel::Calls::VoipPhoneCall), hstring const&, hstring const&, hstring const&, Windows::Foundation::Uri const&, hstring const&, Windows::Foundation::Uri const&, hstring const&, Windows::Foundation::Uri const&, Windows::ApplicationModel::Calls::VoipPhoneCallMedia const&, Windows::Foundation::TimeSpan const&, hstring const&);
            *call = detach_from<Windows::ApplicationModel::Calls::VoipPhoneCall>(this->shim().RequestNewIncomingCall(*reinterpret_cast<hstring const*>(&context), *reinterpret_cast<hstring const*>(&contactName), *reinterpret_cast<hstring const*>(&contactNumber), *reinterpret_cast<Windows::Foundation::Uri const*>(&contactImage), *reinterpret_cast<hstring const*>(&serviceName), *reinterpret_cast<Windows::Foundation::Uri const*>(&brandingImage), *reinterpret_cast<hstring const*>(&callDetails), *reinterpret_cast<Windows::Foundation::Uri const*>(&ringtone), *reinterpret_cast<Windows::ApplicationModel::Calls::VoipPhoneCallMedia const*>(&media), *reinterpret_cast<Windows::Foundation::TimeSpan const*>(&ringTimeout), *reinterpret_cast<hstring const*>(&contactRemoteId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Calls::IVoipCallCoordinator4> : produce_base<D, Windows::ApplicationModel::Calls::IVoipCallCoordinator4>
{
    int32_t WINRT_CALL ReserveOneProcessCallResourcesAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReserveCallResourcesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Calls::VoipPhoneCallResourceReservationStatus>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Calls::VoipPhoneCallResourceReservationStatus>>(this->shim().ReserveCallResourcesAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Calls::IVoipCallCoordinatorStatics> : produce_base<D, Windows::ApplicationModel::Calls::IVoipCallCoordinatorStatics>
{
    int32_t WINRT_CALL GetDefault(void** coordinator) noexcept final
    {
        try
        {
            *coordinator = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefault, WINRT_WRAP(Windows::ApplicationModel::Calls::VoipCallCoordinator));
            *coordinator = detach_from<Windows::ApplicationModel::Calls::VoipCallCoordinator>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Calls::IVoipPhoneCall> : produce_base<D, Windows::ApplicationModel::Calls::IVoipPhoneCall>
{
    int32_t WINRT_CALL add_EndRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EndRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Calls::VoipPhoneCall, Windows::ApplicationModel::Calls::CallStateChangeEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().EndRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Calls::VoipPhoneCall, Windows::ApplicationModel::Calls::CallStateChangeEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_EndRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(EndRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().EndRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_HoldRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HoldRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Calls::VoipPhoneCall, Windows::ApplicationModel::Calls::CallStateChangeEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().HoldRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Calls::VoipPhoneCall, Windows::ApplicationModel::Calls::CallStateChangeEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_HoldRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(HoldRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().HoldRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_ResumeRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResumeRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Calls::VoipPhoneCall, Windows::ApplicationModel::Calls::CallStateChangeEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ResumeRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Calls::VoipPhoneCall, Windows::ApplicationModel::Calls::CallStateChangeEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ResumeRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ResumeRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ResumeRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_AnswerRequested(void* acceptHandler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AnswerRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Calls::VoipPhoneCall, Windows::ApplicationModel::Calls::CallAnswerEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().AnswerRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Calls::VoipPhoneCall, Windows::ApplicationModel::Calls::CallAnswerEventArgs> const*>(&acceptHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_AnswerRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(AnswerRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().AnswerRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_RejectRequested(void* rejectHandler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RejectRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Calls::VoipPhoneCall, Windows::ApplicationModel::Calls::CallRejectEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().RejectRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Calls::VoipPhoneCall, Windows::ApplicationModel::Calls::CallRejectEventArgs> const*>(&rejectHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_RejectRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(RejectRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().RejectRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL NotifyCallHeld() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NotifyCallHeld, WINRT_WRAP(void));
            this->shim().NotifyCallHeld();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL NotifyCallActive() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NotifyCallActive, WINRT_WRAP(void));
            this->shim().NotifyCallActive();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL NotifyCallEnded() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NotifyCallEnded, WINRT_WRAP(void));
            this->shim().NotifyCallEnded();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ContactName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContactName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ContactName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ContactName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContactName, WINRT_WRAP(void), hstring const&);
            this->shim().ContactName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StartTime(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartTime, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().StartTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_StartTime(Windows::Foundation::DateTime value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartTime, WINRT_WRAP(void), Windows::Foundation::DateTime const&);
            this->shim().StartTime(*reinterpret_cast<Windows::Foundation::DateTime const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CallMedia(Windows::ApplicationModel::Calls::VoipPhoneCallMedia* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CallMedia, WINRT_WRAP(Windows::ApplicationModel::Calls::VoipPhoneCallMedia));
            *value = detach_from<Windows::ApplicationModel::Calls::VoipPhoneCallMedia>(this->shim().CallMedia());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CallMedia(Windows::ApplicationModel::Calls::VoipPhoneCallMedia value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CallMedia, WINRT_WRAP(void), Windows::ApplicationModel::Calls::VoipPhoneCallMedia const&);
            this->shim().CallMedia(*reinterpret_cast<Windows::ApplicationModel::Calls::VoipPhoneCallMedia const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL NotifyCallReady() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NotifyCallReady, WINRT_WRAP(void));
            this->shim().NotifyCallReady();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Calls::IVoipPhoneCall2> : produce_base<D, Windows::ApplicationModel::Calls::IVoipPhoneCall2>
{
    int32_t WINRT_CALL TryShowAppUI() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryShowAppUI, WINRT_WRAP(void));
            this->shim().TryShowAppUI();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Calls::IVoipPhoneCall3> : produce_base<D, Windows::ApplicationModel::Calls::IVoipPhoneCall3>
{
    int32_t WINRT_CALL NotifyCallAccepted(Windows::ApplicationModel::Calls::VoipPhoneCallMedia media) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NotifyCallAccepted, WINRT_WRAP(void), Windows::ApplicationModel::Calls::VoipPhoneCallMedia const&);
            this->shim().NotifyCallAccepted(*reinterpret_cast<Windows::ApplicationModel::Calls::VoipPhoneCallMedia const*>(&media));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Calls {

inline bool PhoneCallBlocking::BlockUnknownNumbers()
{
    return impl::call_factory<PhoneCallBlocking, Windows::ApplicationModel::Calls::IPhoneCallBlockingStatics>([&](auto&& f) { return f.BlockUnknownNumbers(); });
}

inline void PhoneCallBlocking::BlockUnknownNumbers(bool value)
{
    impl::call_factory<PhoneCallBlocking, Windows::ApplicationModel::Calls::IPhoneCallBlockingStatics>([&](auto&& f) { return f.BlockUnknownNumbers(value); });
}

inline bool PhoneCallBlocking::BlockPrivateNumbers()
{
    return impl::call_factory<PhoneCallBlocking, Windows::ApplicationModel::Calls::IPhoneCallBlockingStatics>([&](auto&& f) { return f.BlockPrivateNumbers(); });
}

inline void PhoneCallBlocking::BlockPrivateNumbers(bool value)
{
    impl::call_factory<PhoneCallBlocking, Windows::ApplicationModel::Calls::IPhoneCallBlockingStatics>([&](auto&& f) { return f.BlockPrivateNumbers(value); });
}

inline Windows::Foundation::IAsyncOperation<bool> PhoneCallBlocking::SetCallBlockingListAsync(param::async_iterable<hstring> const& phoneNumberList)
{
    return impl::call_factory<PhoneCallBlocking, Windows::ApplicationModel::Calls::IPhoneCallBlockingStatics>([&](auto&& f) { return f.SetCallBlockingListAsync(phoneNumberList); });
}

inline PhoneCallHistoryEntry::PhoneCallHistoryEntry() :
    PhoneCallHistoryEntry(impl::call_factory<PhoneCallHistoryEntry>([](auto&& f) { return f.template ActivateInstance<PhoneCallHistoryEntry>(); }))
{}

inline PhoneCallHistoryEntryAddress::PhoneCallHistoryEntryAddress() :
    PhoneCallHistoryEntryAddress(impl::call_factory<PhoneCallHistoryEntryAddress>([](auto&& f) { return f.template ActivateInstance<PhoneCallHistoryEntryAddress>(); }))
{}

inline PhoneCallHistoryEntryAddress::PhoneCallHistoryEntryAddress(param::hstring const& rawAddress, Windows::ApplicationModel::Calls::PhoneCallHistoryEntryRawAddressKind const& rawAddressKind) :
    PhoneCallHistoryEntryAddress(impl::call_factory<PhoneCallHistoryEntryAddress, Windows::ApplicationModel::Calls::IPhoneCallHistoryEntryAddressFactory>([&](auto&& f) { return f.Create(rawAddress, rawAddressKind); }))
{}

inline PhoneCallHistoryEntryQueryOptions::PhoneCallHistoryEntryQueryOptions() :
    PhoneCallHistoryEntryQueryOptions(impl::call_factory<PhoneCallHistoryEntryQueryOptions>([](auto&& f) { return f.template ActivateInstance<PhoneCallHistoryEntryQueryOptions>(); }))
{}

inline Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Calls::PhoneCallHistoryStore> PhoneCallHistoryManager::RequestStoreAsync(Windows::ApplicationModel::Calls::PhoneCallHistoryStoreAccessType const& accessType)
{
    return impl::call_factory<PhoneCallHistoryManager, Windows::ApplicationModel::Calls::IPhoneCallHistoryManagerStatics>([&](auto&& f) { return f.RequestStoreAsync(accessType); });
}

inline Windows::ApplicationModel::Calls::PhoneCallHistoryManagerForUser PhoneCallHistoryManager::GetForUser(Windows::System::User const& user)
{
    return impl::call_factory<PhoneCallHistoryManager, Windows::ApplicationModel::Calls::IPhoneCallHistoryManagerStatics2>([&](auto&& f) { return f.GetForUser(user); });
}

inline void PhoneCallManager::ShowPhoneCallUI(param::hstring const& phoneNumber, param::hstring const& displayName)
{
    impl::call_factory<PhoneCallManager, Windows::ApplicationModel::Calls::IPhoneCallManagerStatics>([&](auto&& f) { return f.ShowPhoneCallUI(phoneNumber, displayName); });
}

inline winrt::event_token PhoneCallManager::CallStateChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    return impl::call_factory<PhoneCallManager, Windows::ApplicationModel::Calls::IPhoneCallManagerStatics2>([&](auto&& f) { return f.CallStateChanged(handler); });
}

inline PhoneCallManager::CallStateChanged_revoker PhoneCallManager::CallStateChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    auto f = get_activation_factory<PhoneCallManager, Windows::ApplicationModel::Calls::IPhoneCallManagerStatics2>();
    return { f, f.CallStateChanged(handler) };
}

inline void PhoneCallManager::CallStateChanged(winrt::event_token const& token)
{
    impl::call_factory<PhoneCallManager, Windows::ApplicationModel::Calls::IPhoneCallManagerStatics2>([&](auto&& f) { return f.CallStateChanged(token); });
}

inline bool PhoneCallManager::IsCallActive()
{
    return impl::call_factory<PhoneCallManager, Windows::ApplicationModel::Calls::IPhoneCallManagerStatics2>([&](auto&& f) { return f.IsCallActive(); });
}

inline bool PhoneCallManager::IsCallIncoming()
{
    return impl::call_factory<PhoneCallManager, Windows::ApplicationModel::Calls::IPhoneCallManagerStatics2>([&](auto&& f) { return f.IsCallIncoming(); });
}

inline void PhoneCallManager::ShowPhoneCallSettingsUI()
{
    impl::call_factory<PhoneCallManager, Windows::ApplicationModel::Calls::IPhoneCallManagerStatics2>([&](auto&& f) { return f.ShowPhoneCallSettingsUI(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Calls::PhoneCallStore> PhoneCallManager::RequestStoreAsync()
{
    return impl::call_factory<PhoneCallManager, Windows::ApplicationModel::Calls::IPhoneCallManagerStatics2>([&](auto&& f) { return f.RequestStoreAsync(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Calls::PhoneCallVideoCapabilities> PhoneCallVideoCapabilitiesManager::GetCapabilitiesAsync(param::hstring const& phoneNumber)
{
    return impl::call_factory<PhoneCallVideoCapabilitiesManager, Windows::ApplicationModel::Calls::IPhoneCallVideoCapabilitiesManagerStatics>([&](auto&& f) { return f.GetCapabilitiesAsync(phoneNumber); });
}

inline PhoneDialOptions::PhoneDialOptions() :
    PhoneDialOptions(impl::call_factory<PhoneDialOptions>([](auto&& f) { return f.template ActivateInstance<PhoneDialOptions>(); }))
{}

inline Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Calls::PhoneLine> PhoneLine::FromIdAsync(winrt::guid const& lineId)
{
    return impl::call_factory<PhoneLine, Windows::ApplicationModel::Calls::IPhoneLineStatics>([&](auto&& f) { return f.FromIdAsync(lineId); });
}

inline Windows::ApplicationModel::Calls::PhoneLineTransportDevice PhoneLineTransportDevice::FromId(param::hstring const& id)
{
    return impl::call_factory<PhoneLineTransportDevice, Windows::ApplicationModel::Calls::IPhoneLineTransportDeviceStatics>([&](auto&& f) { return f.FromId(id); });
}

inline hstring PhoneLineTransportDevice::GetDeviceSelector()
{
    return impl::call_factory<PhoneLineTransportDevice, Windows::ApplicationModel::Calls::IPhoneLineTransportDeviceStatics>([&](auto&& f) { return f.GetDeviceSelector(); });
}

inline hstring PhoneLineTransportDevice::GetDeviceSelector(Windows::ApplicationModel::Calls::PhoneLineTransport const& transport)
{
    return impl::call_factory<PhoneLineTransportDevice, Windows::ApplicationModel::Calls::IPhoneLineTransportDeviceStatics>([&](auto&& f) { return f.GetDeviceSelector(transport); });
}

inline Windows::ApplicationModel::Calls::VoipCallCoordinator VoipCallCoordinator::GetDefault()
{
    return impl::call_factory<VoipCallCoordinator, Windows::ApplicationModel::Calls::IVoipCallCoordinatorStatics>([&](auto&& f) { return f.GetDefault(); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::ApplicationModel::Calls::ICallAnswerEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::ICallAnswerEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::ICallRejectEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::ICallRejectEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::ICallStateChangeEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::ICallStateChangeEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::ILockScreenCallEndCallDeferral> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::ILockScreenCallEndCallDeferral> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::ILockScreenCallEndRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::ILockScreenCallEndRequestedEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::ILockScreenCallUI> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::ILockScreenCallUI> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::IMuteChangeEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::IMuteChangeEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::IPhoneCallBlockingStatics> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::IPhoneCallBlockingStatics> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::IPhoneCallHistoryEntry> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::IPhoneCallHistoryEntry> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::IPhoneCallHistoryEntryAddress> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::IPhoneCallHistoryEntryAddress> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::IPhoneCallHistoryEntryAddressFactory> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::IPhoneCallHistoryEntryAddressFactory> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::IPhoneCallHistoryEntryQueryOptions> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::IPhoneCallHistoryEntryQueryOptions> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::IPhoneCallHistoryEntryReader> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::IPhoneCallHistoryEntryReader> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::IPhoneCallHistoryManagerForUser> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::IPhoneCallHistoryManagerForUser> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::IPhoneCallHistoryManagerStatics> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::IPhoneCallHistoryManagerStatics> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::IPhoneCallHistoryManagerStatics2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::IPhoneCallHistoryManagerStatics2> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::IPhoneCallHistoryStore> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::IPhoneCallHistoryStore> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::IPhoneCallManagerStatics> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::IPhoneCallManagerStatics> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::IPhoneCallManagerStatics2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::IPhoneCallManagerStatics2> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::IPhoneCallStore> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::IPhoneCallStore> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::IPhoneCallVideoCapabilities> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::IPhoneCallVideoCapabilities> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::IPhoneCallVideoCapabilitiesManagerStatics> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::IPhoneCallVideoCapabilitiesManagerStatics> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::IPhoneDialOptions> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::IPhoneDialOptions> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::IPhoneLine> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::IPhoneLine> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::IPhoneLine2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::IPhoneLine2> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::IPhoneLineCellularDetails> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::IPhoneLineCellularDetails> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::IPhoneLineConfiguration> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::IPhoneLineConfiguration> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::IPhoneLineStatics> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::IPhoneLineStatics> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::IPhoneLineTransportDevice> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::IPhoneLineTransportDevice> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::IPhoneLineTransportDeviceStatics> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::IPhoneLineTransportDeviceStatics> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::IPhoneLineWatcher> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::IPhoneLineWatcher> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::IPhoneLineWatcherEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::IPhoneLineWatcherEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::IPhoneVoicemail> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::IPhoneVoicemail> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::IVoipCallCoordinator> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::IVoipCallCoordinator> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::IVoipCallCoordinator2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::IVoipCallCoordinator2> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::IVoipCallCoordinator3> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::IVoipCallCoordinator3> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::IVoipCallCoordinator4> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::IVoipCallCoordinator4> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::IVoipCallCoordinatorStatics> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::IVoipCallCoordinatorStatics> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::IVoipPhoneCall> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::IVoipPhoneCall> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::IVoipPhoneCall2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::IVoipPhoneCall2> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::IVoipPhoneCall3> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::IVoipPhoneCall3> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::CallAnswerEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::CallAnswerEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::CallRejectEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::CallRejectEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::CallStateChangeEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::CallStateChangeEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::LockScreenCallEndCallDeferral> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::LockScreenCallEndCallDeferral> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::LockScreenCallEndRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::LockScreenCallEndRequestedEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::LockScreenCallUI> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::LockScreenCallUI> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::MuteChangeEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::MuteChangeEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::PhoneCallBlocking> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::PhoneCallBlocking> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::PhoneCallHistoryEntry> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::PhoneCallHistoryEntry> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::PhoneCallHistoryEntryAddress> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::PhoneCallHistoryEntryAddress> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::PhoneCallHistoryEntryQueryOptions> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::PhoneCallHistoryEntryQueryOptions> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::PhoneCallHistoryEntryReader> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::PhoneCallHistoryEntryReader> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::PhoneCallHistoryManager> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::PhoneCallHistoryManager> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::PhoneCallHistoryManagerForUser> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::PhoneCallHistoryManagerForUser> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::PhoneCallHistoryStore> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::PhoneCallHistoryStore> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::PhoneCallManager> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::PhoneCallManager> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::PhoneCallStore> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::PhoneCallStore> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::PhoneCallVideoCapabilities> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::PhoneCallVideoCapabilities> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::PhoneCallVideoCapabilitiesManager> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::PhoneCallVideoCapabilitiesManager> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::PhoneDialOptions> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::PhoneDialOptions> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::PhoneLine> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::PhoneLine> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::PhoneLineCellularDetails> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::PhoneLineCellularDetails> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::PhoneLineConfiguration> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::PhoneLineConfiguration> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::PhoneLineTransportDevice> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::PhoneLineTransportDevice> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::PhoneLineWatcher> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::PhoneLineWatcher> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::PhoneLineWatcherEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::PhoneLineWatcherEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::PhoneVoicemail> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::PhoneVoicemail> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::VoipCallCoordinator> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::VoipCallCoordinator> {};
template<> struct hash<winrt::Windows::ApplicationModel::Calls::VoipPhoneCall> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Calls::VoipPhoneCall> {};

}
