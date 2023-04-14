// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Media.MediaProperties.2.h"
#include "winrt/impl/Windows.Security.Credentials.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.ApplicationModel.Chat.2.h"
#include "winrt/Windows.ApplicationModel.h"

namespace winrt::impl {

template <typename D> bool consume_Windows_ApplicationModel_Chat_IChatCapabilities<D>::IsOnline() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatCapabilities)->get_IsOnline(&result));
    return result;
}

template <typename D> bool consume_Windows_ApplicationModel_Chat_IChatCapabilities<D>::IsChatCapable() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatCapabilities)->get_IsChatCapable(&result));
    return result;
}

template <typename D> bool consume_Windows_ApplicationModel_Chat_IChatCapabilities<D>::IsFileTransferCapable() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatCapabilities)->get_IsFileTransferCapable(&result));
    return result;
}

template <typename D> bool consume_Windows_ApplicationModel_Chat_IChatCapabilities<D>::IsGeoLocationPushCapable() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatCapabilities)->get_IsGeoLocationPushCapable(&result));
    return result;
}

template <typename D> bool consume_Windows_ApplicationModel_Chat_IChatCapabilities<D>::IsIntegratedMessagingCapable() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatCapabilities)->get_IsIntegratedMessagingCapable(&result));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatCapabilities> consume_Windows_ApplicationModel_Chat_IChatCapabilitiesManagerStatics<D>::GetCachedCapabilitiesAsync(param::hstring const& address) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatCapabilities> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatCapabilitiesManagerStatics)->GetCachedCapabilitiesAsync(get_abi(address), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatCapabilities> consume_Windows_ApplicationModel_Chat_IChatCapabilitiesManagerStatics<D>::GetCapabilitiesFromNetworkAsync(param::hstring const& address) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatCapabilities> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatCapabilitiesManagerStatics)->GetCapabilitiesFromNetworkAsync(get_abi(address), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatCapabilities> consume_Windows_ApplicationModel_Chat_IChatCapabilitiesManagerStatics2<D>::GetCachedCapabilitiesAsync(param::hstring const& address, param::hstring const& transportId) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatCapabilities> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatCapabilitiesManagerStatics2)->GetCachedCapabilitiesForTransportAsync(get_abi(address), get_abi(transportId), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatCapabilities> consume_Windows_ApplicationModel_Chat_IChatCapabilitiesManagerStatics2<D>::GetCapabilitiesFromNetworkAsync(param::hstring const& address, param::hstring const& transportId) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatCapabilities> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatCapabilitiesManagerStatics2)->GetCapabilitiesFromNetworkForTransportAsync(get_abi(address), get_abi(transportId), put_abi(operation)));
    return operation;
}

template <typename D> bool consume_Windows_ApplicationModel_Chat_IChatConversation<D>::HasUnreadMessages() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatConversation)->get_HasUnreadMessages(&result));
    return result;
}

template <typename D> hstring consume_Windows_ApplicationModel_Chat_IChatConversation<D>::Id() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatConversation)->get_Id(put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_ApplicationModel_Chat_IChatConversation<D>::Subject() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatConversation)->get_Subject(put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_ApplicationModel_Chat_IChatConversation<D>::Subject(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatConversation)->put_Subject(get_abi(value)));
}

template <typename D> bool consume_Windows_ApplicationModel_Chat_IChatConversation<D>::IsConversationMuted() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatConversation)->get_IsConversationMuted(&result));
    return result;
}

template <typename D> void consume_Windows_ApplicationModel_Chat_IChatConversation<D>::IsConversationMuted(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatConversation)->put_IsConversationMuted(value));
}

template <typename D> hstring consume_Windows_ApplicationModel_Chat_IChatConversation<D>::MostRecentMessageId() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatConversation)->get_MostRecentMessageId(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Collections::IVector<hstring> consume_Windows_ApplicationModel_Chat_IChatConversation<D>::Participants() const
{
    Windows::Foundation::Collections::IVector<hstring> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatConversation)->get_Participants(put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Chat::ChatConversationThreadingInfo consume_Windows_ApplicationModel_Chat_IChatConversation<D>::ThreadingInfo() const
{
    Windows::ApplicationModel::Chat::ChatConversationThreadingInfo result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatConversation)->get_ThreadingInfo(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Chat_IChatConversation<D>::DeleteAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatConversation)->DeleteAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Chat::ChatMessageReader consume_Windows_ApplicationModel_Chat_IChatConversation<D>::GetMessageReader() const
{
    Windows::ApplicationModel::Chat::ChatMessageReader result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatConversation)->GetMessageReader(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Chat_IChatConversation<D>::MarkMessagesAsReadAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatConversation)->MarkAllMessagesAsReadAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Chat_IChatConversation<D>::MarkMessagesAsReadAsync(Windows::Foundation::DateTime const& value) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatConversation)->MarkMessagesAsReadAsync(get_abi(value), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Chat_IChatConversation<D>::SaveAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatConversation)->SaveAsync(put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_ApplicationModel_Chat_IChatConversation<D>::NotifyLocalParticipantComposing(param::hstring const& transportId, param::hstring const& participantAddress, bool isComposing) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatConversation)->NotifyLocalParticipantComposing(get_abi(transportId), get_abi(participantAddress), isComposing));
}

template <typename D> void consume_Windows_ApplicationModel_Chat_IChatConversation<D>::NotifyRemoteParticipantComposing(param::hstring const& transportId, param::hstring const& participantAddress, bool isComposing) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatConversation)->NotifyRemoteParticipantComposing(get_abi(transportId), get_abi(participantAddress), isComposing));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Chat_IChatConversation<D>::RemoteParticipantComposingChanged(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Chat::ChatConversation, Windows::ApplicationModel::Chat::RemoteParticipantComposingChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatConversation)->add_RemoteParticipantComposingChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Chat_IChatConversation<D>::RemoteParticipantComposingChanged_revoker consume_Windows_ApplicationModel_Chat_IChatConversation<D>::RemoteParticipantComposingChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Chat::ChatConversation, Windows::ApplicationModel::Chat::RemoteParticipantComposingChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, RemoteParticipantComposingChanged_revoker>(this, RemoteParticipantComposingChanged(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Chat_IChatConversation<D>::RemoteParticipantComposingChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Chat::IChatConversation)->remove_RemoteParticipantComposingChanged(get_abi(token)));
}

template <typename D> bool consume_Windows_ApplicationModel_Chat_IChatConversation2<D>::CanModifyParticipants() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatConversation2)->get_CanModifyParticipants(&result));
    return result;
}

template <typename D> void consume_Windows_ApplicationModel_Chat_IChatConversation2<D>::CanModifyParticipants(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatConversation2)->put_CanModifyParticipants(value));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Chat::ChatConversation>> consume_Windows_ApplicationModel_Chat_IChatConversationReader<D>::ReadBatchAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Chat::ChatConversation>> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatConversationReader)->ReadBatchAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Chat::ChatConversation>> consume_Windows_ApplicationModel_Chat_IChatConversationReader<D>::ReadBatchAsync(int32_t count) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Chat::ChatConversation>> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatConversationReader)->ReadBatchWithCountAsync(count, put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_ApplicationModel_Chat_IChatConversationThreadingInfo<D>::ContactId() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatConversationThreadingInfo)->get_ContactId(put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_ApplicationModel_Chat_IChatConversationThreadingInfo<D>::ContactId(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatConversationThreadingInfo)->put_ContactId(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Chat_IChatConversationThreadingInfo<D>::Custom() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatConversationThreadingInfo)->get_Custom(put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_ApplicationModel_Chat_IChatConversationThreadingInfo<D>::Custom(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatConversationThreadingInfo)->put_Custom(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Chat_IChatConversationThreadingInfo<D>::ConversationId() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatConversationThreadingInfo)->get_ConversationId(put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_ApplicationModel_Chat_IChatConversationThreadingInfo<D>::ConversationId(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatConversationThreadingInfo)->put_ConversationId(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVector<hstring> consume_Windows_ApplicationModel_Chat_IChatConversationThreadingInfo<D>::Participants() const
{
    Windows::Foundation::Collections::IVector<hstring> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatConversationThreadingInfo)->get_Participants(put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Chat::ChatConversationThreadingKind consume_Windows_ApplicationModel_Chat_IChatConversationThreadingInfo<D>::Kind() const
{
    Windows::ApplicationModel::Chat::ChatConversationThreadingKind result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatConversationThreadingInfo)->get_Kind(put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_ApplicationModel_Chat_IChatConversationThreadingInfo<D>::Kind(Windows::ApplicationModel::Chat::ChatConversationThreadingKind const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatConversationThreadingInfo)->put_Kind(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::Chat::ChatItemKind consume_Windows_ApplicationModel_Chat_IChatItem<D>::ItemKind() const
{
    Windows::ApplicationModel::Chat::ChatItemKind result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatItem)->get_ItemKind(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Chat::ChatMessageAttachment> consume_Windows_ApplicationModel_Chat_IChatMessage<D>::Attachments() const
{
    Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Chat::ChatMessageAttachment> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessage)->get_Attachments(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Chat_IChatMessage<D>::Body() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessage)->get_Body(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Chat_IChatMessage<D>::Body(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessage)->put_Body(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Chat_IChatMessage<D>::From() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessage)->get_From(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Chat_IChatMessage<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessage)->get_Id(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Chat_IChatMessage<D>::IsForwardingDisabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessage)->get_IsForwardingDisabled(&value));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Chat_IChatMessage<D>::IsIncoming() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessage)->get_IsIncoming(&value));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Chat_IChatMessage<D>::IsRead() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessage)->get_IsRead(&value));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_ApplicationModel_Chat_IChatMessage<D>::LocalTimestamp() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessage)->get_LocalTimestamp(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_ApplicationModel_Chat_IChatMessage<D>::NetworkTimestamp() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessage)->get_NetworkTimestamp(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<hstring> consume_Windows_ApplicationModel_Chat_IChatMessage<D>::Recipients() const
{
    Windows::Foundation::Collections::IVector<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessage)->get_Recipients(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IMapView<hstring, Windows::ApplicationModel::Chat::ChatMessageStatus> consume_Windows_ApplicationModel_Chat_IChatMessage<D>::RecipientSendStatuses() const
{
    Windows::Foundation::Collections::IMapView<hstring, Windows::ApplicationModel::Chat::ChatMessageStatus> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessage)->get_RecipientSendStatuses(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Chat::ChatMessageStatus consume_Windows_ApplicationModel_Chat_IChatMessage<D>::Status() const
{
    Windows::ApplicationModel::Chat::ChatMessageStatus value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessage)->get_Status(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Chat_IChatMessage<D>::Subject() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessage)->get_Subject(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Chat_IChatMessage<D>::TransportFriendlyName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessage)->get_TransportFriendlyName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Chat_IChatMessage<D>::TransportId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessage)->get_TransportId(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Chat_IChatMessage<D>::TransportId(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessage)->put_TransportId(get_abi(value)));
}

template <typename D> uint64_t consume_Windows_ApplicationModel_Chat_IChatMessage2<D>::EstimatedDownloadSize() const
{
    uint64_t result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessage2)->get_EstimatedDownloadSize(&result));
    return result;
}

template <typename D> void consume_Windows_ApplicationModel_Chat_IChatMessage2<D>::EstimatedDownloadSize(uint64_t value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessage2)->put_EstimatedDownloadSize(value));
}

template <typename D> void consume_Windows_ApplicationModel_Chat_IChatMessage2<D>::From(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessage2)->put_From(get_abi(value)));
}

template <typename D> bool consume_Windows_ApplicationModel_Chat_IChatMessage2<D>::IsAutoReply() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessage2)->get_IsAutoReply(&result));
    return result;
}

template <typename D> void consume_Windows_ApplicationModel_Chat_IChatMessage2<D>::IsAutoReply(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessage2)->put_IsAutoReply(value));
}

template <typename D> void consume_Windows_ApplicationModel_Chat_IChatMessage2<D>::IsForwardingDisabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessage2)->put_IsForwardingDisabled(value));
}

template <typename D> bool consume_Windows_ApplicationModel_Chat_IChatMessage2<D>::IsReplyDisabled() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessage2)->get_IsReplyDisabled(&result));
    return result;
}

template <typename D> void consume_Windows_ApplicationModel_Chat_IChatMessage2<D>::IsIncoming(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessage2)->put_IsIncoming(value));
}

template <typename D> void consume_Windows_ApplicationModel_Chat_IChatMessage2<D>::IsRead(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessage2)->put_IsRead(value));
}

template <typename D> bool consume_Windows_ApplicationModel_Chat_IChatMessage2<D>::IsSeen() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessage2)->get_IsSeen(&result));
    return result;
}

template <typename D> void consume_Windows_ApplicationModel_Chat_IChatMessage2<D>::IsSeen(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessage2)->put_IsSeen(value));
}

template <typename D> bool consume_Windows_ApplicationModel_Chat_IChatMessage2<D>::IsSimMessage() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessage2)->get_IsSimMessage(&result));
    return result;
}

template <typename D> void consume_Windows_ApplicationModel_Chat_IChatMessage2<D>::LocalTimestamp(Windows::Foundation::DateTime const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessage2)->put_LocalTimestamp(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::Chat::ChatMessageKind consume_Windows_ApplicationModel_Chat_IChatMessage2<D>::MessageKind() const
{
    Windows::ApplicationModel::Chat::ChatMessageKind result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessage2)->get_MessageKind(put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_ApplicationModel_Chat_IChatMessage2<D>::MessageKind(Windows::ApplicationModel::Chat::ChatMessageKind const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessage2)->put_MessageKind(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::Chat::ChatMessageOperatorKind consume_Windows_ApplicationModel_Chat_IChatMessage2<D>::MessageOperatorKind() const
{
    Windows::ApplicationModel::Chat::ChatMessageOperatorKind result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessage2)->get_MessageOperatorKind(put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_ApplicationModel_Chat_IChatMessage2<D>::MessageOperatorKind(Windows::ApplicationModel::Chat::ChatMessageOperatorKind const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessage2)->put_MessageOperatorKind(get_abi(value)));
}

template <typename D> void consume_Windows_ApplicationModel_Chat_IChatMessage2<D>::NetworkTimestamp(Windows::Foundation::DateTime const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessage2)->put_NetworkTimestamp(get_abi(value)));
}

template <typename D> bool consume_Windows_ApplicationModel_Chat_IChatMessage2<D>::IsReceivedDuringQuietHours() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessage2)->get_IsReceivedDuringQuietHours(&result));
    return result;
}

template <typename D> void consume_Windows_ApplicationModel_Chat_IChatMessage2<D>::IsReceivedDuringQuietHours(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessage2)->put_IsReceivedDuringQuietHours(value));
}

template <typename D> void consume_Windows_ApplicationModel_Chat_IChatMessage2<D>::RemoteId(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessage2)->put_RemoteId(get_abi(value)));
}

template <typename D> void consume_Windows_ApplicationModel_Chat_IChatMessage2<D>::Status(Windows::ApplicationModel::Chat::ChatMessageStatus const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessage2)->put_Status(get_abi(value)));
}

template <typename D> void consume_Windows_ApplicationModel_Chat_IChatMessage2<D>::Subject(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessage2)->put_Subject(get_abi(value)));
}

template <typename D> bool consume_Windows_ApplicationModel_Chat_IChatMessage2<D>::ShouldSuppressNotification() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessage2)->get_ShouldSuppressNotification(&result));
    return result;
}

template <typename D> void consume_Windows_ApplicationModel_Chat_IChatMessage2<D>::ShouldSuppressNotification(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessage2)->put_ShouldSuppressNotification(value));
}

template <typename D> Windows::ApplicationModel::Chat::ChatConversationThreadingInfo consume_Windows_ApplicationModel_Chat_IChatMessage2<D>::ThreadingInfo() const
{
    Windows::ApplicationModel::Chat::ChatConversationThreadingInfo result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessage2)->get_ThreadingInfo(put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_ApplicationModel_Chat_IChatMessage2<D>::ThreadingInfo(Windows::ApplicationModel::Chat::ChatConversationThreadingInfo const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessage2)->put_ThreadingInfo(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Chat::ChatRecipientDeliveryInfo> consume_Windows_ApplicationModel_Chat_IChatMessage2<D>::RecipientsDeliveryInfos() const
{
    Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Chat::ChatRecipientDeliveryInfo> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessage2)->get_RecipientsDeliveryInfos(put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_ApplicationModel_Chat_IChatMessage3<D>::RemoteId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessage3)->get_RemoteId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Chat_IChatMessage4<D>::SyncId() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessage4)->get_SyncId(put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_ApplicationModel_Chat_IChatMessage4<D>::SyncId(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessage4)->put_SyncId(get_abi(value)));
}

template <typename D> Windows::Storage::Streams::IRandomAccessStreamReference consume_Windows_ApplicationModel_Chat_IChatMessageAttachment<D>::DataStreamReference() const
{
    Windows::Storage::Streams::IRandomAccessStreamReference value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageAttachment)->get_DataStreamReference(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Chat_IChatMessageAttachment<D>::DataStreamReference(Windows::Storage::Streams::IRandomAccessStreamReference const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageAttachment)->put_DataStreamReference(get_abi(value)));
}

template <typename D> uint32_t consume_Windows_ApplicationModel_Chat_IChatMessageAttachment<D>::GroupId() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageAttachment)->get_GroupId(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Chat_IChatMessageAttachment<D>::GroupId(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageAttachment)->put_GroupId(value));
}

template <typename D> hstring consume_Windows_ApplicationModel_Chat_IChatMessageAttachment<D>::MimeType() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageAttachment)->get_MimeType(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Chat_IChatMessageAttachment<D>::MimeType(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageAttachment)->put_MimeType(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Chat_IChatMessageAttachment<D>::Text() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageAttachment)->get_Text(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Chat_IChatMessageAttachment<D>::Text(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageAttachment)->put_Text(get_abi(value)));
}

template <typename D> Windows::Storage::Streams::IRandomAccessStreamReference consume_Windows_ApplicationModel_Chat_IChatMessageAttachment2<D>::Thumbnail() const
{
    Windows::Storage::Streams::IRandomAccessStreamReference result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageAttachment2)->get_Thumbnail(put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_ApplicationModel_Chat_IChatMessageAttachment2<D>::Thumbnail(Windows::Storage::Streams::IRandomAccessStreamReference const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageAttachment2)->put_Thumbnail(get_abi(value)));
}

template <typename D> double consume_Windows_ApplicationModel_Chat_IChatMessageAttachment2<D>::TransferProgress() const
{
    double result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageAttachment2)->get_TransferProgress(&result));
    return result;
}

template <typename D> void consume_Windows_ApplicationModel_Chat_IChatMessageAttachment2<D>::TransferProgress(double value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageAttachment2)->put_TransferProgress(value));
}

template <typename D> hstring consume_Windows_ApplicationModel_Chat_IChatMessageAttachment2<D>::OriginalFileName() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageAttachment2)->get_OriginalFileName(put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_ApplicationModel_Chat_IChatMessageAttachment2<D>::OriginalFileName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageAttachment2)->put_OriginalFileName(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::Chat::ChatMessageAttachment consume_Windows_ApplicationModel_Chat_IChatMessageAttachmentFactory<D>::CreateChatMessageAttachment(param::hstring const& mimeType, Windows::Storage::Streams::IRandomAccessStreamReference const& dataStreamReference) const
{
    Windows::ApplicationModel::Chat::ChatMessageAttachment value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageAttachmentFactory)->CreateChatMessageAttachment(get_abi(mimeType), get_abi(dataStreamReference), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Chat_IChatMessageBlockingStatic<D>::MarkMessageAsBlockedAsync(param::hstring const& localChatMessageId, bool blocked) const
{
    Windows::Foundation::IAsyncAction value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageBlockingStatic)->MarkMessageAsBlockedAsync(get_abi(localChatMessageId), blocked, put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Chat::ChatMessageChangeType consume_Windows_ApplicationModel_Chat_IChatMessageChange<D>::ChangeType() const
{
    Windows::ApplicationModel::Chat::ChatMessageChangeType value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageChange)->get_ChangeType(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Chat::ChatMessage consume_Windows_ApplicationModel_Chat_IChatMessageChange<D>::Message() const
{
    Windows::ApplicationModel::Chat::ChatMessage value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageChange)->get_Message(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Chat_IChatMessageChangeReader<D>::AcceptChanges() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageChangeReader)->AcceptChanges());
}

template <typename D> void consume_Windows_ApplicationModel_Chat_IChatMessageChangeReader<D>::AcceptChangesThrough(Windows::ApplicationModel::Chat::ChatMessageChange const& lastChangeToAcknowledge) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageChangeReader)->AcceptChangesThrough(get_abi(lastChangeToAcknowledge)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Chat::ChatMessageChange>> consume_Windows_ApplicationModel_Chat_IChatMessageChangeReader<D>::ReadBatchAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Chat::ChatMessageChange>> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageChangeReader)->ReadBatchAsync(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Chat_IChatMessageChangeTracker<D>::Enable() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageChangeTracker)->Enable());
}

template <typename D> Windows::ApplicationModel::Chat::ChatMessageChangeReader consume_Windows_ApplicationModel_Chat_IChatMessageChangeTracker<D>::GetChangeReader() const
{
    Windows::ApplicationModel::Chat::ChatMessageChangeReader value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageChangeTracker)->GetChangeReader(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Chat_IChatMessageChangeTracker<D>::Reset() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageChangeTracker)->Reset());
}

template <typename D> void consume_Windows_ApplicationModel_Chat_IChatMessageChangedDeferral<D>::Complete() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageChangedDeferral)->Complete());
}

template <typename D> Windows::ApplicationModel::Chat::ChatMessageChangedDeferral consume_Windows_ApplicationModel_Chat_IChatMessageChangedEventArgs<D>::GetDeferral() const
{
    Windows::ApplicationModel::Chat::ChatMessageChangedDeferral result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageChangedEventArgs)->GetDeferral(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<hstring> consume_Windows_ApplicationModel_Chat_IChatMessageManager2Statics<D>::RegisterTransportAsync() const
{
    Windows::Foundation::IAsyncOperation<hstring> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageManager2Statics)->RegisterTransportAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatMessageTransport> consume_Windows_ApplicationModel_Chat_IChatMessageManager2Statics<D>::GetTransportAsync(param::hstring const& transportId) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatMessageTransport> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageManager2Statics)->GetTransportAsync(get_abi(transportId), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Chat::ChatMessageTransport>> consume_Windows_ApplicationModel_Chat_IChatMessageManagerStatic<D>::GetTransportsAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Chat::ChatMessageTransport>> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageManagerStatic)->GetTransportsAsync(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatMessageStore> consume_Windows_ApplicationModel_Chat_IChatMessageManagerStatic<D>::RequestStoreAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatMessageStore> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageManagerStatic)->RequestStoreAsync(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Chat_IChatMessageManagerStatic<D>::ShowComposeSmsMessageAsync(Windows::ApplicationModel::Chat::ChatMessage const& message) const
{
    Windows::Foundation::IAsyncAction value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageManagerStatic)->ShowComposeSmsMessageAsync(get_abi(message), put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Chat_IChatMessageManagerStatic<D>::ShowSmsSettings() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageManagerStatic)->ShowSmsSettings());
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatSyncManager> consume_Windows_ApplicationModel_Chat_IChatMessageManagerStatics3<D>::RequestSyncManagerAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatSyncManager> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageManagerStatics3)->RequestSyncManagerAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Chat::ChatMessage consume_Windows_ApplicationModel_Chat_IChatMessageNotificationTriggerDetails<D>::ChatMessage() const
{
    Windows::ApplicationModel::Chat::ChatMessage value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageNotificationTriggerDetails)->get_ChatMessage(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Chat_IChatMessageNotificationTriggerDetails2<D>::ShouldDisplayToast() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageNotificationTriggerDetails2)->get_ShouldDisplayToast(&result));
    return result;
}

template <typename D> bool consume_Windows_ApplicationModel_Chat_IChatMessageNotificationTriggerDetails2<D>::ShouldUpdateDetailText() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageNotificationTriggerDetails2)->get_ShouldUpdateDetailText(&result));
    return result;
}

template <typename D> bool consume_Windows_ApplicationModel_Chat_IChatMessageNotificationTriggerDetails2<D>::ShouldUpdateBadge() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageNotificationTriggerDetails2)->get_ShouldUpdateBadge(&result));
    return result;
}

template <typename D> bool consume_Windows_ApplicationModel_Chat_IChatMessageNotificationTriggerDetails2<D>::ShouldUpdateActionCenter() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageNotificationTriggerDetails2)->get_ShouldUpdateActionCenter(&result));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Chat::ChatMessage>> consume_Windows_ApplicationModel_Chat_IChatMessageReader<D>::ReadBatchAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Chat::ChatMessage>> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageReader)->ReadBatchAsync(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Chat::ChatMessage>> consume_Windows_ApplicationModel_Chat_IChatMessageReader2<D>::ReadBatchAsync(int32_t count) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Chat::ChatMessage>> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageReader2)->ReadBatchWithCountAsync(count, put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Chat::ChatMessageChangeTracker consume_Windows_ApplicationModel_Chat_IChatMessageStore<D>::ChangeTracker() const
{
    Windows::ApplicationModel::Chat::ChatMessageChangeTracker value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageStore)->get_ChangeTracker(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Chat_IChatMessageStore<D>::DeleteMessageAsync(param::hstring const& localMessageId) const
{
    Windows::Foundation::IAsyncAction value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageStore)->DeleteMessageAsync(get_abi(localMessageId), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Chat_IChatMessageStore<D>::DownloadMessageAsync(param::hstring const& localChatMessageId) const
{
    Windows::Foundation::IAsyncAction value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageStore)->DownloadMessageAsync(get_abi(localChatMessageId), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatMessage> consume_Windows_ApplicationModel_Chat_IChatMessageStore<D>::GetMessageAsync(param::hstring const& localChatMessageId) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatMessage> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageStore)->GetMessageAsync(get_abi(localChatMessageId), put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Chat::ChatMessageReader consume_Windows_ApplicationModel_Chat_IChatMessageStore<D>::GetMessageReader() const
{
    Windows::ApplicationModel::Chat::ChatMessageReader value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageStore)->GetMessageReader1(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Chat::ChatMessageReader consume_Windows_ApplicationModel_Chat_IChatMessageStore<D>::GetMessageReader(Windows::Foundation::TimeSpan const& recentTimeLimit) const
{
    Windows::ApplicationModel::Chat::ChatMessageReader value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageStore)->GetMessageReader2(get_abi(recentTimeLimit), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Chat_IChatMessageStore<D>::MarkMessageReadAsync(param::hstring const& localChatMessageId) const
{
    Windows::Foundation::IAsyncAction value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageStore)->MarkMessageReadAsync(get_abi(localChatMessageId), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Chat_IChatMessageStore<D>::RetrySendMessageAsync(param::hstring const& localChatMessageId) const
{
    Windows::Foundation::IAsyncAction value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageStore)->RetrySendMessageAsync(get_abi(localChatMessageId), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Chat_IChatMessageStore<D>::SendMessageAsync(Windows::ApplicationModel::Chat::ChatMessage const& chatMessage) const
{
    Windows::Foundation::IAsyncAction value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageStore)->SendMessageAsync(get_abi(chatMessage), put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Chat::ChatMessageValidationResult consume_Windows_ApplicationModel_Chat_IChatMessageStore<D>::ValidateMessage(Windows::ApplicationModel::Chat::ChatMessage const& chatMessage) const
{
    Windows::ApplicationModel::Chat::ChatMessageValidationResult value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageStore)->ValidateMessage(get_abi(chatMessage), put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Chat_IChatMessageStore<D>::MessageChanged(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Chat::ChatMessageStore, Windows::ApplicationModel::Chat::ChatMessageChangedEventArgs> const& value) const
{
    winrt::event_token returnValue{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageStore)->add_MessageChanged(get_abi(value), put_abi(returnValue)));
    return returnValue;
}

template <typename D> typename consume_Windows_ApplicationModel_Chat_IChatMessageStore<D>::MessageChanged_revoker consume_Windows_ApplicationModel_Chat_IChatMessageStore<D>::MessageChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Chat::ChatMessageStore, Windows::ApplicationModel::Chat::ChatMessageChangedEventArgs> const& value) const
{
    return impl::make_event_revoker<D, MessageChanged_revoker>(this, MessageChanged(value));
}

template <typename D> void consume_Windows_ApplicationModel_Chat_IChatMessageStore<D>::MessageChanged(winrt::event_token const& value) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageStore)->remove_MessageChanged(get_abi(value)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatMessage> consume_Windows_ApplicationModel_Chat_IChatMessageStore2<D>::ForwardMessageAsync(param::hstring const& localChatMessageId, param::async_iterable<hstring> const& addresses) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatMessage> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageStore2)->ForwardMessageAsync(get_abi(localChatMessageId), get_abi(addresses), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatConversation> consume_Windows_ApplicationModel_Chat_IChatMessageStore2<D>::GetConversationAsync(param::hstring const& conversationId) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatConversation> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageStore2)->GetConversationAsync(get_abi(conversationId), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatConversation> consume_Windows_ApplicationModel_Chat_IChatMessageStore2<D>::GetConversationAsync(param::hstring const& conversationId, param::async_iterable<hstring> const& transportIds) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatConversation> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageStore2)->GetConversationForTransportsAsync(get_abi(conversationId), get_abi(transportIds), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatConversation> consume_Windows_ApplicationModel_Chat_IChatMessageStore2<D>::GetConversationFromThreadingInfoAsync(Windows::ApplicationModel::Chat::ChatConversationThreadingInfo const& threadingInfo) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatConversation> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageStore2)->GetConversationFromThreadingInfoAsync(get_abi(threadingInfo), put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Chat::ChatConversationReader consume_Windows_ApplicationModel_Chat_IChatMessageStore2<D>::GetConversationReader() const
{
    Windows::ApplicationModel::Chat::ChatConversationReader result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageStore2)->GetConversationReader(put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Chat::ChatConversationReader consume_Windows_ApplicationModel_Chat_IChatMessageStore2<D>::GetConversationReader(param::iterable<hstring> const& transportIds) const
{
    Windows::ApplicationModel::Chat::ChatConversationReader result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageStore2)->GetConversationForTransportsReader(get_abi(transportIds), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatMessage> consume_Windows_ApplicationModel_Chat_IChatMessageStore2<D>::GetMessageByRemoteIdAsync(param::hstring const& transportId, param::hstring const& remoteId) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatMessage> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageStore2)->GetMessageByRemoteIdAsync(get_abi(transportId), get_abi(remoteId), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<int32_t> consume_Windows_ApplicationModel_Chat_IChatMessageStore2<D>::GetUnseenCountAsync() const
{
    Windows::Foundation::IAsyncOperation<int32_t> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageStore2)->GetUnseenCountAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<int32_t> consume_Windows_ApplicationModel_Chat_IChatMessageStore2<D>::GetUnseenCountAsync(param::async_iterable<hstring> const& transportIds) const
{
    Windows::Foundation::IAsyncOperation<int32_t> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageStore2)->GetUnseenCountForTransportsReaderAsync(get_abi(transportIds), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Chat_IChatMessageStore2<D>::MarkAsSeenAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageStore2)->MarkAsSeenAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Chat_IChatMessageStore2<D>::MarkAsSeenAsync(param::async_iterable<hstring> const& transportIds) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageStore2)->MarkAsSeenForTransportsAsync(get_abi(transportIds), put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Chat::ChatSearchReader consume_Windows_ApplicationModel_Chat_IChatMessageStore2<D>::GetSearchReader(Windows::ApplicationModel::Chat::ChatQueryOptions const& value) const
{
    Windows::ApplicationModel::Chat::ChatSearchReader result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageStore2)->GetSearchReader(get_abi(value), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Chat_IChatMessageStore2<D>::SaveMessageAsync(Windows::ApplicationModel::Chat::ChatMessage const& chatMessage) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageStore2)->SaveMessageAsync(get_abi(chatMessage), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_ApplicationModel_Chat_IChatMessageStore2<D>::TryCancelDownloadMessageAsync(param::hstring const& localChatMessageId) const
{
    Windows::Foundation::IAsyncOperation<bool> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageStore2)->TryCancelDownloadMessageAsync(get_abi(localChatMessageId), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_ApplicationModel_Chat_IChatMessageStore2<D>::TryCancelSendMessageAsync(param::hstring const& localChatMessageId) const
{
    Windows::Foundation::IAsyncOperation<bool> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageStore2)->TryCancelSendMessageAsync(get_abi(localChatMessageId), put_abi(result)));
    return result;
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Chat_IChatMessageStore2<D>::StoreChanged(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Chat::ChatMessageStore, Windows::ApplicationModel::Chat::ChatMessageStoreChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageStore2)->add_StoreChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Chat_IChatMessageStore2<D>::StoreChanged_revoker consume_Windows_ApplicationModel_Chat_IChatMessageStore2<D>::StoreChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Chat::ChatMessageStore, Windows::ApplicationModel::Chat::ChatMessageStoreChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, StoreChanged_revoker>(this, StoreChanged(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Chat_IChatMessageStore2<D>::StoreChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageStore2)->remove_StoreChanged(get_abi(token)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatMessage> consume_Windows_ApplicationModel_Chat_IChatMessageStore3<D>::GetMessageBySyncIdAsync(param::hstring const& syncId) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatMessage> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageStore3)->GetMessageBySyncIdAsync(get_abi(syncId), put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_ApplicationModel_Chat_IChatMessageStoreChangedEventArgs<D>::Id() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageStoreChangedEventArgs)->get_Id(put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Chat::ChatStoreChangedEventKind consume_Windows_ApplicationModel_Chat_IChatMessageStoreChangedEventArgs<D>::Kind() const
{
    Windows::ApplicationModel::Chat::ChatStoreChangedEventKind result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageStoreChangedEventArgs)->get_Kind(put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_ApplicationModel_Chat_IChatMessageTransport<D>::IsAppSetAsNotificationProvider() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageTransport)->get_IsAppSetAsNotificationProvider(&value));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Chat_IChatMessageTransport<D>::IsActive() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageTransport)->get_IsActive(&value));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Chat_IChatMessageTransport<D>::TransportFriendlyName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageTransport)->get_TransportFriendlyName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Chat_IChatMessageTransport<D>::TransportId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageTransport)->get_TransportId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Chat_IChatMessageTransport<D>::RequestSetAsNotificationProviderAsync() const
{
    Windows::Foundation::IAsyncAction value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageTransport)->RequestSetAsNotificationProviderAsync(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Chat::ChatMessageTransportConfiguration consume_Windows_ApplicationModel_Chat_IChatMessageTransport2<D>::Configuration() const
{
    Windows::ApplicationModel::Chat::ChatMessageTransportConfiguration result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageTransport2)->get_Configuration(put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Chat::ChatMessageTransportKind consume_Windows_ApplicationModel_Chat_IChatMessageTransport2<D>::TransportKind() const
{
    Windows::ApplicationModel::Chat::ChatMessageTransportKind result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageTransport2)->get_TransportKind(put_abi(result)));
    return result;
}

template <typename D> int32_t consume_Windows_ApplicationModel_Chat_IChatMessageTransportConfiguration<D>::MaxAttachmentCount() const
{
    int32_t result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageTransportConfiguration)->get_MaxAttachmentCount(&result));
    return result;
}

template <typename D> int32_t consume_Windows_ApplicationModel_Chat_IChatMessageTransportConfiguration<D>::MaxMessageSizeInKilobytes() const
{
    int32_t result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageTransportConfiguration)->get_MaxMessageSizeInKilobytes(&result));
    return result;
}

template <typename D> int32_t consume_Windows_ApplicationModel_Chat_IChatMessageTransportConfiguration<D>::MaxRecipientCount() const
{
    int32_t result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageTransportConfiguration)->get_MaxRecipientCount(&result));
    return result;
}

template <typename D> Windows::Media::MediaProperties::MediaEncodingProfile consume_Windows_ApplicationModel_Chat_IChatMessageTransportConfiguration<D>::SupportedVideoFormat() const
{
    Windows::Media::MediaProperties::MediaEncodingProfile result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageTransportConfiguration)->get_SupportedVideoFormat(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable> consume_Windows_ApplicationModel_Chat_IChatMessageTransportConfiguration<D>::ExtendedProperties() const
{
    Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageTransportConfiguration)->get_ExtendedProperties(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IReference<uint32_t> consume_Windows_ApplicationModel_Chat_IChatMessageValidationResult<D>::MaxPartCount() const
{
    Windows::Foundation::IReference<uint32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageValidationResult)->get_MaxPartCount(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<uint32_t> consume_Windows_ApplicationModel_Chat_IChatMessageValidationResult<D>::PartCount() const
{
    Windows::Foundation::IReference<uint32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageValidationResult)->get_PartCount(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<uint32_t> consume_Windows_ApplicationModel_Chat_IChatMessageValidationResult<D>::RemainingCharacterCountInPart() const
{
    Windows::Foundation::IReference<uint32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageValidationResult)->get_RemainingCharacterCountInPart(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Chat::ChatMessageValidationStatus consume_Windows_ApplicationModel_Chat_IChatMessageValidationResult<D>::Status() const
{
    Windows::ApplicationModel::Chat::ChatMessageValidationStatus value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatMessageValidationResult)->get_Status(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Chat_IChatQueryOptions<D>::SearchString() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatQueryOptions)->get_SearchString(put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_ApplicationModel_Chat_IChatQueryOptions<D>::SearchString(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatQueryOptions)->put_SearchString(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Chat_IChatRecipientDeliveryInfo<D>::TransportAddress() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatRecipientDeliveryInfo)->get_TransportAddress(put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_ApplicationModel_Chat_IChatRecipientDeliveryInfo<D>::TransportAddress(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatRecipientDeliveryInfo)->put_TransportAddress(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::DateTime> consume_Windows_ApplicationModel_Chat_IChatRecipientDeliveryInfo<D>::DeliveryTime() const
{
    Windows::Foundation::IReference<Windows::Foundation::DateTime> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatRecipientDeliveryInfo)->get_DeliveryTime(put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_ApplicationModel_Chat_IChatRecipientDeliveryInfo<D>::DeliveryTime(optional<Windows::Foundation::DateTime> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatRecipientDeliveryInfo)->put_DeliveryTime(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::DateTime> consume_Windows_ApplicationModel_Chat_IChatRecipientDeliveryInfo<D>::ReadTime() const
{
    Windows::Foundation::IReference<Windows::Foundation::DateTime> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatRecipientDeliveryInfo)->get_ReadTime(put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_ApplicationModel_Chat_IChatRecipientDeliveryInfo<D>::ReadTime(optional<Windows::Foundation::DateTime> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatRecipientDeliveryInfo)->put_ReadTime(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::Chat::ChatTransportErrorCodeCategory consume_Windows_ApplicationModel_Chat_IChatRecipientDeliveryInfo<D>::TransportErrorCodeCategory() const
{
    Windows::ApplicationModel::Chat::ChatTransportErrorCodeCategory result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatRecipientDeliveryInfo)->get_TransportErrorCodeCategory(put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Chat::ChatTransportInterpretedErrorCode consume_Windows_ApplicationModel_Chat_IChatRecipientDeliveryInfo<D>::TransportInterpretedErrorCode() const
{
    Windows::ApplicationModel::Chat::ChatTransportInterpretedErrorCode result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatRecipientDeliveryInfo)->get_TransportInterpretedErrorCode(put_abi(result)));
    return result;
}

template <typename D> int32_t consume_Windows_ApplicationModel_Chat_IChatRecipientDeliveryInfo<D>::TransportErrorCode() const
{
    int32_t result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatRecipientDeliveryInfo)->get_TransportErrorCode(&result));
    return result;
}

template <typename D> bool consume_Windows_ApplicationModel_Chat_IChatRecipientDeliveryInfo<D>::IsErrorPermanent() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatRecipientDeliveryInfo)->get_IsErrorPermanent(&result));
    return result;
}

template <typename D> Windows::ApplicationModel::Chat::ChatMessageStatus consume_Windows_ApplicationModel_Chat_IChatRecipientDeliveryInfo<D>::Status() const
{
    Windows::ApplicationModel::Chat::ChatMessageStatus result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatRecipientDeliveryInfo)->get_Status(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Chat::IChatItem>> consume_Windows_ApplicationModel_Chat_IChatSearchReader<D>::ReadBatchAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Chat::IChatItem>> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatSearchReader)->ReadBatchAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Chat::IChatItem>> consume_Windows_ApplicationModel_Chat_IChatSearchReader<D>::ReadBatchAsync(int32_t count) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Chat::IChatItem>> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatSearchReader)->ReadBatchWithCountAsync(count, put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_ApplicationModel_Chat_IChatSyncConfiguration<D>::IsSyncEnabled() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatSyncConfiguration)->get_IsSyncEnabled(&result));
    return result;
}

template <typename D> void consume_Windows_ApplicationModel_Chat_IChatSyncConfiguration<D>::IsSyncEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatSyncConfiguration)->put_IsSyncEnabled(value));
}

template <typename D> Windows::ApplicationModel::Chat::ChatRestoreHistorySpan consume_Windows_ApplicationModel_Chat_IChatSyncConfiguration<D>::RestoreHistorySpan() const
{
    Windows::ApplicationModel::Chat::ChatRestoreHistorySpan result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatSyncConfiguration)->get_RestoreHistorySpan(put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_ApplicationModel_Chat_IChatSyncConfiguration<D>::RestoreHistorySpan(Windows::ApplicationModel::Chat::ChatRestoreHistorySpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatSyncConfiguration)->put_RestoreHistorySpan(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::Chat::ChatSyncConfiguration consume_Windows_ApplicationModel_Chat_IChatSyncManager<D>::Configuration() const
{
    Windows::ApplicationModel::Chat::ChatSyncConfiguration result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatSyncManager)->get_Configuration(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Chat_IChatSyncManager<D>::AssociateAccountAsync(Windows::Security::Credentials::WebAccount const& webAccount) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatSyncManager)->AssociateAccountAsync(get_abi(webAccount), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Chat_IChatSyncManager<D>::UnassociateAccountAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatSyncManager)->UnassociateAccountAsync(put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_ApplicationModel_Chat_IChatSyncManager<D>::IsAccountAssociated(Windows::Security::Credentials::WebAccount const& webAccount) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatSyncManager)->IsAccountAssociated(get_abi(webAccount), &result));
    return result;
}

template <typename D> void consume_Windows_ApplicationModel_Chat_IChatSyncManager<D>::StartSync() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatSyncManager)->StartSync());
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Chat_IChatSyncManager<D>::SetConfigurationAsync(Windows::ApplicationModel::Chat::ChatSyncConfiguration const& configuration) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IChatSyncManager)->SetConfigurationAsync(get_abi(configuration), put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_ApplicationModel_Chat_IRcsEndUserMessage<D>::TransportId() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IRcsEndUserMessage)->get_TransportId(put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_ApplicationModel_Chat_IRcsEndUserMessage<D>::Title() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IRcsEndUserMessage)->get_Title(put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_ApplicationModel_Chat_IRcsEndUserMessage<D>::Text() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IRcsEndUserMessage)->get_Text(put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_ApplicationModel_Chat_IRcsEndUserMessage<D>::IsPinRequired() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IRcsEndUserMessage)->get_IsPinRequired(&result));
    return result;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Chat::RcsEndUserMessageAction> consume_Windows_ApplicationModel_Chat_IRcsEndUserMessage<D>::Actions() const
{
    Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Chat::RcsEndUserMessageAction> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IRcsEndUserMessage)->get_Actions(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Chat_IRcsEndUserMessage<D>::SendResponseAsync(Windows::ApplicationModel::Chat::RcsEndUserMessageAction const& action) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IRcsEndUserMessage)->SendResponseAsync(get_abi(action), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Chat_IRcsEndUserMessage<D>::SendResponseWithPinAsync(Windows::ApplicationModel::Chat::RcsEndUserMessageAction const& action, param::hstring const& pin) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IRcsEndUserMessage)->SendResponseWithPinAsync(get_abi(action), get_abi(pin), put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_ApplicationModel_Chat_IRcsEndUserMessageAction<D>::Label() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IRcsEndUserMessageAction)->get_Label(put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_ApplicationModel_Chat_IRcsEndUserMessageAvailableEventArgs<D>::IsMessageAvailable() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IRcsEndUserMessageAvailableEventArgs)->get_IsMessageAvailable(&result));
    return result;
}

template <typename D> Windows::ApplicationModel::Chat::RcsEndUserMessage consume_Windows_ApplicationModel_Chat_IRcsEndUserMessageAvailableEventArgs<D>::Message() const
{
    Windows::ApplicationModel::Chat::RcsEndUserMessage result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IRcsEndUserMessageAvailableEventArgs)->get_Message(put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_ApplicationModel_Chat_IRcsEndUserMessageAvailableTriggerDetails<D>::Title() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IRcsEndUserMessageAvailableTriggerDetails)->get_Title(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Chat_IRcsEndUserMessageAvailableTriggerDetails<D>::Text() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IRcsEndUserMessageAvailableTriggerDetails)->get_Text(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Chat_IRcsEndUserMessageManager<D>::MessageAvailableChanged(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Chat::RcsEndUserMessageManager, Windows::ApplicationModel::Chat::RcsEndUserMessageAvailableEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IRcsEndUserMessageManager)->add_MessageAvailableChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Chat_IRcsEndUserMessageManager<D>::MessageAvailableChanged_revoker consume_Windows_ApplicationModel_Chat_IRcsEndUserMessageManager<D>::MessageAvailableChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Chat::RcsEndUserMessageManager, Windows::ApplicationModel::Chat::RcsEndUserMessageAvailableEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, MessageAvailableChanged_revoker>(this, MessageAvailableChanged(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Chat_IRcsEndUserMessageManager<D>::MessageAvailableChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Chat::IRcsEndUserMessageManager)->remove_MessageAvailableChanged(get_abi(token)));
}

template <typename D> Windows::ApplicationModel::Chat::RcsEndUserMessageManager consume_Windows_ApplicationModel_Chat_IRcsManagerStatics<D>::GetEndUserMessageManager() const
{
    Windows::ApplicationModel::Chat::RcsEndUserMessageManager result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IRcsManagerStatics)->GetEndUserMessageManager(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Chat::RcsTransport>> consume_Windows_ApplicationModel_Chat_IRcsManagerStatics<D>::GetTransportsAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Chat::RcsTransport>> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IRcsManagerStatics)->GetTransportsAsync(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::RcsTransport> consume_Windows_ApplicationModel_Chat_IRcsManagerStatics<D>::GetTransportAsync(param::hstring const& transportId) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::RcsTransport> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IRcsManagerStatics)->GetTransportAsync(get_abi(transportId), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Chat_IRcsManagerStatics<D>::LeaveConversationAsync(Windows::ApplicationModel::Chat::ChatConversation const& conversation) const
{
    Windows::Foundation::IAsyncAction value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IRcsManagerStatics)->LeaveConversationAsync(get_abi(conversation), put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Chat_IRcsManagerStatics2<D>::TransportListChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IRcsManagerStatics2)->add_TransportListChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Chat_IRcsManagerStatics2<D>::TransportListChanged_revoker consume_Windows_ApplicationModel_Chat_IRcsManagerStatics2<D>::TransportListChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, TransportListChanged_revoker>(this, TransportListChanged(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Chat_IRcsManagerStatics2<D>::TransportListChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Chat::IRcsManagerStatics2)->remove_TransportListChanged(get_abi(token)));
}

template <typename D> Windows::ApplicationModel::Chat::RcsServiceKind consume_Windows_ApplicationModel_Chat_IRcsServiceKindSupportedChangedEventArgs<D>::ServiceKind() const
{
    Windows::ApplicationModel::Chat::RcsServiceKind result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IRcsServiceKindSupportedChangedEventArgs)->get_ServiceKind(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable> consume_Windows_ApplicationModel_Chat_IRcsTransport<D>::ExtendedProperties() const
{
    Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IRcsTransport)->get_ExtendedProperties(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Chat_IRcsTransport<D>::IsActive() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IRcsTransport)->get_IsActive(&value));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Chat_IRcsTransport<D>::TransportFriendlyName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IRcsTransport)->get_TransportFriendlyName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Chat_IRcsTransport<D>::TransportId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IRcsTransport)->get_TransportId(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Chat::RcsTransportConfiguration consume_Windows_ApplicationModel_Chat_IRcsTransport<D>::Configuration() const
{
    Windows::ApplicationModel::Chat::RcsTransportConfiguration result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IRcsTransport)->get_Configuration(put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_ApplicationModel_Chat_IRcsTransport<D>::IsStoreAndForwardEnabled(Windows::ApplicationModel::Chat::RcsServiceKind const& serviceKind) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IRcsTransport)->IsStoreAndForwardEnabled(get_abi(serviceKind), &result));
    return result;
}

template <typename D> bool consume_Windows_ApplicationModel_Chat_IRcsTransport<D>::IsServiceKindSupported(Windows::ApplicationModel::Chat::RcsServiceKind const& serviceKind) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IRcsTransport)->IsServiceKindSupported(get_abi(serviceKind), &result));
    return result;
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Chat_IRcsTransport<D>::ServiceKindSupportedChanged(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Chat::RcsTransport, Windows::ApplicationModel::Chat::RcsServiceKindSupportedChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IRcsTransport)->add_ServiceKindSupportedChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Chat_IRcsTransport<D>::ServiceKindSupportedChanged_revoker consume_Windows_ApplicationModel_Chat_IRcsTransport<D>::ServiceKindSupportedChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Chat::RcsTransport, Windows::ApplicationModel::Chat::RcsServiceKindSupportedChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ServiceKindSupportedChanged_revoker>(this, ServiceKindSupportedChanged(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Chat_IRcsTransport<D>::ServiceKindSupportedChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Chat::IRcsTransport)->remove_ServiceKindSupportedChanged(get_abi(token)));
}

template <typename D> int32_t consume_Windows_ApplicationModel_Chat_IRcsTransportConfiguration<D>::MaxAttachmentCount() const
{
    int32_t result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IRcsTransportConfiguration)->get_MaxAttachmentCount(&result));
    return result;
}

template <typename D> int32_t consume_Windows_ApplicationModel_Chat_IRcsTransportConfiguration<D>::MaxMessageSizeInKilobytes() const
{
    int32_t result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IRcsTransportConfiguration)->get_MaxMessageSizeInKilobytes(&result));
    return result;
}

template <typename D> int32_t consume_Windows_ApplicationModel_Chat_IRcsTransportConfiguration<D>::MaxGroupMessageSizeInKilobytes() const
{
    int32_t result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IRcsTransportConfiguration)->get_MaxGroupMessageSizeInKilobytes(&result));
    return result;
}

template <typename D> int32_t consume_Windows_ApplicationModel_Chat_IRcsTransportConfiguration<D>::MaxRecipientCount() const
{
    int32_t result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IRcsTransportConfiguration)->get_MaxRecipientCount(&result));
    return result;
}

template <typename D> int32_t consume_Windows_ApplicationModel_Chat_IRcsTransportConfiguration<D>::MaxFileSizeInKilobytes() const
{
    int32_t result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IRcsTransportConfiguration)->get_MaxFileSizeInKilobytes(&result));
    return result;
}

template <typename D> int32_t consume_Windows_ApplicationModel_Chat_IRcsTransportConfiguration<D>::WarningFileSizeInKilobytes() const
{
    int32_t result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IRcsTransportConfiguration)->get_WarningFileSizeInKilobytes(&result));
    return result;
}

template <typename D> hstring consume_Windows_ApplicationModel_Chat_IRemoteParticipantComposingChangedEventArgs<D>::TransportId() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IRemoteParticipantComposingChangedEventArgs)->get_TransportId(put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_ApplicationModel_Chat_IRemoteParticipantComposingChangedEventArgs<D>::ParticipantAddress() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IRemoteParticipantComposingChangedEventArgs)->get_ParticipantAddress(put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_ApplicationModel_Chat_IRemoteParticipantComposingChangedEventArgs<D>::IsComposing() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Chat::IRemoteParticipantComposingChangedEventArgs)->get_IsComposing(&result));
    return result;
}

template <typename D>
struct produce<D, Windows::ApplicationModel::Chat::IChatCapabilities> : produce_base<D, Windows::ApplicationModel::Chat::IChatCapabilities>
{
    int32_t WINRT_CALL get_IsOnline(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsOnline, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().IsOnline());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsChatCapable(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsChatCapable, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().IsChatCapable());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsFileTransferCapable(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsFileTransferCapable, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().IsFileTransferCapable());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsGeoLocationPushCapable(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsGeoLocationPushCapable, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().IsGeoLocationPushCapable());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsIntegratedMessagingCapable(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsIntegratedMessagingCapable, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().IsIntegratedMessagingCapable());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Chat::IChatCapabilitiesManagerStatics> : produce_base<D, Windows::ApplicationModel::Chat::IChatCapabilitiesManagerStatics>
{
    int32_t WINRT_CALL GetCachedCapabilitiesAsync(void* address, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCachedCapabilitiesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatCapabilities>), hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatCapabilities>>(this->shim().GetCachedCapabilitiesAsync(*reinterpret_cast<hstring const*>(&address)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetCapabilitiesFromNetworkAsync(void* address, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCapabilitiesFromNetworkAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatCapabilities>), hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatCapabilities>>(this->shim().GetCapabilitiesFromNetworkAsync(*reinterpret_cast<hstring const*>(&address)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Chat::IChatCapabilitiesManagerStatics2> : produce_base<D, Windows::ApplicationModel::Chat::IChatCapabilitiesManagerStatics2>
{
    int32_t WINRT_CALL GetCachedCapabilitiesForTransportAsync(void* address, void* transportId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCachedCapabilitiesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatCapabilities>), hstring const, hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatCapabilities>>(this->shim().GetCachedCapabilitiesAsync(*reinterpret_cast<hstring const*>(&address), *reinterpret_cast<hstring const*>(&transportId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetCapabilitiesFromNetworkForTransportAsync(void* address, void* transportId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCapabilitiesFromNetworkAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatCapabilities>), hstring const, hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatCapabilities>>(this->shim().GetCapabilitiesFromNetworkAsync(*reinterpret_cast<hstring const*>(&address), *reinterpret_cast<hstring const*>(&transportId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Chat::IChatConversation> : produce_base<D, Windows::ApplicationModel::Chat::IChatConversation>
{
    int32_t WINRT_CALL get_HasUnreadMessages(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HasUnreadMessages, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().HasUnreadMessages());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Id(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Id, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Subject(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Subject, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().Subject());
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

    int32_t WINRT_CALL get_IsConversationMuted(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsConversationMuted, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().IsConversationMuted());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsConversationMuted(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsConversationMuted, WINRT_WRAP(void), bool);
            this->shim().IsConversationMuted(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MostRecentMessageId(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MostRecentMessageId, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().MostRecentMessageId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Participants(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Participants, WINRT_WRAP(Windows::Foundation::Collections::IVector<hstring>));
            *result = detach_from<Windows::Foundation::Collections::IVector<hstring>>(this->shim().Participants());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ThreadingInfo(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ThreadingInfo, WINRT_WRAP(Windows::ApplicationModel::Chat::ChatConversationThreadingInfo));
            *result = detach_from<Windows::ApplicationModel::Chat::ChatConversationThreadingInfo>(this->shim().ThreadingInfo());
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

    int32_t WINRT_CALL GetMessageReader(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetMessageReader, WINRT_WRAP(Windows::ApplicationModel::Chat::ChatMessageReader));
            *result = detach_from<Windows::ApplicationModel::Chat::ChatMessageReader>(this->shim().GetMessageReader());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL MarkAllMessagesAsReadAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MarkMessagesAsReadAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().MarkMessagesAsReadAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL MarkMessagesAsReadAsync(Windows::Foundation::DateTime value, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MarkMessagesAsReadAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Foundation::DateTime const);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().MarkMessagesAsReadAsync(*reinterpret_cast<Windows::Foundation::DateTime const*>(&value)));
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

    int32_t WINRT_CALL NotifyLocalParticipantComposing(void* transportId, void* participantAddress, bool isComposing) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NotifyLocalParticipantComposing, WINRT_WRAP(void), hstring const&, hstring const&, bool);
            this->shim().NotifyLocalParticipantComposing(*reinterpret_cast<hstring const*>(&transportId), *reinterpret_cast<hstring const*>(&participantAddress), isComposing);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL NotifyRemoteParticipantComposing(void* transportId, void* participantAddress, bool isComposing) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NotifyRemoteParticipantComposing, WINRT_WRAP(void), hstring const&, hstring const&, bool);
            this->shim().NotifyRemoteParticipantComposing(*reinterpret_cast<hstring const*>(&transportId), *reinterpret_cast<hstring const*>(&participantAddress), isComposing);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_RemoteParticipantComposingChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoteParticipantComposingChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Chat::ChatConversation, Windows::ApplicationModel::Chat::RemoteParticipantComposingChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().RemoteParticipantComposingChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Chat::ChatConversation, Windows::ApplicationModel::Chat::RemoteParticipantComposingChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_RemoteParticipantComposingChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(RemoteParticipantComposingChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().RemoteParticipantComposingChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Chat::IChatConversation2> : produce_base<D, Windows::ApplicationModel::Chat::IChatConversation2>
{
    int32_t WINRT_CALL get_CanModifyParticipants(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanModifyParticipants, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().CanModifyParticipants());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CanModifyParticipants(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanModifyParticipants, WINRT_WRAP(void), bool);
            this->shim().CanModifyParticipants(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Chat::IChatConversationReader> : produce_base<D, Windows::ApplicationModel::Chat::IChatConversationReader>
{
    int32_t WINRT_CALL ReadBatchAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadBatchAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Chat::ChatConversation>>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Chat::ChatConversation>>>(this->shim().ReadBatchAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReadBatchWithCountAsync(int32_t count, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadBatchAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Chat::ChatConversation>>), int32_t);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Chat::ChatConversation>>>(this->shim().ReadBatchAsync(count));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Chat::IChatConversationThreadingInfo> : produce_base<D, Windows::ApplicationModel::Chat::IChatConversationThreadingInfo>
{
    int32_t WINRT_CALL get_ContactId(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContactId, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().ContactId());
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

    int32_t WINRT_CALL get_Custom(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Custom, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().Custom());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Custom(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Custom, WINRT_WRAP(void), hstring const&);
            this->shim().Custom(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ConversationId(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConversationId, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().ConversationId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ConversationId(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConversationId, WINRT_WRAP(void), hstring const&);
            this->shim().ConversationId(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Participants(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Participants, WINRT_WRAP(Windows::Foundation::Collections::IVector<hstring>));
            *result = detach_from<Windows::Foundation::Collections::IVector<hstring>>(this->shim().Participants());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Kind(Windows::ApplicationModel::Chat::ChatConversationThreadingKind* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Kind, WINRT_WRAP(Windows::ApplicationModel::Chat::ChatConversationThreadingKind));
            *result = detach_from<Windows::ApplicationModel::Chat::ChatConversationThreadingKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Kind(Windows::ApplicationModel::Chat::ChatConversationThreadingKind value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Kind, WINRT_WRAP(void), Windows::ApplicationModel::Chat::ChatConversationThreadingKind const&);
            this->shim().Kind(*reinterpret_cast<Windows::ApplicationModel::Chat::ChatConversationThreadingKind const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Chat::IChatItem> : produce_base<D, Windows::ApplicationModel::Chat::IChatItem>
{
    int32_t WINRT_CALL get_ItemKind(Windows::ApplicationModel::Chat::ChatItemKind* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ItemKind, WINRT_WRAP(Windows::ApplicationModel::Chat::ChatItemKind));
            *result = detach_from<Windows::ApplicationModel::Chat::ChatItemKind>(this->shim().ItemKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Chat::IChatMessage> : produce_base<D, Windows::ApplicationModel::Chat::IChatMessage>
{
    int32_t WINRT_CALL get_Attachments(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Attachments, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Chat::ChatMessageAttachment>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Chat::ChatMessageAttachment>>(this->shim().Attachments());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Body(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Body, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Body());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Body(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Body, WINRT_WRAP(void), hstring const&);
            this->shim().Body(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_From(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(From, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().From());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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

    int32_t WINRT_CALL get_IsForwardingDisabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsForwardingDisabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsForwardingDisabled());
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

    int32_t WINRT_CALL get_IsRead(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsRead, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsRead());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LocalTimestamp(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LocalTimestamp, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().LocalTimestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NetworkTimestamp(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NetworkTimestamp, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().NetworkTimestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Recipients(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Recipients, WINRT_WRAP(Windows::Foundation::Collections::IVector<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVector<hstring>>(this->shim().Recipients());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RecipientSendStatuses(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RecipientSendStatuses, WINRT_WRAP(Windows::Foundation::Collections::IMapView<hstring, Windows::ApplicationModel::Chat::ChatMessageStatus>));
            *value = detach_from<Windows::Foundation::Collections::IMapView<hstring, Windows::ApplicationModel::Chat::ChatMessageStatus>>(this->shim().RecipientSendStatuses());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Status(Windows::ApplicationModel::Chat::ChatMessageStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::ApplicationModel::Chat::ChatMessageStatus));
            *value = detach_from<Windows::ApplicationModel::Chat::ChatMessageStatus>(this->shim().Status());
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

    int32_t WINRT_CALL get_TransportFriendlyName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransportFriendlyName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().TransportFriendlyName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TransportId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransportId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().TransportId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TransportId(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransportId, WINRT_WRAP(void), hstring const&);
            this->shim().TransportId(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Chat::IChatMessage2> : produce_base<D, Windows::ApplicationModel::Chat::IChatMessage2>
{
    int32_t WINRT_CALL get_EstimatedDownloadSize(uint64_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EstimatedDownloadSize, WINRT_WRAP(uint64_t));
            *result = detach_from<uint64_t>(this->shim().EstimatedDownloadSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_EstimatedDownloadSize(uint64_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EstimatedDownloadSize, WINRT_WRAP(void), uint64_t);
            this->shim().EstimatedDownloadSize(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_From(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(From, WINRT_WRAP(void), hstring const&);
            this->shim().From(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsAutoReply(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsAutoReply, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().IsAutoReply());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsAutoReply(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsAutoReply, WINRT_WRAP(void), bool);
            this->shim().IsAutoReply(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsForwardingDisabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsForwardingDisabled, WINRT_WRAP(void), bool);
            this->shim().IsForwardingDisabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsReplyDisabled(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsReplyDisabled, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().IsReplyDisabled());
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

    int32_t WINRT_CALL put_IsRead(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsRead, WINRT_WRAP(void), bool);
            this->shim().IsRead(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsSeen(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSeen, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().IsSeen());
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

    int32_t WINRT_CALL get_IsSimMessage(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSimMessage, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().IsSimMessage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_LocalTimestamp(Windows::Foundation::DateTime value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LocalTimestamp, WINRT_WRAP(void), Windows::Foundation::DateTime const&);
            this->shim().LocalTimestamp(*reinterpret_cast<Windows::Foundation::DateTime const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MessageKind(Windows::ApplicationModel::Chat::ChatMessageKind* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MessageKind, WINRT_WRAP(Windows::ApplicationModel::Chat::ChatMessageKind));
            *result = detach_from<Windows::ApplicationModel::Chat::ChatMessageKind>(this->shim().MessageKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MessageKind(Windows::ApplicationModel::Chat::ChatMessageKind value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MessageKind, WINRT_WRAP(void), Windows::ApplicationModel::Chat::ChatMessageKind const&);
            this->shim().MessageKind(*reinterpret_cast<Windows::ApplicationModel::Chat::ChatMessageKind const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MessageOperatorKind(Windows::ApplicationModel::Chat::ChatMessageOperatorKind* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MessageOperatorKind, WINRT_WRAP(Windows::ApplicationModel::Chat::ChatMessageOperatorKind));
            *result = detach_from<Windows::ApplicationModel::Chat::ChatMessageOperatorKind>(this->shim().MessageOperatorKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MessageOperatorKind(Windows::ApplicationModel::Chat::ChatMessageOperatorKind value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MessageOperatorKind, WINRT_WRAP(void), Windows::ApplicationModel::Chat::ChatMessageOperatorKind const&);
            this->shim().MessageOperatorKind(*reinterpret_cast<Windows::ApplicationModel::Chat::ChatMessageOperatorKind const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_NetworkTimestamp(Windows::Foundation::DateTime value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NetworkTimestamp, WINRT_WRAP(void), Windows::Foundation::DateTime const&);
            this->shim().NetworkTimestamp(*reinterpret_cast<Windows::Foundation::DateTime const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsReceivedDuringQuietHours(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsReceivedDuringQuietHours, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().IsReceivedDuringQuietHours());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsReceivedDuringQuietHours(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsReceivedDuringQuietHours, WINRT_WRAP(void), bool);
            this->shim().IsReceivedDuringQuietHours(value);
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

    int32_t WINRT_CALL put_Status(Windows::ApplicationModel::Chat::ChatMessageStatus value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(void), Windows::ApplicationModel::Chat::ChatMessageStatus const&);
            this->shim().Status(*reinterpret_cast<Windows::ApplicationModel::Chat::ChatMessageStatus const*>(&value));
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

    int32_t WINRT_CALL get_ShouldSuppressNotification(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShouldSuppressNotification, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().ShouldSuppressNotification());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ShouldSuppressNotification(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShouldSuppressNotification, WINRT_WRAP(void), bool);
            this->shim().ShouldSuppressNotification(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ThreadingInfo(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ThreadingInfo, WINRT_WRAP(Windows::ApplicationModel::Chat::ChatConversationThreadingInfo));
            *result = detach_from<Windows::ApplicationModel::Chat::ChatConversationThreadingInfo>(this->shim().ThreadingInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ThreadingInfo(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ThreadingInfo, WINRT_WRAP(void), Windows::ApplicationModel::Chat::ChatConversationThreadingInfo const&);
            this->shim().ThreadingInfo(*reinterpret_cast<Windows::ApplicationModel::Chat::ChatConversationThreadingInfo const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RecipientsDeliveryInfos(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RecipientsDeliveryInfos, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Chat::ChatRecipientDeliveryInfo>));
            *result = detach_from<Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Chat::ChatRecipientDeliveryInfo>>(this->shim().RecipientsDeliveryInfos());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Chat::IChatMessage3> : produce_base<D, Windows::ApplicationModel::Chat::IChatMessage3>
{
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
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Chat::IChatMessage4> : produce_base<D, Windows::ApplicationModel::Chat::IChatMessage4>
{
    int32_t WINRT_CALL get_SyncId(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SyncId, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().SyncId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SyncId(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SyncId, WINRT_WRAP(void), hstring const&);
            this->shim().SyncId(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Chat::IChatMessageAttachment> : produce_base<D, Windows::ApplicationModel::Chat::IChatMessageAttachment>
{
    int32_t WINRT_CALL get_DataStreamReference(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DataStreamReference, WINRT_WRAP(Windows::Storage::Streams::IRandomAccessStreamReference));
            *value = detach_from<Windows::Storage::Streams::IRandomAccessStreamReference>(this->shim().DataStreamReference());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DataStreamReference(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DataStreamReference, WINRT_WRAP(void), Windows::Storage::Streams::IRandomAccessStreamReference const&);
            this->shim().DataStreamReference(*reinterpret_cast<Windows::Storage::Streams::IRandomAccessStreamReference const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_GroupId(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GroupId, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().GroupId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_GroupId(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GroupId, WINRT_WRAP(void), uint32_t);
            this->shim().GroupId(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MimeType(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MimeType, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().MimeType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MimeType(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MimeType, WINRT_WRAP(void), hstring const&);
            this->shim().MimeType(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Text(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Text, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Text());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Text(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Text, WINRT_WRAP(void), hstring const&);
            this->shim().Text(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Chat::IChatMessageAttachment2> : produce_base<D, Windows::ApplicationModel::Chat::IChatMessageAttachment2>
{
    int32_t WINRT_CALL get_Thumbnail(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Thumbnail, WINRT_WRAP(Windows::Storage::Streams::IRandomAccessStreamReference));
            *result = detach_from<Windows::Storage::Streams::IRandomAccessStreamReference>(this->shim().Thumbnail());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Thumbnail(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Thumbnail, WINRT_WRAP(void), Windows::Storage::Streams::IRandomAccessStreamReference const&);
            this->shim().Thumbnail(*reinterpret_cast<Windows::Storage::Streams::IRandomAccessStreamReference const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TransferProgress(double* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransferProgress, WINRT_WRAP(double));
            *result = detach_from<double>(this->shim().TransferProgress());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TransferProgress(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransferProgress, WINRT_WRAP(void), double);
            this->shim().TransferProgress(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OriginalFileName(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OriginalFileName, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().OriginalFileName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_OriginalFileName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OriginalFileName, WINRT_WRAP(void), hstring const&);
            this->shim().OriginalFileName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Chat::IChatMessageAttachmentFactory> : produce_base<D, Windows::ApplicationModel::Chat::IChatMessageAttachmentFactory>
{
    int32_t WINRT_CALL CreateChatMessageAttachment(void* mimeType, void* dataStreamReference, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateChatMessageAttachment, WINRT_WRAP(Windows::ApplicationModel::Chat::ChatMessageAttachment), hstring const&, Windows::Storage::Streams::IRandomAccessStreamReference const&);
            *value = detach_from<Windows::ApplicationModel::Chat::ChatMessageAttachment>(this->shim().CreateChatMessageAttachment(*reinterpret_cast<hstring const*>(&mimeType), *reinterpret_cast<Windows::Storage::Streams::IRandomAccessStreamReference const*>(&dataStreamReference)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Chat::IChatMessageBlockingStatic> : produce_base<D, Windows::ApplicationModel::Chat::IChatMessageBlockingStatic>
{
    int32_t WINRT_CALL MarkMessageAsBlockedAsync(void* localChatMessageId, bool blocked, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MarkMessageAsBlockedAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), hstring const, bool);
            *value = detach_from<Windows::Foundation::IAsyncAction>(this->shim().MarkMessageAsBlockedAsync(*reinterpret_cast<hstring const*>(&localChatMessageId), blocked));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Chat::IChatMessageChange> : produce_base<D, Windows::ApplicationModel::Chat::IChatMessageChange>
{
    int32_t WINRT_CALL get_ChangeType(Windows::ApplicationModel::Chat::ChatMessageChangeType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChangeType, WINRT_WRAP(Windows::ApplicationModel::Chat::ChatMessageChangeType));
            *value = detach_from<Windows::ApplicationModel::Chat::ChatMessageChangeType>(this->shim().ChangeType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Message(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Message, WINRT_WRAP(Windows::ApplicationModel::Chat::ChatMessage));
            *value = detach_from<Windows::ApplicationModel::Chat::ChatMessage>(this->shim().Message());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Chat::IChatMessageChangeReader> : produce_base<D, Windows::ApplicationModel::Chat::IChatMessageChangeReader>
{
    int32_t WINRT_CALL AcceptChanges() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AcceptChanges, WINRT_WRAP(void));
            this->shim().AcceptChanges();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AcceptChangesThrough(void* lastChangeToAcknowledge) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AcceptChangesThrough, WINRT_WRAP(void), Windows::ApplicationModel::Chat::ChatMessageChange const&);
            this->shim().AcceptChangesThrough(*reinterpret_cast<Windows::ApplicationModel::Chat::ChatMessageChange const*>(&lastChangeToAcknowledge));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReadBatchAsync(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadBatchAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Chat::ChatMessageChange>>));
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Chat::ChatMessageChange>>>(this->shim().ReadBatchAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Chat::IChatMessageChangeTracker> : produce_base<D, Windows::ApplicationModel::Chat::IChatMessageChangeTracker>
{
    int32_t WINRT_CALL Enable() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Enable, WINRT_WRAP(void));
            this->shim().Enable();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetChangeReader(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetChangeReader, WINRT_WRAP(Windows::ApplicationModel::Chat::ChatMessageChangeReader));
            *value = detach_from<Windows::ApplicationModel::Chat::ChatMessageChangeReader>(this->shim().GetChangeReader());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Reset() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Reset, WINRT_WRAP(void));
            this->shim().Reset();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Chat::IChatMessageChangedDeferral> : produce_base<D, Windows::ApplicationModel::Chat::IChatMessageChangedDeferral>
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
struct produce<D, Windows::ApplicationModel::Chat::IChatMessageChangedEventArgs> : produce_base<D, Windows::ApplicationModel::Chat::IChatMessageChangedEventArgs>
{
    int32_t WINRT_CALL GetDeferral(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeferral, WINRT_WRAP(Windows::ApplicationModel::Chat::ChatMessageChangedDeferral));
            *result = detach_from<Windows::ApplicationModel::Chat::ChatMessageChangedDeferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Chat::IChatMessageManager2Statics> : produce_base<D, Windows::ApplicationModel::Chat::IChatMessageManager2Statics>
{
    int32_t WINRT_CALL RegisterTransportAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RegisterTransportAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<hstring>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<hstring>>(this->shim().RegisterTransportAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetTransportAsync(void* transportId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetTransportAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatMessageTransport>), hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatMessageTransport>>(this->shim().GetTransportAsync(*reinterpret_cast<hstring const*>(&transportId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Chat::IChatMessageManagerStatic> : produce_base<D, Windows::ApplicationModel::Chat::IChatMessageManagerStatic>
{
    int32_t WINRT_CALL GetTransportsAsync(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetTransportsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Chat::ChatMessageTransport>>));
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Chat::ChatMessageTransport>>>(this->shim().GetTransportsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestStoreAsync(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestStoreAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatMessageStore>));
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatMessageStore>>(this->shim().RequestStoreAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ShowComposeSmsMessageAsync(void* message, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowComposeSmsMessageAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::ApplicationModel::Chat::ChatMessage const);
            *value = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ShowComposeSmsMessageAsync(*reinterpret_cast<Windows::ApplicationModel::Chat::ChatMessage const*>(&message)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ShowSmsSettings() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowSmsSettings, WINRT_WRAP(void));
            this->shim().ShowSmsSettings();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Chat::IChatMessageManagerStatics3> : produce_base<D, Windows::ApplicationModel::Chat::IChatMessageManagerStatics3>
{
    int32_t WINRT_CALL RequestSyncManagerAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestSyncManagerAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatSyncManager>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatSyncManager>>(this->shim().RequestSyncManagerAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Chat::IChatMessageNotificationTriggerDetails> : produce_base<D, Windows::ApplicationModel::Chat::IChatMessageNotificationTriggerDetails>
{
    int32_t WINRT_CALL get_ChatMessage(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChatMessage, WINRT_WRAP(Windows::ApplicationModel::Chat::ChatMessage));
            *value = detach_from<Windows::ApplicationModel::Chat::ChatMessage>(this->shim().ChatMessage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Chat::IChatMessageNotificationTriggerDetails2> : produce_base<D, Windows::ApplicationModel::Chat::IChatMessageNotificationTriggerDetails2>
{
    int32_t WINRT_CALL get_ShouldDisplayToast(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShouldDisplayToast, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().ShouldDisplayToast());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ShouldUpdateDetailText(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShouldUpdateDetailText, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().ShouldUpdateDetailText());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ShouldUpdateBadge(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShouldUpdateBadge, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().ShouldUpdateBadge());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ShouldUpdateActionCenter(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShouldUpdateActionCenter, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().ShouldUpdateActionCenter());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Chat::IChatMessageReader> : produce_base<D, Windows::ApplicationModel::Chat::IChatMessageReader>
{
    int32_t WINRT_CALL ReadBatchAsync(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadBatchAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Chat::ChatMessage>>));
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Chat::ChatMessage>>>(this->shim().ReadBatchAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Chat::IChatMessageReader2> : produce_base<D, Windows::ApplicationModel::Chat::IChatMessageReader2>
{
    int32_t WINRT_CALL ReadBatchWithCountAsync(int32_t count, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadBatchAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Chat::ChatMessage>>), int32_t);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Chat::ChatMessage>>>(this->shim().ReadBatchAsync(count));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Chat::IChatMessageStore> : produce_base<D, Windows::ApplicationModel::Chat::IChatMessageStore>
{
    int32_t WINRT_CALL get_ChangeTracker(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChangeTracker, WINRT_WRAP(Windows::ApplicationModel::Chat::ChatMessageChangeTracker));
            *value = detach_from<Windows::ApplicationModel::Chat::ChatMessageChangeTracker>(this->shim().ChangeTracker());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DeleteMessageAsync(void* localMessageId, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeleteMessageAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), hstring const);
            *value = detach_from<Windows::Foundation::IAsyncAction>(this->shim().DeleteMessageAsync(*reinterpret_cast<hstring const*>(&localMessageId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DownloadMessageAsync(void* localChatMessageId, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DownloadMessageAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), hstring const);
            *value = detach_from<Windows::Foundation::IAsyncAction>(this->shim().DownloadMessageAsync(*reinterpret_cast<hstring const*>(&localChatMessageId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetMessageAsync(void* localChatMessageId, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetMessageAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatMessage>), hstring const);
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatMessage>>(this->shim().GetMessageAsync(*reinterpret_cast<hstring const*>(&localChatMessageId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetMessageReader1(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetMessageReader, WINRT_WRAP(Windows::ApplicationModel::Chat::ChatMessageReader));
            *value = detach_from<Windows::ApplicationModel::Chat::ChatMessageReader>(this->shim().GetMessageReader());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetMessageReader2(Windows::Foundation::TimeSpan recentTimeLimit, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetMessageReader, WINRT_WRAP(Windows::ApplicationModel::Chat::ChatMessageReader), Windows::Foundation::TimeSpan const&);
            *value = detach_from<Windows::ApplicationModel::Chat::ChatMessageReader>(this->shim().GetMessageReader(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&recentTimeLimit)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL MarkMessageReadAsync(void* localChatMessageId, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MarkMessageReadAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), hstring const);
            *value = detach_from<Windows::Foundation::IAsyncAction>(this->shim().MarkMessageReadAsync(*reinterpret_cast<hstring const*>(&localChatMessageId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RetrySendMessageAsync(void* localChatMessageId, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RetrySendMessageAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), hstring const);
            *value = detach_from<Windows::Foundation::IAsyncAction>(this->shim().RetrySendMessageAsync(*reinterpret_cast<hstring const*>(&localChatMessageId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SendMessageAsync(void* chatMessage, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SendMessageAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::ApplicationModel::Chat::ChatMessage const);
            *value = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SendMessageAsync(*reinterpret_cast<Windows::ApplicationModel::Chat::ChatMessage const*>(&chatMessage)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ValidateMessage(void* chatMessage, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ValidateMessage, WINRT_WRAP(Windows::ApplicationModel::Chat::ChatMessageValidationResult), Windows::ApplicationModel::Chat::ChatMessage const&);
            *value = detach_from<Windows::ApplicationModel::Chat::ChatMessageValidationResult>(this->shim().ValidateMessage(*reinterpret_cast<Windows::ApplicationModel::Chat::ChatMessage const*>(&chatMessage)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_MessageChanged(void* value, winrt::event_token* returnValue) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MessageChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Chat::ChatMessageStore, Windows::ApplicationModel::Chat::ChatMessageChangedEventArgs> const&);
            *returnValue = detach_from<winrt::event_token>(this->shim().MessageChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Chat::ChatMessageStore, Windows::ApplicationModel::Chat::ChatMessageChangedEventArgs> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_MessageChanged(winrt::event_token value) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(MessageChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().MessageChanged(*reinterpret_cast<winrt::event_token const*>(&value));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Chat::IChatMessageStore2> : produce_base<D, Windows::ApplicationModel::Chat::IChatMessageStore2>
{
    int32_t WINRT_CALL ForwardMessageAsync(void* localChatMessageId, void* addresses, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ForwardMessageAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatMessage>), hstring const, Windows::Foundation::Collections::IIterable<hstring> const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatMessage>>(this->shim().ForwardMessageAsync(*reinterpret_cast<hstring const*>(&localChatMessageId), *reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&addresses)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetConversationAsync(void* conversationId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetConversationAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatConversation>), hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatConversation>>(this->shim().GetConversationAsync(*reinterpret_cast<hstring const*>(&conversationId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetConversationForTransportsAsync(void* conversationId, void* transportIds, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetConversationAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatConversation>), hstring const, Windows::Foundation::Collections::IIterable<hstring> const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatConversation>>(this->shim().GetConversationAsync(*reinterpret_cast<hstring const*>(&conversationId), *reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&transportIds)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetConversationFromThreadingInfoAsync(void* threadingInfo, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetConversationFromThreadingInfoAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatConversation>), Windows::ApplicationModel::Chat::ChatConversationThreadingInfo const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatConversation>>(this->shim().GetConversationFromThreadingInfoAsync(*reinterpret_cast<Windows::ApplicationModel::Chat::ChatConversationThreadingInfo const*>(&threadingInfo)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetConversationReader(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetConversationReader, WINRT_WRAP(Windows::ApplicationModel::Chat::ChatConversationReader));
            *result = detach_from<Windows::ApplicationModel::Chat::ChatConversationReader>(this->shim().GetConversationReader());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetConversationForTransportsReader(void* transportIds, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetConversationReader, WINRT_WRAP(Windows::ApplicationModel::Chat::ChatConversationReader), Windows::Foundation::Collections::IIterable<hstring> const&);
            *result = detach_from<Windows::ApplicationModel::Chat::ChatConversationReader>(this->shim().GetConversationReader(*reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&transportIds)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetMessageByRemoteIdAsync(void* transportId, void* remoteId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetMessageByRemoteIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatMessage>), hstring const, hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatMessage>>(this->shim().GetMessageByRemoteIdAsync(*reinterpret_cast<hstring const*>(&transportId), *reinterpret_cast<hstring const*>(&remoteId)));
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
            WINRT_ASSERT_DECLARATION(GetUnseenCountAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<int32_t>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<int32_t>>(this->shim().GetUnseenCountAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetUnseenCountForTransportsReaderAsync(void* transportIds, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetUnseenCountAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<int32_t>), Windows::Foundation::Collections::IIterable<hstring> const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<int32_t>>(this->shim().GetUnseenCountAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&transportIds)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL MarkAsSeenAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MarkAsSeenAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().MarkAsSeenAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL MarkAsSeenForTransportsAsync(void* transportIds, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MarkAsSeenAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Foundation::Collections::IIterable<hstring> const);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().MarkAsSeenAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&transportIds)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetSearchReader(void* value, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetSearchReader, WINRT_WRAP(Windows::ApplicationModel::Chat::ChatSearchReader), Windows::ApplicationModel::Chat::ChatQueryOptions const&);
            *result = detach_from<Windows::ApplicationModel::Chat::ChatSearchReader>(this->shim().GetSearchReader(*reinterpret_cast<Windows::ApplicationModel::Chat::ChatQueryOptions const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SaveMessageAsync(void* chatMessage, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SaveMessageAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::ApplicationModel::Chat::ChatMessage const);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SaveMessageAsync(*reinterpret_cast<Windows::ApplicationModel::Chat::ChatMessage const*>(&chatMessage)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryCancelDownloadMessageAsync(void* localChatMessageId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryCancelDownloadMessageAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryCancelDownloadMessageAsync(*reinterpret_cast<hstring const*>(&localChatMessageId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryCancelSendMessageAsync(void* localChatMessageId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryCancelSendMessageAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryCancelSendMessageAsync(*reinterpret_cast<hstring const*>(&localChatMessageId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_StoreChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StoreChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Chat::ChatMessageStore, Windows::ApplicationModel::Chat::ChatMessageStoreChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().StoreChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Chat::ChatMessageStore, Windows::ApplicationModel::Chat::ChatMessageStoreChangedEventArgs> const*>(&handler)));
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
struct produce<D, Windows::ApplicationModel::Chat::IChatMessageStore3> : produce_base<D, Windows::ApplicationModel::Chat::IChatMessageStore3>
{
    int32_t WINRT_CALL GetMessageBySyncIdAsync(void* syncId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetMessageBySyncIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatMessage>), hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatMessage>>(this->shim().GetMessageBySyncIdAsync(*reinterpret_cast<hstring const*>(&syncId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Chat::IChatMessageStoreChangedEventArgs> : produce_base<D, Windows::ApplicationModel::Chat::IChatMessageStoreChangedEventArgs>
{
    int32_t WINRT_CALL get_Id(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Id, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Kind(Windows::ApplicationModel::Chat::ChatStoreChangedEventKind* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Kind, WINRT_WRAP(Windows::ApplicationModel::Chat::ChatStoreChangedEventKind));
            *result = detach_from<Windows::ApplicationModel::Chat::ChatStoreChangedEventKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Chat::IChatMessageTransport> : produce_base<D, Windows::ApplicationModel::Chat::IChatMessageTransport>
{
    int32_t WINRT_CALL get_IsAppSetAsNotificationProvider(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsAppSetAsNotificationProvider, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsAppSetAsNotificationProvider());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsActive(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsActive, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsActive());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TransportFriendlyName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransportFriendlyName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().TransportFriendlyName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TransportId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransportId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().TransportId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestSetAsNotificationProviderAsync(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestSetAsNotificationProviderAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *value = detach_from<Windows::Foundation::IAsyncAction>(this->shim().RequestSetAsNotificationProviderAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Chat::IChatMessageTransport2> : produce_base<D, Windows::ApplicationModel::Chat::IChatMessageTransport2>
{
    int32_t WINRT_CALL get_Configuration(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Configuration, WINRT_WRAP(Windows::ApplicationModel::Chat::ChatMessageTransportConfiguration));
            *result = detach_from<Windows::ApplicationModel::Chat::ChatMessageTransportConfiguration>(this->shim().Configuration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TransportKind(Windows::ApplicationModel::Chat::ChatMessageTransportKind* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransportKind, WINRT_WRAP(Windows::ApplicationModel::Chat::ChatMessageTransportKind));
            *result = detach_from<Windows::ApplicationModel::Chat::ChatMessageTransportKind>(this->shim().TransportKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Chat::IChatMessageTransportConfiguration> : produce_base<D, Windows::ApplicationModel::Chat::IChatMessageTransportConfiguration>
{
    int32_t WINRT_CALL get_MaxAttachmentCount(int32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxAttachmentCount, WINRT_WRAP(int32_t));
            *result = detach_from<int32_t>(this->shim().MaxAttachmentCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxMessageSizeInKilobytes(int32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxMessageSizeInKilobytes, WINRT_WRAP(int32_t));
            *result = detach_from<int32_t>(this->shim().MaxMessageSizeInKilobytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxRecipientCount(int32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxRecipientCount, WINRT_WRAP(int32_t));
            *result = detach_from<int32_t>(this->shim().MaxRecipientCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportedVideoFormat(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedVideoFormat, WINRT_WRAP(Windows::Media::MediaProperties::MediaEncodingProfile));
            *result = detach_from<Windows::Media::MediaProperties::MediaEncodingProfile>(this->shim().SupportedVideoFormat());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExtendedProperties(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExtendedProperties, WINRT_WRAP(Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable>));
            *result = detach_from<Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable>>(this->shim().ExtendedProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Chat::IChatMessageValidationResult> : produce_base<D, Windows::ApplicationModel::Chat::IChatMessageValidationResult>
{
    int32_t WINRT_CALL get_MaxPartCount(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxPartCount, WINRT_WRAP(Windows::Foundation::IReference<uint32_t>));
            *value = detach_from<Windows::Foundation::IReference<uint32_t>>(this->shim().MaxPartCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PartCount(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PartCount, WINRT_WRAP(Windows::Foundation::IReference<uint32_t>));
            *value = detach_from<Windows::Foundation::IReference<uint32_t>>(this->shim().PartCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RemainingCharacterCountInPart(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemainingCharacterCountInPart, WINRT_WRAP(Windows::Foundation::IReference<uint32_t>));
            *value = detach_from<Windows::Foundation::IReference<uint32_t>>(this->shim().RemainingCharacterCountInPart());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Status(Windows::ApplicationModel::Chat::ChatMessageValidationStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::ApplicationModel::Chat::ChatMessageValidationStatus));
            *value = detach_from<Windows::ApplicationModel::Chat::ChatMessageValidationStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Chat::IChatQueryOptions> : produce_base<D, Windows::ApplicationModel::Chat::IChatQueryOptions>
{
    int32_t WINRT_CALL get_SearchString(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SearchString, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().SearchString());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SearchString(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SearchString, WINRT_WRAP(void), hstring const&);
            this->shim().SearchString(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Chat::IChatRecipientDeliveryInfo> : produce_base<D, Windows::ApplicationModel::Chat::IChatRecipientDeliveryInfo>
{
    int32_t WINRT_CALL get_TransportAddress(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransportAddress, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().TransportAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TransportAddress(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransportAddress, WINRT_WRAP(void), hstring const&);
            this->shim().TransportAddress(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DeliveryTime(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeliveryTime, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::DateTime>));
            *result = detach_from<Windows::Foundation::IReference<Windows::Foundation::DateTime>>(this->shim().DeliveryTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DeliveryTime(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeliveryTime, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Foundation::DateTime> const&);
            this->shim().DeliveryTime(*reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::DateTime> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ReadTime(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadTime, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::DateTime>));
            *result = detach_from<Windows::Foundation::IReference<Windows::Foundation::DateTime>>(this->shim().ReadTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ReadTime(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadTime, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Foundation::DateTime> const&);
            this->shim().ReadTime(*reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::DateTime> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TransportErrorCodeCategory(Windows::ApplicationModel::Chat::ChatTransportErrorCodeCategory* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransportErrorCodeCategory, WINRT_WRAP(Windows::ApplicationModel::Chat::ChatTransportErrorCodeCategory));
            *result = detach_from<Windows::ApplicationModel::Chat::ChatTransportErrorCodeCategory>(this->shim().TransportErrorCodeCategory());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TransportInterpretedErrorCode(Windows::ApplicationModel::Chat::ChatTransportInterpretedErrorCode* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransportInterpretedErrorCode, WINRT_WRAP(Windows::ApplicationModel::Chat::ChatTransportInterpretedErrorCode));
            *result = detach_from<Windows::ApplicationModel::Chat::ChatTransportInterpretedErrorCode>(this->shim().TransportInterpretedErrorCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TransportErrorCode(int32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransportErrorCode, WINRT_WRAP(int32_t));
            *result = detach_from<int32_t>(this->shim().TransportErrorCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsErrorPermanent(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsErrorPermanent, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().IsErrorPermanent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Status(Windows::ApplicationModel::Chat::ChatMessageStatus* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::ApplicationModel::Chat::ChatMessageStatus));
            *result = detach_from<Windows::ApplicationModel::Chat::ChatMessageStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Chat::IChatSearchReader> : produce_base<D, Windows::ApplicationModel::Chat::IChatSearchReader>
{
    int32_t WINRT_CALL ReadBatchAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadBatchAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Chat::IChatItem>>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Chat::IChatItem>>>(this->shim().ReadBatchAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReadBatchWithCountAsync(int32_t count, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadBatchAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Chat::IChatItem>>), int32_t);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Chat::IChatItem>>>(this->shim().ReadBatchAsync(count));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Chat::IChatSyncConfiguration> : produce_base<D, Windows::ApplicationModel::Chat::IChatSyncConfiguration>
{
    int32_t WINRT_CALL get_IsSyncEnabled(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSyncEnabled, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().IsSyncEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsSyncEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSyncEnabled, WINRT_WRAP(void), bool);
            this->shim().IsSyncEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RestoreHistorySpan(Windows::ApplicationModel::Chat::ChatRestoreHistorySpan* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RestoreHistorySpan, WINRT_WRAP(Windows::ApplicationModel::Chat::ChatRestoreHistorySpan));
            *result = detach_from<Windows::ApplicationModel::Chat::ChatRestoreHistorySpan>(this->shim().RestoreHistorySpan());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RestoreHistorySpan(Windows::ApplicationModel::Chat::ChatRestoreHistorySpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RestoreHistorySpan, WINRT_WRAP(void), Windows::ApplicationModel::Chat::ChatRestoreHistorySpan const&);
            this->shim().RestoreHistorySpan(*reinterpret_cast<Windows::ApplicationModel::Chat::ChatRestoreHistorySpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Chat::IChatSyncManager> : produce_base<D, Windows::ApplicationModel::Chat::IChatSyncManager>
{
    int32_t WINRT_CALL get_Configuration(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Configuration, WINRT_WRAP(Windows::ApplicationModel::Chat::ChatSyncConfiguration));
            *result = detach_from<Windows::ApplicationModel::Chat::ChatSyncConfiguration>(this->shim().Configuration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AssociateAccountAsync(void* webAccount, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AssociateAccountAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Security::Credentials::WebAccount const);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().AssociateAccountAsync(*reinterpret_cast<Windows::Security::Credentials::WebAccount const*>(&webAccount)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UnassociateAccountAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UnassociateAccountAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().UnassociateAccountAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsAccountAssociated(void* webAccount, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsAccountAssociated, WINRT_WRAP(bool), Windows::Security::Credentials::WebAccount const&);
            *result = detach_from<bool>(this->shim().IsAccountAssociated(*reinterpret_cast<Windows::Security::Credentials::WebAccount const*>(&webAccount)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StartSync() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartSync, WINRT_WRAP(void));
            this->shim().StartSync();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetConfigurationAsync(void* configuration, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetConfigurationAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::ApplicationModel::Chat::ChatSyncConfiguration const);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SetConfigurationAsync(*reinterpret_cast<Windows::ApplicationModel::Chat::ChatSyncConfiguration const*>(&configuration)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Chat::IRcsEndUserMessage> : produce_base<D, Windows::ApplicationModel::Chat::IRcsEndUserMessage>
{
    int32_t WINRT_CALL get_TransportId(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransportId, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().TransportId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Title(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Title, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().Title());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Text(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Text, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().Text());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsPinRequired(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsPinRequired, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().IsPinRequired());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Actions(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Actions, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Chat::RcsEndUserMessageAction>));
            *result = detach_from<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Chat::RcsEndUserMessageAction>>(this->shim().Actions());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SendResponseAsync(void* action, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SendResponseAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::ApplicationModel::Chat::RcsEndUserMessageAction const);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SendResponseAsync(*reinterpret_cast<Windows::ApplicationModel::Chat::RcsEndUserMessageAction const*>(&action)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SendResponseWithPinAsync(void* action, void* pin, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SendResponseWithPinAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::ApplicationModel::Chat::RcsEndUserMessageAction const, hstring const);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SendResponseWithPinAsync(*reinterpret_cast<Windows::ApplicationModel::Chat::RcsEndUserMessageAction const*>(&action), *reinterpret_cast<hstring const*>(&pin)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Chat::IRcsEndUserMessageAction> : produce_base<D, Windows::ApplicationModel::Chat::IRcsEndUserMessageAction>
{
    int32_t WINRT_CALL get_Label(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Label, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().Label());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Chat::IRcsEndUserMessageAvailableEventArgs> : produce_base<D, Windows::ApplicationModel::Chat::IRcsEndUserMessageAvailableEventArgs>
{
    int32_t WINRT_CALL get_IsMessageAvailable(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsMessageAvailable, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().IsMessageAvailable());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Message(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Message, WINRT_WRAP(Windows::ApplicationModel::Chat::RcsEndUserMessage));
            *result = detach_from<Windows::ApplicationModel::Chat::RcsEndUserMessage>(this->shim().Message());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Chat::IRcsEndUserMessageAvailableTriggerDetails> : produce_base<D, Windows::ApplicationModel::Chat::IRcsEndUserMessageAvailableTriggerDetails>
{
    int32_t WINRT_CALL get_Title(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Title, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Title());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Text(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Text, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Text());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Chat::IRcsEndUserMessageManager> : produce_base<D, Windows::ApplicationModel::Chat::IRcsEndUserMessageManager>
{
    int32_t WINRT_CALL add_MessageAvailableChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MessageAvailableChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Chat::RcsEndUserMessageManager, Windows::ApplicationModel::Chat::RcsEndUserMessageAvailableEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().MessageAvailableChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Chat::RcsEndUserMessageManager, Windows::ApplicationModel::Chat::RcsEndUserMessageAvailableEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_MessageAvailableChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(MessageAvailableChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().MessageAvailableChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Chat::IRcsManagerStatics> : produce_base<D, Windows::ApplicationModel::Chat::IRcsManagerStatics>
{
    int32_t WINRT_CALL GetEndUserMessageManager(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetEndUserMessageManager, WINRT_WRAP(Windows::ApplicationModel::Chat::RcsEndUserMessageManager));
            *result = detach_from<Windows::ApplicationModel::Chat::RcsEndUserMessageManager>(this->shim().GetEndUserMessageManager());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetTransportsAsync(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetTransportsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Chat::RcsTransport>>));
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Chat::RcsTransport>>>(this->shim().GetTransportsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetTransportAsync(void* transportId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetTransportAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::RcsTransport>), hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::RcsTransport>>(this->shim().GetTransportAsync(*reinterpret_cast<hstring const*>(&transportId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL LeaveConversationAsync(void* conversation, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LeaveConversationAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::ApplicationModel::Chat::ChatConversation const);
            *value = detach_from<Windows::Foundation::IAsyncAction>(this->shim().LeaveConversationAsync(*reinterpret_cast<Windows::ApplicationModel::Chat::ChatConversation const*>(&conversation)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Chat::IRcsManagerStatics2> : produce_base<D, Windows::ApplicationModel::Chat::IRcsManagerStatics2>
{
    int32_t WINRT_CALL add_TransportListChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransportListChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().TransportListChanged(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_TransportListChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(TransportListChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().TransportListChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Chat::IRcsServiceKindSupportedChangedEventArgs> : produce_base<D, Windows::ApplicationModel::Chat::IRcsServiceKindSupportedChangedEventArgs>
{
    int32_t WINRT_CALL get_ServiceKind(Windows::ApplicationModel::Chat::RcsServiceKind* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServiceKind, WINRT_WRAP(Windows::ApplicationModel::Chat::RcsServiceKind));
            *result = detach_from<Windows::ApplicationModel::Chat::RcsServiceKind>(this->shim().ServiceKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Chat::IRcsTransport> : produce_base<D, Windows::ApplicationModel::Chat::IRcsTransport>
{
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

    int32_t WINRT_CALL get_IsActive(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsActive, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsActive());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TransportFriendlyName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransportFriendlyName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().TransportFriendlyName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TransportId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransportId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().TransportId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Configuration(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Configuration, WINRT_WRAP(Windows::ApplicationModel::Chat::RcsTransportConfiguration));
            *result = detach_from<Windows::ApplicationModel::Chat::RcsTransportConfiguration>(this->shim().Configuration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsStoreAndForwardEnabled(Windows::ApplicationModel::Chat::RcsServiceKind serviceKind, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsStoreAndForwardEnabled, WINRT_WRAP(bool), Windows::ApplicationModel::Chat::RcsServiceKind const&);
            *result = detach_from<bool>(this->shim().IsStoreAndForwardEnabled(*reinterpret_cast<Windows::ApplicationModel::Chat::RcsServiceKind const*>(&serviceKind)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsServiceKindSupported(Windows::ApplicationModel::Chat::RcsServiceKind serviceKind, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsServiceKindSupported, WINRT_WRAP(bool), Windows::ApplicationModel::Chat::RcsServiceKind const&);
            *result = detach_from<bool>(this->shim().IsServiceKindSupported(*reinterpret_cast<Windows::ApplicationModel::Chat::RcsServiceKind const*>(&serviceKind)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_ServiceKindSupportedChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServiceKindSupportedChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Chat::RcsTransport, Windows::ApplicationModel::Chat::RcsServiceKindSupportedChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ServiceKindSupportedChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Chat::RcsTransport, Windows::ApplicationModel::Chat::RcsServiceKindSupportedChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ServiceKindSupportedChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ServiceKindSupportedChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ServiceKindSupportedChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Chat::IRcsTransportConfiguration> : produce_base<D, Windows::ApplicationModel::Chat::IRcsTransportConfiguration>
{
    int32_t WINRT_CALL get_MaxAttachmentCount(int32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxAttachmentCount, WINRT_WRAP(int32_t));
            *result = detach_from<int32_t>(this->shim().MaxAttachmentCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxMessageSizeInKilobytes(int32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxMessageSizeInKilobytes, WINRT_WRAP(int32_t));
            *result = detach_from<int32_t>(this->shim().MaxMessageSizeInKilobytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxGroupMessageSizeInKilobytes(int32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxGroupMessageSizeInKilobytes, WINRT_WRAP(int32_t));
            *result = detach_from<int32_t>(this->shim().MaxGroupMessageSizeInKilobytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxRecipientCount(int32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxRecipientCount, WINRT_WRAP(int32_t));
            *result = detach_from<int32_t>(this->shim().MaxRecipientCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxFileSizeInKilobytes(int32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxFileSizeInKilobytes, WINRT_WRAP(int32_t));
            *result = detach_from<int32_t>(this->shim().MaxFileSizeInKilobytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WarningFileSizeInKilobytes(int32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WarningFileSizeInKilobytes, WINRT_WRAP(int32_t));
            *result = detach_from<int32_t>(this->shim().WarningFileSizeInKilobytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Chat::IRemoteParticipantComposingChangedEventArgs> : produce_base<D, Windows::ApplicationModel::Chat::IRemoteParticipantComposingChangedEventArgs>
{
    int32_t WINRT_CALL get_TransportId(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransportId, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().TransportId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ParticipantAddress(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ParticipantAddress, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().ParticipantAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsComposing(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsComposing, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().IsComposing());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Chat {

inline Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatCapabilities> ChatCapabilitiesManager::GetCachedCapabilitiesAsync(param::hstring const& address)
{
    return impl::call_factory<ChatCapabilitiesManager, Windows::ApplicationModel::Chat::IChatCapabilitiesManagerStatics>([&](auto&& f) { return f.GetCachedCapabilitiesAsync(address); });
}

inline Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatCapabilities> ChatCapabilitiesManager::GetCapabilitiesFromNetworkAsync(param::hstring const& address)
{
    return impl::call_factory<ChatCapabilitiesManager, Windows::ApplicationModel::Chat::IChatCapabilitiesManagerStatics>([&](auto&& f) { return f.GetCapabilitiesFromNetworkAsync(address); });
}

inline Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatCapabilities> ChatCapabilitiesManager::GetCachedCapabilitiesAsync(param::hstring const& address, param::hstring const& transportId)
{
    return impl::call_factory<ChatCapabilitiesManager, Windows::ApplicationModel::Chat::IChatCapabilitiesManagerStatics2>([&](auto&& f) { return f.GetCachedCapabilitiesAsync(address, transportId); });
}

inline Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatCapabilities> ChatCapabilitiesManager::GetCapabilitiesFromNetworkAsync(param::hstring const& address, param::hstring const& transportId)
{
    return impl::call_factory<ChatCapabilitiesManager, Windows::ApplicationModel::Chat::IChatCapabilitiesManagerStatics2>([&](auto&& f) { return f.GetCapabilitiesFromNetworkAsync(address, transportId); });
}

inline ChatConversationThreadingInfo::ChatConversationThreadingInfo() :
    ChatConversationThreadingInfo(impl::call_factory<ChatConversationThreadingInfo>([](auto&& f) { return f.template ActivateInstance<ChatConversationThreadingInfo>(); }))
{}

inline ChatMessage::ChatMessage() :
    ChatMessage(impl::call_factory<ChatMessage>([](auto&& f) { return f.template ActivateInstance<ChatMessage>(); }))
{}

inline ChatMessageAttachment::ChatMessageAttachment(param::hstring const& mimeType, Windows::Storage::Streams::IRandomAccessStreamReference const& dataStreamReference) :
    ChatMessageAttachment(impl::call_factory<ChatMessageAttachment, Windows::ApplicationModel::Chat::IChatMessageAttachmentFactory>([&](auto&& f) { return f.CreateChatMessageAttachment(mimeType, dataStreamReference); }))
{}

inline Windows::Foundation::IAsyncAction ChatMessageBlocking::MarkMessageAsBlockedAsync(param::hstring const& localChatMessageId, bool blocked)
{
    return impl::call_factory<ChatMessageBlocking, Windows::ApplicationModel::Chat::IChatMessageBlockingStatic>([&](auto&& f) { return f.MarkMessageAsBlockedAsync(localChatMessageId, blocked); });
}

inline Windows::Foundation::IAsyncOperation<hstring> ChatMessageManager::RegisterTransportAsync()
{
    return impl::call_factory<ChatMessageManager, Windows::ApplicationModel::Chat::IChatMessageManager2Statics>([&](auto&& f) { return f.RegisterTransportAsync(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatMessageTransport> ChatMessageManager::GetTransportAsync(param::hstring const& transportId)
{
    return impl::call_factory<ChatMessageManager, Windows::ApplicationModel::Chat::IChatMessageManager2Statics>([&](auto&& f) { return f.GetTransportAsync(transportId); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Chat::ChatMessageTransport>> ChatMessageManager::GetTransportsAsync()
{
    return impl::call_factory<ChatMessageManager, Windows::ApplicationModel::Chat::IChatMessageManagerStatic>([&](auto&& f) { return f.GetTransportsAsync(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatMessageStore> ChatMessageManager::RequestStoreAsync()
{
    return impl::call_factory<ChatMessageManager, Windows::ApplicationModel::Chat::IChatMessageManagerStatic>([&](auto&& f) { return f.RequestStoreAsync(); });
}

inline Windows::Foundation::IAsyncAction ChatMessageManager::ShowComposeSmsMessageAsync(Windows::ApplicationModel::Chat::ChatMessage const& message)
{
    return impl::call_factory<ChatMessageManager, Windows::ApplicationModel::Chat::IChatMessageManagerStatic>([&](auto&& f) { return f.ShowComposeSmsMessageAsync(message); });
}

inline void ChatMessageManager::ShowSmsSettings()
{
    impl::call_factory<ChatMessageManager, Windows::ApplicationModel::Chat::IChatMessageManagerStatic>([&](auto&& f) { return f.ShowSmsSettings(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::ChatSyncManager> ChatMessageManager::RequestSyncManagerAsync()
{
    return impl::call_factory<ChatMessageManager, Windows::ApplicationModel::Chat::IChatMessageManagerStatics3>([&](auto&& f) { return f.RequestSyncManagerAsync(); });
}

inline ChatQueryOptions::ChatQueryOptions() :
    ChatQueryOptions(impl::call_factory<ChatQueryOptions>([](auto&& f) { return f.template ActivateInstance<ChatQueryOptions>(); }))
{}

inline ChatRecipientDeliveryInfo::ChatRecipientDeliveryInfo() :
    ChatRecipientDeliveryInfo(impl::call_factory<ChatRecipientDeliveryInfo>([](auto&& f) { return f.template ActivateInstance<ChatRecipientDeliveryInfo>(); }))
{}

inline Windows::ApplicationModel::Chat::RcsEndUserMessageManager RcsManager::GetEndUserMessageManager()
{
    return impl::call_factory<RcsManager, Windows::ApplicationModel::Chat::IRcsManagerStatics>([&](auto&& f) { return f.GetEndUserMessageManager(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Chat::RcsTransport>> RcsManager::GetTransportsAsync()
{
    return impl::call_factory<RcsManager, Windows::ApplicationModel::Chat::IRcsManagerStatics>([&](auto&& f) { return f.GetTransportsAsync(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Chat::RcsTransport> RcsManager::GetTransportAsync(param::hstring const& transportId)
{
    return impl::call_factory<RcsManager, Windows::ApplicationModel::Chat::IRcsManagerStatics>([&](auto&& f) { return f.GetTransportAsync(transportId); });
}

inline Windows::Foundation::IAsyncAction RcsManager::LeaveConversationAsync(Windows::ApplicationModel::Chat::ChatConversation const& conversation)
{
    return impl::call_factory<RcsManager, Windows::ApplicationModel::Chat::IRcsManagerStatics>([&](auto&& f) { return f.LeaveConversationAsync(conversation); });
}

inline winrt::event_token RcsManager::TransportListChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    return impl::call_factory<RcsManager, Windows::ApplicationModel::Chat::IRcsManagerStatics2>([&](auto&& f) { return f.TransportListChanged(handler); });
}

inline RcsManager::TransportListChanged_revoker RcsManager::TransportListChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    auto f = get_activation_factory<RcsManager, Windows::ApplicationModel::Chat::IRcsManagerStatics2>();
    return { f, f.TransportListChanged(handler) };
}

inline void RcsManager::TransportListChanged(winrt::event_token const& token)
{
    impl::call_factory<RcsManager, Windows::ApplicationModel::Chat::IRcsManagerStatics2>([&](auto&& f) { return f.TransportListChanged(token); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatCapabilities> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::IChatCapabilities> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatCapabilitiesManagerStatics> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::IChatCapabilitiesManagerStatics> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatCapabilitiesManagerStatics2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::IChatCapabilitiesManagerStatics2> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatConversation> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::IChatConversation> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatConversation2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::IChatConversation2> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatConversationReader> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::IChatConversationReader> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatConversationThreadingInfo> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::IChatConversationThreadingInfo> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatItem> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::IChatItem> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatMessage> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::IChatMessage> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatMessage2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::IChatMessage2> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatMessage3> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::IChatMessage3> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatMessage4> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::IChatMessage4> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatMessageAttachment> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::IChatMessageAttachment> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatMessageAttachment2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::IChatMessageAttachment2> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatMessageAttachmentFactory> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::IChatMessageAttachmentFactory> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatMessageBlockingStatic> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::IChatMessageBlockingStatic> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatMessageChange> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::IChatMessageChange> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatMessageChangeReader> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::IChatMessageChangeReader> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatMessageChangeTracker> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::IChatMessageChangeTracker> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatMessageChangedDeferral> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::IChatMessageChangedDeferral> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatMessageChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::IChatMessageChangedEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatMessageManager2Statics> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::IChatMessageManager2Statics> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatMessageManagerStatic> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::IChatMessageManagerStatic> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatMessageManagerStatics3> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::IChatMessageManagerStatics3> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatMessageNotificationTriggerDetails> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::IChatMessageNotificationTriggerDetails> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatMessageNotificationTriggerDetails2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::IChatMessageNotificationTriggerDetails2> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatMessageReader> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::IChatMessageReader> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatMessageReader2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::IChatMessageReader2> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatMessageStore> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::IChatMessageStore> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatMessageStore2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::IChatMessageStore2> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatMessageStore3> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::IChatMessageStore3> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatMessageStoreChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::IChatMessageStoreChangedEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatMessageTransport> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::IChatMessageTransport> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatMessageTransport2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::IChatMessageTransport2> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatMessageTransportConfiguration> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::IChatMessageTransportConfiguration> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatMessageValidationResult> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::IChatMessageValidationResult> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatQueryOptions> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::IChatQueryOptions> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatRecipientDeliveryInfo> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::IChatRecipientDeliveryInfo> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatSearchReader> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::IChatSearchReader> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatSyncConfiguration> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::IChatSyncConfiguration> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::IChatSyncManager> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::IChatSyncManager> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::IRcsEndUserMessage> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::IRcsEndUserMessage> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::IRcsEndUserMessageAction> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::IRcsEndUserMessageAction> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::IRcsEndUserMessageAvailableEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::IRcsEndUserMessageAvailableEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::IRcsEndUserMessageAvailableTriggerDetails> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::IRcsEndUserMessageAvailableTriggerDetails> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::IRcsEndUserMessageManager> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::IRcsEndUserMessageManager> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::IRcsManagerStatics> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::IRcsManagerStatics> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::IRcsManagerStatics2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::IRcsManagerStatics2> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::IRcsServiceKindSupportedChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::IRcsServiceKindSupportedChangedEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::IRcsTransport> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::IRcsTransport> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::IRcsTransportConfiguration> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::IRcsTransportConfiguration> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::IRemoteParticipantComposingChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::IRemoteParticipantComposingChangedEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::ChatCapabilities> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::ChatCapabilities> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::ChatCapabilitiesManager> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::ChatCapabilitiesManager> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::ChatConversation> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::ChatConversation> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::ChatConversationReader> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::ChatConversationReader> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::ChatConversationThreadingInfo> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::ChatConversationThreadingInfo> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::ChatMessage> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::ChatMessage> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::ChatMessageAttachment> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::ChatMessageAttachment> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::ChatMessageBlocking> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::ChatMessageBlocking> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::ChatMessageChange> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::ChatMessageChange> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::ChatMessageChangeReader> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::ChatMessageChangeReader> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::ChatMessageChangeTracker> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::ChatMessageChangeTracker> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::ChatMessageChangedDeferral> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::ChatMessageChangedDeferral> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::ChatMessageChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::ChatMessageChangedEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::ChatMessageManager> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::ChatMessageManager> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::ChatMessageNotificationTriggerDetails> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::ChatMessageNotificationTriggerDetails> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::ChatMessageReader> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::ChatMessageReader> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::ChatMessageStore> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::ChatMessageStore> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::ChatMessageStoreChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::ChatMessageStoreChangedEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::ChatMessageTransport> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::ChatMessageTransport> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::ChatMessageTransportConfiguration> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::ChatMessageTransportConfiguration> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::ChatMessageValidationResult> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::ChatMessageValidationResult> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::ChatQueryOptions> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::ChatQueryOptions> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::ChatRecipientDeliveryInfo> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::ChatRecipientDeliveryInfo> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::ChatSearchReader> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::ChatSearchReader> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::ChatSyncConfiguration> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::ChatSyncConfiguration> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::ChatSyncManager> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::ChatSyncManager> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::RcsEndUserMessage> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::RcsEndUserMessage> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::RcsEndUserMessageAction> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::RcsEndUserMessageAction> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::RcsEndUserMessageAvailableEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::RcsEndUserMessageAvailableEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::RcsEndUserMessageAvailableTriggerDetails> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::RcsEndUserMessageAvailableTriggerDetails> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::RcsEndUserMessageManager> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::RcsEndUserMessageManager> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::RcsManager> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::RcsManager> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::RcsServiceKindSupportedChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::RcsServiceKindSupportedChangedEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::RcsTransport> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::RcsTransport> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::RcsTransportConfiguration> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::RcsTransportConfiguration> {};
template<> struct hash<winrt::Windows::ApplicationModel::Chat::RemoteParticipantComposingChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Chat::RemoteParticipantComposingChangedEventArgs> {};

}
