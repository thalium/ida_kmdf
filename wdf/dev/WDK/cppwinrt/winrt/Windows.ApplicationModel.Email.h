// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.ApplicationModel.Appointments.2.h"
#include "winrt/impl/Windows.Security.Cryptography.Certificates.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.ApplicationModel.Email.2.h"
#include "winrt/Windows.ApplicationModel.h"

namespace winrt::impl {

template <typename D> hstring consume_Windows_ApplicationModel_Email_IEmailAttachment<D>::FileName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailAttachment)->get_FileName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailAttachment<D>::FileName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailAttachment)->put_FileName(get_abi(value)));
}

template <typename D> Windows::Storage::Streams::IRandomAccessStreamReference consume_Windows_ApplicationModel_Email_IEmailAttachment<D>::Data() const
{
    Windows::Storage::Streams::IRandomAccessStreamReference value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailAttachment)->get_Data(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailAttachment<D>::Data(Windows::Storage::Streams::IRandomAccessStreamReference const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailAttachment)->put_Data(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_IEmailAttachment2<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailAttachment2)->get_Id(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_IEmailAttachment2<D>::ContentId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailAttachment2)->get_ContentId(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailAttachment2<D>::ContentId(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailAttachment2)->put_ContentId(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_IEmailAttachment2<D>::ContentLocation() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailAttachment2)->get_ContentLocation(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailAttachment2<D>::ContentLocation(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailAttachment2)->put_ContentLocation(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::Email::EmailAttachmentDownloadState consume_Windows_ApplicationModel_Email_IEmailAttachment2<D>::DownloadState() const
{
    Windows::ApplicationModel::Email::EmailAttachmentDownloadState value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailAttachment2)->get_DownloadState(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailAttachment2<D>::DownloadState(Windows::ApplicationModel::Email::EmailAttachmentDownloadState const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailAttachment2)->put_DownloadState(get_abi(value)));
}

template <typename D> uint64_t consume_Windows_ApplicationModel_Email_IEmailAttachment2<D>::EstimatedDownloadSizeInBytes() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailAttachment2)->get_EstimatedDownloadSizeInBytes(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailAttachment2<D>::EstimatedDownloadSizeInBytes(uint64_t value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailAttachment2)->put_EstimatedDownloadSizeInBytes(value));
}

template <typename D> bool consume_Windows_ApplicationModel_Email_IEmailAttachment2<D>::IsFromBaseMessage() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailAttachment2)->get_IsFromBaseMessage(&value));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Email_IEmailAttachment2<D>::IsInline() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailAttachment2)->get_IsInline(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailAttachment2<D>::IsInline(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailAttachment2)->put_IsInline(value));
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_IEmailAttachment2<D>::MimeType() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailAttachment2)->get_MimeType(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailAttachment2<D>::MimeType(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailAttachment2)->put_MimeType(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::Email::EmailAttachment consume_Windows_ApplicationModel_Email_IEmailAttachmentFactory<D>::Create(param::hstring const& fileName, Windows::Storage::Streams::IRandomAccessStreamReference const& data) const
{
    Windows::ApplicationModel::Email::EmailAttachment result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailAttachmentFactory)->Create(get_abi(fileName), get_abi(data), put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Email::EmailAttachment consume_Windows_ApplicationModel_Email_IEmailAttachmentFactory2<D>::Create(param::hstring const& fileName, Windows::Storage::Streams::IRandomAccessStreamReference const& data, param::hstring const& mimeType) const
{
    Windows::ApplicationModel::Email::EmailAttachment result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailAttachmentFactory2)->Create(get_abi(fileName), get_abi(data), get_abi(mimeType), put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_IEmailConversation<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailConversation)->get_Id(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_IEmailConversation<D>::MailboxId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailConversation)->get_MailboxId(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Email::EmailFlagState consume_Windows_ApplicationModel_Email_IEmailConversation<D>::FlagState() const
{
    Windows::ApplicationModel::Email::EmailFlagState value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailConversation)->get_FlagState(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Email_IEmailConversation<D>::HasAttachment() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailConversation)->get_HasAttachment(&value));
    return value;
}

template <typename D> Windows::ApplicationModel::Email::EmailImportance consume_Windows_ApplicationModel_Email_IEmailConversation<D>::Importance() const
{
    Windows::ApplicationModel::Email::EmailImportance value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailConversation)->get_Importance(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Email::EmailMessageResponseKind consume_Windows_ApplicationModel_Email_IEmailConversation<D>::LastEmailResponseKind() const
{
    Windows::ApplicationModel::Email::EmailMessageResponseKind value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailConversation)->get_LastEmailResponseKind(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_ApplicationModel_Email_IEmailConversation<D>::MessageCount() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailConversation)->get_MessageCount(&value));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_IEmailConversation<D>::MostRecentMessageId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailConversation)->get_MostRecentMessageId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_ApplicationModel_Email_IEmailConversation<D>::MostRecentMessageTime() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailConversation)->get_MostRecentMessageTime(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_IEmailConversation<D>::Preview() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailConversation)->get_Preview(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Email::EmailRecipient consume_Windows_ApplicationModel_Email_IEmailConversation<D>::LatestSender() const
{
    Windows::ApplicationModel::Email::EmailRecipient value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailConversation)->get_LatestSender(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_IEmailConversation<D>::Subject() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailConversation)->get_Subject(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_ApplicationModel_Email_IEmailConversation<D>::UnreadMessageCount() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailConversation)->get_UnreadMessageCount(&value));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Email::EmailMessage>> consume_Windows_ApplicationModel_Email_IEmailConversation<D>::FindMessagesAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Email::EmailMessage>> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailConversation)->FindMessagesAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Email::EmailMessage>> consume_Windows_ApplicationModel_Email_IEmailConversation<D>::FindMessagesAsync(uint32_t count) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Email::EmailMessage>> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailConversation)->FindMessagesWithCountAsync(count, put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Email::EmailConversation> consume_Windows_ApplicationModel_Email_IEmailConversationBatch<D>::Conversations() const
{
    Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Email::EmailConversation> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailConversationBatch)->get_Conversations(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Email::EmailBatchStatus consume_Windows_ApplicationModel_Email_IEmailConversationBatch<D>::Status() const
{
    Windows::ApplicationModel::Email::EmailBatchStatus value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailConversationBatch)->get_Status(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailConversationBatch> consume_Windows_ApplicationModel_Email_IEmailConversationReader<D>::ReadBatchAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailConversationBatch> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailConversationReader)->ReadBatchAsync(put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_IEmailFolder<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailFolder)->get_Id(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_IEmailFolder<D>::RemoteId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailFolder)->get_RemoteId(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailFolder<D>::RemoteId(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailFolder)->put_RemoteId(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_IEmailFolder<D>::MailboxId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailFolder)->get_MailboxId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_IEmailFolder<D>::ParentFolderId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailFolder)->get_ParentFolderId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_IEmailFolder<D>::DisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailFolder)->get_DisplayName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailFolder<D>::DisplayName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailFolder)->put_DisplayName(get_abi(value)));
}

template <typename D> bool consume_Windows_ApplicationModel_Email_IEmailFolder<D>::IsSyncEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailFolder)->get_IsSyncEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailFolder<D>::IsSyncEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailFolder)->put_IsSyncEnabled(value));
}

template <typename D> Windows::Foundation::DateTime consume_Windows_ApplicationModel_Email_IEmailFolder<D>::LastSuccessfulSyncTime() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailFolder)->get_LastSuccessfulSyncTime(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailFolder<D>::LastSuccessfulSyncTime(Windows::Foundation::DateTime const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailFolder)->put_LastSuccessfulSyncTime(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::Email::EmailSpecialFolderKind consume_Windows_ApplicationModel_Email_IEmailFolder<D>::Kind() const
{
    Windows::ApplicationModel::Email::EmailSpecialFolderKind value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailFolder)->get_Kind(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailFolder> consume_Windows_ApplicationModel_Email_IEmailFolder<D>::CreateFolderAsync(param::hstring const& name) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailFolder> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailFolder)->CreateFolderAsync(get_abi(name), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Email_IEmailFolder<D>::DeleteAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailFolder)->DeleteAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Email::EmailFolder>> consume_Windows_ApplicationModel_Email_IEmailFolder<D>::FindChildFoldersAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Email::EmailFolder>> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailFolder)->FindChildFoldersAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Email::EmailConversationReader consume_Windows_ApplicationModel_Email_IEmailFolder<D>::GetConversationReader() const
{
    Windows::ApplicationModel::Email::EmailConversationReader result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailFolder)->GetConversationReader(put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Email::EmailConversationReader consume_Windows_ApplicationModel_Email_IEmailFolder<D>::GetConversationReader(Windows::ApplicationModel::Email::EmailQueryOptions const& options) const
{
    Windows::ApplicationModel::Email::EmailConversationReader result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailFolder)->GetConversationReaderWithOptions(get_abi(options), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailMessage> consume_Windows_ApplicationModel_Email_IEmailFolder<D>::GetMessageAsync(param::hstring const& id) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailMessage> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailFolder)->GetMessageAsync(get_abi(id), put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Email::EmailMessageReader consume_Windows_ApplicationModel_Email_IEmailFolder<D>::GetMessageReader() const
{
    Windows::ApplicationModel::Email::EmailMessageReader result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailFolder)->GetMessageReader(put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Email::EmailMessageReader consume_Windows_ApplicationModel_Email_IEmailFolder<D>::GetMessageReader(Windows::ApplicationModel::Email::EmailQueryOptions const& options) const
{
    Windows::ApplicationModel::Email::EmailMessageReader result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailFolder)->GetMessageReaderWithOptions(get_abi(options), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailItemCounts> consume_Windows_ApplicationModel_Email_IEmailFolder<D>::GetMessageCountsAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailItemCounts> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailFolder)->GetMessageCountsAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_ApplicationModel_Email_IEmailFolder<D>::TryMoveAsync(Windows::ApplicationModel::Email::EmailFolder const& newParentFolder) const
{
    Windows::Foundation::IAsyncOperation<bool> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailFolder)->TryMoveAsync(get_abi(newParentFolder), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_ApplicationModel_Email_IEmailFolder<D>::TryMoveAsync(Windows::ApplicationModel::Email::EmailFolder const& newParentFolder, param::hstring const& newFolderName) const
{
    Windows::Foundation::IAsyncOperation<bool> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailFolder)->TryMoveWithNewNameAsync(get_abi(newParentFolder), get_abi(newFolderName), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_ApplicationModel_Email_IEmailFolder<D>::TrySaveAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailFolder)->TrySaveAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Email_IEmailFolder<D>::SaveMessageAsync(Windows::ApplicationModel::Email::EmailMessage const& message) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailFolder)->SaveMessageAsync(get_abi(message), put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_ApplicationModel_Email_IEmailIrmInfo<D>::CanEdit() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailIrmInfo)->get_CanEdit(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailIrmInfo<D>::CanEdit(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailIrmInfo)->put_CanEdit(value));
}

template <typename D> bool consume_Windows_ApplicationModel_Email_IEmailIrmInfo<D>::CanExtractData() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailIrmInfo)->get_CanExtractData(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailIrmInfo<D>::CanExtractData(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailIrmInfo)->put_CanExtractData(value));
}

template <typename D> bool consume_Windows_ApplicationModel_Email_IEmailIrmInfo<D>::CanForward() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailIrmInfo)->get_CanForward(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailIrmInfo<D>::CanForward(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailIrmInfo)->put_CanForward(value));
}

template <typename D> bool consume_Windows_ApplicationModel_Email_IEmailIrmInfo<D>::CanModifyRecipientsOnResponse() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailIrmInfo)->get_CanModifyRecipientsOnResponse(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailIrmInfo<D>::CanModifyRecipientsOnResponse(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailIrmInfo)->put_CanModifyRecipientsOnResponse(value));
}

template <typename D> bool consume_Windows_ApplicationModel_Email_IEmailIrmInfo<D>::CanPrintData() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailIrmInfo)->get_CanPrintData(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailIrmInfo<D>::CanPrintData(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailIrmInfo)->put_CanPrintData(value));
}

template <typename D> bool consume_Windows_ApplicationModel_Email_IEmailIrmInfo<D>::CanRemoveIrmOnResponse() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailIrmInfo)->get_CanRemoveIrmOnResponse(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailIrmInfo<D>::CanRemoveIrmOnResponse(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailIrmInfo)->put_CanRemoveIrmOnResponse(value));
}

template <typename D> bool consume_Windows_ApplicationModel_Email_IEmailIrmInfo<D>::CanReply() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailIrmInfo)->get_CanReply(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailIrmInfo<D>::CanReply(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailIrmInfo)->put_CanReply(value));
}

template <typename D> bool consume_Windows_ApplicationModel_Email_IEmailIrmInfo<D>::CanReplyAll() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailIrmInfo)->get_CanReplyAll(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailIrmInfo<D>::CanReplyAll(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailIrmInfo)->put_CanReplyAll(value));
}

template <typename D> Windows::Foundation::DateTime consume_Windows_ApplicationModel_Email_IEmailIrmInfo<D>::ExpirationDate() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailIrmInfo)->get_ExpirationDate(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailIrmInfo<D>::ExpirationDate(Windows::Foundation::DateTime const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailIrmInfo)->put_ExpirationDate(get_abi(value)));
}

template <typename D> bool consume_Windows_ApplicationModel_Email_IEmailIrmInfo<D>::IsIrmOriginator() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailIrmInfo)->get_IsIrmOriginator(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailIrmInfo<D>::IsIrmOriginator(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailIrmInfo)->put_IsIrmOriginator(value));
}

template <typename D> bool consume_Windows_ApplicationModel_Email_IEmailIrmInfo<D>::IsProgramaticAccessAllowed() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailIrmInfo)->get_IsProgramaticAccessAllowed(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailIrmInfo<D>::IsProgramaticAccessAllowed(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailIrmInfo)->put_IsProgramaticAccessAllowed(value));
}

template <typename D> Windows::ApplicationModel::Email::EmailIrmTemplate consume_Windows_ApplicationModel_Email_IEmailIrmInfo<D>::Template() const
{
    Windows::ApplicationModel::Email::EmailIrmTemplate value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailIrmInfo)->get_Template(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailIrmInfo<D>::Template(Windows::ApplicationModel::Email::EmailIrmTemplate const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailIrmInfo)->put_Template(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::Email::EmailIrmInfo consume_Windows_ApplicationModel_Email_IEmailIrmInfoFactory<D>::Create(Windows::Foundation::DateTime const& expiration, Windows::ApplicationModel::Email::EmailIrmTemplate const& irmTemplate) const
{
    Windows::ApplicationModel::Email::EmailIrmInfo result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailIrmInfoFactory)->Create(get_abi(expiration), get_abi(irmTemplate), put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_IEmailIrmTemplate<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailIrmTemplate)->get_Id(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailIrmTemplate<D>::Id(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailIrmTemplate)->put_Id(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_IEmailIrmTemplate<D>::Description() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailIrmTemplate)->get_Description(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailIrmTemplate<D>::Description(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailIrmTemplate)->put_Description(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_IEmailIrmTemplate<D>::Name() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailIrmTemplate)->get_Name(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailIrmTemplate<D>::Name(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailIrmTemplate)->put_Name(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::Email::EmailIrmTemplate consume_Windows_ApplicationModel_Email_IEmailIrmTemplateFactory<D>::Create(param::hstring const& id, param::hstring const& name, param::hstring const& description) const
{
    Windows::ApplicationModel::Email::EmailIrmTemplate result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailIrmTemplateFactory)->Create(get_abi(id), get_abi(name), get_abi(description), put_abi(result)));
    return result;
}

template <typename D> uint32_t consume_Windows_ApplicationModel_Email_IEmailItemCounts<D>::Flagged() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailItemCounts)->get_Flagged(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_ApplicationModel_Email_IEmailItemCounts<D>::Important() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailItemCounts)->get_Important(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_ApplicationModel_Email_IEmailItemCounts<D>::Total() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailItemCounts)->get_Total(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_ApplicationModel_Email_IEmailItemCounts<D>::Unread() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailItemCounts)->get_Unread(&value));
    return value;
}

template <typename D> Windows::ApplicationModel::Email::EmailMailboxCapabilities consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::Capabilities() const
{
    Windows::ApplicationModel::Email::EmailMailboxCapabilities value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailbox)->get_Capabilities(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Email::EmailMailboxChangeTracker consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::ChangeTracker() const
{
    Windows::ApplicationModel::Email::EmailMailboxChangeTracker value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailbox)->get_ChangeTracker(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::DisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailbox)->get_DisplayName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::DisplayName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailbox)->put_DisplayName(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailbox)->get_Id(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::IsOwnedByCurrentApp() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailbox)->get_IsOwnedByCurrentApp(&value));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::IsDataEncryptedUnderLock() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailbox)->get_IsDataEncryptedUnderLock(&value));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::MailAddress() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailbox)->get_MailAddress(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::MailAddress(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailbox)->put_MailAddress(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVector<hstring> consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::MailAddressAliases() const
{
    Windows::Foundation::Collections::IVector<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailbox)->get_MailAddressAliases(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Email::EmailMailboxOtherAppReadAccess consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::OtherAppReadAccess() const
{
    Windows::ApplicationModel::Email::EmailMailboxOtherAppReadAccess value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailbox)->get_OtherAppReadAccess(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::OtherAppReadAccess(Windows::ApplicationModel::Email::EmailMailboxOtherAppReadAccess const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailbox)->put_OtherAppReadAccess(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::Email::EmailMailboxOtherAppWriteAccess consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::OtherAppWriteAccess() const
{
    Windows::ApplicationModel::Email::EmailMailboxOtherAppWriteAccess value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailbox)->get_OtherAppWriteAccess(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::OtherAppWriteAccess(Windows::ApplicationModel::Email::EmailMailboxOtherAppWriteAccess const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailbox)->put_OtherAppWriteAccess(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::Email::EmailMailboxPolicies consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::Policies() const
{
    Windows::ApplicationModel::Email::EmailMailboxPolicies value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailbox)->get_Policies(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::SourceDisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailbox)->get_SourceDisplayName(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Email::EmailMailboxSyncManager consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::SyncManager() const
{
    Windows::ApplicationModel::Email::EmailMailboxSyncManager value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailbox)->get_SyncManager(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::UserDataAccountId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailbox)->get_UserDataAccountId(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Email::EmailConversationReader consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::GetConversationReader() const
{
    Windows::ApplicationModel::Email::EmailConversationReader result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailbox)->GetConversationReader(put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Email::EmailConversationReader consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::GetConversationReader(Windows::ApplicationModel::Email::EmailQueryOptions const& options) const
{
    Windows::ApplicationModel::Email::EmailConversationReader result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailbox)->GetConversationReaderWithOptions(get_abi(options), put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Email::EmailMessageReader consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::GetMessageReader() const
{
    Windows::ApplicationModel::Email::EmailMessageReader result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailbox)->GetMessageReader(put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Email::EmailMessageReader consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::GetMessageReader(Windows::ApplicationModel::Email::EmailQueryOptions const& options) const
{
    Windows::ApplicationModel::Email::EmailMessageReader result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailbox)->GetMessageReaderWithOptions(get_abi(options), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::DeleteAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailbox)->DeleteAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailConversation> consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::GetConversationAsync(param::hstring const& id) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailConversation> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailbox)->GetConversationAsync(get_abi(id), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailFolder> consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::GetFolderAsync(param::hstring const& id) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailFolder> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailbox)->GetFolderAsync(get_abi(id), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailMessage> consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::GetMessageAsync(param::hstring const& id) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailMessage> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailbox)->GetMessageAsync(get_abi(id), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailFolder> consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::GetSpecialFolderAsync(Windows::ApplicationModel::Email::EmailSpecialFolderKind const& folderType) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailFolder> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailbox)->GetSpecialFolderAsync(get_abi(folderType), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::SaveAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailbox)->SaveAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::MarkMessageAsSeenAsync(param::hstring const& messageId) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailbox)->MarkMessageAsSeenAsync(get_abi(messageId), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::MarkFolderAsSeenAsync(param::hstring const& folderId) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailbox)->MarkFolderAsSeenAsync(get_abi(folderId), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::MarkMessageReadAsync(param::hstring const& messageId, bool isRead) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailbox)->MarkMessageReadAsync(get_abi(messageId), isRead, put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::ChangeMessageFlagStateAsync(param::hstring const& messageId, Windows::ApplicationModel::Email::EmailFlagState const& flagState) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailbox)->ChangeMessageFlagStateAsync(get_abi(messageId), get_abi(flagState), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::TryMoveMessageAsync(param::hstring const& messageId, param::hstring const& newParentFolderId) const
{
    Windows::Foundation::IAsyncOperation<bool> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailbox)->TryMoveMessageAsync(get_abi(messageId), get_abi(newParentFolderId), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::TryMoveFolderAsync(param::hstring const& folderId, param::hstring const& newParentFolderId) const
{
    Windows::Foundation::IAsyncOperation<bool> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailbox)->TryMoveFolderAsync(get_abi(folderId), get_abi(newParentFolderId), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::TryMoveFolderAsync(param::hstring const& folderId, param::hstring const& newParentFolderId, param::hstring const& newFolderName) const
{
    Windows::Foundation::IAsyncOperation<bool> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailbox)->TryMoveFolderWithNewNameAsync(get_abi(folderId), get_abi(newParentFolderId), get_abi(newFolderName), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::DeleteMessageAsync(param::hstring const& messageId) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailbox)->DeleteMessageAsync(get_abi(messageId), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::MarkFolderSyncEnabledAsync(param::hstring const& folderId, bool isSyncEnabled) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailbox)->MarkFolderSyncEnabledAsync(get_abi(folderId), isSyncEnabled, put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::SendMessageAsync(Windows::ApplicationModel::Email::EmailMessage const& message) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailbox)->SendMessageAsync(get_abi(message), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::SaveDraftAsync(Windows::ApplicationModel::Email::EmailMessage const& message) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailbox)->SaveDraftAsync(get_abi(message), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::DownloadMessageAsync(param::hstring const& messageId) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailbox)->DownloadMessageAsync(get_abi(messageId), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::DownloadAttachmentAsync(param::hstring const& attachmentId) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailbox)->DownloadAttachmentAsync(get_abi(attachmentId), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailMessage> consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::CreateResponseMessageAsync(param::hstring const& messageId, Windows::ApplicationModel::Email::EmailMessageResponseKind const& responseType, param::hstring const& subject, Windows::ApplicationModel::Email::EmailMessageBodyKind const& responseHeaderType, param::hstring const& responseHeader) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailMessage> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailbox)->CreateResponseMessageAsync(get_abi(messageId), get_abi(responseType), get_abi(subject), get_abi(responseHeaderType), get_abi(responseHeader), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::TryUpdateMeetingResponseAsync(Windows::ApplicationModel::Email::EmailMessage const& meeting, Windows::ApplicationModel::Email::EmailMeetingResponseType const& response, param::hstring const& subject, param::hstring const& comment, bool sendUpdate) const
{
    Windows::Foundation::IAsyncOperation<bool> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailbox)->TryUpdateMeetingResponseAsync(get_abi(meeting), get_abi(response), get_abi(subject), get_abi(comment), sendUpdate, put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::TryForwardMeetingAsync(Windows::ApplicationModel::Email::EmailMessage const& meeting, param::async_iterable<Windows::ApplicationModel::Email::EmailRecipient> const& recipients, param::hstring const& subject, Windows::ApplicationModel::Email::EmailMessageBodyKind const& forwardHeaderType, param::hstring const& forwardHeader, param::hstring const& comment) const
{
    Windows::Foundation::IAsyncOperation<bool> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailbox)->TryForwardMeetingAsync(get_abi(meeting), get_abi(recipients), get_abi(subject), get_abi(forwardHeaderType), get_abi(forwardHeader), get_abi(comment), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::TryProposeNewTimeForMeetingAsync(Windows::ApplicationModel::Email::EmailMessage const& meeting, Windows::Foundation::DateTime const& newStartTime, Windows::Foundation::TimeSpan const& newDuration, param::hstring const& subject, param::hstring const& comment) const
{
    Windows::Foundation::IAsyncOperation<bool> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailbox)->TryProposeNewTimeForMeetingAsync(get_abi(meeting), get_abi(newStartTime), get_abi(newDuration), get_abi(subject), get_abi(comment), put_abi(result)));
    return result;
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::MailboxChanged(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Email::EmailMailbox, Windows::ApplicationModel::Email::EmailMailboxChangedEventArgs> const& pHandler) const
{
    winrt::event_token pToken{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailbox)->add_MailboxChanged(get_abi(pHandler), put_abi(pToken)));
    return pToken;
}

template <typename D> typename consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::MailboxChanged_revoker consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::MailboxChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Email::EmailMailbox, Windows::ApplicationModel::Email::EmailMailboxChangedEventArgs> const& pHandler) const
{
    return impl::make_event_revoker<D, MailboxChanged_revoker>(this, MailboxChanged(pHandler));
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::MailboxChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailbox)->remove_MailboxChanged(get_abi(token)));
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::SendMessageAsync(Windows::ApplicationModel::Email::EmailMessage const& message, bool smartSend) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailbox)->SmartSendMessageAsync(get_abi(message), smartSend, put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::TrySetAutoReplySettingsAsync(Windows::ApplicationModel::Email::EmailMailboxAutoReplySettings const& autoReplySettings) const
{
    Windows::Foundation::IAsyncOperation<bool> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailbox)->TrySetAutoReplySettingsAsync(get_abi(autoReplySettings), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailMailboxAutoReplySettings> consume_Windows_ApplicationModel_Email_IEmailMailbox<D>::TryGetAutoReplySettingsAsync(Windows::ApplicationModel::Email::EmailMailboxAutoReplyMessageResponseKind const& requestedFormat) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailMailboxAutoReplySettings> autoReplySettings{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailbox)->TryGetAutoReplySettingsAsync(get_abi(requestedFormat), put_abi(autoReplySettings)));
    return autoReplySettings;
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_IEmailMailbox2<D>::LinkedMailboxId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailbox2)->get_LinkedMailboxId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_IEmailMailbox2<D>::NetworkAccountId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailbox2)->get_NetworkAccountId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_IEmailMailbox2<D>::NetworkId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailbox2)->get_NetworkId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Email::EmailRecipientResolutionResult>> consume_Windows_ApplicationModel_Email_IEmailMailbox3<D>::ResolveRecipientsAsync(param::async_iterable<hstring> const& recipients) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Email::EmailRecipientResolutionResult>> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailbox3)->ResolveRecipientsAsync(get_abi(recipients), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Email::EmailCertificateValidationStatus>> consume_Windows_ApplicationModel_Email_IEmailMailbox3<D>::ValidateCertificatesAsync(param::async_iterable<Windows::Security::Cryptography::Certificates::Certificate> const& certificates) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Email::EmailCertificateValidationStatus>> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailbox3)->ValidateCertificatesAsync(get_abi(certificates), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailMailboxEmptyFolderStatus> consume_Windows_ApplicationModel_Email_IEmailMailbox3<D>::TryEmptyFolderAsync(param::hstring const& folderId) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailMailboxEmptyFolderStatus> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailbox3)->TryEmptyFolderAsync(get_abi(folderId), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailMailboxCreateFolderResult> consume_Windows_ApplicationModel_Email_IEmailMailbox3<D>::TryCreateFolderAsync(param::hstring const& parentFolderId, param::hstring const& name) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailMailboxCreateFolderResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailbox3)->TryCreateFolderAsync(get_abi(parentFolderId), get_abi(name), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailMailboxDeleteFolderStatus> consume_Windows_ApplicationModel_Email_IEmailMailbox3<D>::TryDeleteFolderAsync(param::hstring const& folderId) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailMailboxDeleteFolderStatus> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailbox3)->TryDeleteFolderAsync(get_abi(folderId), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Email_IEmailMailbox4<D>::RegisterSyncManagerAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailbox4)->RegisterSyncManagerAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Email::EmailMailboxChangeTracker consume_Windows_ApplicationModel_Email_IEmailMailbox5<D>::GetChangeTracker(param::hstring const& identity) const
{
    Windows::ApplicationModel::Email::EmailMailboxChangeTracker result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailbox5)->GetChangeTracker(get_abi(identity), put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Email::EmailMailboxActionKind consume_Windows_ApplicationModel_Email_IEmailMailboxAction<D>::Kind() const
{
    Windows::ApplicationModel::Email::EmailMailboxActionKind value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxAction)->get_Kind(put_abi(value)));
    return value;
}

template <typename D> uint64_t consume_Windows_ApplicationModel_Email_IEmailMailboxAction<D>::ChangeNumber() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxAction)->get_ChangeNumber(&value));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Email_IEmailMailboxAutoReply<D>::IsEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxAutoReply)->get_IsEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMailboxAutoReply<D>::IsEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxAutoReply)->put_IsEnabled(value));
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_IEmailMailboxAutoReply<D>::Response() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxAutoReply)->get_Response(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMailboxAutoReply<D>::Response(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxAutoReply)->put_Response(get_abi(value)));
}

template <typename D> bool consume_Windows_ApplicationModel_Email_IEmailMailboxAutoReplySettings<D>::IsEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxAutoReplySettings)->get_IsEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMailboxAutoReplySettings<D>::IsEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxAutoReplySettings)->put_IsEnabled(value));
}

template <typename D> Windows::ApplicationModel::Email::EmailMailboxAutoReplyMessageResponseKind consume_Windows_ApplicationModel_Email_IEmailMailboxAutoReplySettings<D>::ResponseKind() const
{
    Windows::ApplicationModel::Email::EmailMailboxAutoReplyMessageResponseKind value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxAutoReplySettings)->get_ResponseKind(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMailboxAutoReplySettings<D>::ResponseKind(Windows::ApplicationModel::Email::EmailMailboxAutoReplyMessageResponseKind const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxAutoReplySettings)->put_ResponseKind(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::DateTime> consume_Windows_ApplicationModel_Email_IEmailMailboxAutoReplySettings<D>::StartTime() const
{
    Windows::Foundation::IReference<Windows::Foundation::DateTime> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxAutoReplySettings)->get_StartTime(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMailboxAutoReplySettings<D>::StartTime(optional<Windows::Foundation::DateTime> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxAutoReplySettings)->put_StartTime(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::DateTime> consume_Windows_ApplicationModel_Email_IEmailMailboxAutoReplySettings<D>::EndTime() const
{
    Windows::Foundation::IReference<Windows::Foundation::DateTime> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxAutoReplySettings)->get_EndTime(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMailboxAutoReplySettings<D>::EndTime(optional<Windows::Foundation::DateTime> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxAutoReplySettings)->put_EndTime(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::Email::EmailMailboxAutoReply consume_Windows_ApplicationModel_Email_IEmailMailboxAutoReplySettings<D>::InternalReply() const
{
    Windows::ApplicationModel::Email::EmailMailboxAutoReply value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxAutoReplySettings)->get_InternalReply(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Email::EmailMailboxAutoReply consume_Windows_ApplicationModel_Email_IEmailMailboxAutoReplySettings<D>::KnownExternalReply() const
{
    Windows::ApplicationModel::Email::EmailMailboxAutoReply value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxAutoReplySettings)->get_KnownExternalReply(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Email::EmailMailboxAutoReply consume_Windows_ApplicationModel_Email_IEmailMailboxAutoReplySettings<D>::UnknownExternalReply() const
{
    Windows::ApplicationModel::Email::EmailMailboxAutoReply value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxAutoReplySettings)->get_UnknownExternalReply(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Email_IEmailMailboxCapabilities<D>::CanForwardMeetings() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxCapabilities)->get_CanForwardMeetings(&value));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Email_IEmailMailboxCapabilities<D>::CanGetAndSetExternalAutoReplies() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxCapabilities)->get_CanGetAndSetExternalAutoReplies(&value));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Email_IEmailMailboxCapabilities<D>::CanGetAndSetInternalAutoReplies() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxCapabilities)->get_CanGetAndSetInternalAutoReplies(&value));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Email_IEmailMailboxCapabilities<D>::CanUpdateMeetingResponses() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxCapabilities)->get_CanUpdateMeetingResponses(&value));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Email_IEmailMailboxCapabilities<D>::CanServerSearchFolders() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxCapabilities)->get_CanServerSearchFolders(&value));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Email_IEmailMailboxCapabilities<D>::CanServerSearchMailbox() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxCapabilities)->get_CanServerSearchMailbox(&value));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Email_IEmailMailboxCapabilities<D>::CanProposeNewTimeForMeetings() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxCapabilities)->get_CanProposeNewTimeForMeetings(&value));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Email_IEmailMailboxCapabilities<D>::CanSmartSend() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxCapabilities)->get_CanSmartSend(&value));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Email_IEmailMailboxCapabilities2<D>::CanResolveRecipients() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxCapabilities2)->get_CanResolveRecipients(&value));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Email_IEmailMailboxCapabilities2<D>::CanValidateCertificates() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxCapabilities2)->get_CanValidateCertificates(&value));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Email_IEmailMailboxCapabilities2<D>::CanEmptyFolder() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxCapabilities2)->get_CanEmptyFolder(&value));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Email_IEmailMailboxCapabilities2<D>::CanCreateFolder() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxCapabilities2)->get_CanCreateFolder(&value));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Email_IEmailMailboxCapabilities2<D>::CanDeleteFolder() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxCapabilities2)->get_CanDeleteFolder(&value));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Email_IEmailMailboxCapabilities2<D>::CanMoveFolder() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxCapabilities2)->get_CanMoveFolder(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMailboxCapabilities3<D>::CanForwardMeetings(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxCapabilities3)->put_CanForwardMeetings(value));
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMailboxCapabilities3<D>::CanGetAndSetExternalAutoReplies(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxCapabilities3)->put_CanGetAndSetExternalAutoReplies(value));
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMailboxCapabilities3<D>::CanGetAndSetInternalAutoReplies(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxCapabilities3)->put_CanGetAndSetInternalAutoReplies(value));
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMailboxCapabilities3<D>::CanUpdateMeetingResponses(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxCapabilities3)->put_CanUpdateMeetingResponses(value));
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMailboxCapabilities3<D>::CanServerSearchFolders(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxCapabilities3)->put_CanServerSearchFolders(value));
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMailboxCapabilities3<D>::CanServerSearchMailbox(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxCapabilities3)->put_CanServerSearchMailbox(value));
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMailboxCapabilities3<D>::CanProposeNewTimeForMeetings(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxCapabilities3)->put_CanProposeNewTimeForMeetings(value));
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMailboxCapabilities3<D>::CanSmartSend(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxCapabilities3)->put_CanSmartSend(value));
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMailboxCapabilities3<D>::CanResolveRecipients(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxCapabilities3)->put_CanResolveRecipients(value));
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMailboxCapabilities3<D>::CanValidateCertificates(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxCapabilities3)->put_CanValidateCertificates(value));
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMailboxCapabilities3<D>::CanEmptyFolder(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxCapabilities3)->put_CanEmptyFolder(value));
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMailboxCapabilities3<D>::CanCreateFolder(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxCapabilities3)->put_CanCreateFolder(value));
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMailboxCapabilities3<D>::CanDeleteFolder(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxCapabilities3)->put_CanDeleteFolder(value));
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMailboxCapabilities3<D>::CanMoveFolder(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxCapabilities3)->put_CanMoveFolder(value));
}

template <typename D> Windows::ApplicationModel::Email::EmailMailboxChangeType consume_Windows_ApplicationModel_Email_IEmailMailboxChange<D>::ChangeType() const
{
    Windows::ApplicationModel::Email::EmailMailboxChangeType value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxChange)->get_ChangeType(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Email::EmailMailboxAction> consume_Windows_ApplicationModel_Email_IEmailMailboxChange<D>::MailboxActions() const
{
    Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Email::EmailMailboxAction> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxChange)->get_MailboxActions(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Email::EmailMessage consume_Windows_ApplicationModel_Email_IEmailMailboxChange<D>::Message() const
{
    Windows::ApplicationModel::Email::EmailMessage value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxChange)->get_Message(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Email::EmailFolder consume_Windows_ApplicationModel_Email_IEmailMailboxChange<D>::Folder() const
{
    Windows::ApplicationModel::Email::EmailFolder value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxChange)->get_Folder(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMailboxChangeReader<D>::AcceptChanges() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxChangeReader)->AcceptChanges());
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMailboxChangeReader<D>::AcceptChangesThrough(Windows::ApplicationModel::Email::EmailMailboxChange const& lastChangeToAcknowledge) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxChangeReader)->AcceptChangesThrough(get_abi(lastChangeToAcknowledge)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Email::EmailMailboxChange>> consume_Windows_ApplicationModel_Email_IEmailMailboxChangeReader<D>::ReadBatchAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Email::EmailMailboxChange>> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxChangeReader)->ReadBatchAsync(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Email_IEmailMailboxChangeTracker<D>::IsTracking() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxChangeTracker)->get_IsTracking(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMailboxChangeTracker<D>::Enable() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxChangeTracker)->Enable());
}

template <typename D> Windows::ApplicationModel::Email::EmailMailboxChangeReader consume_Windows_ApplicationModel_Email_IEmailMailboxChangeTracker<D>::GetChangeReader() const
{
    Windows::ApplicationModel::Email::EmailMailboxChangeReader value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxChangeTracker)->GetChangeReader(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMailboxChangeTracker<D>::Reset() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxChangeTracker)->Reset());
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMailboxChangedDeferral<D>::Complete() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxChangedDeferral)->Complete());
}

template <typename D> Windows::ApplicationModel::Email::EmailMailboxChangedDeferral consume_Windows_ApplicationModel_Email_IEmailMailboxChangedEventArgs<D>::GetDeferral() const
{
    Windows::ApplicationModel::Email::EmailMailboxChangedDeferral result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxChangedEventArgs)->GetDeferral(put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Email::EmailMailboxCreateFolderStatus consume_Windows_ApplicationModel_Email_IEmailMailboxCreateFolderResult<D>::Status() const
{
    Windows::ApplicationModel::Email::EmailMailboxCreateFolderStatus value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxCreateFolderResult)->get_Status(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Email::EmailFolder consume_Windows_ApplicationModel_Email_IEmailMailboxCreateFolderResult<D>::Folder() const
{
    Windows::ApplicationModel::Email::EmailFolder value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxCreateFolderResult)->get_Folder(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Email::EmailMailboxAllowedSmimeEncryptionAlgorithmNegotiation consume_Windows_ApplicationModel_Email_IEmailMailboxPolicies<D>::AllowedSmimeEncryptionAlgorithmNegotiation() const
{
    Windows::ApplicationModel::Email::EmailMailboxAllowedSmimeEncryptionAlgorithmNegotiation value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxPolicies)->get_AllowedSmimeEncryptionAlgorithmNegotiation(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Email_IEmailMailboxPolicies<D>::AllowSmimeSoftCertificates() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxPolicies)->get_AllowSmimeSoftCertificates(&value));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::ApplicationModel::Email::EmailMailboxSmimeEncryptionAlgorithm> consume_Windows_ApplicationModel_Email_IEmailMailboxPolicies<D>::RequiredSmimeEncryptionAlgorithm() const
{
    Windows::Foundation::IReference<Windows::ApplicationModel::Email::EmailMailboxSmimeEncryptionAlgorithm> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxPolicies)->get_RequiredSmimeEncryptionAlgorithm(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::ApplicationModel::Email::EmailMailboxSmimeSigningAlgorithm> consume_Windows_ApplicationModel_Email_IEmailMailboxPolicies<D>::RequiredSmimeSigningAlgorithm() const
{
    Windows::Foundation::IReference<Windows::ApplicationModel::Email::EmailMailboxSmimeSigningAlgorithm> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxPolicies)->get_RequiredSmimeSigningAlgorithm(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Email_IEmailMailboxPolicies2<D>::MustEncryptSmimeMessages() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxPolicies2)->get_MustEncryptSmimeMessages(&value));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Email_IEmailMailboxPolicies2<D>::MustSignSmimeMessages() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxPolicies2)->get_MustSignSmimeMessages(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMailboxPolicies3<D>::AllowedSmimeEncryptionAlgorithmNegotiation(Windows::ApplicationModel::Email::EmailMailboxAllowedSmimeEncryptionAlgorithmNegotiation const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxPolicies3)->put_AllowedSmimeEncryptionAlgorithmNegotiation(get_abi(value)));
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMailboxPolicies3<D>::AllowSmimeSoftCertificates(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxPolicies3)->put_AllowSmimeSoftCertificates(value));
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMailboxPolicies3<D>::RequiredSmimeEncryptionAlgorithm(optional<Windows::ApplicationModel::Email::EmailMailboxSmimeEncryptionAlgorithm> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxPolicies3)->put_RequiredSmimeEncryptionAlgorithm(get_abi(value)));
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMailboxPolicies3<D>::RequiredSmimeSigningAlgorithm(optional<Windows::ApplicationModel::Email::EmailMailboxSmimeSigningAlgorithm> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxPolicies3)->put_RequiredSmimeSigningAlgorithm(get_abi(value)));
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMailboxPolicies3<D>::MustEncryptSmimeMessages(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxPolicies3)->put_MustEncryptSmimeMessages(value));
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMailboxPolicies3<D>::MustSignSmimeMessages(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxPolicies3)->put_MustSignSmimeMessages(value));
}

template <typename D> Windows::ApplicationModel::Email::EmailMailboxSyncStatus consume_Windows_ApplicationModel_Email_IEmailMailboxSyncManager<D>::Status() const
{
    Windows::ApplicationModel::Email::EmailMailboxSyncStatus value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxSyncManager)->get_Status(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_ApplicationModel_Email_IEmailMailboxSyncManager<D>::LastSuccessfulSyncTime() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxSyncManager)->get_LastSuccessfulSyncTime(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_ApplicationModel_Email_IEmailMailboxSyncManager<D>::LastAttemptedSyncTime() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxSyncManager)->get_LastAttemptedSyncTime(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_ApplicationModel_Email_IEmailMailboxSyncManager<D>::SyncAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxSyncManager)->SyncAsync(put_abi(result)));
    return result;
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Email_IEmailMailboxSyncManager<D>::SyncStatusChanged(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Email::EmailMailboxSyncManager, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxSyncManager)->add_SyncStatusChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Email_IEmailMailboxSyncManager<D>::SyncStatusChanged_revoker consume_Windows_ApplicationModel_Email_IEmailMailboxSyncManager<D>::SyncStatusChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Email::EmailMailboxSyncManager, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, SyncStatusChanged_revoker>(this, SyncStatusChanged(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMailboxSyncManager<D>::SyncStatusChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxSyncManager)->remove_SyncStatusChanged(get_abi(token)));
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMailboxSyncManager2<D>::Status(Windows::ApplicationModel::Email::EmailMailboxSyncStatus const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxSyncManager2)->put_Status(get_abi(value)));
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMailboxSyncManager2<D>::LastSuccessfulSyncTime(Windows::Foundation::DateTime const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxSyncManager2)->put_LastSuccessfulSyncTime(get_abi(value)));
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMailboxSyncManager2<D>::LastAttemptedSyncTime(Windows::Foundation::DateTime const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMailboxSyncManager2)->put_LastAttemptedSyncTime(get_abi(value)));
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Email_IEmailManagerForUser<D>::ShowComposeNewEmailAsync(Windows::ApplicationModel::Email::EmailMessage const& message) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailManagerForUser)->ShowComposeNewEmailAsync(get_abi(message), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailStore> consume_Windows_ApplicationModel_Email_IEmailManagerForUser<D>::RequestStoreAsync(Windows::ApplicationModel::Email::EmailStoreAccessType const& accessType) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailStore> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailManagerForUser)->RequestStoreAsync(get_abi(accessType), put_abi(result)));
    return result;
}

template <typename D> Windows::System::User consume_Windows_ApplicationModel_Email_IEmailManagerForUser<D>::User() const
{
    Windows::System::User value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailManagerForUser)->get_User(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Email_IEmailManagerStatics<D>::ShowComposeNewEmailAsync(Windows::ApplicationModel::Email::EmailMessage const& message) const
{
    Windows::Foundation::IAsyncAction asyncAction{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailManagerStatics)->ShowComposeNewEmailAsync(get_abi(message), put_abi(asyncAction)));
    return asyncAction;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailStore> consume_Windows_ApplicationModel_Email_IEmailManagerStatics2<D>::RequestStoreAsync(Windows::ApplicationModel::Email::EmailStoreAccessType const& accessType) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailStore> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailManagerStatics2)->RequestStoreAsync(get_abi(accessType), put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Email::EmailManagerForUser consume_Windows_ApplicationModel_Email_IEmailManagerStatics3<D>::GetForUser(Windows::System::User const& user) const
{
    Windows::ApplicationModel::Email::EmailManagerForUser result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailManagerStatics3)->GetForUser(get_abi(user), put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_ApplicationModel_Email_IEmailMeetingInfo<D>::AllowNewTimeProposal() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMeetingInfo)->get_AllowNewTimeProposal(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMeetingInfo<D>::AllowNewTimeProposal(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMeetingInfo)->put_AllowNewTimeProposal(value));
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_IEmailMeetingInfo<D>::AppointmentRoamingId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMeetingInfo)->get_AppointmentRoamingId(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMeetingInfo<D>::AppointmentRoamingId(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMeetingInfo)->put_AppointmentRoamingId(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::DateTime> consume_Windows_ApplicationModel_Email_IEmailMeetingInfo<D>::AppointmentOriginalStartTime() const
{
    Windows::Foundation::IReference<Windows::Foundation::DateTime> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMeetingInfo)->get_AppointmentOriginalStartTime(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMeetingInfo<D>::AppointmentOriginalStartTime(optional<Windows::Foundation::DateTime> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMeetingInfo)->put_AppointmentOriginalStartTime(get_abi(value)));
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_ApplicationModel_Email_IEmailMeetingInfo<D>::Duration() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMeetingInfo)->get_Duration(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMeetingInfo<D>::Duration(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMeetingInfo)->put_Duration(get_abi(value)));
}

template <typename D> bool consume_Windows_ApplicationModel_Email_IEmailMeetingInfo<D>::IsAllDay() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMeetingInfo)->get_IsAllDay(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMeetingInfo<D>::IsAllDay(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMeetingInfo)->put_IsAllDay(value));
}

template <typename D> bool consume_Windows_ApplicationModel_Email_IEmailMeetingInfo<D>::IsResponseRequested() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMeetingInfo)->get_IsResponseRequested(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMeetingInfo<D>::IsResponseRequested(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMeetingInfo)->put_IsResponseRequested(value));
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_IEmailMeetingInfo<D>::Location() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMeetingInfo)->get_Location(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMeetingInfo<D>::Location(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMeetingInfo)->put_Location(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::DateTime> consume_Windows_ApplicationModel_Email_IEmailMeetingInfo<D>::ProposedStartTime() const
{
    Windows::Foundation::IReference<Windows::Foundation::DateTime> proposedStartTime{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMeetingInfo)->get_ProposedStartTime(put_abi(proposedStartTime)));
    return proposedStartTime;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMeetingInfo<D>::ProposedStartTime(optional<Windows::Foundation::DateTime> const& proposedStartTime) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMeetingInfo)->put_ProposedStartTime(get_abi(proposedStartTime)));
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::TimeSpan> consume_Windows_ApplicationModel_Email_IEmailMeetingInfo<D>::ProposedDuration() const
{
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> duration{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMeetingInfo)->get_ProposedDuration(put_abi(duration)));
    return duration;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMeetingInfo<D>::ProposedDuration(optional<Windows::Foundation::TimeSpan> const& duration) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMeetingInfo)->put_ProposedDuration(get_abi(duration)));
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::DateTime> consume_Windows_ApplicationModel_Email_IEmailMeetingInfo<D>::RecurrenceStartTime() const
{
    Windows::Foundation::IReference<Windows::Foundation::DateTime> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMeetingInfo)->get_RecurrenceStartTime(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMeetingInfo<D>::RecurrenceStartTime(optional<Windows::Foundation::DateTime> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMeetingInfo)->put_RecurrenceStartTime(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::Appointments::AppointmentRecurrence consume_Windows_ApplicationModel_Email_IEmailMeetingInfo<D>::Recurrence() const
{
    Windows::ApplicationModel::Appointments::AppointmentRecurrence value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMeetingInfo)->get_Recurrence(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMeetingInfo<D>::Recurrence(Windows::ApplicationModel::Appointments::AppointmentRecurrence const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMeetingInfo)->put_Recurrence(get_abi(value)));
}

template <typename D> uint64_t consume_Windows_ApplicationModel_Email_IEmailMeetingInfo<D>::RemoteChangeNumber() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMeetingInfo)->get_RemoteChangeNumber(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMeetingInfo<D>::RemoteChangeNumber(uint64_t value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMeetingInfo)->put_RemoteChangeNumber(value));
}

template <typename D> Windows::Foundation::DateTime consume_Windows_ApplicationModel_Email_IEmailMeetingInfo<D>::StartTime() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMeetingInfo)->get_StartTime(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMeetingInfo<D>::StartTime(Windows::Foundation::DateTime const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMeetingInfo)->put_StartTime(get_abi(value)));
}

template <typename D> bool consume_Windows_ApplicationModel_Email_IEmailMeetingInfo2<D>::IsReportedOutOfDateByServer() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMeetingInfo2)->get_IsReportedOutOfDateByServer(&value));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_IEmailMessage<D>::Subject() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMessage)->get_Subject(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMessage<D>::Subject(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMessage)->put_Subject(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_IEmailMessage<D>::Body() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMessage)->get_Body(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMessage<D>::Body(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMessage)->put_Body(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Email::EmailRecipient> consume_Windows_ApplicationModel_Email_IEmailMessage<D>::To() const
{
    Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Email::EmailRecipient> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMessage)->get_To(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Email::EmailRecipient> consume_Windows_ApplicationModel_Email_IEmailMessage<D>::CC() const
{
    Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Email::EmailRecipient> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMessage)->get_CC(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Email::EmailRecipient> consume_Windows_ApplicationModel_Email_IEmailMessage<D>::Bcc() const
{
    Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Email::EmailRecipient> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMessage)->get_Bcc(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Email::EmailAttachment> consume_Windows_ApplicationModel_Email_IEmailMessage<D>::Attachments() const
{
    Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Email::EmailAttachment> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMessage)->get_Attachments(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMessage2)->get_Id(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::RemoteId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMessage2)->get_RemoteId(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::RemoteId(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMessage2)->put_RemoteId(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::MailboxId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMessage2)->get_MailboxId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::ConversationId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMessage2)->get_ConversationId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::FolderId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMessage2)->get_FolderId(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::AllowInternetImages() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMessage2)->get_AllowInternetImages(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::AllowInternetImages(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMessage2)->put_AllowInternetImages(value));
}

template <typename D> uint64_t consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::ChangeNumber() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMessage2)->get_ChangeNumber(&value));
    return value;
}

template <typename D> Windows::ApplicationModel::Email::EmailMessageDownloadState consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::DownloadState() const
{
    Windows::ApplicationModel::Email::EmailMessageDownloadState value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMessage2)->get_DownloadState(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::DownloadState(Windows::ApplicationModel::Email::EmailMessageDownloadState const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMessage2)->put_DownloadState(get_abi(value)));
}

template <typename D> uint32_t consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::EstimatedDownloadSizeInBytes() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMessage2)->get_EstimatedDownloadSizeInBytes(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::EstimatedDownloadSizeInBytes(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMessage2)->put_EstimatedDownloadSizeInBytes(value));
}

template <typename D> Windows::ApplicationModel::Email::EmailFlagState consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::FlagState() const
{
    Windows::ApplicationModel::Email::EmailFlagState value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMessage2)->get_FlagState(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::FlagState(Windows::ApplicationModel::Email::EmailFlagState const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMessage2)->put_FlagState(get_abi(value)));
}

template <typename D> bool consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::HasPartialBodies() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMessage2)->get_HasPartialBodies(&value));
    return value;
}

template <typename D> Windows::ApplicationModel::Email::EmailImportance consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::Importance() const
{
    Windows::ApplicationModel::Email::EmailImportance value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMessage2)->get_Importance(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::Importance(Windows::ApplicationModel::Email::EmailImportance const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMessage2)->put_Importance(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::InResponseToMessageId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMessage2)->get_InResponseToMessageId(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Email::EmailIrmInfo consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::IrmInfo() const
{
    Windows::ApplicationModel::Email::EmailIrmInfo value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMessage2)->get_IrmInfo(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::IrmInfo(Windows::ApplicationModel::Email::EmailIrmInfo const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMessage2)->put_IrmInfo(get_abi(value)));
}

template <typename D> bool consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::IsDraftMessage() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMessage2)->get_IsDraftMessage(&value));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::IsRead() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMessage2)->get_IsRead(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::IsRead(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMessage2)->put_IsRead(value));
}

template <typename D> bool consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::IsSeen() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMessage2)->get_IsSeen(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::IsSeen(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMessage2)->put_IsSeen(value));
}

template <typename D> bool consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::IsServerSearchMessage() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMessage2)->get_IsServerSearchMessage(&value));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::IsSmartSendable() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMessage2)->get_IsSmartSendable(&value));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::MessageClass() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMessage2)->get_MessageClass(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::MessageClass(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMessage2)->put_MessageClass(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::NormalizedSubject() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMessage2)->get_NormalizedSubject(put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::OriginalCodePage() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMessage2)->get_OriginalCodePage(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::OriginalCodePage(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMessage2)->put_OriginalCodePage(value));
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::Preview() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMessage2)->get_Preview(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::Preview(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMessage2)->put_Preview(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::Email::EmailMessageResponseKind consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::LastResponseKind() const
{
    Windows::ApplicationModel::Email::EmailMessageResponseKind value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMessage2)->get_LastResponseKind(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::LastResponseKind(Windows::ApplicationModel::Email::EmailMessageResponseKind const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMessage2)->put_LastResponseKind(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::Email::EmailRecipient consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::Sender() const
{
    Windows::ApplicationModel::Email::EmailRecipient value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMessage2)->get_Sender(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::Sender(Windows::ApplicationModel::Email::EmailRecipient const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMessage2)->put_Sender(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::DateTime> consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::SentTime() const
{
    Windows::Foundation::IReference<Windows::Foundation::DateTime> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMessage2)->get_SentTime(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::SentTime(optional<Windows::Foundation::DateTime> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMessage2)->put_SentTime(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::Email::EmailMeetingInfo consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::MeetingInfo() const
{
    Windows::ApplicationModel::Email::EmailMeetingInfo value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMessage2)->get_MeetingInfo(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::MeetingInfo(Windows::ApplicationModel::Email::EmailMeetingInfo const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMessage2)->put_MeetingInfo(get_abi(value)));
}

template <typename D> Windows::Storage::Streams::IRandomAccessStreamReference consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::GetBodyStream(Windows::ApplicationModel::Email::EmailMessageBodyKind const& type) const
{
    Windows::Storage::Streams::IRandomAccessStreamReference result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMessage2)->GetBodyStream(get_abi(type), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMessage2<D>::SetBodyStream(Windows::ApplicationModel::Email::EmailMessageBodyKind const& type, Windows::Storage::Streams::IRandomAccessStreamReference const& stream) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMessage2)->SetBodyStream(get_abi(type), get_abi(stream)));
}

template <typename D> Windows::Storage::Streams::IRandomAccessStreamReference consume_Windows_ApplicationModel_Email_IEmailMessage3<D>::SmimeData() const
{
    Windows::Storage::Streams::IRandomAccessStreamReference value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMessage3)->get_SmimeData(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMessage3<D>::SmimeData(Windows::Storage::Streams::IRandomAccessStreamReference const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMessage3)->put_SmimeData(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::Email::EmailMessageSmimeKind consume_Windows_ApplicationModel_Email_IEmailMessage3<D>::SmimeKind() const
{
    Windows::ApplicationModel::Email::EmailMessageSmimeKind value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMessage3)->get_SmimeKind(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMessage3<D>::SmimeKind(Windows::ApplicationModel::Email::EmailMessageSmimeKind const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMessage3)->put_SmimeKind(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Email::EmailRecipient> consume_Windows_ApplicationModel_Email_IEmailMessage4<D>::ReplyTo() const
{
    Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Email::EmailRecipient> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMessage4)->get_ReplyTo(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Email::EmailRecipient consume_Windows_ApplicationModel_Email_IEmailMessage4<D>::SentRepresenting() const
{
    Windows::ApplicationModel::Email::EmailRecipient value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMessage4)->get_SentRepresenting(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailMessage4<D>::SentRepresenting(Windows::ApplicationModel::Email::EmailRecipient const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMessage4)->put_SentRepresenting(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Email::EmailMessage> consume_Windows_ApplicationModel_Email_IEmailMessageBatch<D>::Messages() const
{
    Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Email::EmailMessage> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMessageBatch)->get_Messages(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Email::EmailBatchStatus consume_Windows_ApplicationModel_Email_IEmailMessageBatch<D>::Status() const
{
    Windows::ApplicationModel::Email::EmailBatchStatus value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMessageBatch)->get_Status(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailMessageBatch> consume_Windows_ApplicationModel_Email_IEmailMessageReader<D>::ReadBatchAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailMessageBatch> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailMessageReader)->ReadBatchAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Email::EmailQueryTextSearch consume_Windows_ApplicationModel_Email_IEmailQueryOptions<D>::TextSearch() const
{
    Windows::ApplicationModel::Email::EmailQueryTextSearch value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailQueryOptions)->get_TextSearch(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Email::EmailQuerySortDirection consume_Windows_ApplicationModel_Email_IEmailQueryOptions<D>::SortDirection() const
{
    Windows::ApplicationModel::Email::EmailQuerySortDirection value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailQueryOptions)->get_SortDirection(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailQueryOptions<D>::SortDirection(Windows::ApplicationModel::Email::EmailQuerySortDirection const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailQueryOptions)->put_SortDirection(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::Email::EmailQuerySortProperty consume_Windows_ApplicationModel_Email_IEmailQueryOptions<D>::SortProperty() const
{
    Windows::ApplicationModel::Email::EmailQuerySortProperty value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailQueryOptions)->get_SortProperty(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailQueryOptions<D>::SortProperty(Windows::ApplicationModel::Email::EmailQuerySortProperty const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailQueryOptions)->put_SortProperty(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::Email::EmailQueryKind consume_Windows_ApplicationModel_Email_IEmailQueryOptions<D>::Kind() const
{
    Windows::ApplicationModel::Email::EmailQueryKind value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailQueryOptions)->get_Kind(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailQueryOptions<D>::Kind(Windows::ApplicationModel::Email::EmailQueryKind const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailQueryOptions)->put_Kind(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVector<hstring> consume_Windows_ApplicationModel_Email_IEmailQueryOptions<D>::FolderIds() const
{
    Windows::Foundation::Collections::IVector<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailQueryOptions)->get_FolderIds(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Email::EmailQueryOptions consume_Windows_ApplicationModel_Email_IEmailQueryOptionsFactory<D>::CreateWithText(param::hstring const& text) const
{
    Windows::ApplicationModel::Email::EmailQueryOptions result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailQueryOptionsFactory)->CreateWithText(get_abi(text), put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Email::EmailQueryOptions consume_Windows_ApplicationModel_Email_IEmailQueryOptionsFactory<D>::CreateWithTextAndFields(param::hstring const& text, Windows::ApplicationModel::Email::EmailQuerySearchFields const& fields) const
{
    Windows::ApplicationModel::Email::EmailQueryOptions result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailQueryOptionsFactory)->CreateWithTextAndFields(get_abi(text), get_abi(fields), put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Email::EmailQuerySearchFields consume_Windows_ApplicationModel_Email_IEmailQueryTextSearch<D>::Fields() const
{
    Windows::ApplicationModel::Email::EmailQuerySearchFields value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailQueryTextSearch)->get_Fields(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailQueryTextSearch<D>::Fields(Windows::ApplicationModel::Email::EmailQuerySearchFields const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailQueryTextSearch)->put_Fields(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::Email::EmailQuerySearchScope consume_Windows_ApplicationModel_Email_IEmailQueryTextSearch<D>::SearchScope() const
{
    Windows::ApplicationModel::Email::EmailQuerySearchScope value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailQueryTextSearch)->get_SearchScope(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailQueryTextSearch<D>::SearchScope(Windows::ApplicationModel::Email::EmailQuerySearchScope const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailQueryTextSearch)->put_SearchScope(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_IEmailQueryTextSearch<D>::Text() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailQueryTextSearch)->get_Text(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailQueryTextSearch<D>::Text(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailQueryTextSearch)->put_Text(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_IEmailRecipient<D>::Name() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailRecipient)->get_Name(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailRecipient<D>::Name(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailRecipient)->put_Name(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_IEmailRecipient<D>::Address() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailRecipient)->get_Address(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailRecipient<D>::Address(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailRecipient)->put_Address(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::Email::EmailRecipient consume_Windows_ApplicationModel_Email_IEmailRecipientFactory<D>::Create(param::hstring const& address) const
{
    Windows::ApplicationModel::Email::EmailRecipient result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailRecipientFactory)->Create(get_abi(address), put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Email::EmailRecipient consume_Windows_ApplicationModel_Email_IEmailRecipientFactory<D>::CreateWithName(param::hstring const& address, param::hstring const& name) const
{
    Windows::ApplicationModel::Email::EmailRecipient result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailRecipientFactory)->CreateWithName(get_abi(address), get_abi(name), put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Email::EmailRecipientResolutionStatus consume_Windows_ApplicationModel_Email_IEmailRecipientResolutionResult<D>::Status() const
{
    Windows::ApplicationModel::Email::EmailRecipientResolutionStatus value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailRecipientResolutionResult)->get_Status(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Security::Cryptography::Certificates::Certificate> consume_Windows_ApplicationModel_Email_IEmailRecipientResolutionResult<D>::PublicKeys() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Security::Cryptography::Certificates::Certificate> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailRecipientResolutionResult)->get_PublicKeys(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailRecipientResolutionResult2<D>::Status(Windows::ApplicationModel::Email::EmailRecipientResolutionStatus const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailRecipientResolutionResult2)->put_Status(get_abi(value)));
}

template <typename D> void consume_Windows_ApplicationModel_Email_IEmailRecipientResolutionResult2<D>::SetPublicKeys(param::iterable<Windows::Security::Cryptography::Certificates::Certificate> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailRecipientResolutionResult2)->SetPublicKeys(get_abi(value)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Email::EmailMailbox>> consume_Windows_ApplicationModel_Email_IEmailStore<D>::FindMailboxesAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Email::EmailMailbox>> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailStore)->FindMailboxesAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Email::EmailConversationReader consume_Windows_ApplicationModel_Email_IEmailStore<D>::GetConversationReader() const
{
    Windows::ApplicationModel::Email::EmailConversationReader result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailStore)->GetConversationReader(put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Email::EmailConversationReader consume_Windows_ApplicationModel_Email_IEmailStore<D>::GetConversationReader(Windows::ApplicationModel::Email::EmailQueryOptions const& options) const
{
    Windows::ApplicationModel::Email::EmailConversationReader result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailStore)->GetConversationReaderWithOptions(get_abi(options), put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Email::EmailMessageReader consume_Windows_ApplicationModel_Email_IEmailStore<D>::GetMessageReader() const
{
    Windows::ApplicationModel::Email::EmailMessageReader result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailStore)->GetMessageReader(put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Email::EmailMessageReader consume_Windows_ApplicationModel_Email_IEmailStore<D>::GetMessageReader(Windows::ApplicationModel::Email::EmailQueryOptions const& options) const
{
    Windows::ApplicationModel::Email::EmailMessageReader result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailStore)->GetMessageReaderWithOptions(get_abi(options), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailMailbox> consume_Windows_ApplicationModel_Email_IEmailStore<D>::GetMailboxAsync(param::hstring const& id) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailMailbox> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailStore)->GetMailboxAsync(get_abi(id), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailConversation> consume_Windows_ApplicationModel_Email_IEmailStore<D>::GetConversationAsync(param::hstring const& id) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailConversation> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailStore)->GetConversationAsync(get_abi(id), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailFolder> consume_Windows_ApplicationModel_Email_IEmailStore<D>::GetFolderAsync(param::hstring const& id) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailFolder> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailStore)->GetFolderAsync(get_abi(id), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailMessage> consume_Windows_ApplicationModel_Email_IEmailStore<D>::GetMessageAsync(param::hstring const& id) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailMessage> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailStore)->GetMessageAsync(get_abi(id), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailMailbox> consume_Windows_ApplicationModel_Email_IEmailStore<D>::CreateMailboxAsync(param::hstring const& accountName, param::hstring const& accountAddress) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailMailbox> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailStore)->CreateMailboxAsync(get_abi(accountName), get_abi(accountAddress), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailMailbox> consume_Windows_ApplicationModel_Email_IEmailStore<D>::CreateMailboxAsync(param::hstring const& accountName, param::hstring const& accountAddress, param::hstring const& userDataAccountId) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailMailbox> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::IEmailStore)->CreateMailboxInAccountAsync(get_abi(accountName), get_abi(accountAddress), get_abi(userDataAccountId), put_abi(result)));
    return result;
}

template <typename D>
struct produce<D, Windows::ApplicationModel::Email::IEmailAttachment> : produce_base<D, Windows::ApplicationModel::Email::IEmailAttachment>
{
    int32_t WINRT_CALL get_FileName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FileName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().FileName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FileName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FileName, WINRT_WRAP(void), hstring const&);
            this->shim().FileName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Data(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Data, WINRT_WRAP(Windows::Storage::Streams::IRandomAccessStreamReference));
            *value = detach_from<Windows::Storage::Streams::IRandomAccessStreamReference>(this->shim().Data());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Data(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Data, WINRT_WRAP(void), Windows::Storage::Streams::IRandomAccessStreamReference const&);
            this->shim().Data(*reinterpret_cast<Windows::Storage::Streams::IRandomAccessStreamReference const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Email::IEmailAttachment2> : produce_base<D, Windows::ApplicationModel::Email::IEmailAttachment2>
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

    int32_t WINRT_CALL get_ContentId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ContentId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ContentId(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentId, WINRT_WRAP(void), hstring const&);
            this->shim().ContentId(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ContentLocation(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentLocation, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ContentLocation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ContentLocation(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentLocation, WINRT_WRAP(void), hstring const&);
            this->shim().ContentLocation(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DownloadState(Windows::ApplicationModel::Email::EmailAttachmentDownloadState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DownloadState, WINRT_WRAP(Windows::ApplicationModel::Email::EmailAttachmentDownloadState));
            *value = detach_from<Windows::ApplicationModel::Email::EmailAttachmentDownloadState>(this->shim().DownloadState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DownloadState(Windows::ApplicationModel::Email::EmailAttachmentDownloadState value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DownloadState, WINRT_WRAP(void), Windows::ApplicationModel::Email::EmailAttachmentDownloadState const&);
            this->shim().DownloadState(*reinterpret_cast<Windows::ApplicationModel::Email::EmailAttachmentDownloadState const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EstimatedDownloadSizeInBytes(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EstimatedDownloadSizeInBytes, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().EstimatedDownloadSizeInBytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_EstimatedDownloadSizeInBytes(uint64_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EstimatedDownloadSizeInBytes, WINRT_WRAP(void), uint64_t);
            this->shim().EstimatedDownloadSizeInBytes(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsFromBaseMessage(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsFromBaseMessage, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsFromBaseMessage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsInline(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsInline, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsInline());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsInline(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsInline, WINRT_WRAP(void), bool);
            this->shim().IsInline(value);
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
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Email::IEmailAttachmentFactory> : produce_base<D, Windows::ApplicationModel::Email::IEmailAttachmentFactory>
{
    int32_t WINRT_CALL Create(void* fileName, void* data, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::ApplicationModel::Email::EmailAttachment), hstring const&, Windows::Storage::Streams::IRandomAccessStreamReference const&);
            *result = detach_from<Windows::ApplicationModel::Email::EmailAttachment>(this->shim().Create(*reinterpret_cast<hstring const*>(&fileName), *reinterpret_cast<Windows::Storage::Streams::IRandomAccessStreamReference const*>(&data)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Email::IEmailAttachmentFactory2> : produce_base<D, Windows::ApplicationModel::Email::IEmailAttachmentFactory2>
{
    int32_t WINRT_CALL Create(void* fileName, void* data, void* mimeType, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::ApplicationModel::Email::EmailAttachment), hstring const&, Windows::Storage::Streams::IRandomAccessStreamReference const&, hstring const&);
            *result = detach_from<Windows::ApplicationModel::Email::EmailAttachment>(this->shim().Create(*reinterpret_cast<hstring const*>(&fileName), *reinterpret_cast<Windows::Storage::Streams::IRandomAccessStreamReference const*>(&data), *reinterpret_cast<hstring const*>(&mimeType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Email::IEmailConversation> : produce_base<D, Windows::ApplicationModel::Email::IEmailConversation>
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

    int32_t WINRT_CALL get_MailboxId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MailboxId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().MailboxId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FlagState(Windows::ApplicationModel::Email::EmailFlagState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FlagState, WINRT_WRAP(Windows::ApplicationModel::Email::EmailFlagState));
            *value = detach_from<Windows::ApplicationModel::Email::EmailFlagState>(this->shim().FlagState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HasAttachment(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HasAttachment, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().HasAttachment());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Importance(Windows::ApplicationModel::Email::EmailImportance* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Importance, WINRT_WRAP(Windows::ApplicationModel::Email::EmailImportance));
            *value = detach_from<Windows::ApplicationModel::Email::EmailImportance>(this->shim().Importance());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LastEmailResponseKind(Windows::ApplicationModel::Email::EmailMessageResponseKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LastEmailResponseKind, WINRT_WRAP(Windows::ApplicationModel::Email::EmailMessageResponseKind));
            *value = detach_from<Windows::ApplicationModel::Email::EmailMessageResponseKind>(this->shim().LastEmailResponseKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MessageCount(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MessageCount, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().MessageCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MostRecentMessageId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MostRecentMessageId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().MostRecentMessageId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MostRecentMessageTime(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MostRecentMessageTime, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().MostRecentMessageTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Preview(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Preview, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Preview());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LatestSender(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LatestSender, WINRT_WRAP(Windows::ApplicationModel::Email::EmailRecipient));
            *value = detach_from<Windows::ApplicationModel::Email::EmailRecipient>(this->shim().LatestSender());
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

    int32_t WINRT_CALL get_UnreadMessageCount(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UnreadMessageCount, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().UnreadMessageCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindMessagesAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindMessagesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Email::EmailMessage>>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Email::EmailMessage>>>(this->shim().FindMessagesAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindMessagesWithCountAsync(uint32_t count, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindMessagesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Email::EmailMessage>>), uint32_t);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Email::EmailMessage>>>(this->shim().FindMessagesAsync(count));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Email::IEmailConversationBatch> : produce_base<D, Windows::ApplicationModel::Email::IEmailConversationBatch>
{
    int32_t WINRT_CALL get_Conversations(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Conversations, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Email::EmailConversation>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Email::EmailConversation>>(this->shim().Conversations());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Status(Windows::ApplicationModel::Email::EmailBatchStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::ApplicationModel::Email::EmailBatchStatus));
            *value = detach_from<Windows::ApplicationModel::Email::EmailBatchStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Email::IEmailConversationReader> : produce_base<D, Windows::ApplicationModel::Email::IEmailConversationReader>
{
    int32_t WINRT_CALL ReadBatchAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadBatchAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailConversationBatch>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailConversationBatch>>(this->shim().ReadBatchAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Email::IEmailFolder> : produce_base<D, Windows::ApplicationModel::Email::IEmailFolder>
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

    int32_t WINRT_CALL get_MailboxId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MailboxId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().MailboxId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ParentFolderId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ParentFolderId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ParentFolderId());
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

    int32_t WINRT_CALL get_IsSyncEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSyncEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsSyncEnabled());
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

    int32_t WINRT_CALL get_Kind(Windows::ApplicationModel::Email::EmailSpecialFolderKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Kind, WINRT_WRAP(Windows::ApplicationModel::Email::EmailSpecialFolderKind));
            *value = detach_from<Windows::ApplicationModel::Email::EmailSpecialFolderKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFolderAsync(void* name, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFolderAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailFolder>), hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailFolder>>(this->shim().CreateFolderAsync(*reinterpret_cast<hstring const*>(&name)));
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

    int32_t WINRT_CALL FindChildFoldersAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindChildFoldersAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Email::EmailFolder>>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Email::EmailFolder>>>(this->shim().FindChildFoldersAsync());
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
            WINRT_ASSERT_DECLARATION(GetConversationReader, WINRT_WRAP(Windows::ApplicationModel::Email::EmailConversationReader));
            *result = detach_from<Windows::ApplicationModel::Email::EmailConversationReader>(this->shim().GetConversationReader());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetConversationReaderWithOptions(void* options, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetConversationReader, WINRT_WRAP(Windows::ApplicationModel::Email::EmailConversationReader), Windows::ApplicationModel::Email::EmailQueryOptions const&);
            *result = detach_from<Windows::ApplicationModel::Email::EmailConversationReader>(this->shim().GetConversationReader(*reinterpret_cast<Windows::ApplicationModel::Email::EmailQueryOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetMessageAsync(void* id, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetMessageAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailMessage>), hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailMessage>>(this->shim().GetMessageAsync(*reinterpret_cast<hstring const*>(&id)));
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
            WINRT_ASSERT_DECLARATION(GetMessageReader, WINRT_WRAP(Windows::ApplicationModel::Email::EmailMessageReader));
            *result = detach_from<Windows::ApplicationModel::Email::EmailMessageReader>(this->shim().GetMessageReader());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetMessageReaderWithOptions(void* options, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetMessageReader, WINRT_WRAP(Windows::ApplicationModel::Email::EmailMessageReader), Windows::ApplicationModel::Email::EmailQueryOptions const&);
            *result = detach_from<Windows::ApplicationModel::Email::EmailMessageReader>(this->shim().GetMessageReader(*reinterpret_cast<Windows::ApplicationModel::Email::EmailQueryOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetMessageCountsAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetMessageCountsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailItemCounts>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailItemCounts>>(this->shim().GetMessageCountsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryMoveAsync(void* newParentFolder, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryMoveAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::ApplicationModel::Email::EmailFolder const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryMoveAsync(*reinterpret_cast<Windows::ApplicationModel::Email::EmailFolder const*>(&newParentFolder)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryMoveWithNewNameAsync(void* newParentFolder, void* newFolderName, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryMoveAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::ApplicationModel::Email::EmailFolder const, hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryMoveAsync(*reinterpret_cast<Windows::ApplicationModel::Email::EmailFolder const*>(&newParentFolder), *reinterpret_cast<hstring const*>(&newFolderName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TrySaveAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrySaveAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TrySaveAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SaveMessageAsync(void* message, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SaveMessageAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::ApplicationModel::Email::EmailMessage const);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SaveMessageAsync(*reinterpret_cast<Windows::ApplicationModel::Email::EmailMessage const*>(&message)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Email::IEmailIrmInfo> : produce_base<D, Windows::ApplicationModel::Email::IEmailIrmInfo>
{
    int32_t WINRT_CALL get_CanEdit(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanEdit, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanEdit());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CanEdit(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanEdit, WINRT_WRAP(void), bool);
            this->shim().CanEdit(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanExtractData(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanExtractData, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanExtractData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CanExtractData(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanExtractData, WINRT_WRAP(void), bool);
            this->shim().CanExtractData(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanForward(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanForward, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanForward());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CanForward(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanForward, WINRT_WRAP(void), bool);
            this->shim().CanForward(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanModifyRecipientsOnResponse(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanModifyRecipientsOnResponse, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanModifyRecipientsOnResponse());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CanModifyRecipientsOnResponse(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanModifyRecipientsOnResponse, WINRT_WRAP(void), bool);
            this->shim().CanModifyRecipientsOnResponse(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanPrintData(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanPrintData, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanPrintData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CanPrintData(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanPrintData, WINRT_WRAP(void), bool);
            this->shim().CanPrintData(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanRemoveIrmOnResponse(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanRemoveIrmOnResponse, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanRemoveIrmOnResponse());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CanRemoveIrmOnResponse(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanRemoveIrmOnResponse, WINRT_WRAP(void), bool);
            this->shim().CanRemoveIrmOnResponse(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanReply(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanReply, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanReply());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CanReply(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanReply, WINRT_WRAP(void), bool);
            this->shim().CanReply(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanReplyAll(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanReplyAll, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanReplyAll());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CanReplyAll(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanReplyAll, WINRT_WRAP(void), bool);
            this->shim().CanReplyAll(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExpirationDate(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExpirationDate, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().ExpirationDate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ExpirationDate(Windows::Foundation::DateTime value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExpirationDate, WINRT_WRAP(void), Windows::Foundation::DateTime const&);
            this->shim().ExpirationDate(*reinterpret_cast<Windows::Foundation::DateTime const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsIrmOriginator(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsIrmOriginator, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsIrmOriginator());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsIrmOriginator(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsIrmOriginator, WINRT_WRAP(void), bool);
            this->shim().IsIrmOriginator(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsProgramaticAccessAllowed(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsProgramaticAccessAllowed, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsProgramaticAccessAllowed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsProgramaticAccessAllowed(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsProgramaticAccessAllowed, WINRT_WRAP(void), bool);
            this->shim().IsProgramaticAccessAllowed(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Template(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Template, WINRT_WRAP(Windows::ApplicationModel::Email::EmailIrmTemplate));
            *value = detach_from<Windows::ApplicationModel::Email::EmailIrmTemplate>(this->shim().Template());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Template(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Template, WINRT_WRAP(void), Windows::ApplicationModel::Email::EmailIrmTemplate const&);
            this->shim().Template(*reinterpret_cast<Windows::ApplicationModel::Email::EmailIrmTemplate const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Email::IEmailIrmInfoFactory> : produce_base<D, Windows::ApplicationModel::Email::IEmailIrmInfoFactory>
{
    int32_t WINRT_CALL Create(Windows::Foundation::DateTime expiration, void* irmTemplate, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::ApplicationModel::Email::EmailIrmInfo), Windows::Foundation::DateTime const&, Windows::ApplicationModel::Email::EmailIrmTemplate const&);
            *result = detach_from<Windows::ApplicationModel::Email::EmailIrmInfo>(this->shim().Create(*reinterpret_cast<Windows::Foundation::DateTime const*>(&expiration), *reinterpret_cast<Windows::ApplicationModel::Email::EmailIrmTemplate const*>(&irmTemplate)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Email::IEmailIrmTemplate> : produce_base<D, Windows::ApplicationModel::Email::IEmailIrmTemplate>
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

    int32_t WINRT_CALL put_Id(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Id, WINRT_WRAP(void), hstring const&);
            this->shim().Id(*reinterpret_cast<hstring const*>(&value));
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

    int32_t WINRT_CALL put_Description(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Description, WINRT_WRAP(void), hstring const&);
            this->shim().Description(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Name(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Name, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Name(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Name, WINRT_WRAP(void), hstring const&);
            this->shim().Name(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Email::IEmailIrmTemplateFactory> : produce_base<D, Windows::ApplicationModel::Email::IEmailIrmTemplateFactory>
{
    int32_t WINRT_CALL Create(void* id, void* name, void* description, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::ApplicationModel::Email::EmailIrmTemplate), hstring const&, hstring const&, hstring const&);
            *result = detach_from<Windows::ApplicationModel::Email::EmailIrmTemplate>(this->shim().Create(*reinterpret_cast<hstring const*>(&id), *reinterpret_cast<hstring const*>(&name), *reinterpret_cast<hstring const*>(&description)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Email::IEmailItemCounts> : produce_base<D, Windows::ApplicationModel::Email::IEmailItemCounts>
{
    int32_t WINRT_CALL get_Flagged(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Flagged, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Flagged());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Important(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Important, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Important());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Total(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Total, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Total());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Unread(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Unread, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Unread());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Email::IEmailMailbox> : produce_base<D, Windows::ApplicationModel::Email::IEmailMailbox>
{
    int32_t WINRT_CALL get_Capabilities(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Capabilities, WINRT_WRAP(Windows::ApplicationModel::Email::EmailMailboxCapabilities));
            *value = detach_from<Windows::ApplicationModel::Email::EmailMailboxCapabilities>(this->shim().Capabilities());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ChangeTracker(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChangeTracker, WINRT_WRAP(Windows::ApplicationModel::Email::EmailMailboxChangeTracker));
            *value = detach_from<Windows::ApplicationModel::Email::EmailMailboxChangeTracker>(this->shim().ChangeTracker());
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

    int32_t WINRT_CALL get_IsOwnedByCurrentApp(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsOwnedByCurrentApp, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsOwnedByCurrentApp());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsDataEncryptedUnderLock(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDataEncryptedUnderLock, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsDataEncryptedUnderLock());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MailAddress(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MailAddress, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().MailAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MailAddress(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MailAddress, WINRT_WRAP(void), hstring const&);
            this->shim().MailAddress(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MailAddressAliases(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MailAddressAliases, WINRT_WRAP(Windows::Foundation::Collections::IVector<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVector<hstring>>(this->shim().MailAddressAliases());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OtherAppReadAccess(Windows::ApplicationModel::Email::EmailMailboxOtherAppReadAccess* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OtherAppReadAccess, WINRT_WRAP(Windows::ApplicationModel::Email::EmailMailboxOtherAppReadAccess));
            *value = detach_from<Windows::ApplicationModel::Email::EmailMailboxOtherAppReadAccess>(this->shim().OtherAppReadAccess());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_OtherAppReadAccess(Windows::ApplicationModel::Email::EmailMailboxOtherAppReadAccess value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OtherAppReadAccess, WINRT_WRAP(void), Windows::ApplicationModel::Email::EmailMailboxOtherAppReadAccess const&);
            this->shim().OtherAppReadAccess(*reinterpret_cast<Windows::ApplicationModel::Email::EmailMailboxOtherAppReadAccess const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OtherAppWriteAccess(Windows::ApplicationModel::Email::EmailMailboxOtherAppWriteAccess* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OtherAppWriteAccess, WINRT_WRAP(Windows::ApplicationModel::Email::EmailMailboxOtherAppWriteAccess));
            *value = detach_from<Windows::ApplicationModel::Email::EmailMailboxOtherAppWriteAccess>(this->shim().OtherAppWriteAccess());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_OtherAppWriteAccess(Windows::ApplicationModel::Email::EmailMailboxOtherAppWriteAccess value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OtherAppWriteAccess, WINRT_WRAP(void), Windows::ApplicationModel::Email::EmailMailboxOtherAppWriteAccess const&);
            this->shim().OtherAppWriteAccess(*reinterpret_cast<Windows::ApplicationModel::Email::EmailMailboxOtherAppWriteAccess const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Policies(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Policies, WINRT_WRAP(Windows::ApplicationModel::Email::EmailMailboxPolicies));
            *value = detach_from<Windows::ApplicationModel::Email::EmailMailboxPolicies>(this->shim().Policies());
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

    int32_t WINRT_CALL get_SyncManager(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SyncManager, WINRT_WRAP(Windows::ApplicationModel::Email::EmailMailboxSyncManager));
            *value = detach_from<Windows::ApplicationModel::Email::EmailMailboxSyncManager>(this->shim().SyncManager());
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

    int32_t WINRT_CALL GetConversationReader(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetConversationReader, WINRT_WRAP(Windows::ApplicationModel::Email::EmailConversationReader));
            *result = detach_from<Windows::ApplicationModel::Email::EmailConversationReader>(this->shim().GetConversationReader());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetConversationReaderWithOptions(void* options, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetConversationReader, WINRT_WRAP(Windows::ApplicationModel::Email::EmailConversationReader), Windows::ApplicationModel::Email::EmailQueryOptions const&);
            *result = detach_from<Windows::ApplicationModel::Email::EmailConversationReader>(this->shim().GetConversationReader(*reinterpret_cast<Windows::ApplicationModel::Email::EmailQueryOptions const*>(&options)));
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
            WINRT_ASSERT_DECLARATION(GetMessageReader, WINRT_WRAP(Windows::ApplicationModel::Email::EmailMessageReader));
            *result = detach_from<Windows::ApplicationModel::Email::EmailMessageReader>(this->shim().GetMessageReader());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetMessageReaderWithOptions(void* options, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetMessageReader, WINRT_WRAP(Windows::ApplicationModel::Email::EmailMessageReader), Windows::ApplicationModel::Email::EmailQueryOptions const&);
            *result = detach_from<Windows::ApplicationModel::Email::EmailMessageReader>(this->shim().GetMessageReader(*reinterpret_cast<Windows::ApplicationModel::Email::EmailQueryOptions const*>(&options)));
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

    int32_t WINRT_CALL GetConversationAsync(void* id, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetConversationAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailConversation>), hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailConversation>>(this->shim().GetConversationAsync(*reinterpret_cast<hstring const*>(&id)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetFolderAsync(void* id, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetFolderAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailFolder>), hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailFolder>>(this->shim().GetFolderAsync(*reinterpret_cast<hstring const*>(&id)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetMessageAsync(void* id, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetMessageAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailMessage>), hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailMessage>>(this->shim().GetMessageAsync(*reinterpret_cast<hstring const*>(&id)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetSpecialFolderAsync(Windows::ApplicationModel::Email::EmailSpecialFolderKind folderType, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetSpecialFolderAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailFolder>), Windows::ApplicationModel::Email::EmailSpecialFolderKind const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailFolder>>(this->shim().GetSpecialFolderAsync(*reinterpret_cast<Windows::ApplicationModel::Email::EmailSpecialFolderKind const*>(&folderType)));
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

    int32_t WINRT_CALL MarkMessageAsSeenAsync(void* messageId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MarkMessageAsSeenAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), hstring const);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().MarkMessageAsSeenAsync(*reinterpret_cast<hstring const*>(&messageId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL MarkFolderAsSeenAsync(void* folderId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MarkFolderAsSeenAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), hstring const);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().MarkFolderAsSeenAsync(*reinterpret_cast<hstring const*>(&folderId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL MarkMessageReadAsync(void* messageId, bool isRead, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MarkMessageReadAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), hstring const, bool);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().MarkMessageReadAsync(*reinterpret_cast<hstring const*>(&messageId), isRead));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ChangeMessageFlagStateAsync(void* messageId, Windows::ApplicationModel::Email::EmailFlagState flagState, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChangeMessageFlagStateAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), hstring const, Windows::ApplicationModel::Email::EmailFlagState const);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ChangeMessageFlagStateAsync(*reinterpret_cast<hstring const*>(&messageId), *reinterpret_cast<Windows::ApplicationModel::Email::EmailFlagState const*>(&flagState)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryMoveMessageAsync(void* messageId, void* newParentFolderId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryMoveMessageAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), hstring const, hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryMoveMessageAsync(*reinterpret_cast<hstring const*>(&messageId), *reinterpret_cast<hstring const*>(&newParentFolderId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryMoveFolderAsync(void* folderId, void* newParentFolderId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryMoveFolderAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), hstring const, hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryMoveFolderAsync(*reinterpret_cast<hstring const*>(&folderId), *reinterpret_cast<hstring const*>(&newParentFolderId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryMoveFolderWithNewNameAsync(void* folderId, void* newParentFolderId, void* newFolderName, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryMoveFolderAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), hstring const, hstring const, hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryMoveFolderAsync(*reinterpret_cast<hstring const*>(&folderId), *reinterpret_cast<hstring const*>(&newParentFolderId), *reinterpret_cast<hstring const*>(&newFolderName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DeleteMessageAsync(void* messageId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeleteMessageAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), hstring const);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().DeleteMessageAsync(*reinterpret_cast<hstring const*>(&messageId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL MarkFolderSyncEnabledAsync(void* folderId, bool isSyncEnabled, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MarkFolderSyncEnabledAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), hstring const, bool);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().MarkFolderSyncEnabledAsync(*reinterpret_cast<hstring const*>(&folderId), isSyncEnabled));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SendMessageAsync(void* message, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SendMessageAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::ApplicationModel::Email::EmailMessage const);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SendMessageAsync(*reinterpret_cast<Windows::ApplicationModel::Email::EmailMessage const*>(&message)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SaveDraftAsync(void* message, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SaveDraftAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::ApplicationModel::Email::EmailMessage const);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SaveDraftAsync(*reinterpret_cast<Windows::ApplicationModel::Email::EmailMessage const*>(&message)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DownloadMessageAsync(void* messageId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DownloadMessageAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), hstring const);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().DownloadMessageAsync(*reinterpret_cast<hstring const*>(&messageId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DownloadAttachmentAsync(void* attachmentId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DownloadAttachmentAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), hstring const);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().DownloadAttachmentAsync(*reinterpret_cast<hstring const*>(&attachmentId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateResponseMessageAsync(void* messageId, Windows::ApplicationModel::Email::EmailMessageResponseKind responseType, void* subject, Windows::ApplicationModel::Email::EmailMessageBodyKind responseHeaderType, void* responseHeader, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateResponseMessageAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailMessage>), hstring const, Windows::ApplicationModel::Email::EmailMessageResponseKind const, hstring const, Windows::ApplicationModel::Email::EmailMessageBodyKind const, hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailMessage>>(this->shim().CreateResponseMessageAsync(*reinterpret_cast<hstring const*>(&messageId), *reinterpret_cast<Windows::ApplicationModel::Email::EmailMessageResponseKind const*>(&responseType), *reinterpret_cast<hstring const*>(&subject), *reinterpret_cast<Windows::ApplicationModel::Email::EmailMessageBodyKind const*>(&responseHeaderType), *reinterpret_cast<hstring const*>(&responseHeader)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryUpdateMeetingResponseAsync(void* meeting, Windows::ApplicationModel::Email::EmailMeetingResponseType response, void* subject, void* comment, bool sendUpdate, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryUpdateMeetingResponseAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::ApplicationModel::Email::EmailMessage const, Windows::ApplicationModel::Email::EmailMeetingResponseType const, hstring const, hstring const, bool);
            *result = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryUpdateMeetingResponseAsync(*reinterpret_cast<Windows::ApplicationModel::Email::EmailMessage const*>(&meeting), *reinterpret_cast<Windows::ApplicationModel::Email::EmailMeetingResponseType const*>(&response), *reinterpret_cast<hstring const*>(&subject), *reinterpret_cast<hstring const*>(&comment), sendUpdate));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryForwardMeetingAsync(void* meeting, void* recipients, void* subject, Windows::ApplicationModel::Email::EmailMessageBodyKind forwardHeaderType, void* forwardHeader, void* comment, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryForwardMeetingAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::ApplicationModel::Email::EmailMessage const, Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Email::EmailRecipient> const, hstring const, Windows::ApplicationModel::Email::EmailMessageBodyKind const, hstring const, hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryForwardMeetingAsync(*reinterpret_cast<Windows::ApplicationModel::Email::EmailMessage const*>(&meeting), *reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Email::EmailRecipient> const*>(&recipients), *reinterpret_cast<hstring const*>(&subject), *reinterpret_cast<Windows::ApplicationModel::Email::EmailMessageBodyKind const*>(&forwardHeaderType), *reinterpret_cast<hstring const*>(&forwardHeader), *reinterpret_cast<hstring const*>(&comment)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryProposeNewTimeForMeetingAsync(void* meeting, Windows::Foundation::DateTime newStartTime, Windows::Foundation::TimeSpan newDuration, void* subject, void* comment, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryProposeNewTimeForMeetingAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::ApplicationModel::Email::EmailMessage const, Windows::Foundation::DateTime const, Windows::Foundation::TimeSpan const, hstring const, hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryProposeNewTimeForMeetingAsync(*reinterpret_cast<Windows::ApplicationModel::Email::EmailMessage const*>(&meeting), *reinterpret_cast<Windows::Foundation::DateTime const*>(&newStartTime), *reinterpret_cast<Windows::Foundation::TimeSpan const*>(&newDuration), *reinterpret_cast<hstring const*>(&subject), *reinterpret_cast<hstring const*>(&comment)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_MailboxChanged(void* pHandler, winrt::event_token* pToken) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MailboxChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Email::EmailMailbox, Windows::ApplicationModel::Email::EmailMailboxChangedEventArgs> const&);
            *pToken = detach_from<winrt::event_token>(this->shim().MailboxChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Email::EmailMailbox, Windows::ApplicationModel::Email::EmailMailboxChangedEventArgs> const*>(&pHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_MailboxChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(MailboxChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().MailboxChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL SmartSendMessageAsync(void* message, bool smartSend, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SendMessageAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::ApplicationModel::Email::EmailMessage const, bool);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SendMessageAsync(*reinterpret_cast<Windows::ApplicationModel::Email::EmailMessage const*>(&message), smartSend));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TrySetAutoReplySettingsAsync(void* autoReplySettings, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrySetAutoReplySettingsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::ApplicationModel::Email::EmailMailboxAutoReplySettings const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TrySetAutoReplySettingsAsync(*reinterpret_cast<Windows::ApplicationModel::Email::EmailMailboxAutoReplySettings const*>(&autoReplySettings)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryGetAutoReplySettingsAsync(Windows::ApplicationModel::Email::EmailMailboxAutoReplyMessageResponseKind requestedFormat, void** autoReplySettings) noexcept final
    {
        try
        {
            *autoReplySettings = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryGetAutoReplySettingsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailMailboxAutoReplySettings>), Windows::ApplicationModel::Email::EmailMailboxAutoReplyMessageResponseKind const);
            *autoReplySettings = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailMailboxAutoReplySettings>>(this->shim().TryGetAutoReplySettingsAsync(*reinterpret_cast<Windows::ApplicationModel::Email::EmailMailboxAutoReplyMessageResponseKind const*>(&requestedFormat)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Email::IEmailMailbox2> : produce_base<D, Windows::ApplicationModel::Email::IEmailMailbox2>
{
    int32_t WINRT_CALL get_LinkedMailboxId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LinkedMailboxId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().LinkedMailboxId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NetworkAccountId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NetworkAccountId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().NetworkAccountId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NetworkId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NetworkId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().NetworkId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Email::IEmailMailbox3> : produce_base<D, Windows::ApplicationModel::Email::IEmailMailbox3>
{
    int32_t WINRT_CALL ResolveRecipientsAsync(void* recipients, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResolveRecipientsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Email::EmailRecipientResolutionResult>>), Windows::Foundation::Collections::IIterable<hstring> const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Email::EmailRecipientResolutionResult>>>(this->shim().ResolveRecipientsAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&recipients)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ValidateCertificatesAsync(void* certificates, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ValidateCertificatesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Email::EmailCertificateValidationStatus>>), Windows::Foundation::Collections::IIterable<Windows::Security::Cryptography::Certificates::Certificate> const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Email::EmailCertificateValidationStatus>>>(this->shim().ValidateCertificatesAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Security::Cryptography::Certificates::Certificate> const*>(&certificates)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryEmptyFolderAsync(void* folderId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryEmptyFolderAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailMailboxEmptyFolderStatus>), hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailMailboxEmptyFolderStatus>>(this->shim().TryEmptyFolderAsync(*reinterpret_cast<hstring const*>(&folderId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryCreateFolderAsync(void* parentFolderId, void* name, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryCreateFolderAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailMailboxCreateFolderResult>), hstring const, hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailMailboxCreateFolderResult>>(this->shim().TryCreateFolderAsync(*reinterpret_cast<hstring const*>(&parentFolderId), *reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryDeleteFolderAsync(void* folderId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryDeleteFolderAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailMailboxDeleteFolderStatus>), hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailMailboxDeleteFolderStatus>>(this->shim().TryDeleteFolderAsync(*reinterpret_cast<hstring const*>(&folderId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Email::IEmailMailbox4> : produce_base<D, Windows::ApplicationModel::Email::IEmailMailbox4>
{
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
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Email::IEmailMailbox5> : produce_base<D, Windows::ApplicationModel::Email::IEmailMailbox5>
{
    int32_t WINRT_CALL GetChangeTracker(void* identity, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetChangeTracker, WINRT_WRAP(Windows::ApplicationModel::Email::EmailMailboxChangeTracker), hstring const&);
            *result = detach_from<Windows::ApplicationModel::Email::EmailMailboxChangeTracker>(this->shim().GetChangeTracker(*reinterpret_cast<hstring const*>(&identity)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Email::IEmailMailboxAction> : produce_base<D, Windows::ApplicationModel::Email::IEmailMailboxAction>
{
    int32_t WINRT_CALL get_Kind(Windows::ApplicationModel::Email::EmailMailboxActionKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Kind, WINRT_WRAP(Windows::ApplicationModel::Email::EmailMailboxActionKind));
            *value = detach_from<Windows::ApplicationModel::Email::EmailMailboxActionKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ChangeNumber(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChangeNumber, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().ChangeNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Email::IEmailMailboxAutoReply> : produce_base<D, Windows::ApplicationModel::Email::IEmailMailboxAutoReply>
{
    int32_t WINRT_CALL get_IsEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsEnabled, WINRT_WRAP(void), bool);
            this->shim().IsEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Response(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Response, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Response());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Response(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Response, WINRT_WRAP(void), hstring const&);
            this->shim().Response(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Email::IEmailMailboxAutoReplySettings> : produce_base<D, Windows::ApplicationModel::Email::IEmailMailboxAutoReplySettings>
{
    int32_t WINRT_CALL get_IsEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsEnabled, WINRT_WRAP(void), bool);
            this->shim().IsEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ResponseKind(Windows::ApplicationModel::Email::EmailMailboxAutoReplyMessageResponseKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResponseKind, WINRT_WRAP(Windows::ApplicationModel::Email::EmailMailboxAutoReplyMessageResponseKind));
            *value = detach_from<Windows::ApplicationModel::Email::EmailMailboxAutoReplyMessageResponseKind>(this->shim().ResponseKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ResponseKind(Windows::ApplicationModel::Email::EmailMailboxAutoReplyMessageResponseKind value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResponseKind, WINRT_WRAP(void), Windows::ApplicationModel::Email::EmailMailboxAutoReplyMessageResponseKind const&);
            this->shim().ResponseKind(*reinterpret_cast<Windows::ApplicationModel::Email::EmailMailboxAutoReplyMessageResponseKind const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StartTime(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartTime, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::DateTime>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::DateTime>>(this->shim().StartTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_StartTime(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartTime, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Foundation::DateTime> const&);
            this->shim().StartTime(*reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::DateTime> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EndTime(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EndTime, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::DateTime>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::DateTime>>(this->shim().EndTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_EndTime(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EndTime, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Foundation::DateTime> const&);
            this->shim().EndTime(*reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::DateTime> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InternalReply(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InternalReply, WINRT_WRAP(Windows::ApplicationModel::Email::EmailMailboxAutoReply));
            *value = detach_from<Windows::ApplicationModel::Email::EmailMailboxAutoReply>(this->shim().InternalReply());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_KnownExternalReply(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KnownExternalReply, WINRT_WRAP(Windows::ApplicationModel::Email::EmailMailboxAutoReply));
            *value = detach_from<Windows::ApplicationModel::Email::EmailMailboxAutoReply>(this->shim().KnownExternalReply());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UnknownExternalReply(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UnknownExternalReply, WINRT_WRAP(Windows::ApplicationModel::Email::EmailMailboxAutoReply));
            *value = detach_from<Windows::ApplicationModel::Email::EmailMailboxAutoReply>(this->shim().UnknownExternalReply());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Email::IEmailMailboxCapabilities> : produce_base<D, Windows::ApplicationModel::Email::IEmailMailboxCapabilities>
{
    int32_t WINRT_CALL get_CanForwardMeetings(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanForwardMeetings, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanForwardMeetings());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanGetAndSetExternalAutoReplies(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanGetAndSetExternalAutoReplies, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanGetAndSetExternalAutoReplies());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanGetAndSetInternalAutoReplies(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanGetAndSetInternalAutoReplies, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanGetAndSetInternalAutoReplies());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanUpdateMeetingResponses(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanUpdateMeetingResponses, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanUpdateMeetingResponses());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanServerSearchFolders(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanServerSearchFolders, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanServerSearchFolders());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanServerSearchMailbox(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanServerSearchMailbox, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanServerSearchMailbox());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanProposeNewTimeForMeetings(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanProposeNewTimeForMeetings, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanProposeNewTimeForMeetings());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanSmartSend(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanSmartSend, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanSmartSend());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Email::IEmailMailboxCapabilities2> : produce_base<D, Windows::ApplicationModel::Email::IEmailMailboxCapabilities2>
{
    int32_t WINRT_CALL get_CanResolveRecipients(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanResolveRecipients, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanResolveRecipients());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanValidateCertificates(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanValidateCertificates, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanValidateCertificates());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanEmptyFolder(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanEmptyFolder, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanEmptyFolder());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanCreateFolder(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanCreateFolder, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanCreateFolder());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanDeleteFolder(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanDeleteFolder, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanDeleteFolder());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanMoveFolder(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanMoveFolder, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanMoveFolder());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Email::IEmailMailboxCapabilities3> : produce_base<D, Windows::ApplicationModel::Email::IEmailMailboxCapabilities3>
{
    int32_t WINRT_CALL put_CanForwardMeetings(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanForwardMeetings, WINRT_WRAP(void), bool);
            this->shim().CanForwardMeetings(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CanGetAndSetExternalAutoReplies(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanGetAndSetExternalAutoReplies, WINRT_WRAP(void), bool);
            this->shim().CanGetAndSetExternalAutoReplies(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CanGetAndSetInternalAutoReplies(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanGetAndSetInternalAutoReplies, WINRT_WRAP(void), bool);
            this->shim().CanGetAndSetInternalAutoReplies(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CanUpdateMeetingResponses(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanUpdateMeetingResponses, WINRT_WRAP(void), bool);
            this->shim().CanUpdateMeetingResponses(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CanServerSearchFolders(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanServerSearchFolders, WINRT_WRAP(void), bool);
            this->shim().CanServerSearchFolders(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CanServerSearchMailbox(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanServerSearchMailbox, WINRT_WRAP(void), bool);
            this->shim().CanServerSearchMailbox(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CanProposeNewTimeForMeetings(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanProposeNewTimeForMeetings, WINRT_WRAP(void), bool);
            this->shim().CanProposeNewTimeForMeetings(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CanSmartSend(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanSmartSend, WINRT_WRAP(void), bool);
            this->shim().CanSmartSend(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CanResolveRecipients(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanResolveRecipients, WINRT_WRAP(void), bool);
            this->shim().CanResolveRecipients(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CanValidateCertificates(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanValidateCertificates, WINRT_WRAP(void), bool);
            this->shim().CanValidateCertificates(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CanEmptyFolder(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanEmptyFolder, WINRT_WRAP(void), bool);
            this->shim().CanEmptyFolder(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CanCreateFolder(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanCreateFolder, WINRT_WRAP(void), bool);
            this->shim().CanCreateFolder(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CanDeleteFolder(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanDeleteFolder, WINRT_WRAP(void), bool);
            this->shim().CanDeleteFolder(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CanMoveFolder(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanMoveFolder, WINRT_WRAP(void), bool);
            this->shim().CanMoveFolder(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Email::IEmailMailboxChange> : produce_base<D, Windows::ApplicationModel::Email::IEmailMailboxChange>
{
    int32_t WINRT_CALL get_ChangeType(Windows::ApplicationModel::Email::EmailMailboxChangeType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChangeType, WINRT_WRAP(Windows::ApplicationModel::Email::EmailMailboxChangeType));
            *value = detach_from<Windows::ApplicationModel::Email::EmailMailboxChangeType>(this->shim().ChangeType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MailboxActions(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MailboxActions, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Email::EmailMailboxAction>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Email::EmailMailboxAction>>(this->shim().MailboxActions());
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
            WINRT_ASSERT_DECLARATION(Message, WINRT_WRAP(Windows::ApplicationModel::Email::EmailMessage));
            *value = detach_from<Windows::ApplicationModel::Email::EmailMessage>(this->shim().Message());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Folder(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Folder, WINRT_WRAP(Windows::ApplicationModel::Email::EmailFolder));
            *value = detach_from<Windows::ApplicationModel::Email::EmailFolder>(this->shim().Folder());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Email::IEmailMailboxChangeReader> : produce_base<D, Windows::ApplicationModel::Email::IEmailMailboxChangeReader>
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
            WINRT_ASSERT_DECLARATION(AcceptChangesThrough, WINRT_WRAP(void), Windows::ApplicationModel::Email::EmailMailboxChange const&);
            this->shim().AcceptChangesThrough(*reinterpret_cast<Windows::ApplicationModel::Email::EmailMailboxChange const*>(&lastChangeToAcknowledge));
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
            WINRT_ASSERT_DECLARATION(ReadBatchAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Email::EmailMailboxChange>>));
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Email::EmailMailboxChange>>>(this->shim().ReadBatchAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Email::IEmailMailboxChangeTracker> : produce_base<D, Windows::ApplicationModel::Email::IEmailMailboxChangeTracker>
{
    int32_t WINRT_CALL get_IsTracking(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsTracking, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsTracking());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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
            WINRT_ASSERT_DECLARATION(GetChangeReader, WINRT_WRAP(Windows::ApplicationModel::Email::EmailMailboxChangeReader));
            *value = detach_from<Windows::ApplicationModel::Email::EmailMailboxChangeReader>(this->shim().GetChangeReader());
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
struct produce<D, Windows::ApplicationModel::Email::IEmailMailboxChangedDeferral> : produce_base<D, Windows::ApplicationModel::Email::IEmailMailboxChangedDeferral>
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
struct produce<D, Windows::ApplicationModel::Email::IEmailMailboxChangedEventArgs> : produce_base<D, Windows::ApplicationModel::Email::IEmailMailboxChangedEventArgs>
{
    int32_t WINRT_CALL GetDeferral(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeferral, WINRT_WRAP(Windows::ApplicationModel::Email::EmailMailboxChangedDeferral));
            *result = detach_from<Windows::ApplicationModel::Email::EmailMailboxChangedDeferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Email::IEmailMailboxCreateFolderResult> : produce_base<D, Windows::ApplicationModel::Email::IEmailMailboxCreateFolderResult>
{
    int32_t WINRT_CALL get_Status(Windows::ApplicationModel::Email::EmailMailboxCreateFolderStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::ApplicationModel::Email::EmailMailboxCreateFolderStatus));
            *value = detach_from<Windows::ApplicationModel::Email::EmailMailboxCreateFolderStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Folder(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Folder, WINRT_WRAP(Windows::ApplicationModel::Email::EmailFolder));
            *value = detach_from<Windows::ApplicationModel::Email::EmailFolder>(this->shim().Folder());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Email::IEmailMailboxPolicies> : produce_base<D, Windows::ApplicationModel::Email::IEmailMailboxPolicies>
{
    int32_t WINRT_CALL get_AllowedSmimeEncryptionAlgorithmNegotiation(Windows::ApplicationModel::Email::EmailMailboxAllowedSmimeEncryptionAlgorithmNegotiation* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllowedSmimeEncryptionAlgorithmNegotiation, WINRT_WRAP(Windows::ApplicationModel::Email::EmailMailboxAllowedSmimeEncryptionAlgorithmNegotiation));
            *value = detach_from<Windows::ApplicationModel::Email::EmailMailboxAllowedSmimeEncryptionAlgorithmNegotiation>(this->shim().AllowedSmimeEncryptionAlgorithmNegotiation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AllowSmimeSoftCertificates(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllowSmimeSoftCertificates, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AllowSmimeSoftCertificates());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RequiredSmimeEncryptionAlgorithm(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequiredSmimeEncryptionAlgorithm, WINRT_WRAP(Windows::Foundation::IReference<Windows::ApplicationModel::Email::EmailMailboxSmimeEncryptionAlgorithm>));
            *value = detach_from<Windows::Foundation::IReference<Windows::ApplicationModel::Email::EmailMailboxSmimeEncryptionAlgorithm>>(this->shim().RequiredSmimeEncryptionAlgorithm());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RequiredSmimeSigningAlgorithm(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequiredSmimeSigningAlgorithm, WINRT_WRAP(Windows::Foundation::IReference<Windows::ApplicationModel::Email::EmailMailboxSmimeSigningAlgorithm>));
            *value = detach_from<Windows::Foundation::IReference<Windows::ApplicationModel::Email::EmailMailboxSmimeSigningAlgorithm>>(this->shim().RequiredSmimeSigningAlgorithm());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Email::IEmailMailboxPolicies2> : produce_base<D, Windows::ApplicationModel::Email::IEmailMailboxPolicies2>
{
    int32_t WINRT_CALL get_MustEncryptSmimeMessages(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MustEncryptSmimeMessages, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().MustEncryptSmimeMessages());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MustSignSmimeMessages(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MustSignSmimeMessages, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().MustSignSmimeMessages());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Email::IEmailMailboxPolicies3> : produce_base<D, Windows::ApplicationModel::Email::IEmailMailboxPolicies3>
{
    int32_t WINRT_CALL put_AllowedSmimeEncryptionAlgorithmNegotiation(Windows::ApplicationModel::Email::EmailMailboxAllowedSmimeEncryptionAlgorithmNegotiation value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllowedSmimeEncryptionAlgorithmNegotiation, WINRT_WRAP(void), Windows::ApplicationModel::Email::EmailMailboxAllowedSmimeEncryptionAlgorithmNegotiation const&);
            this->shim().AllowedSmimeEncryptionAlgorithmNegotiation(*reinterpret_cast<Windows::ApplicationModel::Email::EmailMailboxAllowedSmimeEncryptionAlgorithmNegotiation const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AllowSmimeSoftCertificates(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllowSmimeSoftCertificates, WINRT_WRAP(void), bool);
            this->shim().AllowSmimeSoftCertificates(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RequiredSmimeEncryptionAlgorithm(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequiredSmimeEncryptionAlgorithm, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::ApplicationModel::Email::EmailMailboxSmimeEncryptionAlgorithm> const&);
            this->shim().RequiredSmimeEncryptionAlgorithm(*reinterpret_cast<Windows::Foundation::IReference<Windows::ApplicationModel::Email::EmailMailboxSmimeEncryptionAlgorithm> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RequiredSmimeSigningAlgorithm(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequiredSmimeSigningAlgorithm, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::ApplicationModel::Email::EmailMailboxSmimeSigningAlgorithm> const&);
            this->shim().RequiredSmimeSigningAlgorithm(*reinterpret_cast<Windows::Foundation::IReference<Windows::ApplicationModel::Email::EmailMailboxSmimeSigningAlgorithm> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MustEncryptSmimeMessages(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MustEncryptSmimeMessages, WINRT_WRAP(void), bool);
            this->shim().MustEncryptSmimeMessages(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MustSignSmimeMessages(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MustSignSmimeMessages, WINRT_WRAP(void), bool);
            this->shim().MustSignSmimeMessages(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Email::IEmailMailboxSyncManager> : produce_base<D, Windows::ApplicationModel::Email::IEmailMailboxSyncManager>
{
    int32_t WINRT_CALL get_Status(Windows::ApplicationModel::Email::EmailMailboxSyncStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::ApplicationModel::Email::EmailMailboxSyncStatus));
            *value = detach_from<Windows::ApplicationModel::Email::EmailMailboxSyncStatus>(this->shim().Status());
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
            WINRT_ASSERT_DECLARATION(SyncStatusChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Email::EmailMailboxSyncManager, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().SyncStatusChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Email::EmailMailboxSyncManager, Windows::Foundation::IInspectable> const*>(&handler)));
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
struct produce<D, Windows::ApplicationModel::Email::IEmailMailboxSyncManager2> : produce_base<D, Windows::ApplicationModel::Email::IEmailMailboxSyncManager2>
{
    int32_t WINRT_CALL put_Status(Windows::ApplicationModel::Email::EmailMailboxSyncStatus value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(void), Windows::ApplicationModel::Email::EmailMailboxSyncStatus const&);
            this->shim().Status(*reinterpret_cast<Windows::ApplicationModel::Email::EmailMailboxSyncStatus const*>(&value));
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
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Email::IEmailManagerForUser> : produce_base<D, Windows::ApplicationModel::Email::IEmailManagerForUser>
{
    int32_t WINRT_CALL ShowComposeNewEmailAsync(void* message, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowComposeNewEmailAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::ApplicationModel::Email::EmailMessage const);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ShowComposeNewEmailAsync(*reinterpret_cast<Windows::ApplicationModel::Email::EmailMessage const*>(&message)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestStoreAsync(Windows::ApplicationModel::Email::EmailStoreAccessType accessType, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestStoreAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailStore>), Windows::ApplicationModel::Email::EmailStoreAccessType const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailStore>>(this->shim().RequestStoreAsync(*reinterpret_cast<Windows::ApplicationModel::Email::EmailStoreAccessType const*>(&accessType)));
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
struct produce<D, Windows::ApplicationModel::Email::IEmailManagerStatics> : produce_base<D, Windows::ApplicationModel::Email::IEmailManagerStatics>
{
    int32_t WINRT_CALL ShowComposeNewEmailAsync(void* message, void** asyncAction) noexcept final
    {
        try
        {
            *asyncAction = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowComposeNewEmailAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::ApplicationModel::Email::EmailMessage const);
            *asyncAction = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ShowComposeNewEmailAsync(*reinterpret_cast<Windows::ApplicationModel::Email::EmailMessage const*>(&message)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Email::IEmailManagerStatics2> : produce_base<D, Windows::ApplicationModel::Email::IEmailManagerStatics2>
{
    int32_t WINRT_CALL RequestStoreAsync(Windows::ApplicationModel::Email::EmailStoreAccessType accessType, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestStoreAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailStore>), Windows::ApplicationModel::Email::EmailStoreAccessType const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailStore>>(this->shim().RequestStoreAsync(*reinterpret_cast<Windows::ApplicationModel::Email::EmailStoreAccessType const*>(&accessType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Email::IEmailManagerStatics3> : produce_base<D, Windows::ApplicationModel::Email::IEmailManagerStatics3>
{
    int32_t WINRT_CALL GetForUser(void* user, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForUser, WINRT_WRAP(Windows::ApplicationModel::Email::EmailManagerForUser), Windows::System::User const&);
            *result = detach_from<Windows::ApplicationModel::Email::EmailManagerForUser>(this->shim().GetForUser(*reinterpret_cast<Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Email::IEmailMeetingInfo> : produce_base<D, Windows::ApplicationModel::Email::IEmailMeetingInfo>
{
    int32_t WINRT_CALL get_AllowNewTimeProposal(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllowNewTimeProposal, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AllowNewTimeProposal());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AllowNewTimeProposal(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllowNewTimeProposal, WINRT_WRAP(void), bool);
            this->shim().AllowNewTimeProposal(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AppointmentRoamingId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppointmentRoamingId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AppointmentRoamingId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AppointmentRoamingId(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppointmentRoamingId, WINRT_WRAP(void), hstring const&);
            this->shim().AppointmentRoamingId(*reinterpret_cast<hstring const*>(&value));
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

    int32_t WINRT_CALL put_AppointmentOriginalStartTime(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppointmentOriginalStartTime, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Foundation::DateTime> const&);
            this->shim().AppointmentOriginalStartTime(*reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::DateTime> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Duration(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Duration, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().Duration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Duration(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Duration, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().Duration(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsAllDay(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsAllDay, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsAllDay());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsAllDay(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsAllDay, WINRT_WRAP(void), bool);
            this->shim().IsAllDay(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsResponseRequested(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsResponseRequested, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsResponseRequested());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsResponseRequested(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsResponseRequested, WINRT_WRAP(void), bool);
            this->shim().IsResponseRequested(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Location(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Location, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Location());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Location(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Location, WINRT_WRAP(void), hstring const&);
            this->shim().Location(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProposedStartTime(void** proposedStartTime) noexcept final
    {
        try
        {
            *proposedStartTime = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProposedStartTime, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::DateTime>));
            *proposedStartTime = detach_from<Windows::Foundation::IReference<Windows::Foundation::DateTime>>(this->shim().ProposedStartTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ProposedStartTime(void* proposedStartTime) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProposedStartTime, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Foundation::DateTime> const&);
            this->shim().ProposedStartTime(*reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::DateTime> const*>(&proposedStartTime));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProposedDuration(void** duration) noexcept final
    {
        try
        {
            *duration = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProposedDuration, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::TimeSpan>));
            *duration = detach_from<Windows::Foundation::IReference<Windows::Foundation::TimeSpan>>(this->shim().ProposedDuration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ProposedDuration(void* duration) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProposedDuration, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Foundation::TimeSpan> const&);
            this->shim().ProposedDuration(*reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::TimeSpan> const*>(&duration));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RecurrenceStartTime(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RecurrenceStartTime, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::DateTime>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::DateTime>>(this->shim().RecurrenceStartTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RecurrenceStartTime(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RecurrenceStartTime, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Foundation::DateTime> const&);
            this->shim().RecurrenceStartTime(*reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::DateTime> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Recurrence(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Recurrence, WINRT_WRAP(Windows::ApplicationModel::Appointments::AppointmentRecurrence));
            *value = detach_from<Windows::ApplicationModel::Appointments::AppointmentRecurrence>(this->shim().Recurrence());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Recurrence(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Recurrence, WINRT_WRAP(void), Windows::ApplicationModel::Appointments::AppointmentRecurrence const&);
            this->shim().Recurrence(*reinterpret_cast<Windows::ApplicationModel::Appointments::AppointmentRecurrence const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RemoteChangeNumber(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoteChangeNumber, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().RemoteChangeNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RemoteChangeNumber(uint64_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoteChangeNumber, WINRT_WRAP(void), uint64_t);
            this->shim().RemoteChangeNumber(value);
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
struct produce<D, Windows::ApplicationModel::Email::IEmailMeetingInfo2> : produce_base<D, Windows::ApplicationModel::Email::IEmailMeetingInfo2>
{
    int32_t WINRT_CALL get_IsReportedOutOfDateByServer(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsReportedOutOfDateByServer, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsReportedOutOfDateByServer());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Email::IEmailMessage> : produce_base<D, Windows::ApplicationModel::Email::IEmailMessage>
{
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

    int32_t WINRT_CALL get_To(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(To, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Email::EmailRecipient>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Email::EmailRecipient>>(this->shim().To());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CC(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CC, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Email::EmailRecipient>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Email::EmailRecipient>>(this->shim().CC());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Bcc(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Bcc, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Email::EmailRecipient>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Email::EmailRecipient>>(this->shim().Bcc());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Attachments(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Attachments, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Email::EmailAttachment>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Email::EmailAttachment>>(this->shim().Attachments());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Email::IEmailMessage2> : produce_base<D, Windows::ApplicationModel::Email::IEmailMessage2>
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

    int32_t WINRT_CALL get_MailboxId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MailboxId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().MailboxId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ConversationId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConversationId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ConversationId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FolderId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FolderId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().FolderId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AllowInternetImages(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllowInternetImages, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AllowInternetImages());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AllowInternetImages(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllowInternetImages, WINRT_WRAP(void), bool);
            this->shim().AllowInternetImages(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ChangeNumber(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChangeNumber, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().ChangeNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DownloadState(Windows::ApplicationModel::Email::EmailMessageDownloadState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DownloadState, WINRT_WRAP(Windows::ApplicationModel::Email::EmailMessageDownloadState));
            *value = detach_from<Windows::ApplicationModel::Email::EmailMessageDownloadState>(this->shim().DownloadState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DownloadState(Windows::ApplicationModel::Email::EmailMessageDownloadState value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DownloadState, WINRT_WRAP(void), Windows::ApplicationModel::Email::EmailMessageDownloadState const&);
            this->shim().DownloadState(*reinterpret_cast<Windows::ApplicationModel::Email::EmailMessageDownloadState const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EstimatedDownloadSizeInBytes(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EstimatedDownloadSizeInBytes, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().EstimatedDownloadSizeInBytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_EstimatedDownloadSizeInBytes(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EstimatedDownloadSizeInBytes, WINRT_WRAP(void), uint32_t);
            this->shim().EstimatedDownloadSizeInBytes(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FlagState(Windows::ApplicationModel::Email::EmailFlagState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FlagState, WINRT_WRAP(Windows::ApplicationModel::Email::EmailFlagState));
            *value = detach_from<Windows::ApplicationModel::Email::EmailFlagState>(this->shim().FlagState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FlagState(Windows::ApplicationModel::Email::EmailFlagState value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FlagState, WINRT_WRAP(void), Windows::ApplicationModel::Email::EmailFlagState const&);
            this->shim().FlagState(*reinterpret_cast<Windows::ApplicationModel::Email::EmailFlagState const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HasPartialBodies(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HasPartialBodies, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().HasPartialBodies());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Importance(Windows::ApplicationModel::Email::EmailImportance* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Importance, WINRT_WRAP(Windows::ApplicationModel::Email::EmailImportance));
            *value = detach_from<Windows::ApplicationModel::Email::EmailImportance>(this->shim().Importance());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Importance(Windows::ApplicationModel::Email::EmailImportance value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Importance, WINRT_WRAP(void), Windows::ApplicationModel::Email::EmailImportance const&);
            this->shim().Importance(*reinterpret_cast<Windows::ApplicationModel::Email::EmailImportance const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InResponseToMessageId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InResponseToMessageId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().InResponseToMessageId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IrmInfo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IrmInfo, WINRT_WRAP(Windows::ApplicationModel::Email::EmailIrmInfo));
            *value = detach_from<Windows::ApplicationModel::Email::EmailIrmInfo>(this->shim().IrmInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IrmInfo(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IrmInfo, WINRT_WRAP(void), Windows::ApplicationModel::Email::EmailIrmInfo const&);
            this->shim().IrmInfo(*reinterpret_cast<Windows::ApplicationModel::Email::EmailIrmInfo const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsDraftMessage(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDraftMessage, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsDraftMessage());
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

    int32_t WINRT_CALL get_IsServerSearchMessage(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsServerSearchMessage, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsServerSearchMessage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsSmartSendable(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSmartSendable, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsSmartSendable());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MessageClass(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MessageClass, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().MessageClass());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MessageClass(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MessageClass, WINRT_WRAP(void), hstring const&);
            this->shim().MessageClass(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NormalizedSubject(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NormalizedSubject, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().NormalizedSubject());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OriginalCodePage(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OriginalCodePage, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().OriginalCodePage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_OriginalCodePage(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OriginalCodePage, WINRT_WRAP(void), int32_t);
            this->shim().OriginalCodePage(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Preview(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Preview, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Preview());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Preview(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Preview, WINRT_WRAP(void), hstring const&);
            this->shim().Preview(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LastResponseKind(Windows::ApplicationModel::Email::EmailMessageResponseKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LastResponseKind, WINRT_WRAP(Windows::ApplicationModel::Email::EmailMessageResponseKind));
            *value = detach_from<Windows::ApplicationModel::Email::EmailMessageResponseKind>(this->shim().LastResponseKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_LastResponseKind(Windows::ApplicationModel::Email::EmailMessageResponseKind value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LastResponseKind, WINRT_WRAP(void), Windows::ApplicationModel::Email::EmailMessageResponseKind const&);
            this->shim().LastResponseKind(*reinterpret_cast<Windows::ApplicationModel::Email::EmailMessageResponseKind const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Sender(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Sender, WINRT_WRAP(Windows::ApplicationModel::Email::EmailRecipient));
            *value = detach_from<Windows::ApplicationModel::Email::EmailRecipient>(this->shim().Sender());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Sender(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Sender, WINRT_WRAP(void), Windows::ApplicationModel::Email::EmailRecipient const&);
            this->shim().Sender(*reinterpret_cast<Windows::ApplicationModel::Email::EmailRecipient const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SentTime(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SentTime, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::DateTime>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::DateTime>>(this->shim().SentTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SentTime(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SentTime, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Foundation::DateTime> const&);
            this->shim().SentTime(*reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::DateTime> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MeetingInfo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MeetingInfo, WINRT_WRAP(Windows::ApplicationModel::Email::EmailMeetingInfo));
            *value = detach_from<Windows::ApplicationModel::Email::EmailMeetingInfo>(this->shim().MeetingInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MeetingInfo(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MeetingInfo, WINRT_WRAP(void), Windows::ApplicationModel::Email::EmailMeetingInfo const&);
            this->shim().MeetingInfo(*reinterpret_cast<Windows::ApplicationModel::Email::EmailMeetingInfo const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetBodyStream(Windows::ApplicationModel::Email::EmailMessageBodyKind type, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetBodyStream, WINRT_WRAP(Windows::Storage::Streams::IRandomAccessStreamReference), Windows::ApplicationModel::Email::EmailMessageBodyKind const&);
            *result = detach_from<Windows::Storage::Streams::IRandomAccessStreamReference>(this->shim().GetBodyStream(*reinterpret_cast<Windows::ApplicationModel::Email::EmailMessageBodyKind const*>(&type)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetBodyStream(Windows::ApplicationModel::Email::EmailMessageBodyKind type, void* stream) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetBodyStream, WINRT_WRAP(void), Windows::ApplicationModel::Email::EmailMessageBodyKind const&, Windows::Storage::Streams::IRandomAccessStreamReference const&);
            this->shim().SetBodyStream(*reinterpret_cast<Windows::ApplicationModel::Email::EmailMessageBodyKind const*>(&type), *reinterpret_cast<Windows::Storage::Streams::IRandomAccessStreamReference const*>(&stream));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Email::IEmailMessage3> : produce_base<D, Windows::ApplicationModel::Email::IEmailMessage3>
{
    int32_t WINRT_CALL get_SmimeData(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SmimeData, WINRT_WRAP(Windows::Storage::Streams::IRandomAccessStreamReference));
            *value = detach_from<Windows::Storage::Streams::IRandomAccessStreamReference>(this->shim().SmimeData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SmimeData(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SmimeData, WINRT_WRAP(void), Windows::Storage::Streams::IRandomAccessStreamReference const&);
            this->shim().SmimeData(*reinterpret_cast<Windows::Storage::Streams::IRandomAccessStreamReference const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SmimeKind(Windows::ApplicationModel::Email::EmailMessageSmimeKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SmimeKind, WINRT_WRAP(Windows::ApplicationModel::Email::EmailMessageSmimeKind));
            *value = detach_from<Windows::ApplicationModel::Email::EmailMessageSmimeKind>(this->shim().SmimeKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SmimeKind(Windows::ApplicationModel::Email::EmailMessageSmimeKind value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SmimeKind, WINRT_WRAP(void), Windows::ApplicationModel::Email::EmailMessageSmimeKind const&);
            this->shim().SmimeKind(*reinterpret_cast<Windows::ApplicationModel::Email::EmailMessageSmimeKind const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Email::IEmailMessage4> : produce_base<D, Windows::ApplicationModel::Email::IEmailMessage4>
{
    int32_t WINRT_CALL get_ReplyTo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReplyTo, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Email::EmailRecipient>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::ApplicationModel::Email::EmailRecipient>>(this->shim().ReplyTo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SentRepresenting(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SentRepresenting, WINRT_WRAP(Windows::ApplicationModel::Email::EmailRecipient));
            *value = detach_from<Windows::ApplicationModel::Email::EmailRecipient>(this->shim().SentRepresenting());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SentRepresenting(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SentRepresenting, WINRT_WRAP(void), Windows::ApplicationModel::Email::EmailRecipient const&);
            this->shim().SentRepresenting(*reinterpret_cast<Windows::ApplicationModel::Email::EmailRecipient const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Email::IEmailMessageBatch> : produce_base<D, Windows::ApplicationModel::Email::IEmailMessageBatch>
{
    int32_t WINRT_CALL get_Messages(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Messages, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Email::EmailMessage>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Email::EmailMessage>>(this->shim().Messages());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Status(Windows::ApplicationModel::Email::EmailBatchStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::ApplicationModel::Email::EmailBatchStatus));
            *value = detach_from<Windows::ApplicationModel::Email::EmailBatchStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Email::IEmailMessageReader> : produce_base<D, Windows::ApplicationModel::Email::IEmailMessageReader>
{
    int32_t WINRT_CALL ReadBatchAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadBatchAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailMessageBatch>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailMessageBatch>>(this->shim().ReadBatchAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Email::IEmailQueryOptions> : produce_base<D, Windows::ApplicationModel::Email::IEmailQueryOptions>
{
    int32_t WINRT_CALL get_TextSearch(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TextSearch, WINRT_WRAP(Windows::ApplicationModel::Email::EmailQueryTextSearch));
            *value = detach_from<Windows::ApplicationModel::Email::EmailQueryTextSearch>(this->shim().TextSearch());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SortDirection(Windows::ApplicationModel::Email::EmailQuerySortDirection* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SortDirection, WINRT_WRAP(Windows::ApplicationModel::Email::EmailQuerySortDirection));
            *value = detach_from<Windows::ApplicationModel::Email::EmailQuerySortDirection>(this->shim().SortDirection());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SortDirection(Windows::ApplicationModel::Email::EmailQuerySortDirection value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SortDirection, WINRT_WRAP(void), Windows::ApplicationModel::Email::EmailQuerySortDirection const&);
            this->shim().SortDirection(*reinterpret_cast<Windows::ApplicationModel::Email::EmailQuerySortDirection const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SortProperty(Windows::ApplicationModel::Email::EmailQuerySortProperty* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SortProperty, WINRT_WRAP(Windows::ApplicationModel::Email::EmailQuerySortProperty));
            *value = detach_from<Windows::ApplicationModel::Email::EmailQuerySortProperty>(this->shim().SortProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SortProperty(Windows::ApplicationModel::Email::EmailQuerySortProperty value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SortProperty, WINRT_WRAP(void), Windows::ApplicationModel::Email::EmailQuerySortProperty const&);
            this->shim().SortProperty(*reinterpret_cast<Windows::ApplicationModel::Email::EmailQuerySortProperty const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Kind(Windows::ApplicationModel::Email::EmailQueryKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Kind, WINRT_WRAP(Windows::ApplicationModel::Email::EmailQueryKind));
            *value = detach_from<Windows::ApplicationModel::Email::EmailQueryKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Kind(Windows::ApplicationModel::Email::EmailQueryKind value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Kind, WINRT_WRAP(void), Windows::ApplicationModel::Email::EmailQueryKind const&);
            this->shim().Kind(*reinterpret_cast<Windows::ApplicationModel::Email::EmailQueryKind const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FolderIds(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FolderIds, WINRT_WRAP(Windows::Foundation::Collections::IVector<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVector<hstring>>(this->shim().FolderIds());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Email::IEmailQueryOptionsFactory> : produce_base<D, Windows::ApplicationModel::Email::IEmailQueryOptionsFactory>
{
    int32_t WINRT_CALL CreateWithText(void* text, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithText, WINRT_WRAP(Windows::ApplicationModel::Email::EmailQueryOptions), hstring const&);
            *result = detach_from<Windows::ApplicationModel::Email::EmailQueryOptions>(this->shim().CreateWithText(*reinterpret_cast<hstring const*>(&text)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithTextAndFields(void* text, Windows::ApplicationModel::Email::EmailQuerySearchFields fields, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithTextAndFields, WINRT_WRAP(Windows::ApplicationModel::Email::EmailQueryOptions), hstring const&, Windows::ApplicationModel::Email::EmailQuerySearchFields const&);
            *result = detach_from<Windows::ApplicationModel::Email::EmailQueryOptions>(this->shim().CreateWithTextAndFields(*reinterpret_cast<hstring const*>(&text), *reinterpret_cast<Windows::ApplicationModel::Email::EmailQuerySearchFields const*>(&fields)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Email::IEmailQueryTextSearch> : produce_base<D, Windows::ApplicationModel::Email::IEmailQueryTextSearch>
{
    int32_t WINRT_CALL get_Fields(Windows::ApplicationModel::Email::EmailQuerySearchFields* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Fields, WINRT_WRAP(Windows::ApplicationModel::Email::EmailQuerySearchFields));
            *value = detach_from<Windows::ApplicationModel::Email::EmailQuerySearchFields>(this->shim().Fields());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Fields(Windows::ApplicationModel::Email::EmailQuerySearchFields value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Fields, WINRT_WRAP(void), Windows::ApplicationModel::Email::EmailQuerySearchFields const&);
            this->shim().Fields(*reinterpret_cast<Windows::ApplicationModel::Email::EmailQuerySearchFields const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SearchScope(Windows::ApplicationModel::Email::EmailQuerySearchScope* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SearchScope, WINRT_WRAP(Windows::ApplicationModel::Email::EmailQuerySearchScope));
            *value = detach_from<Windows::ApplicationModel::Email::EmailQuerySearchScope>(this->shim().SearchScope());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SearchScope(Windows::ApplicationModel::Email::EmailQuerySearchScope value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SearchScope, WINRT_WRAP(void), Windows::ApplicationModel::Email::EmailQuerySearchScope const&);
            this->shim().SearchScope(*reinterpret_cast<Windows::ApplicationModel::Email::EmailQuerySearchScope const*>(&value));
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
struct produce<D, Windows::ApplicationModel::Email::IEmailRecipient> : produce_base<D, Windows::ApplicationModel::Email::IEmailRecipient>
{
    int32_t WINRT_CALL get_Name(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Name, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Name(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Name, WINRT_WRAP(void), hstring const&);
            this->shim().Name(*reinterpret_cast<hstring const*>(&value));
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
            WINRT_ASSERT_DECLARATION(Address, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Address());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Address(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Address, WINRT_WRAP(void), hstring const&);
            this->shim().Address(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Email::IEmailRecipientFactory> : produce_base<D, Windows::ApplicationModel::Email::IEmailRecipientFactory>
{
    int32_t WINRT_CALL Create(void* address, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::ApplicationModel::Email::EmailRecipient), hstring const&);
            *result = detach_from<Windows::ApplicationModel::Email::EmailRecipient>(this->shim().Create(*reinterpret_cast<hstring const*>(&address)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithName(void* address, void* name, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithName, WINRT_WRAP(Windows::ApplicationModel::Email::EmailRecipient), hstring const&, hstring const&);
            *result = detach_from<Windows::ApplicationModel::Email::EmailRecipient>(this->shim().CreateWithName(*reinterpret_cast<hstring const*>(&address), *reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Email::IEmailRecipientResolutionResult> : produce_base<D, Windows::ApplicationModel::Email::IEmailRecipientResolutionResult>
{
    int32_t WINRT_CALL get_Status(Windows::ApplicationModel::Email::EmailRecipientResolutionStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::ApplicationModel::Email::EmailRecipientResolutionStatus));
            *value = detach_from<Windows::ApplicationModel::Email::EmailRecipientResolutionStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PublicKeys(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PublicKeys, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Security::Cryptography::Certificates::Certificate>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Security::Cryptography::Certificates::Certificate>>(this->shim().PublicKeys());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Email::IEmailRecipientResolutionResult2> : produce_base<D, Windows::ApplicationModel::Email::IEmailRecipientResolutionResult2>
{
    int32_t WINRT_CALL put_Status(Windows::ApplicationModel::Email::EmailRecipientResolutionStatus value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(void), Windows::ApplicationModel::Email::EmailRecipientResolutionStatus const&);
            this->shim().Status(*reinterpret_cast<Windows::ApplicationModel::Email::EmailRecipientResolutionStatus const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetPublicKeys(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetPublicKeys, WINRT_WRAP(void), Windows::Foundation::Collections::IIterable<Windows::Security::Cryptography::Certificates::Certificate> const&);
            this->shim().SetPublicKeys(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Security::Cryptography::Certificates::Certificate> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Email::IEmailStore> : produce_base<D, Windows::ApplicationModel::Email::IEmailStore>
{
    int32_t WINRT_CALL FindMailboxesAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindMailboxesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Email::EmailMailbox>>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Email::EmailMailbox>>>(this->shim().FindMailboxesAsync());
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
            WINRT_ASSERT_DECLARATION(GetConversationReader, WINRT_WRAP(Windows::ApplicationModel::Email::EmailConversationReader));
            *result = detach_from<Windows::ApplicationModel::Email::EmailConversationReader>(this->shim().GetConversationReader());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetConversationReaderWithOptions(void* options, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetConversationReader, WINRT_WRAP(Windows::ApplicationModel::Email::EmailConversationReader), Windows::ApplicationModel::Email::EmailQueryOptions const&);
            *result = detach_from<Windows::ApplicationModel::Email::EmailConversationReader>(this->shim().GetConversationReader(*reinterpret_cast<Windows::ApplicationModel::Email::EmailQueryOptions const*>(&options)));
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
            WINRT_ASSERT_DECLARATION(GetMessageReader, WINRT_WRAP(Windows::ApplicationModel::Email::EmailMessageReader));
            *result = detach_from<Windows::ApplicationModel::Email::EmailMessageReader>(this->shim().GetMessageReader());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetMessageReaderWithOptions(void* options, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetMessageReader, WINRT_WRAP(Windows::ApplicationModel::Email::EmailMessageReader), Windows::ApplicationModel::Email::EmailQueryOptions const&);
            *result = detach_from<Windows::ApplicationModel::Email::EmailMessageReader>(this->shim().GetMessageReader(*reinterpret_cast<Windows::ApplicationModel::Email::EmailQueryOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetMailboxAsync(void* id, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetMailboxAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailMailbox>), hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailMailbox>>(this->shim().GetMailboxAsync(*reinterpret_cast<hstring const*>(&id)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetConversationAsync(void* id, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetConversationAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailConversation>), hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailConversation>>(this->shim().GetConversationAsync(*reinterpret_cast<hstring const*>(&id)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetFolderAsync(void* id, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetFolderAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailFolder>), hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailFolder>>(this->shim().GetFolderAsync(*reinterpret_cast<hstring const*>(&id)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetMessageAsync(void* id, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetMessageAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailMessage>), hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailMessage>>(this->shim().GetMessageAsync(*reinterpret_cast<hstring const*>(&id)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateMailboxAsync(void* accountName, void* accountAddress, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateMailboxAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailMailbox>), hstring const, hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailMailbox>>(this->shim().CreateMailboxAsync(*reinterpret_cast<hstring const*>(&accountName), *reinterpret_cast<hstring const*>(&accountAddress)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateMailboxInAccountAsync(void* accountName, void* accountAddress, void* userDataAccountId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateMailboxAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailMailbox>), hstring const, hstring const, hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailMailbox>>(this->shim().CreateMailboxAsync(*reinterpret_cast<hstring const*>(&accountName), *reinterpret_cast<hstring const*>(&accountAddress), *reinterpret_cast<hstring const*>(&userDataAccountId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Email::IEmailStoreNotificationTriggerDetails> : produce_base<D, Windows::ApplicationModel::Email::IEmailStoreNotificationTriggerDetails>
{};

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Email {

inline EmailAttachment::EmailAttachment() :
    EmailAttachment(impl::call_factory<EmailAttachment>([](auto&& f) { return f.template ActivateInstance<EmailAttachment>(); }))
{}

inline EmailAttachment::EmailAttachment(param::hstring const& fileName, Windows::Storage::Streams::IRandomAccessStreamReference const& data) :
    EmailAttachment(impl::call_factory<EmailAttachment, Windows::ApplicationModel::Email::IEmailAttachmentFactory>([&](auto&& f) { return f.Create(fileName, data); }))
{}

inline EmailAttachment::EmailAttachment(param::hstring const& fileName, Windows::Storage::Streams::IRandomAccessStreamReference const& data, param::hstring const& mimeType) :
    EmailAttachment(impl::call_factory<EmailAttachment, Windows::ApplicationModel::Email::IEmailAttachmentFactory2>([&](auto&& f) { return f.Create(fileName, data, mimeType); }))
{}

inline EmailIrmInfo::EmailIrmInfo() :
    EmailIrmInfo(impl::call_factory<EmailIrmInfo>([](auto&& f) { return f.template ActivateInstance<EmailIrmInfo>(); }))
{}

inline EmailIrmInfo::EmailIrmInfo(Windows::Foundation::DateTime const& expiration, Windows::ApplicationModel::Email::EmailIrmTemplate const& irmTemplate) :
    EmailIrmInfo(impl::call_factory<EmailIrmInfo, Windows::ApplicationModel::Email::IEmailIrmInfoFactory>([&](auto&& f) { return f.Create(expiration, irmTemplate); }))
{}

inline EmailIrmTemplate::EmailIrmTemplate() :
    EmailIrmTemplate(impl::call_factory<EmailIrmTemplate>([](auto&& f) { return f.template ActivateInstance<EmailIrmTemplate>(); }))
{}

inline EmailIrmTemplate::EmailIrmTemplate(param::hstring const& id, param::hstring const& name, param::hstring const& description) :
    EmailIrmTemplate(impl::call_factory<EmailIrmTemplate, Windows::ApplicationModel::Email::IEmailIrmTemplateFactory>([&](auto&& f) { return f.Create(id, name, description); }))
{}

inline EmailMailboxAutoReplySettings::EmailMailboxAutoReplySettings() :
    EmailMailboxAutoReplySettings(impl::call_factory<EmailMailboxAutoReplySettings>([](auto&& f) { return f.template ActivateInstance<EmailMailboxAutoReplySettings>(); }))
{}

inline Windows::Foundation::IAsyncAction EmailManager::ShowComposeNewEmailAsync(Windows::ApplicationModel::Email::EmailMessage const& message)
{
    return impl::call_factory<EmailManager, Windows::ApplicationModel::Email::IEmailManagerStatics>([&](auto&& f) { return f.ShowComposeNewEmailAsync(message); });
}

inline Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Email::EmailStore> EmailManager::RequestStoreAsync(Windows::ApplicationModel::Email::EmailStoreAccessType const& accessType)
{
    return impl::call_factory<EmailManager, Windows::ApplicationModel::Email::IEmailManagerStatics2>([&](auto&& f) { return f.RequestStoreAsync(accessType); });
}

inline Windows::ApplicationModel::Email::EmailManagerForUser EmailManager::GetForUser(Windows::System::User const& user)
{
    return impl::call_factory<EmailManager, Windows::ApplicationModel::Email::IEmailManagerStatics3>([&](auto&& f) { return f.GetForUser(user); });
}

inline EmailMeetingInfo::EmailMeetingInfo() :
    EmailMeetingInfo(impl::call_factory<EmailMeetingInfo>([](auto&& f) { return f.template ActivateInstance<EmailMeetingInfo>(); }))
{}

inline EmailMessage::EmailMessage() :
    EmailMessage(impl::call_factory<EmailMessage>([](auto&& f) { return f.template ActivateInstance<EmailMessage>(); }))
{}

inline EmailQueryOptions::EmailQueryOptions() :
    EmailQueryOptions(impl::call_factory<EmailQueryOptions>([](auto&& f) { return f.template ActivateInstance<EmailQueryOptions>(); }))
{}

inline EmailQueryOptions::EmailQueryOptions(param::hstring const& text) :
    EmailQueryOptions(impl::call_factory<EmailQueryOptions, Windows::ApplicationModel::Email::IEmailQueryOptionsFactory>([&](auto&& f) { return f.CreateWithText(text); }))
{}

inline EmailQueryOptions::EmailQueryOptions(param::hstring const& text, Windows::ApplicationModel::Email::EmailQuerySearchFields const& fields) :
    EmailQueryOptions(impl::call_factory<EmailQueryOptions, Windows::ApplicationModel::Email::IEmailQueryOptionsFactory>([&](auto&& f) { return f.CreateWithTextAndFields(text, fields); }))
{}

inline EmailRecipient::EmailRecipient() :
    EmailRecipient(impl::call_factory<EmailRecipient>([](auto&& f) { return f.template ActivateInstance<EmailRecipient>(); }))
{}

inline EmailRecipient::EmailRecipient(param::hstring const& address) :
    EmailRecipient(impl::call_factory<EmailRecipient, Windows::ApplicationModel::Email::IEmailRecipientFactory>([&](auto&& f) { return f.Create(address); }))
{}

inline EmailRecipient::EmailRecipient(param::hstring const& address, param::hstring const& name) :
    EmailRecipient(impl::call_factory<EmailRecipient, Windows::ApplicationModel::Email::IEmailRecipientFactory>([&](auto&& f) { return f.CreateWithName(address, name); }))
{}

inline EmailRecipientResolutionResult::EmailRecipientResolutionResult() :
    EmailRecipientResolutionResult(impl::call_factory<EmailRecipientResolutionResult>([](auto&& f) { return f.template ActivateInstance<EmailRecipientResolutionResult>(); }))
{}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailAttachment> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::IEmailAttachment> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailAttachment2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::IEmailAttachment2> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailAttachmentFactory> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::IEmailAttachmentFactory> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailAttachmentFactory2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::IEmailAttachmentFactory2> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailConversation> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::IEmailConversation> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailConversationBatch> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::IEmailConversationBatch> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailConversationReader> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::IEmailConversationReader> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailFolder> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::IEmailFolder> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailIrmInfo> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::IEmailIrmInfo> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailIrmInfoFactory> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::IEmailIrmInfoFactory> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailIrmTemplate> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::IEmailIrmTemplate> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailIrmTemplateFactory> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::IEmailIrmTemplateFactory> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailItemCounts> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::IEmailItemCounts> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailMailbox> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::IEmailMailbox> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailMailbox2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::IEmailMailbox2> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailMailbox3> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::IEmailMailbox3> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailMailbox4> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::IEmailMailbox4> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailMailbox5> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::IEmailMailbox5> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailMailboxAction> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::IEmailMailboxAction> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailMailboxAutoReply> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::IEmailMailboxAutoReply> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailMailboxAutoReplySettings> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::IEmailMailboxAutoReplySettings> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailMailboxCapabilities> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::IEmailMailboxCapabilities> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailMailboxCapabilities2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::IEmailMailboxCapabilities2> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailMailboxCapabilities3> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::IEmailMailboxCapabilities3> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailMailboxChange> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::IEmailMailboxChange> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailMailboxChangeReader> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::IEmailMailboxChangeReader> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailMailboxChangeTracker> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::IEmailMailboxChangeTracker> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailMailboxChangedDeferral> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::IEmailMailboxChangedDeferral> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailMailboxChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::IEmailMailboxChangedEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailMailboxCreateFolderResult> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::IEmailMailboxCreateFolderResult> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailMailboxPolicies> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::IEmailMailboxPolicies> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailMailboxPolicies2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::IEmailMailboxPolicies2> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailMailboxPolicies3> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::IEmailMailboxPolicies3> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailMailboxSyncManager> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::IEmailMailboxSyncManager> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailMailboxSyncManager2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::IEmailMailboxSyncManager2> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailManagerForUser> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::IEmailManagerForUser> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailManagerStatics> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::IEmailManagerStatics> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailManagerStatics2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::IEmailManagerStatics2> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailManagerStatics3> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::IEmailManagerStatics3> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailMeetingInfo> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::IEmailMeetingInfo> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailMeetingInfo2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::IEmailMeetingInfo2> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailMessage> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::IEmailMessage> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailMessage2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::IEmailMessage2> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailMessage3> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::IEmailMessage3> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailMessage4> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::IEmailMessage4> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailMessageBatch> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::IEmailMessageBatch> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailMessageReader> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::IEmailMessageReader> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailQueryOptions> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::IEmailQueryOptions> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailQueryOptionsFactory> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::IEmailQueryOptionsFactory> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailQueryTextSearch> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::IEmailQueryTextSearch> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailRecipient> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::IEmailRecipient> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailRecipientFactory> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::IEmailRecipientFactory> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailRecipientResolutionResult> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::IEmailRecipientResolutionResult> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailRecipientResolutionResult2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::IEmailRecipientResolutionResult2> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailStore> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::IEmailStore> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::IEmailStoreNotificationTriggerDetails> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::IEmailStoreNotificationTriggerDetails> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::EmailAttachment> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::EmailAttachment> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::EmailConversation> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::EmailConversation> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::EmailConversationBatch> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::EmailConversationBatch> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::EmailConversationReader> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::EmailConversationReader> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::EmailFolder> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::EmailFolder> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::EmailIrmInfo> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::EmailIrmInfo> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::EmailIrmTemplate> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::EmailIrmTemplate> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::EmailItemCounts> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::EmailItemCounts> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::EmailMailbox> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::EmailMailbox> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::EmailMailboxAction> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::EmailMailboxAction> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::EmailMailboxAutoReply> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::EmailMailboxAutoReply> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::EmailMailboxAutoReplySettings> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::EmailMailboxAutoReplySettings> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::EmailMailboxCapabilities> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::EmailMailboxCapabilities> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::EmailMailboxChange> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::EmailMailboxChange> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::EmailMailboxChangeReader> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::EmailMailboxChangeReader> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::EmailMailboxChangeTracker> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::EmailMailboxChangeTracker> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::EmailMailboxChangedDeferral> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::EmailMailboxChangedDeferral> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::EmailMailboxChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::EmailMailboxChangedEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::EmailMailboxCreateFolderResult> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::EmailMailboxCreateFolderResult> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::EmailMailboxPolicies> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::EmailMailboxPolicies> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::EmailMailboxSyncManager> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::EmailMailboxSyncManager> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::EmailManager> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::EmailManager> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::EmailManagerForUser> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::EmailManagerForUser> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::EmailMeetingInfo> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::EmailMeetingInfo> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::EmailMessage> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::EmailMessage> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::EmailMessageBatch> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::EmailMessageBatch> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::EmailMessageReader> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::EmailMessageReader> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::EmailQueryOptions> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::EmailQueryOptions> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::EmailQueryTextSearch> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::EmailQueryTextSearch> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::EmailRecipient> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::EmailRecipient> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::EmailRecipientResolutionResult> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::EmailRecipientResolutionResult> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::EmailStore> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::EmailStore> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::EmailStoreNotificationTriggerDetails> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::EmailStoreNotificationTriggerDetails> {};

}
