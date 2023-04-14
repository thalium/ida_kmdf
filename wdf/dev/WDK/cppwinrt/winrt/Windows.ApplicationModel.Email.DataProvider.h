// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.ApplicationModel.Email.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Security.Cryptography.Certificates.2.h"
#include "winrt/impl/Windows.ApplicationModel.Email.DataProvider.2.h"
#include "winrt/Windows.ApplicationModel.Email.h"

namespace winrt::impl {

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Email_DataProvider_IEmailDataProviderConnection<D>::MailboxSyncRequested(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, Windows::ApplicationModel::Email::DataProvider::EmailMailboxSyncManagerSyncRequestEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderConnection)->add_MailboxSyncRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Email_DataProvider_IEmailDataProviderConnection<D>::MailboxSyncRequested_revoker consume_Windows_ApplicationModel_Email_DataProvider_IEmailDataProviderConnection<D>::MailboxSyncRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, Windows::ApplicationModel::Email::DataProvider::EmailMailboxSyncManagerSyncRequestEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, MailboxSyncRequested_revoker>(this, MailboxSyncRequested(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Email_DataProvider_IEmailDataProviderConnection<D>::MailboxSyncRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderConnection)->remove_MailboxSyncRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Email_DataProvider_IEmailDataProviderConnection<D>::DownloadMessageRequested(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, Windows::ApplicationModel::Email::DataProvider::EmailMailboxDownloadMessageRequestEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderConnection)->add_DownloadMessageRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Email_DataProvider_IEmailDataProviderConnection<D>::DownloadMessageRequested_revoker consume_Windows_ApplicationModel_Email_DataProvider_IEmailDataProviderConnection<D>::DownloadMessageRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, Windows::ApplicationModel::Email::DataProvider::EmailMailboxDownloadMessageRequestEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, DownloadMessageRequested_revoker>(this, DownloadMessageRequested(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Email_DataProvider_IEmailDataProviderConnection<D>::DownloadMessageRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderConnection)->remove_DownloadMessageRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Email_DataProvider_IEmailDataProviderConnection<D>::DownloadAttachmentRequested(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, Windows::ApplicationModel::Email::DataProvider::EmailMailboxDownloadAttachmentRequestEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderConnection)->add_DownloadAttachmentRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Email_DataProvider_IEmailDataProviderConnection<D>::DownloadAttachmentRequested_revoker consume_Windows_ApplicationModel_Email_DataProvider_IEmailDataProviderConnection<D>::DownloadAttachmentRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, Windows::ApplicationModel::Email::DataProvider::EmailMailboxDownloadAttachmentRequestEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, DownloadAttachmentRequested_revoker>(this, DownloadAttachmentRequested(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Email_DataProvider_IEmailDataProviderConnection<D>::DownloadAttachmentRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderConnection)->remove_DownloadAttachmentRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Email_DataProvider_IEmailDataProviderConnection<D>::CreateFolderRequested(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, Windows::ApplicationModel::Email::DataProvider::EmailMailboxCreateFolderRequestEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderConnection)->add_CreateFolderRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Email_DataProvider_IEmailDataProviderConnection<D>::CreateFolderRequested_revoker consume_Windows_ApplicationModel_Email_DataProvider_IEmailDataProviderConnection<D>::CreateFolderRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, Windows::ApplicationModel::Email::DataProvider::EmailMailboxCreateFolderRequestEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, CreateFolderRequested_revoker>(this, CreateFolderRequested(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Email_DataProvider_IEmailDataProviderConnection<D>::CreateFolderRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderConnection)->remove_CreateFolderRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Email_DataProvider_IEmailDataProviderConnection<D>::DeleteFolderRequested(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, Windows::ApplicationModel::Email::DataProvider::EmailMailboxDeleteFolderRequestEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderConnection)->add_DeleteFolderRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Email_DataProvider_IEmailDataProviderConnection<D>::DeleteFolderRequested_revoker consume_Windows_ApplicationModel_Email_DataProvider_IEmailDataProviderConnection<D>::DeleteFolderRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, Windows::ApplicationModel::Email::DataProvider::EmailMailboxDeleteFolderRequestEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, DeleteFolderRequested_revoker>(this, DeleteFolderRequested(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Email_DataProvider_IEmailDataProviderConnection<D>::DeleteFolderRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderConnection)->remove_DeleteFolderRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Email_DataProvider_IEmailDataProviderConnection<D>::EmptyFolderRequested(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, Windows::ApplicationModel::Email::DataProvider::EmailMailboxEmptyFolderRequestEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderConnection)->add_EmptyFolderRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Email_DataProvider_IEmailDataProviderConnection<D>::EmptyFolderRequested_revoker consume_Windows_ApplicationModel_Email_DataProvider_IEmailDataProviderConnection<D>::EmptyFolderRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, Windows::ApplicationModel::Email::DataProvider::EmailMailboxEmptyFolderRequestEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, EmptyFolderRequested_revoker>(this, EmptyFolderRequested(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Email_DataProvider_IEmailDataProviderConnection<D>::EmptyFolderRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderConnection)->remove_EmptyFolderRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Email_DataProvider_IEmailDataProviderConnection<D>::MoveFolderRequested(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, Windows::ApplicationModel::Email::DataProvider::EmailMailboxMoveFolderRequestEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderConnection)->add_MoveFolderRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Email_DataProvider_IEmailDataProviderConnection<D>::MoveFolderRequested_revoker consume_Windows_ApplicationModel_Email_DataProvider_IEmailDataProviderConnection<D>::MoveFolderRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, Windows::ApplicationModel::Email::DataProvider::EmailMailboxMoveFolderRequestEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, MoveFolderRequested_revoker>(this, MoveFolderRequested(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Email_DataProvider_IEmailDataProviderConnection<D>::MoveFolderRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderConnection)->remove_MoveFolderRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Email_DataProvider_IEmailDataProviderConnection<D>::UpdateMeetingResponseRequested(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, Windows::ApplicationModel::Email::DataProvider::EmailMailboxUpdateMeetingResponseRequestEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderConnection)->add_UpdateMeetingResponseRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Email_DataProvider_IEmailDataProviderConnection<D>::UpdateMeetingResponseRequested_revoker consume_Windows_ApplicationModel_Email_DataProvider_IEmailDataProviderConnection<D>::UpdateMeetingResponseRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, Windows::ApplicationModel::Email::DataProvider::EmailMailboxUpdateMeetingResponseRequestEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, UpdateMeetingResponseRequested_revoker>(this, UpdateMeetingResponseRequested(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Email_DataProvider_IEmailDataProviderConnection<D>::UpdateMeetingResponseRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderConnection)->remove_UpdateMeetingResponseRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Email_DataProvider_IEmailDataProviderConnection<D>::ForwardMeetingRequested(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, Windows::ApplicationModel::Email::DataProvider::EmailMailboxForwardMeetingRequestEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderConnection)->add_ForwardMeetingRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Email_DataProvider_IEmailDataProviderConnection<D>::ForwardMeetingRequested_revoker consume_Windows_ApplicationModel_Email_DataProvider_IEmailDataProviderConnection<D>::ForwardMeetingRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, Windows::ApplicationModel::Email::DataProvider::EmailMailboxForwardMeetingRequestEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ForwardMeetingRequested_revoker>(this, ForwardMeetingRequested(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Email_DataProvider_IEmailDataProviderConnection<D>::ForwardMeetingRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderConnection)->remove_ForwardMeetingRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Email_DataProvider_IEmailDataProviderConnection<D>::ProposeNewTimeForMeetingRequested(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, Windows::ApplicationModel::Email::DataProvider::EmailMailboxProposeNewTimeForMeetingRequestEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderConnection)->add_ProposeNewTimeForMeetingRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Email_DataProvider_IEmailDataProviderConnection<D>::ProposeNewTimeForMeetingRequested_revoker consume_Windows_ApplicationModel_Email_DataProvider_IEmailDataProviderConnection<D>::ProposeNewTimeForMeetingRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, Windows::ApplicationModel::Email::DataProvider::EmailMailboxProposeNewTimeForMeetingRequestEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ProposeNewTimeForMeetingRequested_revoker>(this, ProposeNewTimeForMeetingRequested(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Email_DataProvider_IEmailDataProviderConnection<D>::ProposeNewTimeForMeetingRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderConnection)->remove_ProposeNewTimeForMeetingRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Email_DataProvider_IEmailDataProviderConnection<D>::SetAutoReplySettingsRequested(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, Windows::ApplicationModel::Email::DataProvider::EmailMailboxSetAutoReplySettingsRequestEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderConnection)->add_SetAutoReplySettingsRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Email_DataProvider_IEmailDataProviderConnection<D>::SetAutoReplySettingsRequested_revoker consume_Windows_ApplicationModel_Email_DataProvider_IEmailDataProviderConnection<D>::SetAutoReplySettingsRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, Windows::ApplicationModel::Email::DataProvider::EmailMailboxSetAutoReplySettingsRequestEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, SetAutoReplySettingsRequested_revoker>(this, SetAutoReplySettingsRequested(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Email_DataProvider_IEmailDataProviderConnection<D>::SetAutoReplySettingsRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderConnection)->remove_SetAutoReplySettingsRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Email_DataProvider_IEmailDataProviderConnection<D>::GetAutoReplySettingsRequested(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, Windows::ApplicationModel::Email::DataProvider::EmailMailboxGetAutoReplySettingsRequestEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderConnection)->add_GetAutoReplySettingsRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Email_DataProvider_IEmailDataProviderConnection<D>::GetAutoReplySettingsRequested_revoker consume_Windows_ApplicationModel_Email_DataProvider_IEmailDataProviderConnection<D>::GetAutoReplySettingsRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, Windows::ApplicationModel::Email::DataProvider::EmailMailboxGetAutoReplySettingsRequestEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, GetAutoReplySettingsRequested_revoker>(this, GetAutoReplySettingsRequested(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Email_DataProvider_IEmailDataProviderConnection<D>::GetAutoReplySettingsRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderConnection)->remove_GetAutoReplySettingsRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Email_DataProvider_IEmailDataProviderConnection<D>::ResolveRecipientsRequested(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, Windows::ApplicationModel::Email::DataProvider::EmailMailboxResolveRecipientsRequestEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderConnection)->add_ResolveRecipientsRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Email_DataProvider_IEmailDataProviderConnection<D>::ResolveRecipientsRequested_revoker consume_Windows_ApplicationModel_Email_DataProvider_IEmailDataProviderConnection<D>::ResolveRecipientsRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, Windows::ApplicationModel::Email::DataProvider::EmailMailboxResolveRecipientsRequestEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ResolveRecipientsRequested_revoker>(this, ResolveRecipientsRequested(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Email_DataProvider_IEmailDataProviderConnection<D>::ResolveRecipientsRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderConnection)->remove_ResolveRecipientsRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Email_DataProvider_IEmailDataProviderConnection<D>::ValidateCertificatesRequested(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, Windows::ApplicationModel::Email::DataProvider::EmailMailboxValidateCertificatesRequestEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderConnection)->add_ValidateCertificatesRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Email_DataProvider_IEmailDataProviderConnection<D>::ValidateCertificatesRequested_revoker consume_Windows_ApplicationModel_Email_DataProvider_IEmailDataProviderConnection<D>::ValidateCertificatesRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, Windows::ApplicationModel::Email::DataProvider::EmailMailboxValidateCertificatesRequestEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ValidateCertificatesRequested_revoker>(this, ValidateCertificatesRequested(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Email_DataProvider_IEmailDataProviderConnection<D>::ValidateCertificatesRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderConnection)->remove_ValidateCertificatesRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Email_DataProvider_IEmailDataProviderConnection<D>::ServerSearchReadBatchRequested(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, Windows::ApplicationModel::Email::DataProvider::EmailMailboxServerSearchReadBatchRequestEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderConnection)->add_ServerSearchReadBatchRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Email_DataProvider_IEmailDataProviderConnection<D>::ServerSearchReadBatchRequested_revoker consume_Windows_ApplicationModel_Email_DataProvider_IEmailDataProviderConnection<D>::ServerSearchReadBatchRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, Windows::ApplicationModel::Email::DataProvider::EmailMailboxServerSearchReadBatchRequestEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ServerSearchReadBatchRequested_revoker>(this, ServerSearchReadBatchRequested(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Email_DataProvider_IEmailDataProviderConnection<D>::ServerSearchReadBatchRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderConnection)->remove_ServerSearchReadBatchRequested(get_abi(token)));
}

template <typename D> void consume_Windows_ApplicationModel_Email_DataProvider_IEmailDataProviderConnection<D>::Start() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderConnection)->Start());
}

template <typename D> Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection consume_Windows_ApplicationModel_Email_DataProvider_IEmailDataProviderTriggerDetails<D>::Connection() const
{
    Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderTriggerDetails)->get_Connection(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxCreateFolderRequest<D>::EmailMailboxId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxCreateFolderRequest)->get_EmailMailboxId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxCreateFolderRequest<D>::ParentFolderId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxCreateFolderRequest)->get_ParentFolderId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxCreateFolderRequest<D>::Name() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxCreateFolderRequest)->get_Name(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxCreateFolderRequest<D>::ReportCompletedAsync(Windows::ApplicationModel::Email::EmailFolder const& folder) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxCreateFolderRequest)->ReportCompletedAsync(get_abi(folder), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxCreateFolderRequest<D>::ReportFailedAsync(Windows::ApplicationModel::Email::EmailMailboxCreateFolderStatus const& status) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxCreateFolderRequest)->ReportFailedAsync(get_abi(status), put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Email::DataProvider::EmailMailboxCreateFolderRequest consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxCreateFolderRequestEventArgs<D>::Request() const
{
    Windows::ApplicationModel::Email::DataProvider::EmailMailboxCreateFolderRequest value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxCreateFolderRequestEventArgs)->get_Request(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Deferral consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxCreateFolderRequestEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxCreateFolderRequestEventArgs)->GetDeferral(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxDeleteFolderRequest<D>::EmailMailboxId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDeleteFolderRequest)->get_EmailMailboxId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxDeleteFolderRequest<D>::EmailFolderId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDeleteFolderRequest)->get_EmailFolderId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxDeleteFolderRequest<D>::ReportCompletedAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDeleteFolderRequest)->ReportCompletedAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxDeleteFolderRequest<D>::ReportFailedAsync(Windows::ApplicationModel::Email::EmailMailboxDeleteFolderStatus const& status) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDeleteFolderRequest)->ReportFailedAsync(get_abi(status), put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Email::DataProvider::EmailMailboxDeleteFolderRequest consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxDeleteFolderRequestEventArgs<D>::Request() const
{
    Windows::ApplicationModel::Email::DataProvider::EmailMailboxDeleteFolderRequest value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDeleteFolderRequestEventArgs)->get_Request(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Deferral consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxDeleteFolderRequestEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDeleteFolderRequestEventArgs)->GetDeferral(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxDownloadAttachmentRequest<D>::EmailMailboxId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDownloadAttachmentRequest)->get_EmailMailboxId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxDownloadAttachmentRequest<D>::EmailMessageId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDownloadAttachmentRequest)->get_EmailMessageId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxDownloadAttachmentRequest<D>::EmailAttachmentId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDownloadAttachmentRequest)->get_EmailAttachmentId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxDownloadAttachmentRequest<D>::ReportCompletedAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDownloadAttachmentRequest)->ReportCompletedAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxDownloadAttachmentRequest<D>::ReportFailedAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDownloadAttachmentRequest)->ReportFailedAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Email::DataProvider::EmailMailboxDownloadAttachmentRequest consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxDownloadAttachmentRequestEventArgs<D>::Request() const
{
    Windows::ApplicationModel::Email::DataProvider::EmailMailboxDownloadAttachmentRequest value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDownloadAttachmentRequestEventArgs)->get_Request(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Deferral consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxDownloadAttachmentRequestEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDownloadAttachmentRequestEventArgs)->GetDeferral(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxDownloadMessageRequest<D>::EmailMailboxId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDownloadMessageRequest)->get_EmailMailboxId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxDownloadMessageRequest<D>::EmailMessageId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDownloadMessageRequest)->get_EmailMessageId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxDownloadMessageRequest<D>::ReportCompletedAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDownloadMessageRequest)->ReportCompletedAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxDownloadMessageRequest<D>::ReportFailedAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDownloadMessageRequest)->ReportFailedAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Email::DataProvider::EmailMailboxDownloadMessageRequest consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxDownloadMessageRequestEventArgs<D>::Request() const
{
    Windows::ApplicationModel::Email::DataProvider::EmailMailboxDownloadMessageRequest value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDownloadMessageRequestEventArgs)->get_Request(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Deferral consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxDownloadMessageRequestEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDownloadMessageRequestEventArgs)->GetDeferral(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxEmptyFolderRequest<D>::EmailMailboxId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxEmptyFolderRequest)->get_EmailMailboxId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxEmptyFolderRequest<D>::EmailFolderId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxEmptyFolderRequest)->get_EmailFolderId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxEmptyFolderRequest<D>::ReportCompletedAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxEmptyFolderRequest)->ReportCompletedAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxEmptyFolderRequest<D>::ReportFailedAsync(Windows::ApplicationModel::Email::EmailMailboxEmptyFolderStatus const& status) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxEmptyFolderRequest)->ReportFailedAsync(get_abi(status), put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Email::DataProvider::EmailMailboxEmptyFolderRequest consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxEmptyFolderRequestEventArgs<D>::Request() const
{
    Windows::ApplicationModel::Email::DataProvider::EmailMailboxEmptyFolderRequest value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxEmptyFolderRequestEventArgs)->get_Request(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Deferral consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxEmptyFolderRequestEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxEmptyFolderRequestEventArgs)->GetDeferral(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxForwardMeetingRequest<D>::EmailMailboxId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxForwardMeetingRequest)->get_EmailMailboxId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxForwardMeetingRequest<D>::EmailMessageId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxForwardMeetingRequest)->get_EmailMessageId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Email::EmailRecipient> consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxForwardMeetingRequest<D>::Recipients() const
{
    Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Email::EmailRecipient> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxForwardMeetingRequest)->get_Recipients(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxForwardMeetingRequest<D>::Subject() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxForwardMeetingRequest)->get_Subject(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Email::EmailMessageBodyKind consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxForwardMeetingRequest<D>::ForwardHeaderType() const
{
    Windows::ApplicationModel::Email::EmailMessageBodyKind value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxForwardMeetingRequest)->get_ForwardHeaderType(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxForwardMeetingRequest<D>::ForwardHeader() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxForwardMeetingRequest)->get_ForwardHeader(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxForwardMeetingRequest<D>::Comment() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxForwardMeetingRequest)->get_Comment(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxForwardMeetingRequest<D>::ReportCompletedAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxForwardMeetingRequest)->ReportCompletedAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxForwardMeetingRequest<D>::ReportFailedAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxForwardMeetingRequest)->ReportFailedAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Email::DataProvider::EmailMailboxForwardMeetingRequest consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxForwardMeetingRequestEventArgs<D>::Request() const
{
    Windows::ApplicationModel::Email::DataProvider::EmailMailboxForwardMeetingRequest value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxForwardMeetingRequestEventArgs)->get_Request(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Deferral consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxForwardMeetingRequestEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxForwardMeetingRequestEventArgs)->GetDeferral(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxGetAutoReplySettingsRequest<D>::EmailMailboxId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxGetAutoReplySettingsRequest)->get_EmailMailboxId(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Email::EmailMailboxAutoReplyMessageResponseKind consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxGetAutoReplySettingsRequest<D>::RequestedFormat() const
{
    Windows::ApplicationModel::Email::EmailMailboxAutoReplyMessageResponseKind value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxGetAutoReplySettingsRequest)->get_RequestedFormat(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxGetAutoReplySettingsRequest<D>::ReportCompletedAsync(Windows::ApplicationModel::Email::EmailMailboxAutoReplySettings const& autoReplySettings) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxGetAutoReplySettingsRequest)->ReportCompletedAsync(get_abi(autoReplySettings), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxGetAutoReplySettingsRequest<D>::ReportFailedAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxGetAutoReplySettingsRequest)->ReportFailedAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Email::DataProvider::EmailMailboxGetAutoReplySettingsRequest consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxGetAutoReplySettingsRequestEventArgs<D>::Request() const
{
    Windows::ApplicationModel::Email::DataProvider::EmailMailboxGetAutoReplySettingsRequest value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxGetAutoReplySettingsRequestEventArgs)->get_Request(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Deferral consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxGetAutoReplySettingsRequestEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxGetAutoReplySettingsRequestEventArgs)->GetDeferral(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxMoveFolderRequest<D>::EmailMailboxId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxMoveFolderRequest)->get_EmailMailboxId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxMoveFolderRequest<D>::EmailFolderId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxMoveFolderRequest)->get_EmailFolderId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxMoveFolderRequest<D>::NewParentFolderId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxMoveFolderRequest)->get_NewParentFolderId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxMoveFolderRequest<D>::NewFolderName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxMoveFolderRequest)->get_NewFolderName(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxMoveFolderRequest<D>::ReportCompletedAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxMoveFolderRequest)->ReportCompletedAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxMoveFolderRequest<D>::ReportFailedAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxMoveFolderRequest)->ReportFailedAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Email::DataProvider::EmailMailboxMoveFolderRequest consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxMoveFolderRequestEventArgs<D>::Request() const
{
    Windows::ApplicationModel::Email::DataProvider::EmailMailboxMoveFolderRequest value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxMoveFolderRequestEventArgs)->get_Request(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Deferral consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxMoveFolderRequestEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxMoveFolderRequestEventArgs)->GetDeferral(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxProposeNewTimeForMeetingRequest<D>::EmailMailboxId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxProposeNewTimeForMeetingRequest)->get_EmailMailboxId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxProposeNewTimeForMeetingRequest<D>::EmailMessageId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxProposeNewTimeForMeetingRequest)->get_EmailMessageId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxProposeNewTimeForMeetingRequest<D>::NewStartTime() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxProposeNewTimeForMeetingRequest)->get_NewStartTime(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxProposeNewTimeForMeetingRequest<D>::NewDuration() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxProposeNewTimeForMeetingRequest)->get_NewDuration(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxProposeNewTimeForMeetingRequest<D>::Subject() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxProposeNewTimeForMeetingRequest)->get_Subject(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxProposeNewTimeForMeetingRequest<D>::Comment() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxProposeNewTimeForMeetingRequest)->get_Comment(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxProposeNewTimeForMeetingRequest<D>::ReportCompletedAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxProposeNewTimeForMeetingRequest)->ReportCompletedAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxProposeNewTimeForMeetingRequest<D>::ReportFailedAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxProposeNewTimeForMeetingRequest)->ReportFailedAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Email::DataProvider::EmailMailboxProposeNewTimeForMeetingRequest consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxProposeNewTimeForMeetingRequestEventArgs<D>::Request() const
{
    Windows::ApplicationModel::Email::DataProvider::EmailMailboxProposeNewTimeForMeetingRequest value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxProposeNewTimeForMeetingRequestEventArgs)->get_Request(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Deferral consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxProposeNewTimeForMeetingRequestEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxProposeNewTimeForMeetingRequestEventArgs)->GetDeferral(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxResolveRecipientsRequest<D>::EmailMailboxId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxResolveRecipientsRequest)->get_EmailMailboxId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<hstring> consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxResolveRecipientsRequest<D>::Recipients() const
{
    Windows::Foundation::Collections::IVectorView<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxResolveRecipientsRequest)->get_Recipients(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxResolveRecipientsRequest<D>::ReportCompletedAsync(param::async_iterable<Windows::ApplicationModel::Email::EmailRecipientResolutionResult> const& resolutionResults) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxResolveRecipientsRequest)->ReportCompletedAsync(get_abi(resolutionResults), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxResolveRecipientsRequest<D>::ReportFailedAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxResolveRecipientsRequest)->ReportFailedAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Email::DataProvider::EmailMailboxResolveRecipientsRequest consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxResolveRecipientsRequestEventArgs<D>::Request() const
{
    Windows::ApplicationModel::Email::DataProvider::EmailMailboxResolveRecipientsRequest value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxResolveRecipientsRequestEventArgs)->get_Request(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Deferral consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxResolveRecipientsRequestEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxResolveRecipientsRequestEventArgs)->GetDeferral(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxServerSearchReadBatchRequest<D>::SessionId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxServerSearchReadBatchRequest)->get_SessionId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxServerSearchReadBatchRequest<D>::EmailMailboxId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxServerSearchReadBatchRequest)->get_EmailMailboxId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxServerSearchReadBatchRequest<D>::EmailFolderId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxServerSearchReadBatchRequest)->get_EmailFolderId(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Email::EmailQueryOptions consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxServerSearchReadBatchRequest<D>::Options() const
{
    Windows::ApplicationModel::Email::EmailQueryOptions value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxServerSearchReadBatchRequest)->get_Options(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxServerSearchReadBatchRequest<D>::SuggestedBatchSize() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxServerSearchReadBatchRequest)->get_SuggestedBatchSize(&value));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxServerSearchReadBatchRequest<D>::SaveMessageAsync(Windows::ApplicationModel::Email::EmailMessage const& message) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxServerSearchReadBatchRequest)->SaveMessageAsync(get_abi(message), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxServerSearchReadBatchRequest<D>::ReportCompletedAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxServerSearchReadBatchRequest)->ReportCompletedAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxServerSearchReadBatchRequest<D>::ReportFailedAsync(Windows::ApplicationModel::Email::EmailBatchStatus const& batchStatus) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxServerSearchReadBatchRequest)->ReportFailedAsync(get_abi(batchStatus), put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Email::DataProvider::EmailMailboxServerSearchReadBatchRequest consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxServerSearchReadBatchRequestEventArgs<D>::Request() const
{
    Windows::ApplicationModel::Email::DataProvider::EmailMailboxServerSearchReadBatchRequest value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxServerSearchReadBatchRequestEventArgs)->get_Request(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Deferral consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxServerSearchReadBatchRequestEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxServerSearchReadBatchRequestEventArgs)->GetDeferral(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxSetAutoReplySettingsRequest<D>::EmailMailboxId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxSetAutoReplySettingsRequest)->get_EmailMailboxId(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Email::EmailMailboxAutoReplySettings consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxSetAutoReplySettingsRequest<D>::AutoReplySettings() const
{
    Windows::ApplicationModel::Email::EmailMailboxAutoReplySettings value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxSetAutoReplySettingsRequest)->get_AutoReplySettings(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxSetAutoReplySettingsRequest<D>::ReportCompletedAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxSetAutoReplySettingsRequest)->ReportCompletedAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxSetAutoReplySettingsRequest<D>::ReportFailedAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxSetAutoReplySettingsRequest)->ReportFailedAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Email::DataProvider::EmailMailboxSetAutoReplySettingsRequest consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxSetAutoReplySettingsRequestEventArgs<D>::Request() const
{
    Windows::ApplicationModel::Email::DataProvider::EmailMailboxSetAutoReplySettingsRequest value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxSetAutoReplySettingsRequestEventArgs)->get_Request(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Deferral consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxSetAutoReplySettingsRequestEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxSetAutoReplySettingsRequestEventArgs)->GetDeferral(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxSyncManagerSyncRequest<D>::EmailMailboxId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxSyncManagerSyncRequest)->get_EmailMailboxId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxSyncManagerSyncRequest<D>::ReportCompletedAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxSyncManagerSyncRequest)->ReportCompletedAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxSyncManagerSyncRequest<D>::ReportFailedAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxSyncManagerSyncRequest)->ReportFailedAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Email::DataProvider::EmailMailboxSyncManagerSyncRequest consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxSyncManagerSyncRequestEventArgs<D>::Request() const
{
    Windows::ApplicationModel::Email::DataProvider::EmailMailboxSyncManagerSyncRequest value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxSyncManagerSyncRequestEventArgs)->get_Request(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Deferral consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxSyncManagerSyncRequestEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxSyncManagerSyncRequestEventArgs)->GetDeferral(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxUpdateMeetingResponseRequest<D>::EmailMailboxId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxUpdateMeetingResponseRequest)->get_EmailMailboxId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxUpdateMeetingResponseRequest<D>::EmailMessageId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxUpdateMeetingResponseRequest)->get_EmailMessageId(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Email::EmailMeetingResponseType consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxUpdateMeetingResponseRequest<D>::Response() const
{
    Windows::ApplicationModel::Email::EmailMeetingResponseType response{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxUpdateMeetingResponseRequest)->get_Response(put_abi(response)));
    return response;
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxUpdateMeetingResponseRequest<D>::Subject() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxUpdateMeetingResponseRequest)->get_Subject(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxUpdateMeetingResponseRequest<D>::Comment() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxUpdateMeetingResponseRequest)->get_Comment(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxUpdateMeetingResponseRequest<D>::SendUpdate() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxUpdateMeetingResponseRequest)->get_SendUpdate(&value));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxUpdateMeetingResponseRequest<D>::ReportCompletedAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxUpdateMeetingResponseRequest)->ReportCompletedAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxUpdateMeetingResponseRequest<D>::ReportFailedAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxUpdateMeetingResponseRequest)->ReportFailedAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Email::DataProvider::EmailMailboxUpdateMeetingResponseRequest consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxUpdateMeetingResponseRequestEventArgs<D>::Request() const
{
    Windows::ApplicationModel::Email::DataProvider::EmailMailboxUpdateMeetingResponseRequest value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxUpdateMeetingResponseRequestEventArgs)->get_Request(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Deferral consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxUpdateMeetingResponseRequestEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxUpdateMeetingResponseRequestEventArgs)->GetDeferral(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxValidateCertificatesRequest<D>::EmailMailboxId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxValidateCertificatesRequest)->get_EmailMailboxId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Security::Cryptography::Certificates::Certificate> consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxValidateCertificatesRequest<D>::Certificates() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Security::Cryptography::Certificates::Certificate> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxValidateCertificatesRequest)->get_Certificates(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxValidateCertificatesRequest<D>::ReportCompletedAsync(param::async_iterable<Windows::ApplicationModel::Email::EmailCertificateValidationStatus> const& validationStatuses) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxValidateCertificatesRequest)->ReportCompletedAsync(get_abi(validationStatuses), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxValidateCertificatesRequest<D>::ReportFailedAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxValidateCertificatesRequest)->ReportFailedAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::ApplicationModel::Email::DataProvider::EmailMailboxValidateCertificatesRequest consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxValidateCertificatesRequestEventArgs<D>::Request() const
{
    Windows::ApplicationModel::Email::DataProvider::EmailMailboxValidateCertificatesRequest value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxValidateCertificatesRequestEventArgs)->get_Request(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Deferral consume_Windows_ApplicationModel_Email_DataProvider_IEmailMailboxValidateCertificatesRequestEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Email::DataProvider::IEmailMailboxValidateCertificatesRequestEventArgs)->GetDeferral(put_abi(value)));
    return value;
}

template <typename D>
struct produce<D, Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderConnection> : produce_base<D, Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderConnection>
{
    int32_t WINRT_CALL add_MailboxSyncRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MailboxSyncRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, Windows::ApplicationModel::Email::DataProvider::EmailMailboxSyncManagerSyncRequestEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().MailboxSyncRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, Windows::ApplicationModel::Email::DataProvider::EmailMailboxSyncManagerSyncRequestEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_MailboxSyncRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(MailboxSyncRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().MailboxSyncRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_DownloadMessageRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DownloadMessageRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, Windows::ApplicationModel::Email::DataProvider::EmailMailboxDownloadMessageRequestEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().DownloadMessageRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, Windows::ApplicationModel::Email::DataProvider::EmailMailboxDownloadMessageRequestEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_DownloadMessageRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(DownloadMessageRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().DownloadMessageRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_DownloadAttachmentRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DownloadAttachmentRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, Windows::ApplicationModel::Email::DataProvider::EmailMailboxDownloadAttachmentRequestEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().DownloadAttachmentRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, Windows::ApplicationModel::Email::DataProvider::EmailMailboxDownloadAttachmentRequestEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_DownloadAttachmentRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(DownloadAttachmentRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().DownloadAttachmentRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_CreateFolderRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFolderRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, Windows::ApplicationModel::Email::DataProvider::EmailMailboxCreateFolderRequestEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().CreateFolderRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, Windows::ApplicationModel::Email::DataProvider::EmailMailboxCreateFolderRequestEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_CreateFolderRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(CreateFolderRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().CreateFolderRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_DeleteFolderRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeleteFolderRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, Windows::ApplicationModel::Email::DataProvider::EmailMailboxDeleteFolderRequestEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().DeleteFolderRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, Windows::ApplicationModel::Email::DataProvider::EmailMailboxDeleteFolderRequestEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_DeleteFolderRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(DeleteFolderRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().DeleteFolderRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_EmptyFolderRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EmptyFolderRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, Windows::ApplicationModel::Email::DataProvider::EmailMailboxEmptyFolderRequestEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().EmptyFolderRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, Windows::ApplicationModel::Email::DataProvider::EmailMailboxEmptyFolderRequestEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_EmptyFolderRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(EmptyFolderRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().EmptyFolderRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_MoveFolderRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MoveFolderRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, Windows::ApplicationModel::Email::DataProvider::EmailMailboxMoveFolderRequestEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().MoveFolderRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, Windows::ApplicationModel::Email::DataProvider::EmailMailboxMoveFolderRequestEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_MoveFolderRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(MoveFolderRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().MoveFolderRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_UpdateMeetingResponseRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpdateMeetingResponseRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, Windows::ApplicationModel::Email::DataProvider::EmailMailboxUpdateMeetingResponseRequestEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().UpdateMeetingResponseRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, Windows::ApplicationModel::Email::DataProvider::EmailMailboxUpdateMeetingResponseRequestEventArgs> const*>(&handler)));
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

    int32_t WINRT_CALL add_ForwardMeetingRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ForwardMeetingRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, Windows::ApplicationModel::Email::DataProvider::EmailMailboxForwardMeetingRequestEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ForwardMeetingRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, Windows::ApplicationModel::Email::DataProvider::EmailMailboxForwardMeetingRequestEventArgs> const*>(&handler)));
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
            WINRT_ASSERT_DECLARATION(ProposeNewTimeForMeetingRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, Windows::ApplicationModel::Email::DataProvider::EmailMailboxProposeNewTimeForMeetingRequestEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ProposeNewTimeForMeetingRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, Windows::ApplicationModel::Email::DataProvider::EmailMailboxProposeNewTimeForMeetingRequestEventArgs> const*>(&handler)));
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

    int32_t WINRT_CALL add_SetAutoReplySettingsRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetAutoReplySettingsRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, Windows::ApplicationModel::Email::DataProvider::EmailMailboxSetAutoReplySettingsRequestEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().SetAutoReplySettingsRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, Windows::ApplicationModel::Email::DataProvider::EmailMailboxSetAutoReplySettingsRequestEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_SetAutoReplySettingsRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(SetAutoReplySettingsRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().SetAutoReplySettingsRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_GetAutoReplySettingsRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAutoReplySettingsRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, Windows::ApplicationModel::Email::DataProvider::EmailMailboxGetAutoReplySettingsRequestEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().GetAutoReplySettingsRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, Windows::ApplicationModel::Email::DataProvider::EmailMailboxGetAutoReplySettingsRequestEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_GetAutoReplySettingsRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(GetAutoReplySettingsRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().GetAutoReplySettingsRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_ResolveRecipientsRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResolveRecipientsRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, Windows::ApplicationModel::Email::DataProvider::EmailMailboxResolveRecipientsRequestEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ResolveRecipientsRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, Windows::ApplicationModel::Email::DataProvider::EmailMailboxResolveRecipientsRequestEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ResolveRecipientsRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ResolveRecipientsRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ResolveRecipientsRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_ValidateCertificatesRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ValidateCertificatesRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, Windows::ApplicationModel::Email::DataProvider::EmailMailboxValidateCertificatesRequestEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ValidateCertificatesRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, Windows::ApplicationModel::Email::DataProvider::EmailMailboxValidateCertificatesRequestEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ValidateCertificatesRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ValidateCertificatesRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ValidateCertificatesRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_ServerSearchReadBatchRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServerSearchReadBatchRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, Windows::ApplicationModel::Email::DataProvider::EmailMailboxServerSearchReadBatchRequestEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ServerSearchReadBatchRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection, Windows::ApplicationModel::Email::DataProvider::EmailMailboxServerSearchReadBatchRequestEventArgs> const*>(&handler)));
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
struct produce<D, Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderTriggerDetails> : produce_base<D, Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderTriggerDetails>
{
    int32_t WINRT_CALL get_Connection(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Connection, WINRT_WRAP(Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection));
            *value = detach_from<Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection>(this->shim().Connection());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Email::DataProvider::IEmailMailboxCreateFolderRequest> : produce_base<D, Windows::ApplicationModel::Email::DataProvider::IEmailMailboxCreateFolderRequest>
{
    int32_t WINRT_CALL get_EmailMailboxId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EmailMailboxId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().EmailMailboxId());
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

    int32_t WINRT_CALL ReportCompletedAsync(void* folder, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportCompletedAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::ApplicationModel::Email::EmailFolder const);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ReportCompletedAsync(*reinterpret_cast<Windows::ApplicationModel::Email::EmailFolder const*>(&folder)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReportFailedAsync(Windows::ApplicationModel::Email::EmailMailboxCreateFolderStatus status, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportFailedAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::ApplicationModel::Email::EmailMailboxCreateFolderStatus const);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ReportFailedAsync(*reinterpret_cast<Windows::ApplicationModel::Email::EmailMailboxCreateFolderStatus const*>(&status)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Email::DataProvider::IEmailMailboxCreateFolderRequestEventArgs> : produce_base<D, Windows::ApplicationModel::Email::DataProvider::IEmailMailboxCreateFolderRequestEventArgs>
{
    int32_t WINRT_CALL get_Request(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Request, WINRT_WRAP(Windows::ApplicationModel::Email::DataProvider::EmailMailboxCreateFolderRequest));
            *value = detach_from<Windows::ApplicationModel::Email::DataProvider::EmailMailboxCreateFolderRequest>(this->shim().Request());
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
struct produce<D, Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDeleteFolderRequest> : produce_base<D, Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDeleteFolderRequest>
{
    int32_t WINRT_CALL get_EmailMailboxId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EmailMailboxId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().EmailMailboxId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EmailFolderId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EmailFolderId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().EmailFolderId());
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

    int32_t WINRT_CALL ReportFailedAsync(Windows::ApplicationModel::Email::EmailMailboxDeleteFolderStatus status, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportFailedAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::ApplicationModel::Email::EmailMailboxDeleteFolderStatus const);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ReportFailedAsync(*reinterpret_cast<Windows::ApplicationModel::Email::EmailMailboxDeleteFolderStatus const*>(&status)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDeleteFolderRequestEventArgs> : produce_base<D, Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDeleteFolderRequestEventArgs>
{
    int32_t WINRT_CALL get_Request(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Request, WINRT_WRAP(Windows::ApplicationModel::Email::DataProvider::EmailMailboxDeleteFolderRequest));
            *value = detach_from<Windows::ApplicationModel::Email::DataProvider::EmailMailboxDeleteFolderRequest>(this->shim().Request());
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
struct produce<D, Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDownloadAttachmentRequest> : produce_base<D, Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDownloadAttachmentRequest>
{
    int32_t WINRT_CALL get_EmailMailboxId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EmailMailboxId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().EmailMailboxId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EmailMessageId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EmailMessageId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().EmailMessageId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EmailAttachmentId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EmailAttachmentId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().EmailAttachmentId());
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
struct produce<D, Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDownloadAttachmentRequestEventArgs> : produce_base<D, Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDownloadAttachmentRequestEventArgs>
{
    int32_t WINRT_CALL get_Request(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Request, WINRT_WRAP(Windows::ApplicationModel::Email::DataProvider::EmailMailboxDownloadAttachmentRequest));
            *value = detach_from<Windows::ApplicationModel::Email::DataProvider::EmailMailboxDownloadAttachmentRequest>(this->shim().Request());
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
struct produce<D, Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDownloadMessageRequest> : produce_base<D, Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDownloadMessageRequest>
{
    int32_t WINRT_CALL get_EmailMailboxId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EmailMailboxId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().EmailMailboxId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EmailMessageId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EmailMessageId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().EmailMessageId());
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
struct produce<D, Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDownloadMessageRequestEventArgs> : produce_base<D, Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDownloadMessageRequestEventArgs>
{
    int32_t WINRT_CALL get_Request(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Request, WINRT_WRAP(Windows::ApplicationModel::Email::DataProvider::EmailMailboxDownloadMessageRequest));
            *value = detach_from<Windows::ApplicationModel::Email::DataProvider::EmailMailboxDownloadMessageRequest>(this->shim().Request());
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
struct produce<D, Windows::ApplicationModel::Email::DataProvider::IEmailMailboxEmptyFolderRequest> : produce_base<D, Windows::ApplicationModel::Email::DataProvider::IEmailMailboxEmptyFolderRequest>
{
    int32_t WINRT_CALL get_EmailMailboxId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EmailMailboxId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().EmailMailboxId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EmailFolderId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EmailFolderId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().EmailFolderId());
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

    int32_t WINRT_CALL ReportFailedAsync(Windows::ApplicationModel::Email::EmailMailboxEmptyFolderStatus status, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportFailedAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::ApplicationModel::Email::EmailMailboxEmptyFolderStatus const);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ReportFailedAsync(*reinterpret_cast<Windows::ApplicationModel::Email::EmailMailboxEmptyFolderStatus const*>(&status)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Email::DataProvider::IEmailMailboxEmptyFolderRequestEventArgs> : produce_base<D, Windows::ApplicationModel::Email::DataProvider::IEmailMailboxEmptyFolderRequestEventArgs>
{
    int32_t WINRT_CALL get_Request(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Request, WINRT_WRAP(Windows::ApplicationModel::Email::DataProvider::EmailMailboxEmptyFolderRequest));
            *value = detach_from<Windows::ApplicationModel::Email::DataProvider::EmailMailboxEmptyFolderRequest>(this->shim().Request());
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
struct produce<D, Windows::ApplicationModel::Email::DataProvider::IEmailMailboxForwardMeetingRequest> : produce_base<D, Windows::ApplicationModel::Email::DataProvider::IEmailMailboxForwardMeetingRequest>
{
    int32_t WINRT_CALL get_EmailMailboxId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EmailMailboxId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().EmailMailboxId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EmailMessageId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EmailMessageId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().EmailMessageId());
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
            WINRT_ASSERT_DECLARATION(Recipients, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Email::EmailRecipient>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Email::EmailRecipient>>(this->shim().Recipients());
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

    int32_t WINRT_CALL get_ForwardHeaderType(Windows::ApplicationModel::Email::EmailMessageBodyKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ForwardHeaderType, WINRT_WRAP(Windows::ApplicationModel::Email::EmailMessageBodyKind));
            *value = detach_from<Windows::ApplicationModel::Email::EmailMessageBodyKind>(this->shim().ForwardHeaderType());
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
struct produce<D, Windows::ApplicationModel::Email::DataProvider::IEmailMailboxForwardMeetingRequestEventArgs> : produce_base<D, Windows::ApplicationModel::Email::DataProvider::IEmailMailboxForwardMeetingRequestEventArgs>
{
    int32_t WINRT_CALL get_Request(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Request, WINRT_WRAP(Windows::ApplicationModel::Email::DataProvider::EmailMailboxForwardMeetingRequest));
            *value = detach_from<Windows::ApplicationModel::Email::DataProvider::EmailMailboxForwardMeetingRequest>(this->shim().Request());
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
struct produce<D, Windows::ApplicationModel::Email::DataProvider::IEmailMailboxGetAutoReplySettingsRequest> : produce_base<D, Windows::ApplicationModel::Email::DataProvider::IEmailMailboxGetAutoReplySettingsRequest>
{
    int32_t WINRT_CALL get_EmailMailboxId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EmailMailboxId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().EmailMailboxId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RequestedFormat(Windows::ApplicationModel::Email::EmailMailboxAutoReplyMessageResponseKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestedFormat, WINRT_WRAP(Windows::ApplicationModel::Email::EmailMailboxAutoReplyMessageResponseKind));
            *value = detach_from<Windows::ApplicationModel::Email::EmailMailboxAutoReplyMessageResponseKind>(this->shim().RequestedFormat());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReportCompletedAsync(void* autoReplySettings, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportCompletedAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::ApplicationModel::Email::EmailMailboxAutoReplySettings const);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ReportCompletedAsync(*reinterpret_cast<Windows::ApplicationModel::Email::EmailMailboxAutoReplySettings const*>(&autoReplySettings)));
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
struct produce<D, Windows::ApplicationModel::Email::DataProvider::IEmailMailboxGetAutoReplySettingsRequestEventArgs> : produce_base<D, Windows::ApplicationModel::Email::DataProvider::IEmailMailboxGetAutoReplySettingsRequestEventArgs>
{
    int32_t WINRT_CALL get_Request(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Request, WINRT_WRAP(Windows::ApplicationModel::Email::DataProvider::EmailMailboxGetAutoReplySettingsRequest));
            *value = detach_from<Windows::ApplicationModel::Email::DataProvider::EmailMailboxGetAutoReplySettingsRequest>(this->shim().Request());
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
struct produce<D, Windows::ApplicationModel::Email::DataProvider::IEmailMailboxMoveFolderRequest> : produce_base<D, Windows::ApplicationModel::Email::DataProvider::IEmailMailboxMoveFolderRequest>
{
    int32_t WINRT_CALL get_EmailMailboxId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EmailMailboxId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().EmailMailboxId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EmailFolderId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EmailFolderId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().EmailFolderId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NewParentFolderId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NewParentFolderId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().NewParentFolderId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NewFolderName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NewFolderName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().NewFolderName());
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
struct produce<D, Windows::ApplicationModel::Email::DataProvider::IEmailMailboxMoveFolderRequestEventArgs> : produce_base<D, Windows::ApplicationModel::Email::DataProvider::IEmailMailboxMoveFolderRequestEventArgs>
{
    int32_t WINRT_CALL get_Request(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Request, WINRT_WRAP(Windows::ApplicationModel::Email::DataProvider::EmailMailboxMoveFolderRequest));
            *value = detach_from<Windows::ApplicationModel::Email::DataProvider::EmailMailboxMoveFolderRequest>(this->shim().Request());
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
struct produce<D, Windows::ApplicationModel::Email::DataProvider::IEmailMailboxProposeNewTimeForMeetingRequest> : produce_base<D, Windows::ApplicationModel::Email::DataProvider::IEmailMailboxProposeNewTimeForMeetingRequest>
{
    int32_t WINRT_CALL get_EmailMailboxId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EmailMailboxId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().EmailMailboxId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EmailMessageId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EmailMessageId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().EmailMessageId());
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
struct produce<D, Windows::ApplicationModel::Email::DataProvider::IEmailMailboxProposeNewTimeForMeetingRequestEventArgs> : produce_base<D, Windows::ApplicationModel::Email::DataProvider::IEmailMailboxProposeNewTimeForMeetingRequestEventArgs>
{
    int32_t WINRT_CALL get_Request(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Request, WINRT_WRAP(Windows::ApplicationModel::Email::DataProvider::EmailMailboxProposeNewTimeForMeetingRequest));
            *value = detach_from<Windows::ApplicationModel::Email::DataProvider::EmailMailboxProposeNewTimeForMeetingRequest>(this->shim().Request());
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
struct produce<D, Windows::ApplicationModel::Email::DataProvider::IEmailMailboxResolveRecipientsRequest> : produce_base<D, Windows::ApplicationModel::Email::DataProvider::IEmailMailboxResolveRecipientsRequest>
{
    int32_t WINRT_CALL get_EmailMailboxId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EmailMailboxId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().EmailMailboxId());
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
            WINRT_ASSERT_DECLARATION(Recipients, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().Recipients());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReportCompletedAsync(void* resolutionResults, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportCompletedAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Email::EmailRecipientResolutionResult> const);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ReportCompletedAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Email::EmailRecipientResolutionResult> const*>(&resolutionResults)));
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
struct produce<D, Windows::ApplicationModel::Email::DataProvider::IEmailMailboxResolveRecipientsRequestEventArgs> : produce_base<D, Windows::ApplicationModel::Email::DataProvider::IEmailMailboxResolveRecipientsRequestEventArgs>
{
    int32_t WINRT_CALL get_Request(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Request, WINRT_WRAP(Windows::ApplicationModel::Email::DataProvider::EmailMailboxResolveRecipientsRequest));
            *value = detach_from<Windows::ApplicationModel::Email::DataProvider::EmailMailboxResolveRecipientsRequest>(this->shim().Request());
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
struct produce<D, Windows::ApplicationModel::Email::DataProvider::IEmailMailboxServerSearchReadBatchRequest> : produce_base<D, Windows::ApplicationModel::Email::DataProvider::IEmailMailboxServerSearchReadBatchRequest>
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

    int32_t WINRT_CALL get_EmailMailboxId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EmailMailboxId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().EmailMailboxId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EmailFolderId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EmailFolderId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().EmailFolderId());
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
            WINRT_ASSERT_DECLARATION(Options, WINRT_WRAP(Windows::ApplicationModel::Email::EmailQueryOptions));
            *value = detach_from<Windows::ApplicationModel::Email::EmailQueryOptions>(this->shim().Options());
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

    int32_t WINRT_CALL ReportFailedAsync(Windows::ApplicationModel::Email::EmailBatchStatus batchStatus, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportFailedAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::ApplicationModel::Email::EmailBatchStatus const);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ReportFailedAsync(*reinterpret_cast<Windows::ApplicationModel::Email::EmailBatchStatus const*>(&batchStatus)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Email::DataProvider::IEmailMailboxServerSearchReadBatchRequestEventArgs> : produce_base<D, Windows::ApplicationModel::Email::DataProvider::IEmailMailboxServerSearchReadBatchRequestEventArgs>
{
    int32_t WINRT_CALL get_Request(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Request, WINRT_WRAP(Windows::ApplicationModel::Email::DataProvider::EmailMailboxServerSearchReadBatchRequest));
            *value = detach_from<Windows::ApplicationModel::Email::DataProvider::EmailMailboxServerSearchReadBatchRequest>(this->shim().Request());
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
struct produce<D, Windows::ApplicationModel::Email::DataProvider::IEmailMailboxSetAutoReplySettingsRequest> : produce_base<D, Windows::ApplicationModel::Email::DataProvider::IEmailMailboxSetAutoReplySettingsRequest>
{
    int32_t WINRT_CALL get_EmailMailboxId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EmailMailboxId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().EmailMailboxId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AutoReplySettings(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AutoReplySettings, WINRT_WRAP(Windows::ApplicationModel::Email::EmailMailboxAutoReplySettings));
            *value = detach_from<Windows::ApplicationModel::Email::EmailMailboxAutoReplySettings>(this->shim().AutoReplySettings());
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
struct produce<D, Windows::ApplicationModel::Email::DataProvider::IEmailMailboxSetAutoReplySettingsRequestEventArgs> : produce_base<D, Windows::ApplicationModel::Email::DataProvider::IEmailMailboxSetAutoReplySettingsRequestEventArgs>
{
    int32_t WINRT_CALL get_Request(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Request, WINRT_WRAP(Windows::ApplicationModel::Email::DataProvider::EmailMailboxSetAutoReplySettingsRequest));
            *value = detach_from<Windows::ApplicationModel::Email::DataProvider::EmailMailboxSetAutoReplySettingsRequest>(this->shim().Request());
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
struct produce<D, Windows::ApplicationModel::Email::DataProvider::IEmailMailboxSyncManagerSyncRequest> : produce_base<D, Windows::ApplicationModel::Email::DataProvider::IEmailMailboxSyncManagerSyncRequest>
{
    int32_t WINRT_CALL get_EmailMailboxId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EmailMailboxId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().EmailMailboxId());
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
struct produce<D, Windows::ApplicationModel::Email::DataProvider::IEmailMailboxSyncManagerSyncRequestEventArgs> : produce_base<D, Windows::ApplicationModel::Email::DataProvider::IEmailMailboxSyncManagerSyncRequestEventArgs>
{
    int32_t WINRT_CALL get_Request(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Request, WINRT_WRAP(Windows::ApplicationModel::Email::DataProvider::EmailMailboxSyncManagerSyncRequest));
            *value = detach_from<Windows::ApplicationModel::Email::DataProvider::EmailMailboxSyncManagerSyncRequest>(this->shim().Request());
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
struct produce<D, Windows::ApplicationModel::Email::DataProvider::IEmailMailboxUpdateMeetingResponseRequest> : produce_base<D, Windows::ApplicationModel::Email::DataProvider::IEmailMailboxUpdateMeetingResponseRequest>
{
    int32_t WINRT_CALL get_EmailMailboxId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EmailMailboxId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().EmailMailboxId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EmailMessageId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EmailMessageId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().EmailMessageId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Response(Windows::ApplicationModel::Email::EmailMeetingResponseType* response) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Response, WINRT_WRAP(Windows::ApplicationModel::Email::EmailMeetingResponseType));
            *response = detach_from<Windows::ApplicationModel::Email::EmailMeetingResponseType>(this->shim().Response());
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
struct produce<D, Windows::ApplicationModel::Email::DataProvider::IEmailMailboxUpdateMeetingResponseRequestEventArgs> : produce_base<D, Windows::ApplicationModel::Email::DataProvider::IEmailMailboxUpdateMeetingResponseRequestEventArgs>
{
    int32_t WINRT_CALL get_Request(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Request, WINRT_WRAP(Windows::ApplicationModel::Email::DataProvider::EmailMailboxUpdateMeetingResponseRequest));
            *value = detach_from<Windows::ApplicationModel::Email::DataProvider::EmailMailboxUpdateMeetingResponseRequest>(this->shim().Request());
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
struct produce<D, Windows::ApplicationModel::Email::DataProvider::IEmailMailboxValidateCertificatesRequest> : produce_base<D, Windows::ApplicationModel::Email::DataProvider::IEmailMailboxValidateCertificatesRequest>
{
    int32_t WINRT_CALL get_EmailMailboxId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EmailMailboxId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().EmailMailboxId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Certificates(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Certificates, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Security::Cryptography::Certificates::Certificate>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Security::Cryptography::Certificates::Certificate>>(this->shim().Certificates());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReportCompletedAsync(void* validationStatuses, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportCompletedAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Email::EmailCertificateValidationStatus> const);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ReportCompletedAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::Email::EmailCertificateValidationStatus> const*>(&validationStatuses)));
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
struct produce<D, Windows::ApplicationModel::Email::DataProvider::IEmailMailboxValidateCertificatesRequestEventArgs> : produce_base<D, Windows::ApplicationModel::Email::DataProvider::IEmailMailboxValidateCertificatesRequestEventArgs>
{
    int32_t WINRT_CALL get_Request(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Request, WINRT_WRAP(Windows::ApplicationModel::Email::DataProvider::EmailMailboxValidateCertificatesRequest));
            *value = detach_from<Windows::ApplicationModel::Email::DataProvider::EmailMailboxValidateCertificatesRequest>(this->shim().Request());
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

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Email::DataProvider {

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderConnection> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderConnection> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderTriggerDetails> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailDataProviderTriggerDetails> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxCreateFolderRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxCreateFolderRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxCreateFolderRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxCreateFolderRequestEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDeleteFolderRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDeleteFolderRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDeleteFolderRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDeleteFolderRequestEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDownloadAttachmentRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDownloadAttachmentRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDownloadAttachmentRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDownloadAttachmentRequestEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDownloadMessageRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDownloadMessageRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDownloadMessageRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxDownloadMessageRequestEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxEmptyFolderRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxEmptyFolderRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxEmptyFolderRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxEmptyFolderRequestEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxForwardMeetingRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxForwardMeetingRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxForwardMeetingRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxForwardMeetingRequestEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxGetAutoReplySettingsRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxGetAutoReplySettingsRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxGetAutoReplySettingsRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxGetAutoReplySettingsRequestEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxMoveFolderRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxMoveFolderRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxMoveFolderRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxMoveFolderRequestEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxProposeNewTimeForMeetingRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxProposeNewTimeForMeetingRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxProposeNewTimeForMeetingRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxProposeNewTimeForMeetingRequestEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxResolveRecipientsRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxResolveRecipientsRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxResolveRecipientsRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxResolveRecipientsRequestEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxServerSearchReadBatchRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxServerSearchReadBatchRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxServerSearchReadBatchRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxServerSearchReadBatchRequestEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxSetAutoReplySettingsRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxSetAutoReplySettingsRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxSetAutoReplySettingsRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxSetAutoReplySettingsRequestEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxSyncManagerSyncRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxSyncManagerSyncRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxSyncManagerSyncRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxSyncManagerSyncRequestEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxUpdateMeetingResponseRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxUpdateMeetingResponseRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxUpdateMeetingResponseRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxUpdateMeetingResponseRequestEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxValidateCertificatesRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxValidateCertificatesRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxValidateCertificatesRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::DataProvider::IEmailMailboxValidateCertificatesRequestEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::DataProvider::EmailDataProviderConnection> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::DataProvider::EmailDataProviderTriggerDetails> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::DataProvider::EmailDataProviderTriggerDetails> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxCreateFolderRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxCreateFolderRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxCreateFolderRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxCreateFolderRequestEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxDeleteFolderRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxDeleteFolderRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxDeleteFolderRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxDeleteFolderRequestEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxDownloadAttachmentRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxDownloadAttachmentRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxDownloadAttachmentRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxDownloadAttachmentRequestEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxDownloadMessageRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxDownloadMessageRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxDownloadMessageRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxDownloadMessageRequestEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxEmptyFolderRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxEmptyFolderRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxEmptyFolderRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxEmptyFolderRequestEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxForwardMeetingRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxForwardMeetingRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxForwardMeetingRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxForwardMeetingRequestEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxGetAutoReplySettingsRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxGetAutoReplySettingsRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxGetAutoReplySettingsRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxGetAutoReplySettingsRequestEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxMoveFolderRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxMoveFolderRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxMoveFolderRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxMoveFolderRequestEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxProposeNewTimeForMeetingRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxProposeNewTimeForMeetingRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxProposeNewTimeForMeetingRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxProposeNewTimeForMeetingRequestEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxResolveRecipientsRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxResolveRecipientsRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxResolveRecipientsRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxResolveRecipientsRequestEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxServerSearchReadBatchRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxServerSearchReadBatchRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxServerSearchReadBatchRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxServerSearchReadBatchRequestEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxSetAutoReplySettingsRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxSetAutoReplySettingsRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxSetAutoReplySettingsRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxSetAutoReplySettingsRequestEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxSyncManagerSyncRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxSyncManagerSyncRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxSyncManagerSyncRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxSyncManagerSyncRequestEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxUpdateMeetingResponseRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxUpdateMeetingResponseRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxUpdateMeetingResponseRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxUpdateMeetingResponseRequestEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxValidateCertificatesRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxValidateCertificatesRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxValidateCertificatesRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Email::DataProvider::EmailMailboxValidateCertificatesRequestEventArgs> {};

}
