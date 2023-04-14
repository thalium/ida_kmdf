// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Security.Credentials.2.h"
#include "winrt/impl/Windows.ApplicationModel.UserDataAccounts.SystemAccess.2.h"
#include "winrt/Windows.ApplicationModel.UserDataAccounts.h"

namespace winrt::impl {

template <typename D> hstring consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration<D>::AccountName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration)->get_AccountName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration<D>::AccountName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration)->put_AccountName(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration<D>::DeviceAccountTypeId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration)->get_DeviceAccountTypeId(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration<D>::DeviceAccountTypeId(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration)->put_DeviceAccountTypeId(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountServerType consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration<D>::ServerType() const
{
    Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountServerType value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration)->get_ServerType(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration<D>::ServerType(Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountServerType const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration)->put_ServerType(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration<D>::EmailAddress() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration)->get_EmailAddress(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration<D>::EmailAddress(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration)->put_EmailAddress(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration<D>::Domain() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration)->get_Domain(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration<D>::Domain(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration)->put_Domain(get_abi(value)));
}

template <typename D> bool consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration<D>::EmailSyncEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration)->get_EmailSyncEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration<D>::EmailSyncEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration)->put_EmailSyncEnabled(value));
}

template <typename D> bool consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration<D>::ContactsSyncEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration)->get_ContactsSyncEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration<D>::ContactsSyncEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration)->put_ContactsSyncEnabled(value));
}

template <typename D> bool consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration<D>::CalendarSyncEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration)->get_CalendarSyncEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration<D>::CalendarSyncEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration)->put_CalendarSyncEnabled(value));
}

template <typename D> hstring consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration<D>::IncomingServerAddress() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration)->get_IncomingServerAddress(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration<D>::IncomingServerAddress(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration)->put_IncomingServerAddress(get_abi(value)));
}

template <typename D> int32_t consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration<D>::IncomingServerPort() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration)->get_IncomingServerPort(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration<D>::IncomingServerPort(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration)->put_IncomingServerPort(value));
}

template <typename D> bool consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration<D>::IncomingServerRequiresSsl() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration)->get_IncomingServerRequiresSsl(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration<D>::IncomingServerRequiresSsl(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration)->put_IncomingServerRequiresSsl(value));
}

template <typename D> hstring consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration<D>::IncomingServerUsername() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration)->get_IncomingServerUsername(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration<D>::IncomingServerUsername(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration)->put_IncomingServerUsername(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration<D>::OutgoingServerAddress() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration)->get_OutgoingServerAddress(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration<D>::OutgoingServerAddress(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration)->put_OutgoingServerAddress(get_abi(value)));
}

template <typename D> int32_t consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration<D>::OutgoingServerPort() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration)->get_OutgoingServerPort(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration<D>::OutgoingServerPort(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration)->put_OutgoingServerPort(value));
}

template <typename D> bool consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration<D>::OutgoingServerRequiresSsl() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration)->get_OutgoingServerRequiresSsl(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration<D>::OutgoingServerRequiresSsl(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration)->put_OutgoingServerRequiresSsl(value));
}

template <typename D> hstring consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration<D>::OutgoingServerUsername() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration)->get_OutgoingServerUsername(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration<D>::OutgoingServerUsername(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration)->put_OutgoingServerUsername(get_abi(value)));
}

template <typename D> Windows::Security::Credentials::PasswordCredential consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::IncomingServerCredential() const
{
    Windows::Security::Credentials::PasswordCredential value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->get_IncomingServerCredential(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::IncomingServerCredential(Windows::Security::Credentials::PasswordCredential const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->put_IncomingServerCredential(get_abi(value)));
}

template <typename D> Windows::Security::Credentials::PasswordCredential consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::OutgoingServerCredential() const
{
    Windows::Security::Credentials::PasswordCredential value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->get_OutgoingServerCredential(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::OutgoingServerCredential(Windows::Security::Credentials::PasswordCredential const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->put_OutgoingServerCredential(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::OAuthRefreshToken() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->get_OAuthRefreshToken(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::OAuthRefreshToken(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->put_OAuthRefreshToken(get_abi(value)));
}

template <typename D> bool consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::IsExternallyManaged() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->get_IsExternallyManaged(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::IsExternallyManaged(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->put_IsExternallyManaged(value));
}

template <typename D> Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountIconId consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::AccountIconId() const
{
    Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountIconId value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->get_AccountIconId(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::AccountIconId(Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountIconId const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->put_AccountIconId(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountAuthenticationType consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::AuthenticationType() const
{
    Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountAuthenticationType value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->get_AuthenticationType(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::AuthenticationType(Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountAuthenticationType const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->put_AuthenticationType(get_abi(value)));
}

template <typename D> bool consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::IsSsoAuthenticationSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->get_IsSsoAuthenticationSupported(&value));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::SsoAccountId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->get_SsoAccountId(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::SsoAccountId(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->put_SsoAccountId(get_abi(value)));
}

template <typename D> bool consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::AlwaysDownloadFullMessage() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->get_AlwaysDownloadFullMessage(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::AlwaysDownloadFullMessage(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->put_AlwaysDownloadFullMessage(value));
}

template <typename D> bool consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::DoesPolicyAllowMailSync() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->get_DoesPolicyAllowMailSync(&value));
    return value;
}

template <typename D> Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountSyncScheduleKind consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::SyncScheduleKind() const
{
    Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountSyncScheduleKind value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->get_SyncScheduleKind(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::SyncScheduleKind(Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountSyncScheduleKind const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->put_SyncScheduleKind(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountMailAgeFilter consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::MailAgeFilter() const
{
    Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountMailAgeFilter value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->get_MailAgeFilter(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::MailAgeFilter(Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountMailAgeFilter const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->put_MailAgeFilter(get_abi(value)));
}

template <typename D> bool consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::IsClientAuthenticationCertificateRequired() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->get_IsClientAuthenticationCertificateRequired(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::IsClientAuthenticationCertificateRequired(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->put_IsClientAuthenticationCertificateRequired(value));
}

template <typename D> bool consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::AutoSelectAuthenticationCertificate() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->get_AutoSelectAuthenticationCertificate(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::AutoSelectAuthenticationCertificate(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->put_AutoSelectAuthenticationCertificate(value));
}

template <typename D> hstring consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::AuthenticationCertificateId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->get_AuthenticationCertificateId(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::AuthenticationCertificateId(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->put_AuthenticationCertificateId(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountSyncScheduleKind consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::CardDavSyncScheduleKind() const
{
    Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountSyncScheduleKind value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->get_CardDavSyncScheduleKind(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::CardDavSyncScheduleKind(Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountSyncScheduleKind const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->put_CardDavSyncScheduleKind(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountSyncScheduleKind consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::CalDavSyncScheduleKind() const
{
    Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountSyncScheduleKind value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->get_CalDavSyncScheduleKind(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::CalDavSyncScheduleKind(Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountSyncScheduleKind const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->put_CalDavSyncScheduleKind(get_abi(value)));
}

template <typename D> Windows::Foundation::Uri consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::CardDavServerUrl() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->get_CardDavServerUrl(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::CardDavServerUrl(Windows::Foundation::Uri const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->put_CardDavServerUrl(get_abi(value)));
}

template <typename D> bool consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::CardDavRequiresSsl() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->get_CardDavRequiresSsl(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::CardDavRequiresSsl(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->put_CardDavRequiresSsl(value));
}

template <typename D> Windows::Foundation::Uri consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::CalDavServerUrl() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->get_CalDavServerUrl(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::CalDavServerUrl(Windows::Foundation::Uri const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->put_CalDavServerUrl(get_abi(value)));
}

template <typename D> bool consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::CalDavRequiresSsl() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->get_CalDavRequiresSsl(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::CalDavRequiresSsl(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->put_CalDavRequiresSsl(value));
}

template <typename D> bool consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::WasModifiedByUser() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->get_WasModifiedByUser(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::WasModifiedByUser(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->put_WasModifiedByUser(value));
}

template <typename D> bool consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::WasIncomingServerCertificateHashConfirmed() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->get_WasIncomingServerCertificateHashConfirmed(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::WasIncomingServerCertificateHashConfirmed(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->put_WasIncomingServerCertificateHashConfirmed(value));
}

template <typename D> hstring consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::IncomingServerCertificateHash() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->get_IncomingServerCertificateHash(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::IncomingServerCertificateHash(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->put_IncomingServerCertificateHash(get_abi(value)));
}

template <typename D> bool consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::IsOutgoingServerAuthenticationRequired() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->get_IsOutgoingServerAuthenticationRequired(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::IsOutgoingServerAuthenticationRequired(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->put_IsOutgoingServerAuthenticationRequired(value));
}

template <typename D> bool consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::IsOutgoingServerAuthenticationEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->get_IsOutgoingServerAuthenticationEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::IsOutgoingServerAuthenticationEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->put_IsOutgoingServerAuthenticationEnabled(value));
}

template <typename D> bool consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::WasOutgoingServerCertificateHashConfirmed() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->get_WasOutgoingServerCertificateHashConfirmed(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::WasOutgoingServerCertificateHashConfirmed(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->put_WasOutgoingServerCertificateHashConfirmed(value));
}

template <typename D> hstring consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::OutgoingServerCertificateHash() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->get_OutgoingServerCertificateHash(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::OutgoingServerCertificateHash(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->put_OutgoingServerCertificateHash(get_abi(value)));
}

template <typename D> bool consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::IsSyncScheduleManagedBySystem() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->get_IsSyncScheduleManagedBySystem(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IDeviceAccountConfiguration2<D>::IsSyncScheduleManagedBySystem(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2)->put_IsSyncScheduleManagedBySystem(value));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<hstring>> consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IUserDataAccountSystemAccessManagerStatics<D>::AddAndShowDeviceAccountsAsync(param::async_iterable<Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountConfiguration> const& accounts) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<hstring>> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IUserDataAccountSystemAccessManagerStatics)->AddAndShowDeviceAccountsAsync(get_abi(accounts), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IUserDataAccountSystemAccessManagerStatics2<D>::SuppressLocalAccountWithAccountAsync(param::hstring const& userDataAccountId) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IUserDataAccountSystemAccessManagerStatics2)->SuppressLocalAccountWithAccountAsync(get_abi(userDataAccountId), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<hstring> consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IUserDataAccountSystemAccessManagerStatics2<D>::CreateDeviceAccountAsync(Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountConfiguration const& account) const
{
    Windows::Foundation::IAsyncOperation<hstring> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IUserDataAccountSystemAccessManagerStatics2)->CreateDeviceAccountAsync(get_abi(account), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IUserDataAccountSystemAccessManagerStatics2<D>::DeleteDeviceAccountAsync(param::hstring const& accountId) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IUserDataAccountSystemAccessManagerStatics2)->DeleteDeviceAccountAsync(get_abi(accountId), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountConfiguration> consume_Windows_ApplicationModel_UserDataAccounts_SystemAccess_IUserDataAccountSystemAccessManagerStatics2<D>::GetDeviceAccountConfigurationAsync(param::hstring const& accountId) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountConfiguration> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::UserDataAccounts::SystemAccess::IUserDataAccountSystemAccessManagerStatics2)->GetDeviceAccountConfigurationAsync(get_abi(accountId), put_abi(result)));
    return result;
}

template <typename D>
struct produce<D, Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration> : produce_base<D, Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration>
{
    int32_t WINRT_CALL get_AccountName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AccountName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AccountName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AccountName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AccountName, WINRT_WRAP(void), hstring const&);
            this->shim().AccountName(*reinterpret_cast<hstring const*>(&value));
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

    int32_t WINRT_CALL put_DeviceAccountTypeId(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceAccountTypeId, WINRT_WRAP(void), hstring const&);
            this->shim().DeviceAccountTypeId(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ServerType(Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountServerType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServerType, WINRT_WRAP(Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountServerType));
            *value = detach_from<Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountServerType>(this->shim().ServerType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ServerType(Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountServerType value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServerType, WINRT_WRAP(void), Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountServerType const&);
            this->shim().ServerType(*reinterpret_cast<Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountServerType const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EmailAddress(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EmailAddress, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().EmailAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_EmailAddress(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EmailAddress, WINRT_WRAP(void), hstring const&);
            this->shim().EmailAddress(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Domain(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Domain, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Domain());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Domain(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Domain, WINRT_WRAP(void), hstring const&);
            this->shim().Domain(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EmailSyncEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EmailSyncEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().EmailSyncEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_EmailSyncEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EmailSyncEnabled, WINRT_WRAP(void), bool);
            this->shim().EmailSyncEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ContactsSyncEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContactsSyncEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().ContactsSyncEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ContactsSyncEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContactsSyncEnabled, WINRT_WRAP(void), bool);
            this->shim().ContactsSyncEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CalendarSyncEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CalendarSyncEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CalendarSyncEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CalendarSyncEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CalendarSyncEnabled, WINRT_WRAP(void), bool);
            this->shim().CalendarSyncEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IncomingServerAddress(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IncomingServerAddress, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().IncomingServerAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IncomingServerAddress(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IncomingServerAddress, WINRT_WRAP(void), hstring const&);
            this->shim().IncomingServerAddress(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IncomingServerPort(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IncomingServerPort, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().IncomingServerPort());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IncomingServerPort(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IncomingServerPort, WINRT_WRAP(void), int32_t);
            this->shim().IncomingServerPort(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IncomingServerRequiresSsl(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IncomingServerRequiresSsl, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IncomingServerRequiresSsl());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IncomingServerRequiresSsl(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IncomingServerRequiresSsl, WINRT_WRAP(void), bool);
            this->shim().IncomingServerRequiresSsl(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IncomingServerUsername(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IncomingServerUsername, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().IncomingServerUsername());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IncomingServerUsername(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IncomingServerUsername, WINRT_WRAP(void), hstring const&);
            this->shim().IncomingServerUsername(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OutgoingServerAddress(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OutgoingServerAddress, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().OutgoingServerAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_OutgoingServerAddress(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OutgoingServerAddress, WINRT_WRAP(void), hstring const&);
            this->shim().OutgoingServerAddress(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OutgoingServerPort(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OutgoingServerPort, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().OutgoingServerPort());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_OutgoingServerPort(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OutgoingServerPort, WINRT_WRAP(void), int32_t);
            this->shim().OutgoingServerPort(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OutgoingServerRequiresSsl(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OutgoingServerRequiresSsl, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().OutgoingServerRequiresSsl());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_OutgoingServerRequiresSsl(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OutgoingServerRequiresSsl, WINRT_WRAP(void), bool);
            this->shim().OutgoingServerRequiresSsl(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OutgoingServerUsername(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OutgoingServerUsername, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().OutgoingServerUsername());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_OutgoingServerUsername(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OutgoingServerUsername, WINRT_WRAP(void), hstring const&);
            this->shim().OutgoingServerUsername(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2> : produce_base<D, Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2>
{
    int32_t WINRT_CALL get_IncomingServerCredential(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IncomingServerCredential, WINRT_WRAP(Windows::Security::Credentials::PasswordCredential));
            *value = detach_from<Windows::Security::Credentials::PasswordCredential>(this->shim().IncomingServerCredential());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IncomingServerCredential(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IncomingServerCredential, WINRT_WRAP(void), Windows::Security::Credentials::PasswordCredential const&);
            this->shim().IncomingServerCredential(*reinterpret_cast<Windows::Security::Credentials::PasswordCredential const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OutgoingServerCredential(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OutgoingServerCredential, WINRT_WRAP(Windows::Security::Credentials::PasswordCredential));
            *value = detach_from<Windows::Security::Credentials::PasswordCredential>(this->shim().OutgoingServerCredential());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_OutgoingServerCredential(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OutgoingServerCredential, WINRT_WRAP(void), Windows::Security::Credentials::PasswordCredential const&);
            this->shim().OutgoingServerCredential(*reinterpret_cast<Windows::Security::Credentials::PasswordCredential const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OAuthRefreshToken(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OAuthRefreshToken, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().OAuthRefreshToken());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_OAuthRefreshToken(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OAuthRefreshToken, WINRT_WRAP(void), hstring const&);
            this->shim().OAuthRefreshToken(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsExternallyManaged(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsExternallyManaged, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsExternallyManaged());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsExternallyManaged(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsExternallyManaged, WINRT_WRAP(void), bool);
            this->shim().IsExternallyManaged(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AccountIconId(Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountIconId* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AccountIconId, WINRT_WRAP(Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountIconId));
            *value = detach_from<Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountIconId>(this->shim().AccountIconId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AccountIconId(Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountIconId value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AccountIconId, WINRT_WRAP(void), Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountIconId const&);
            this->shim().AccountIconId(*reinterpret_cast<Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountIconId const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AuthenticationType(Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountAuthenticationType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AuthenticationType, WINRT_WRAP(Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountAuthenticationType));
            *value = detach_from<Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountAuthenticationType>(this->shim().AuthenticationType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AuthenticationType(Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountAuthenticationType value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AuthenticationType, WINRT_WRAP(void), Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountAuthenticationType const&);
            this->shim().AuthenticationType(*reinterpret_cast<Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountAuthenticationType const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsSsoAuthenticationSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSsoAuthenticationSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsSsoAuthenticationSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SsoAccountId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SsoAccountId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SsoAccountId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SsoAccountId(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SsoAccountId, WINRT_WRAP(void), hstring const&);
            this->shim().SsoAccountId(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AlwaysDownloadFullMessage(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AlwaysDownloadFullMessage, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AlwaysDownloadFullMessage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AlwaysDownloadFullMessage(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AlwaysDownloadFullMessage, WINRT_WRAP(void), bool);
            this->shim().AlwaysDownloadFullMessage(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DoesPolicyAllowMailSync(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DoesPolicyAllowMailSync, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().DoesPolicyAllowMailSync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SyncScheduleKind(Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountSyncScheduleKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SyncScheduleKind, WINRT_WRAP(Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountSyncScheduleKind));
            *value = detach_from<Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountSyncScheduleKind>(this->shim().SyncScheduleKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SyncScheduleKind(Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountSyncScheduleKind value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SyncScheduleKind, WINRT_WRAP(void), Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountSyncScheduleKind const&);
            this->shim().SyncScheduleKind(*reinterpret_cast<Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountSyncScheduleKind const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MailAgeFilter(Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountMailAgeFilter* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MailAgeFilter, WINRT_WRAP(Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountMailAgeFilter));
            *value = detach_from<Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountMailAgeFilter>(this->shim().MailAgeFilter());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MailAgeFilter(Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountMailAgeFilter value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MailAgeFilter, WINRT_WRAP(void), Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountMailAgeFilter const&);
            this->shim().MailAgeFilter(*reinterpret_cast<Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountMailAgeFilter const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsClientAuthenticationCertificateRequired(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsClientAuthenticationCertificateRequired, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsClientAuthenticationCertificateRequired());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsClientAuthenticationCertificateRequired(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsClientAuthenticationCertificateRequired, WINRT_WRAP(void), bool);
            this->shim().IsClientAuthenticationCertificateRequired(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AutoSelectAuthenticationCertificate(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AutoSelectAuthenticationCertificate, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AutoSelectAuthenticationCertificate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AutoSelectAuthenticationCertificate(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AutoSelectAuthenticationCertificate, WINRT_WRAP(void), bool);
            this->shim().AutoSelectAuthenticationCertificate(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AuthenticationCertificateId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AuthenticationCertificateId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AuthenticationCertificateId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AuthenticationCertificateId(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AuthenticationCertificateId, WINRT_WRAP(void), hstring const&);
            this->shim().AuthenticationCertificateId(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CardDavSyncScheduleKind(Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountSyncScheduleKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CardDavSyncScheduleKind, WINRT_WRAP(Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountSyncScheduleKind));
            *value = detach_from<Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountSyncScheduleKind>(this->shim().CardDavSyncScheduleKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CardDavSyncScheduleKind(Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountSyncScheduleKind value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CardDavSyncScheduleKind, WINRT_WRAP(void), Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountSyncScheduleKind const&);
            this->shim().CardDavSyncScheduleKind(*reinterpret_cast<Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountSyncScheduleKind const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CalDavSyncScheduleKind(Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountSyncScheduleKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CalDavSyncScheduleKind, WINRT_WRAP(Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountSyncScheduleKind));
            *value = detach_from<Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountSyncScheduleKind>(this->shim().CalDavSyncScheduleKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CalDavSyncScheduleKind(Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountSyncScheduleKind value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CalDavSyncScheduleKind, WINRT_WRAP(void), Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountSyncScheduleKind const&);
            this->shim().CalDavSyncScheduleKind(*reinterpret_cast<Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountSyncScheduleKind const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CardDavServerUrl(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CardDavServerUrl, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().CardDavServerUrl());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CardDavServerUrl(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CardDavServerUrl, WINRT_WRAP(void), Windows::Foundation::Uri const&);
            this->shim().CardDavServerUrl(*reinterpret_cast<Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CardDavRequiresSsl(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CardDavRequiresSsl, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CardDavRequiresSsl());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CardDavRequiresSsl(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CardDavRequiresSsl, WINRT_WRAP(void), bool);
            this->shim().CardDavRequiresSsl(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CalDavServerUrl(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CalDavServerUrl, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().CalDavServerUrl());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CalDavServerUrl(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CalDavServerUrl, WINRT_WRAP(void), Windows::Foundation::Uri const&);
            this->shim().CalDavServerUrl(*reinterpret_cast<Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CalDavRequiresSsl(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CalDavRequiresSsl, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CalDavRequiresSsl());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CalDavRequiresSsl(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CalDavRequiresSsl, WINRT_WRAP(void), bool);
            this->shim().CalDavRequiresSsl(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WasModifiedByUser(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WasModifiedByUser, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().WasModifiedByUser());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_WasModifiedByUser(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WasModifiedByUser, WINRT_WRAP(void), bool);
            this->shim().WasModifiedByUser(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WasIncomingServerCertificateHashConfirmed(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WasIncomingServerCertificateHashConfirmed, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().WasIncomingServerCertificateHashConfirmed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_WasIncomingServerCertificateHashConfirmed(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WasIncomingServerCertificateHashConfirmed, WINRT_WRAP(void), bool);
            this->shim().WasIncomingServerCertificateHashConfirmed(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IncomingServerCertificateHash(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IncomingServerCertificateHash, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().IncomingServerCertificateHash());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IncomingServerCertificateHash(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IncomingServerCertificateHash, WINRT_WRAP(void), hstring const&);
            this->shim().IncomingServerCertificateHash(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsOutgoingServerAuthenticationRequired(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsOutgoingServerAuthenticationRequired, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsOutgoingServerAuthenticationRequired());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsOutgoingServerAuthenticationRequired(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsOutgoingServerAuthenticationRequired, WINRT_WRAP(void), bool);
            this->shim().IsOutgoingServerAuthenticationRequired(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsOutgoingServerAuthenticationEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsOutgoingServerAuthenticationEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsOutgoingServerAuthenticationEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsOutgoingServerAuthenticationEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsOutgoingServerAuthenticationEnabled, WINRT_WRAP(void), bool);
            this->shim().IsOutgoingServerAuthenticationEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WasOutgoingServerCertificateHashConfirmed(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WasOutgoingServerCertificateHashConfirmed, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().WasOutgoingServerCertificateHashConfirmed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_WasOutgoingServerCertificateHashConfirmed(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WasOutgoingServerCertificateHashConfirmed, WINRT_WRAP(void), bool);
            this->shim().WasOutgoingServerCertificateHashConfirmed(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OutgoingServerCertificateHash(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OutgoingServerCertificateHash, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().OutgoingServerCertificateHash());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_OutgoingServerCertificateHash(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OutgoingServerCertificateHash, WINRT_WRAP(void), hstring const&);
            this->shim().OutgoingServerCertificateHash(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsSyncScheduleManagedBySystem(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSyncScheduleManagedBySystem, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsSyncScheduleManagedBySystem());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsSyncScheduleManagedBySystem(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSyncScheduleManagedBySystem, WINRT_WRAP(void), bool);
            this->shim().IsSyncScheduleManagedBySystem(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::UserDataAccounts::SystemAccess::IUserDataAccountSystemAccessManagerStatics> : produce_base<D, Windows::ApplicationModel::UserDataAccounts::SystemAccess::IUserDataAccountSystemAccessManagerStatics>
{
    int32_t WINRT_CALL AddAndShowDeviceAccountsAsync(void* accounts, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddAndShowDeviceAccountsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<hstring>>), Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountConfiguration> const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<hstring>>>(this->shim().AddAndShowDeviceAccountsAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountConfiguration> const*>(&accounts)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::UserDataAccounts::SystemAccess::IUserDataAccountSystemAccessManagerStatics2> : produce_base<D, Windows::ApplicationModel::UserDataAccounts::SystemAccess::IUserDataAccountSystemAccessManagerStatics2>
{
    int32_t WINRT_CALL SuppressLocalAccountWithAccountAsync(void* userDataAccountId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SuppressLocalAccountWithAccountAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), hstring const);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SuppressLocalAccountWithAccountAsync(*reinterpret_cast<hstring const*>(&userDataAccountId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateDeviceAccountAsync(void* account, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateDeviceAccountAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<hstring>), Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountConfiguration const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<hstring>>(this->shim().CreateDeviceAccountAsync(*reinterpret_cast<Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountConfiguration const*>(&account)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DeleteDeviceAccountAsync(void* accountId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeleteDeviceAccountAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), hstring const);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().DeleteDeviceAccountAsync(*reinterpret_cast<hstring const*>(&accountId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeviceAccountConfigurationAsync(void* accountId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceAccountConfigurationAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountConfiguration>), hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountConfiguration>>(this->shim().GetDeviceAccountConfigurationAsync(*reinterpret_cast<hstring const*>(&accountId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess {

inline DeviceAccountConfiguration::DeviceAccountConfiguration() :
    DeviceAccountConfiguration(impl::call_factory<DeviceAccountConfiguration>([](auto&& f) { return f.template ActivateInstance<DeviceAccountConfiguration>(); }))
{}

inline Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<hstring>> UserDataAccountSystemAccessManager::AddAndShowDeviceAccountsAsync(param::async_iterable<Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountConfiguration> const& accounts)
{
    return impl::call_factory<UserDataAccountSystemAccessManager, Windows::ApplicationModel::UserDataAccounts::SystemAccess::IUserDataAccountSystemAccessManagerStatics>([&](auto&& f) { return f.AddAndShowDeviceAccountsAsync(accounts); });
}

inline Windows::Foundation::IAsyncAction UserDataAccountSystemAccessManager::SuppressLocalAccountWithAccountAsync(param::hstring const& userDataAccountId)
{
    return impl::call_factory<UserDataAccountSystemAccessManager, Windows::ApplicationModel::UserDataAccounts::SystemAccess::IUserDataAccountSystemAccessManagerStatics2>([&](auto&& f) { return f.SuppressLocalAccountWithAccountAsync(userDataAccountId); });
}

inline Windows::Foundation::IAsyncOperation<hstring> UserDataAccountSystemAccessManager::CreateDeviceAccountAsync(Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountConfiguration const& account)
{
    return impl::call_factory<UserDataAccountSystemAccessManager, Windows::ApplicationModel::UserDataAccounts::SystemAccess::IUserDataAccountSystemAccessManagerStatics2>([&](auto&& f) { return f.CreateDeviceAccountAsync(account); });
}

inline Windows::Foundation::IAsyncAction UserDataAccountSystemAccessManager::DeleteDeviceAccountAsync(param::hstring const& accountId)
{
    return impl::call_factory<UserDataAccountSystemAccessManager, Windows::ApplicationModel::UserDataAccounts::SystemAccess::IUserDataAccountSystemAccessManagerStatics2>([&](auto&& f) { return f.DeleteDeviceAccountAsync(accountId); });
}

inline Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountConfiguration> UserDataAccountSystemAccessManager::GetDeviceAccountConfigurationAsync(param::hstring const& accountId)
{
    return impl::call_factory<UserDataAccountSystemAccessManager, Windows::ApplicationModel::UserDataAccounts::SystemAccess::IUserDataAccountSystemAccessManagerStatics2>([&](auto&& f) { return f.GetDeviceAccountConfigurationAsync(accountId); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IDeviceAccountConfiguration2> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IUserDataAccountSystemAccessManagerStatics> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IUserDataAccountSystemAccessManagerStatics> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IUserDataAccountSystemAccessManagerStatics2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::IUserDataAccountSystemAccessManagerStatics2> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountConfiguration> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::DeviceAccountConfiguration> {};
template<> struct hash<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::UserDataAccountSystemAccessManager> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::UserDataAccounts::SystemAccess::UserDataAccountSystemAccessManager> {};

}
