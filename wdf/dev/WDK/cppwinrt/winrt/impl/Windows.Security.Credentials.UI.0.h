// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Storage::Streams {

struct IBuffer;

}

WINRT_EXPORT namespace winrt::Windows::Security::Credentials::UI {

enum class AuthenticationProtocol : int32_t
{
    Basic = 0,
    Digest = 1,
    Ntlm = 2,
    Kerberos = 3,
    Negotiate = 4,
    CredSsp = 5,
    Custom = 6,
};

enum class CredentialSaveOption : int32_t
{
    Unselected = 0,
    Selected = 1,
    Hidden = 2,
};

enum class UserConsentVerificationResult : int32_t
{
    Verified = 0,
    DeviceNotPresent = 1,
    NotConfiguredForUser = 2,
    DisabledByPolicy = 3,
    DeviceBusy = 4,
    RetriesExhausted = 5,
    Canceled = 6,
};

enum class UserConsentVerifierAvailability : int32_t
{
    Available = 0,
    DeviceNotPresent = 1,
    NotConfiguredForUser = 2,
    DisabledByPolicy = 3,
    DeviceBusy = 4,
};

struct ICredentialPickerOptions;
struct ICredentialPickerResults;
struct ICredentialPickerStatics;
struct IUserConsentVerifierStatics;
struct CredentialPicker;
struct CredentialPickerOptions;
struct CredentialPickerResults;
struct UserConsentVerifier;

}

namespace winrt::impl {

template <> struct category<Windows::Security::Credentials::UI::ICredentialPickerOptions>{ using type = interface_category; };
template <> struct category<Windows::Security::Credentials::UI::ICredentialPickerResults>{ using type = interface_category; };
template <> struct category<Windows::Security::Credentials::UI::ICredentialPickerStatics>{ using type = interface_category; };
template <> struct category<Windows::Security::Credentials::UI::IUserConsentVerifierStatics>{ using type = interface_category; };
template <> struct category<Windows::Security::Credentials::UI::CredentialPicker>{ using type = class_category; };
template <> struct category<Windows::Security::Credentials::UI::CredentialPickerOptions>{ using type = class_category; };
template <> struct category<Windows::Security::Credentials::UI::CredentialPickerResults>{ using type = class_category; };
template <> struct category<Windows::Security::Credentials::UI::UserConsentVerifier>{ using type = class_category; };
template <> struct category<Windows::Security::Credentials::UI::AuthenticationProtocol>{ using type = enum_category; };
template <> struct category<Windows::Security::Credentials::UI::CredentialSaveOption>{ using type = enum_category; };
template <> struct category<Windows::Security::Credentials::UI::UserConsentVerificationResult>{ using type = enum_category; };
template <> struct category<Windows::Security::Credentials::UI::UserConsentVerifierAvailability>{ using type = enum_category; };
template <> struct name<Windows::Security::Credentials::UI::ICredentialPickerOptions>{ static constexpr auto & value{ L"Windows.Security.Credentials.UI.ICredentialPickerOptions" }; };
template <> struct name<Windows::Security::Credentials::UI::ICredentialPickerResults>{ static constexpr auto & value{ L"Windows.Security.Credentials.UI.ICredentialPickerResults" }; };
template <> struct name<Windows::Security::Credentials::UI::ICredentialPickerStatics>{ static constexpr auto & value{ L"Windows.Security.Credentials.UI.ICredentialPickerStatics" }; };
template <> struct name<Windows::Security::Credentials::UI::IUserConsentVerifierStatics>{ static constexpr auto & value{ L"Windows.Security.Credentials.UI.IUserConsentVerifierStatics" }; };
template <> struct name<Windows::Security::Credentials::UI::CredentialPicker>{ static constexpr auto & value{ L"Windows.Security.Credentials.UI.CredentialPicker" }; };
template <> struct name<Windows::Security::Credentials::UI::CredentialPickerOptions>{ static constexpr auto & value{ L"Windows.Security.Credentials.UI.CredentialPickerOptions" }; };
template <> struct name<Windows::Security::Credentials::UI::CredentialPickerResults>{ static constexpr auto & value{ L"Windows.Security.Credentials.UI.CredentialPickerResults" }; };
template <> struct name<Windows::Security::Credentials::UI::UserConsentVerifier>{ static constexpr auto & value{ L"Windows.Security.Credentials.UI.UserConsentVerifier" }; };
template <> struct name<Windows::Security::Credentials::UI::AuthenticationProtocol>{ static constexpr auto & value{ L"Windows.Security.Credentials.UI.AuthenticationProtocol" }; };
template <> struct name<Windows::Security::Credentials::UI::CredentialSaveOption>{ static constexpr auto & value{ L"Windows.Security.Credentials.UI.CredentialSaveOption" }; };
template <> struct name<Windows::Security::Credentials::UI::UserConsentVerificationResult>{ static constexpr auto & value{ L"Windows.Security.Credentials.UI.UserConsentVerificationResult" }; };
template <> struct name<Windows::Security::Credentials::UI::UserConsentVerifierAvailability>{ static constexpr auto & value{ L"Windows.Security.Credentials.UI.UserConsentVerifierAvailability" }; };
template <> struct guid_storage<Windows::Security::Credentials::UI::ICredentialPickerOptions>{ static constexpr guid value{ 0x965A0B4C,0x95FA,0x467F,{ 0x99,0x2B,0x0B,0x22,0xE5,0x85,0x9B,0xF6 } }; };
template <> struct guid_storage<Windows::Security::Credentials::UI::ICredentialPickerResults>{ static constexpr guid value{ 0x1948F99A,0xCC30,0x410C,{ 0x9C,0x38,0xCC,0x08,0x84,0xC5,0xB3,0xD7 } }; };
template <> struct guid_storage<Windows::Security::Credentials::UI::ICredentialPickerStatics>{ static constexpr guid value{ 0xAA3A5C73,0xC9EA,0x4782,{ 0x99,0xFB,0xE6,0xD7,0xE9,0x38,0xE1,0x2D } }; };
template <> struct guid_storage<Windows::Security::Credentials::UI::IUserConsentVerifierStatics>{ static constexpr guid value{ 0xAF4F3F91,0x564C,0x4DDC,{ 0xB8,0xB5,0x97,0x34,0x47,0x62,0x7C,0x65 } }; };
template <> struct default_interface<Windows::Security::Credentials::UI::CredentialPickerOptions>{ using type = Windows::Security::Credentials::UI::ICredentialPickerOptions; };
template <> struct default_interface<Windows::Security::Credentials::UI::CredentialPickerResults>{ using type = Windows::Security::Credentials::UI::ICredentialPickerResults; };

template <> struct abi<Windows::Security::Credentials::UI::ICredentialPickerOptions>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL put_Caption(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Caption(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Message(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Message(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ErrorCode(uint32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ErrorCode(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_TargetName(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TargetName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_AuthenticationProtocol(Windows::Security::Credentials::UI::AuthenticationProtocol value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AuthenticationProtocol(Windows::Security::Credentials::UI::AuthenticationProtocol* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_CustomAuthenticationProtocol(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CustomAuthenticationProtocol(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_PreviousCredential(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PreviousCredential(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_AlwaysDisplayDialog(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AlwaysDisplayDialog(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_CallerSavesCredential(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CallerSavesCredential(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_CredentialSaveOption(Windows::Security::Credentials::UI::CredentialSaveOption value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CredentialSaveOption(Windows::Security::Credentials::UI::CredentialSaveOption* value) noexcept = 0;
};};

template <> struct abi<Windows::Security::Credentials::UI::ICredentialPickerResults>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ErrorCode(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CredentialSaveOption(Windows::Security::Credentials::UI::CredentialSaveOption* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CredentialSaved(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Credential(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CredentialDomainName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CredentialUserName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CredentialPassword(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Security::Credentials::UI::ICredentialPickerStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL PickWithOptionsAsync(void* options, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL PickWithMessageAsync(void* targetName, void* message, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL PickWithCaptionAsync(void* targetName, void* message, void* caption, void** operation) noexcept = 0;
};};

template <> struct abi<Windows::Security::Credentials::UI::IUserConsentVerifierStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CheckAvailabilityAsync(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL RequestVerificationAsync(void* message, void** result) noexcept = 0;
};};

template <typename D>
struct consume_Windows_Security_Credentials_UI_ICredentialPickerOptions
{
    void Caption(param::hstring const& value) const;
    hstring Caption() const;
    void Message(param::hstring const& value) const;
    hstring Message() const;
    void ErrorCode(uint32_t value) const;
    uint32_t ErrorCode() const;
    void TargetName(param::hstring const& value) const;
    hstring TargetName() const;
    void AuthenticationProtocol(Windows::Security::Credentials::UI::AuthenticationProtocol const& value) const;
    Windows::Security::Credentials::UI::AuthenticationProtocol AuthenticationProtocol() const;
    void CustomAuthenticationProtocol(param::hstring const& value) const;
    hstring CustomAuthenticationProtocol() const;
    void PreviousCredential(Windows::Storage::Streams::IBuffer const& value) const;
    Windows::Storage::Streams::IBuffer PreviousCredential() const;
    void AlwaysDisplayDialog(bool value) const;
    bool AlwaysDisplayDialog() const;
    void CallerSavesCredential(bool value) const;
    bool CallerSavesCredential() const;
    void CredentialSaveOption(Windows::Security::Credentials::UI::CredentialSaveOption const& value) const;
    Windows::Security::Credentials::UI::CredentialSaveOption CredentialSaveOption() const;
};
template <> struct consume<Windows::Security::Credentials::UI::ICredentialPickerOptions> { template <typename D> using type = consume_Windows_Security_Credentials_UI_ICredentialPickerOptions<D>; };

template <typename D>
struct consume_Windows_Security_Credentials_UI_ICredentialPickerResults
{
    uint32_t ErrorCode() const;
    Windows::Security::Credentials::UI::CredentialSaveOption CredentialSaveOption() const;
    bool CredentialSaved() const;
    Windows::Storage::Streams::IBuffer Credential() const;
    hstring CredentialDomainName() const;
    hstring CredentialUserName() const;
    hstring CredentialPassword() const;
};
template <> struct consume<Windows::Security::Credentials::UI::ICredentialPickerResults> { template <typename D> using type = consume_Windows_Security_Credentials_UI_ICredentialPickerResults<D>; };

template <typename D>
struct consume_Windows_Security_Credentials_UI_ICredentialPickerStatics
{
    Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::UI::CredentialPickerResults> PickAsync(Windows::Security::Credentials::UI::CredentialPickerOptions const& options) const;
    Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::UI::CredentialPickerResults> PickAsync(param::hstring const& targetName, param::hstring const& message) const;
    Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::UI::CredentialPickerResults> PickAsync(param::hstring const& targetName, param::hstring const& message, param::hstring const& caption) const;
};
template <> struct consume<Windows::Security::Credentials::UI::ICredentialPickerStatics> { template <typename D> using type = consume_Windows_Security_Credentials_UI_ICredentialPickerStatics<D>; };

template <typename D>
struct consume_Windows_Security_Credentials_UI_IUserConsentVerifierStatics
{
    Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::UI::UserConsentVerifierAvailability> CheckAvailabilityAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::UI::UserConsentVerificationResult> RequestVerificationAsync(param::hstring const& message) const;
};
template <> struct consume<Windows::Security::Credentials::UI::IUserConsentVerifierStatics> { template <typename D> using type = consume_Windows_Security_Credentials_UI_IUserConsentVerifierStatics<D>; };

}
