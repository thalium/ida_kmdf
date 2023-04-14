// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Foundation {

struct Uri;

}

WINRT_EXPORT namespace winrt::Windows::Foundation::Collections {

struct IPropertySet;

}

WINRT_EXPORT namespace winrt::Windows::Security::Cryptography::Core {

enum class CryptographicPublicKeyBlobType;

}

WINRT_EXPORT namespace winrt::Windows::Storage::Streams {

struct IBuffer;
struct IRandomAccessStream;

}

WINRT_EXPORT namespace winrt::Windows::System {

struct User;

}

WINRT_EXPORT namespace winrt::Windows::Foundation::Collections {

struct IPropertySet;

}

WINRT_EXPORT namespace winrt::Windows::Security::Credentials {

enum class KeyCredentialAttestationStatus : int32_t
{
    Success = 0,
    UnknownError = 1,
    NotSupported = 2,
    TemporaryFailure = 3,
};

enum class KeyCredentialCreationOption : int32_t
{
    ReplaceExisting = 0,
    FailIfExists = 1,
};

enum class KeyCredentialStatus : int32_t
{
    Success = 0,
    UnknownError = 1,
    NotFound = 2,
    UserCanceled = 3,
    UserPrefersPassword = 4,
    CredentialAlreadyExists = 5,
    SecurityDeviceLocked = 6,
};

enum class WebAccountPictureSize : int32_t
{
    Size64x64 = 64,
    Size208x208 = 208,
    Size424x424 = 424,
    Size1080x1080 = 1080,
};

enum class WebAccountState : int32_t
{
    None = 0,
    Connected = 1,
    Error = 2,
};

struct ICredentialFactory;
struct IKeyCredential;
struct IKeyCredentialAttestationResult;
struct IKeyCredentialManagerStatics;
struct IKeyCredentialOperationResult;
struct IKeyCredentialRetrievalResult;
struct IPasswordCredential;
struct IPasswordVault;
struct IWebAccount;
struct IWebAccount2;
struct IWebAccountFactory;
struct IWebAccountProvider;
struct IWebAccountProvider2;
struct IWebAccountProvider3;
struct IWebAccountProvider4;
struct IWebAccountProviderFactory;
struct KeyCredential;
struct KeyCredentialAttestationResult;
struct KeyCredentialManager;
struct KeyCredentialOperationResult;
struct KeyCredentialRetrievalResult;
struct PasswordCredential;
struct PasswordCredentialPropertyStore;
struct PasswordVault;
struct WebAccount;
struct WebAccountProvider;

}

namespace winrt::impl {

template <> struct category<Windows::Security::Credentials::ICredentialFactory>{ using type = interface_category; };
template <> struct category<Windows::Security::Credentials::IKeyCredential>{ using type = interface_category; };
template <> struct category<Windows::Security::Credentials::IKeyCredentialAttestationResult>{ using type = interface_category; };
template <> struct category<Windows::Security::Credentials::IKeyCredentialManagerStatics>{ using type = interface_category; };
template <> struct category<Windows::Security::Credentials::IKeyCredentialOperationResult>{ using type = interface_category; };
template <> struct category<Windows::Security::Credentials::IKeyCredentialRetrievalResult>{ using type = interface_category; };
template <> struct category<Windows::Security::Credentials::IPasswordCredential>{ using type = interface_category; };
template <> struct category<Windows::Security::Credentials::IPasswordVault>{ using type = interface_category; };
template <> struct category<Windows::Security::Credentials::IWebAccount>{ using type = interface_category; };
template <> struct category<Windows::Security::Credentials::IWebAccount2>{ using type = interface_category; };
template <> struct category<Windows::Security::Credentials::IWebAccountFactory>{ using type = interface_category; };
template <> struct category<Windows::Security::Credentials::IWebAccountProvider>{ using type = interface_category; };
template <> struct category<Windows::Security::Credentials::IWebAccountProvider2>{ using type = interface_category; };
template <> struct category<Windows::Security::Credentials::IWebAccountProvider3>{ using type = interface_category; };
template <> struct category<Windows::Security::Credentials::IWebAccountProvider4>{ using type = interface_category; };
template <> struct category<Windows::Security::Credentials::IWebAccountProviderFactory>{ using type = interface_category; };
template <> struct category<Windows::Security::Credentials::KeyCredential>{ using type = class_category; };
template <> struct category<Windows::Security::Credentials::KeyCredentialAttestationResult>{ using type = class_category; };
template <> struct category<Windows::Security::Credentials::KeyCredentialManager>{ using type = class_category; };
template <> struct category<Windows::Security::Credentials::KeyCredentialOperationResult>{ using type = class_category; };
template <> struct category<Windows::Security::Credentials::KeyCredentialRetrievalResult>{ using type = class_category; };
template <> struct category<Windows::Security::Credentials::PasswordCredential>{ using type = class_category; };
template <> struct category<Windows::Security::Credentials::PasswordCredentialPropertyStore>{ using type = class_category; };
template <> struct category<Windows::Security::Credentials::PasswordVault>{ using type = class_category; };
template <> struct category<Windows::Security::Credentials::WebAccount>{ using type = class_category; };
template <> struct category<Windows::Security::Credentials::WebAccountProvider>{ using type = class_category; };
template <> struct category<Windows::Security::Credentials::KeyCredentialAttestationStatus>{ using type = enum_category; };
template <> struct category<Windows::Security::Credentials::KeyCredentialCreationOption>{ using type = enum_category; };
template <> struct category<Windows::Security::Credentials::KeyCredentialStatus>{ using type = enum_category; };
template <> struct category<Windows::Security::Credentials::WebAccountPictureSize>{ using type = enum_category; };
template <> struct category<Windows::Security::Credentials::WebAccountState>{ using type = enum_category; };
template <> struct name<Windows::Security::Credentials::ICredentialFactory>{ static constexpr auto & value{ L"Windows.Security.Credentials.ICredentialFactory" }; };
template <> struct name<Windows::Security::Credentials::IKeyCredential>{ static constexpr auto & value{ L"Windows.Security.Credentials.IKeyCredential" }; };
template <> struct name<Windows::Security::Credentials::IKeyCredentialAttestationResult>{ static constexpr auto & value{ L"Windows.Security.Credentials.IKeyCredentialAttestationResult" }; };
template <> struct name<Windows::Security::Credentials::IKeyCredentialManagerStatics>{ static constexpr auto & value{ L"Windows.Security.Credentials.IKeyCredentialManagerStatics" }; };
template <> struct name<Windows::Security::Credentials::IKeyCredentialOperationResult>{ static constexpr auto & value{ L"Windows.Security.Credentials.IKeyCredentialOperationResult" }; };
template <> struct name<Windows::Security::Credentials::IKeyCredentialRetrievalResult>{ static constexpr auto & value{ L"Windows.Security.Credentials.IKeyCredentialRetrievalResult" }; };
template <> struct name<Windows::Security::Credentials::IPasswordCredential>{ static constexpr auto & value{ L"Windows.Security.Credentials.IPasswordCredential" }; };
template <> struct name<Windows::Security::Credentials::IPasswordVault>{ static constexpr auto & value{ L"Windows.Security.Credentials.IPasswordVault" }; };
template <> struct name<Windows::Security::Credentials::IWebAccount>{ static constexpr auto & value{ L"Windows.Security.Credentials.IWebAccount" }; };
template <> struct name<Windows::Security::Credentials::IWebAccount2>{ static constexpr auto & value{ L"Windows.Security.Credentials.IWebAccount2" }; };
template <> struct name<Windows::Security::Credentials::IWebAccountFactory>{ static constexpr auto & value{ L"Windows.Security.Credentials.IWebAccountFactory" }; };
template <> struct name<Windows::Security::Credentials::IWebAccountProvider>{ static constexpr auto & value{ L"Windows.Security.Credentials.IWebAccountProvider" }; };
template <> struct name<Windows::Security::Credentials::IWebAccountProvider2>{ static constexpr auto & value{ L"Windows.Security.Credentials.IWebAccountProvider2" }; };
template <> struct name<Windows::Security::Credentials::IWebAccountProvider3>{ static constexpr auto & value{ L"Windows.Security.Credentials.IWebAccountProvider3" }; };
template <> struct name<Windows::Security::Credentials::IWebAccountProvider4>{ static constexpr auto & value{ L"Windows.Security.Credentials.IWebAccountProvider4" }; };
template <> struct name<Windows::Security::Credentials::IWebAccountProviderFactory>{ static constexpr auto & value{ L"Windows.Security.Credentials.IWebAccountProviderFactory" }; };
template <> struct name<Windows::Security::Credentials::KeyCredential>{ static constexpr auto & value{ L"Windows.Security.Credentials.KeyCredential" }; };
template <> struct name<Windows::Security::Credentials::KeyCredentialAttestationResult>{ static constexpr auto & value{ L"Windows.Security.Credentials.KeyCredentialAttestationResult" }; };
template <> struct name<Windows::Security::Credentials::KeyCredentialManager>{ static constexpr auto & value{ L"Windows.Security.Credentials.KeyCredentialManager" }; };
template <> struct name<Windows::Security::Credentials::KeyCredentialOperationResult>{ static constexpr auto & value{ L"Windows.Security.Credentials.KeyCredentialOperationResult" }; };
template <> struct name<Windows::Security::Credentials::KeyCredentialRetrievalResult>{ static constexpr auto & value{ L"Windows.Security.Credentials.KeyCredentialRetrievalResult" }; };
template <> struct name<Windows::Security::Credentials::PasswordCredential>{ static constexpr auto & value{ L"Windows.Security.Credentials.PasswordCredential" }; };
template <> struct name<Windows::Security::Credentials::PasswordCredentialPropertyStore>{ static constexpr auto & value{ L"Windows.Security.Credentials.PasswordCredentialPropertyStore" }; };
template <> struct name<Windows::Security::Credentials::PasswordVault>{ static constexpr auto & value{ L"Windows.Security.Credentials.PasswordVault" }; };
template <> struct name<Windows::Security::Credentials::WebAccount>{ static constexpr auto & value{ L"Windows.Security.Credentials.WebAccount" }; };
template <> struct name<Windows::Security::Credentials::WebAccountProvider>{ static constexpr auto & value{ L"Windows.Security.Credentials.WebAccountProvider" }; };
template <> struct name<Windows::Security::Credentials::KeyCredentialAttestationStatus>{ static constexpr auto & value{ L"Windows.Security.Credentials.KeyCredentialAttestationStatus" }; };
template <> struct name<Windows::Security::Credentials::KeyCredentialCreationOption>{ static constexpr auto & value{ L"Windows.Security.Credentials.KeyCredentialCreationOption" }; };
template <> struct name<Windows::Security::Credentials::KeyCredentialStatus>{ static constexpr auto & value{ L"Windows.Security.Credentials.KeyCredentialStatus" }; };
template <> struct name<Windows::Security::Credentials::WebAccountPictureSize>{ static constexpr auto & value{ L"Windows.Security.Credentials.WebAccountPictureSize" }; };
template <> struct name<Windows::Security::Credentials::WebAccountState>{ static constexpr auto & value{ L"Windows.Security.Credentials.WebAccountState" }; };
template <> struct guid_storage<Windows::Security::Credentials::ICredentialFactory>{ static constexpr guid value{ 0x54EF13A1,0xBF26,0x47B5,{ 0x97,0xDD,0xDE,0x77,0x9B,0x7C,0xAD,0x58 } }; };
template <> struct guid_storage<Windows::Security::Credentials::IKeyCredential>{ static constexpr guid value{ 0x9585EF8D,0x457B,0x4847,{ 0xB1,0x1A,0xFA,0x96,0x0B,0xBD,0xB1,0x38 } }; };
template <> struct guid_storage<Windows::Security::Credentials::IKeyCredentialAttestationResult>{ static constexpr guid value{ 0x78AAB3A1,0xA3C1,0x4103,{ 0xB6,0xCC,0x47,0x2C,0x44,0x17,0x1C,0xBB } }; };
template <> struct guid_storage<Windows::Security::Credentials::IKeyCredentialManagerStatics>{ static constexpr guid value{ 0x6AAC468B,0x0EF1,0x4CE0,{ 0x82,0x90,0x41,0x06,0xDA,0x6A,0x63,0xB5 } }; };
template <> struct guid_storage<Windows::Security::Credentials::IKeyCredentialOperationResult>{ static constexpr guid value{ 0xF53786C1,0x5261,0x4CDD,{ 0x97,0x6D,0xCC,0x90,0x9A,0xC7,0x16,0x20 } }; };
template <> struct guid_storage<Windows::Security::Credentials::IKeyCredentialRetrievalResult>{ static constexpr guid value{ 0x58CD7703,0x8D87,0x4249,{ 0x9B,0x58,0xF6,0x59,0x8C,0xC9,0x64,0x4E } }; };
template <> struct guid_storage<Windows::Security::Credentials::IPasswordCredential>{ static constexpr guid value{ 0x6AB18989,0xC720,0x41A7,{ 0xA6,0xC1,0xFE,0xAD,0xB3,0x63,0x29,0xA0 } }; };
template <> struct guid_storage<Windows::Security::Credentials::IPasswordVault>{ static constexpr guid value{ 0x61FD2C0B,0xC8D4,0x48C1,{ 0xA5,0x4F,0xBC,0x5A,0x64,0x20,0x5A,0xF2 } }; };
template <> struct guid_storage<Windows::Security::Credentials::IWebAccount>{ static constexpr guid value{ 0x69473EB2,0x8031,0x49BE,{ 0x80,0xBB,0x96,0xCB,0x46,0xD9,0x9A,0xBA } }; };
template <> struct guid_storage<Windows::Security::Credentials::IWebAccount2>{ static constexpr guid value{ 0x7B56D6F8,0x990B,0x4EB5,{ 0x94,0xA7,0x56,0x21,0xF3,0xA8,0xB8,0x24 } }; };
template <> struct guid_storage<Windows::Security::Credentials::IWebAccountFactory>{ static constexpr guid value{ 0xAC9AFB39,0x1DE9,0x4E92,{ 0xB7,0x8F,0x05,0x81,0xA8,0x7F,0x6E,0x5C } }; };
template <> struct guid_storage<Windows::Security::Credentials::IWebAccountProvider>{ static constexpr guid value{ 0x29DCC8C3,0x7AB9,0x4A7C,{ 0xA3,0x36,0xB9,0x42,0xF9,0xDB,0xF7,0xC7 } }; };
template <> struct guid_storage<Windows::Security::Credentials::IWebAccountProvider2>{ static constexpr guid value{ 0x4A01EB05,0x4E42,0x41D4,{ 0xB5,0x18,0xE0,0x08,0xA5,0x16,0x36,0x14 } }; };
template <> struct guid_storage<Windows::Security::Credentials::IWebAccountProvider3>{ static constexpr guid value{ 0xDA1C518B,0x970D,0x4D49,{ 0x82,0x5C,0xF2,0x70,0x6F,0x8C,0xA7,0xFE } }; };
template <> struct guid_storage<Windows::Security::Credentials::IWebAccountProvider4>{ static constexpr guid value{ 0x718FD8DB,0xE796,0x4210,{ 0xB7,0x4E,0x84,0xD2,0x98,0x94,0xB0,0x80 } }; };
template <> struct guid_storage<Windows::Security::Credentials::IWebAccountProviderFactory>{ static constexpr guid value{ 0x1D767DF1,0xE1E1,0x4B9A,{ 0xA7,0x74,0x5C,0x7C,0x7E,0x3B,0xF3,0x71 } }; };
template <> struct default_interface<Windows::Security::Credentials::KeyCredential>{ using type = Windows::Security::Credentials::IKeyCredential; };
template <> struct default_interface<Windows::Security::Credentials::KeyCredentialAttestationResult>{ using type = Windows::Security::Credentials::IKeyCredentialAttestationResult; };
template <> struct default_interface<Windows::Security::Credentials::KeyCredentialOperationResult>{ using type = Windows::Security::Credentials::IKeyCredentialOperationResult; };
template <> struct default_interface<Windows::Security::Credentials::KeyCredentialRetrievalResult>{ using type = Windows::Security::Credentials::IKeyCredentialRetrievalResult; };
template <> struct default_interface<Windows::Security::Credentials::PasswordCredential>{ using type = Windows::Security::Credentials::IPasswordCredential; };
template <> struct default_interface<Windows::Security::Credentials::PasswordCredentialPropertyStore>{ using type = Windows::Foundation::Collections::IPropertySet; };
template <> struct default_interface<Windows::Security::Credentials::PasswordVault>{ using type = Windows::Security::Credentials::IPasswordVault; };
template <> struct default_interface<Windows::Security::Credentials::WebAccount>{ using type = Windows::Security::Credentials::IWebAccount; };
template <> struct default_interface<Windows::Security::Credentials::WebAccountProvider>{ using type = Windows::Security::Credentials::IWebAccountProvider; };

template <> struct abi<Windows::Security::Credentials::ICredentialFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreatePasswordCredential(void* resource, void* userName, void* password, void** credential) noexcept = 0;
};};

template <> struct abi<Windows::Security::Credentials::IKeyCredential>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Name(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL RetrievePublicKeyWithDefaultBlobType(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL RetrievePublicKeyWithBlobType(Windows::Security::Cryptography::Core::CryptographicPublicKeyBlobType blobType, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL RequestSignAsync(void* data, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetAttestationAsync(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Security::Credentials::IKeyCredentialAttestationResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_CertificateChainBuffer(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AttestationBuffer(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Status(Windows::Security::Credentials::KeyCredentialAttestationStatus* value) noexcept = 0;
};};

template <> struct abi<Windows::Security::Credentials::IKeyCredentialManagerStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL IsSupportedAsync(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL RenewAttestationAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL RequestCreateAsync(void* name, Windows::Security::Credentials::KeyCredentialCreationOption option, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL OpenAsync(void* name, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL DeleteAsync(void* name, void** operation) noexcept = 0;
};};

template <> struct abi<Windows::Security::Credentials::IKeyCredentialOperationResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Result(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Status(Windows::Security::Credentials::KeyCredentialStatus* value) noexcept = 0;
};};

template <> struct abi<Windows::Security::Credentials::IKeyCredentialRetrievalResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Credential(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Status(Windows::Security::Credentials::KeyCredentialStatus* value) noexcept = 0;
};};

template <> struct abi<Windows::Security::Credentials::IPasswordCredential>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Resource(void** resource) noexcept = 0;
    virtual int32_t WINRT_CALL put_Resource(void* resource) noexcept = 0;
    virtual int32_t WINRT_CALL get_UserName(void** userName) noexcept = 0;
    virtual int32_t WINRT_CALL put_UserName(void* userName) noexcept = 0;
    virtual int32_t WINRT_CALL get_Password(void** password) noexcept = 0;
    virtual int32_t WINRT_CALL put_Password(void* password) noexcept = 0;
    virtual int32_t WINRT_CALL RetrievePassword() noexcept = 0;
    virtual int32_t WINRT_CALL get_Properties(void** props) noexcept = 0;
};};

template <> struct abi<Windows::Security::Credentials::IPasswordVault>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Add(void* credential) noexcept = 0;
    virtual int32_t WINRT_CALL Remove(void* credential) noexcept = 0;
    virtual int32_t WINRT_CALL Retrieve(void* resource, void* userName, void** credential) noexcept = 0;
    virtual int32_t WINRT_CALL FindAllByResource(void* resource, void** credentials) noexcept = 0;
    virtual int32_t WINRT_CALL FindAllByUserName(void* userName, void** credentials) noexcept = 0;
    virtual int32_t WINRT_CALL RetrieveAll(void** credentials) noexcept = 0;
};};

template <> struct abi<Windows::Security::Credentials::IWebAccount>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_WebAccountProvider(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_UserName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_State(Windows::Security::Credentials::WebAccountState* value) noexcept = 0;
};};

template <> struct abi<Windows::Security::Credentials::IWebAccount2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Id(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Properties(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetPictureAsync(Windows::Security::Credentials::WebAccountPictureSize desizedSize, void** asyncInfo) noexcept = 0;
    virtual int32_t WINRT_CALL SignOutAsync(void** asyncInfo) noexcept = 0;
    virtual int32_t WINRT_CALL SignOutWithClientIdAsync(void* clientId, void** asyncInfo) noexcept = 0;
};};

template <> struct abi<Windows::Security::Credentials::IWebAccountFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateWebAccount(void* webAccountProvider, void* userName, Windows::Security::Credentials::WebAccountState state, void** instance) noexcept = 0;
};};

template <> struct abi<Windows::Security::Credentials::IWebAccountProvider>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Id(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DisplayName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IconUri(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Security::Credentials::IWebAccountProvider2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_DisplayPurpose(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Authority(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Security::Credentials::IWebAccountProvider3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_User(void** user) noexcept = 0;
};};

template <> struct abi<Windows::Security::Credentials::IWebAccountProvider4>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsSystemProvider(bool* value) noexcept = 0;
};};

template <> struct abi<Windows::Security::Credentials::IWebAccountProviderFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateWebAccountProvider(void* id, void* displayName, void* iconUri, void** instance) noexcept = 0;
};};

template <typename D>
struct consume_Windows_Security_Credentials_ICredentialFactory
{
    Windows::Security::Credentials::PasswordCredential CreatePasswordCredential(param::hstring const& resource, param::hstring const& userName, param::hstring const& password) const;
};
template <> struct consume<Windows::Security::Credentials::ICredentialFactory> { template <typename D> using type = consume_Windows_Security_Credentials_ICredentialFactory<D>; };

template <typename D>
struct consume_Windows_Security_Credentials_IKeyCredential
{
    hstring Name() const;
    Windows::Storage::Streams::IBuffer RetrievePublicKey() const;
    Windows::Storage::Streams::IBuffer RetrievePublicKey(Windows::Security::Cryptography::Core::CryptographicPublicKeyBlobType const& blobType) const;
    Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::KeyCredentialOperationResult> RequestSignAsync(Windows::Storage::Streams::IBuffer const& data) const;
    Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::KeyCredentialAttestationResult> GetAttestationAsync() const;
};
template <> struct consume<Windows::Security::Credentials::IKeyCredential> { template <typename D> using type = consume_Windows_Security_Credentials_IKeyCredential<D>; };

template <typename D>
struct consume_Windows_Security_Credentials_IKeyCredentialAttestationResult
{
    Windows::Storage::Streams::IBuffer CertificateChainBuffer() const;
    Windows::Storage::Streams::IBuffer AttestationBuffer() const;
    Windows::Security::Credentials::KeyCredentialAttestationStatus Status() const;
};
template <> struct consume<Windows::Security::Credentials::IKeyCredentialAttestationResult> { template <typename D> using type = consume_Windows_Security_Credentials_IKeyCredentialAttestationResult<D>; };

template <typename D>
struct consume_Windows_Security_Credentials_IKeyCredentialManagerStatics
{
    Windows::Foundation::IAsyncOperation<bool> IsSupportedAsync() const;
    Windows::Foundation::IAsyncAction RenewAttestationAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::KeyCredentialRetrievalResult> RequestCreateAsync(param::hstring const& name, Windows::Security::Credentials::KeyCredentialCreationOption const& option) const;
    Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::KeyCredentialRetrievalResult> OpenAsync(param::hstring const& name) const;
    Windows::Foundation::IAsyncAction DeleteAsync(param::hstring const& name) const;
};
template <> struct consume<Windows::Security::Credentials::IKeyCredentialManagerStatics> { template <typename D> using type = consume_Windows_Security_Credentials_IKeyCredentialManagerStatics<D>; };

template <typename D>
struct consume_Windows_Security_Credentials_IKeyCredentialOperationResult
{
    Windows::Storage::Streams::IBuffer Result() const;
    Windows::Security::Credentials::KeyCredentialStatus Status() const;
};
template <> struct consume<Windows::Security::Credentials::IKeyCredentialOperationResult> { template <typename D> using type = consume_Windows_Security_Credentials_IKeyCredentialOperationResult<D>; };

template <typename D>
struct consume_Windows_Security_Credentials_IKeyCredentialRetrievalResult
{
    Windows::Security::Credentials::KeyCredential Credential() const;
    Windows::Security::Credentials::KeyCredentialStatus Status() const;
};
template <> struct consume<Windows::Security::Credentials::IKeyCredentialRetrievalResult> { template <typename D> using type = consume_Windows_Security_Credentials_IKeyCredentialRetrievalResult<D>; };

template <typename D>
struct consume_Windows_Security_Credentials_IPasswordCredential
{
    hstring Resource() const;
    void Resource(param::hstring const& resource) const;
    hstring UserName() const;
    void UserName(param::hstring const& userName) const;
    hstring Password() const;
    void Password(param::hstring const& password) const;
    void RetrievePassword() const;
    Windows::Foundation::Collections::IPropertySet Properties() const;
};
template <> struct consume<Windows::Security::Credentials::IPasswordCredential> { template <typename D> using type = consume_Windows_Security_Credentials_IPasswordCredential<D>; };

template <typename D>
struct consume_Windows_Security_Credentials_IPasswordVault
{
    void Add(Windows::Security::Credentials::PasswordCredential const& credential) const;
    void Remove(Windows::Security::Credentials::PasswordCredential const& credential) const;
    Windows::Security::Credentials::PasswordCredential Retrieve(param::hstring const& resource, param::hstring const& userName) const;
    Windows::Foundation::Collections::IVectorView<Windows::Security::Credentials::PasswordCredential> FindAllByResource(param::hstring const& resource) const;
    Windows::Foundation::Collections::IVectorView<Windows::Security::Credentials::PasswordCredential> FindAllByUserName(param::hstring const& userName) const;
    Windows::Foundation::Collections::IVectorView<Windows::Security::Credentials::PasswordCredential> RetrieveAll() const;
};
template <> struct consume<Windows::Security::Credentials::IPasswordVault> { template <typename D> using type = consume_Windows_Security_Credentials_IPasswordVault<D>; };

template <typename D>
struct consume_Windows_Security_Credentials_IWebAccount
{
    Windows::Security::Credentials::WebAccountProvider WebAccountProvider() const;
    hstring UserName() const;
    Windows::Security::Credentials::WebAccountState State() const;
};
template <> struct consume<Windows::Security::Credentials::IWebAccount> { template <typename D> using type = consume_Windows_Security_Credentials_IWebAccount<D>; };

template <typename D>
struct consume_Windows_Security_Credentials_IWebAccount2
{
    hstring Id() const;
    Windows::Foundation::Collections::IMapView<hstring, hstring> Properties() const;
    Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStream> GetPictureAsync(Windows::Security::Credentials::WebAccountPictureSize const& desizedSize) const;
    Windows::Foundation::IAsyncAction SignOutAsync() const;
    Windows::Foundation::IAsyncAction SignOutAsync(param::hstring const& clientId) const;
};
template <> struct consume<Windows::Security::Credentials::IWebAccount2> { template <typename D> using type = consume_Windows_Security_Credentials_IWebAccount2<D>; };

template <typename D>
struct consume_Windows_Security_Credentials_IWebAccountFactory
{
    Windows::Security::Credentials::WebAccount CreateWebAccount(Windows::Security::Credentials::WebAccountProvider const& webAccountProvider, param::hstring const& userName, Windows::Security::Credentials::WebAccountState const& state) const;
};
template <> struct consume<Windows::Security::Credentials::IWebAccountFactory> { template <typename D> using type = consume_Windows_Security_Credentials_IWebAccountFactory<D>; };

template <typename D>
struct consume_Windows_Security_Credentials_IWebAccountProvider
{
    hstring Id() const;
    hstring DisplayName() const;
    Windows::Foundation::Uri IconUri() const;
};
template <> struct consume<Windows::Security::Credentials::IWebAccountProvider> { template <typename D> using type = consume_Windows_Security_Credentials_IWebAccountProvider<D>; };

template <typename D>
struct consume_Windows_Security_Credentials_IWebAccountProvider2
{
    hstring DisplayPurpose() const;
    hstring Authority() const;
};
template <> struct consume<Windows::Security::Credentials::IWebAccountProvider2> { template <typename D> using type = consume_Windows_Security_Credentials_IWebAccountProvider2<D>; };

template <typename D>
struct consume_Windows_Security_Credentials_IWebAccountProvider3
{
    Windows::System::User User() const;
};
template <> struct consume<Windows::Security::Credentials::IWebAccountProvider3> { template <typename D> using type = consume_Windows_Security_Credentials_IWebAccountProvider3<D>; };

template <typename D>
struct consume_Windows_Security_Credentials_IWebAccountProvider4
{
    bool IsSystemProvider() const;
};
template <> struct consume<Windows::Security::Credentials::IWebAccountProvider4> { template <typename D> using type = consume_Windows_Security_Credentials_IWebAccountProvider4<D>; };

template <typename D>
struct consume_Windows_Security_Credentials_IWebAccountProviderFactory
{
    Windows::Security::Credentials::WebAccountProvider CreateWebAccountProvider(param::hstring const& id, param::hstring const& displayName, Windows::Foundation::Uri const& iconUri) const;
};
template <> struct consume<Windows::Security::Credentials::IWebAccountProviderFactory> { template <typename D> using type = consume_Windows_Security_Credentials_IWebAccountProviderFactory<D>; };

}
