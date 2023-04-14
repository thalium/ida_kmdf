// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Security.Cryptography.Core.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.Security.Credentials.2.h"

namespace winrt::impl {

template <typename D> Windows::Security::Credentials::PasswordCredential consume_Windows_Security_Credentials_ICredentialFactory<D>::CreatePasswordCredential(param::hstring const& resource, param::hstring const& userName, param::hstring const& password) const
{
    Windows::Security::Credentials::PasswordCredential credential{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::ICredentialFactory)->CreatePasswordCredential(get_abi(resource), get_abi(userName), get_abi(password), put_abi(credential)));
    return credential;
}

template <typename D> hstring consume_Windows_Security_Credentials_IKeyCredential<D>::Name() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::IKeyCredential)->get_Name(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Security_Credentials_IKeyCredential<D>::RetrievePublicKey() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::IKeyCredential)->RetrievePublicKeyWithDefaultBlobType(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Security_Credentials_IKeyCredential<D>::RetrievePublicKey(Windows::Security::Cryptography::Core::CryptographicPublicKeyBlobType const& blobType) const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::IKeyCredential)->RetrievePublicKeyWithBlobType(get_abi(blobType), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::KeyCredentialOperationResult> consume_Windows_Security_Credentials_IKeyCredential<D>::RequestSignAsync(Windows::Storage::Streams::IBuffer const& data) const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::KeyCredentialOperationResult> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::IKeyCredential)->RequestSignAsync(get_abi(data), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::KeyCredentialAttestationResult> consume_Windows_Security_Credentials_IKeyCredential<D>::GetAttestationAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::KeyCredentialAttestationResult> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::IKeyCredential)->GetAttestationAsync(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Security_Credentials_IKeyCredentialAttestationResult<D>::CertificateChainBuffer() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::IKeyCredentialAttestationResult)->get_CertificateChainBuffer(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Security_Credentials_IKeyCredentialAttestationResult<D>::AttestationBuffer() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::IKeyCredentialAttestationResult)->get_AttestationBuffer(put_abi(value)));
    return value;
}

template <typename D> Windows::Security::Credentials::KeyCredentialAttestationStatus consume_Windows_Security_Credentials_IKeyCredentialAttestationResult<D>::Status() const
{
    Windows::Security::Credentials::KeyCredentialAttestationStatus value{};
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::IKeyCredentialAttestationResult)->get_Status(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Security_Credentials_IKeyCredentialManagerStatics<D>::IsSupportedAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::IKeyCredentialManagerStatics)->IsSupportedAsync(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Security_Credentials_IKeyCredentialManagerStatics<D>::RenewAttestationAsync() const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::IKeyCredentialManagerStatics)->RenewAttestationAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::KeyCredentialRetrievalResult> consume_Windows_Security_Credentials_IKeyCredentialManagerStatics<D>::RequestCreateAsync(param::hstring const& name, Windows::Security::Credentials::KeyCredentialCreationOption const& option) const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::KeyCredentialRetrievalResult> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::IKeyCredentialManagerStatics)->RequestCreateAsync(get_abi(name), get_abi(option), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::KeyCredentialRetrievalResult> consume_Windows_Security_Credentials_IKeyCredentialManagerStatics<D>::OpenAsync(param::hstring const& name) const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::KeyCredentialRetrievalResult> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::IKeyCredentialManagerStatics)->OpenAsync(get_abi(name), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Security_Credentials_IKeyCredentialManagerStatics<D>::DeleteAsync(param::hstring const& name) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::IKeyCredentialManagerStatics)->DeleteAsync(get_abi(name), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Security_Credentials_IKeyCredentialOperationResult<D>::Result() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::IKeyCredentialOperationResult)->get_Result(put_abi(value)));
    return value;
}

template <typename D> Windows::Security::Credentials::KeyCredentialStatus consume_Windows_Security_Credentials_IKeyCredentialOperationResult<D>::Status() const
{
    Windows::Security::Credentials::KeyCredentialStatus value{};
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::IKeyCredentialOperationResult)->get_Status(put_abi(value)));
    return value;
}

template <typename D> Windows::Security::Credentials::KeyCredential consume_Windows_Security_Credentials_IKeyCredentialRetrievalResult<D>::Credential() const
{
    Windows::Security::Credentials::KeyCredential value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::IKeyCredentialRetrievalResult)->get_Credential(put_abi(value)));
    return value;
}

template <typename D> Windows::Security::Credentials::KeyCredentialStatus consume_Windows_Security_Credentials_IKeyCredentialRetrievalResult<D>::Status() const
{
    Windows::Security::Credentials::KeyCredentialStatus value{};
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::IKeyCredentialRetrievalResult)->get_Status(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Credentials_IPasswordCredential<D>::Resource() const
{
    hstring resource{};
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::IPasswordCredential)->get_Resource(put_abi(resource)));
    return resource;
}

template <typename D> void consume_Windows_Security_Credentials_IPasswordCredential<D>::Resource(param::hstring const& resource) const
{
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::IPasswordCredential)->put_Resource(get_abi(resource)));
}

template <typename D> hstring consume_Windows_Security_Credentials_IPasswordCredential<D>::UserName() const
{
    hstring userName{};
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::IPasswordCredential)->get_UserName(put_abi(userName)));
    return userName;
}

template <typename D> void consume_Windows_Security_Credentials_IPasswordCredential<D>::UserName(param::hstring const& userName) const
{
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::IPasswordCredential)->put_UserName(get_abi(userName)));
}

template <typename D> hstring consume_Windows_Security_Credentials_IPasswordCredential<D>::Password() const
{
    hstring password{};
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::IPasswordCredential)->get_Password(put_abi(password)));
    return password;
}

template <typename D> void consume_Windows_Security_Credentials_IPasswordCredential<D>::Password(param::hstring const& password) const
{
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::IPasswordCredential)->put_Password(get_abi(password)));
}

template <typename D> void consume_Windows_Security_Credentials_IPasswordCredential<D>::RetrievePassword() const
{
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::IPasswordCredential)->RetrievePassword());
}

template <typename D> Windows::Foundation::Collections::IPropertySet consume_Windows_Security_Credentials_IPasswordCredential<D>::Properties() const
{
    Windows::Foundation::Collections::IPropertySet props{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::IPasswordCredential)->get_Properties(put_abi(props)));
    return props;
}

template <typename D> void consume_Windows_Security_Credentials_IPasswordVault<D>::Add(Windows::Security::Credentials::PasswordCredential const& credential) const
{
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::IPasswordVault)->Add(get_abi(credential)));
}

template <typename D> void consume_Windows_Security_Credentials_IPasswordVault<D>::Remove(Windows::Security::Credentials::PasswordCredential const& credential) const
{
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::IPasswordVault)->Remove(get_abi(credential)));
}

template <typename D> Windows::Security::Credentials::PasswordCredential consume_Windows_Security_Credentials_IPasswordVault<D>::Retrieve(param::hstring const& resource, param::hstring const& userName) const
{
    Windows::Security::Credentials::PasswordCredential credential{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::IPasswordVault)->Retrieve(get_abi(resource), get_abi(userName), put_abi(credential)));
    return credential;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Security::Credentials::PasswordCredential> consume_Windows_Security_Credentials_IPasswordVault<D>::FindAllByResource(param::hstring const& resource) const
{
    Windows::Foundation::Collections::IVectorView<Windows::Security::Credentials::PasswordCredential> credentials{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::IPasswordVault)->FindAllByResource(get_abi(resource), put_abi(credentials)));
    return credentials;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Security::Credentials::PasswordCredential> consume_Windows_Security_Credentials_IPasswordVault<D>::FindAllByUserName(param::hstring const& userName) const
{
    Windows::Foundation::Collections::IVectorView<Windows::Security::Credentials::PasswordCredential> credentials{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::IPasswordVault)->FindAllByUserName(get_abi(userName), put_abi(credentials)));
    return credentials;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Security::Credentials::PasswordCredential> consume_Windows_Security_Credentials_IPasswordVault<D>::RetrieveAll() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Security::Credentials::PasswordCredential> credentials{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::IPasswordVault)->RetrieveAll(put_abi(credentials)));
    return credentials;
}

template <typename D> Windows::Security::Credentials::WebAccountProvider consume_Windows_Security_Credentials_IWebAccount<D>::WebAccountProvider() const
{
    Windows::Security::Credentials::WebAccountProvider value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::IWebAccount)->get_WebAccountProvider(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Credentials_IWebAccount<D>::UserName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::IWebAccount)->get_UserName(put_abi(value)));
    return value;
}

template <typename D> Windows::Security::Credentials::WebAccountState consume_Windows_Security_Credentials_IWebAccount<D>::State() const
{
    Windows::Security::Credentials::WebAccountState value{};
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::IWebAccount)->get_State(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Credentials_IWebAccount2<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::IWebAccount2)->get_Id(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IMapView<hstring, hstring> consume_Windows_Security_Credentials_IWebAccount2<D>::Properties() const
{
    Windows::Foundation::Collections::IMapView<hstring, hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::IWebAccount2)->get_Properties(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStream> consume_Windows_Security_Credentials_IWebAccount2<D>::GetPictureAsync(Windows::Security::Credentials::WebAccountPictureSize const& desizedSize) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStream> asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::IWebAccount2)->GetPictureAsync(get_abi(desizedSize), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Security_Credentials_IWebAccount2<D>::SignOutAsync() const
{
    Windows::Foundation::IAsyncAction asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::IWebAccount2)->SignOutAsync(put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Security_Credentials_IWebAccount2<D>::SignOutAsync(param::hstring const& clientId) const
{
    Windows::Foundation::IAsyncAction asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::IWebAccount2)->SignOutWithClientIdAsync(get_abi(clientId), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Security::Credentials::WebAccount consume_Windows_Security_Credentials_IWebAccountFactory<D>::CreateWebAccount(Windows::Security::Credentials::WebAccountProvider const& webAccountProvider, param::hstring const& userName, Windows::Security::Credentials::WebAccountState const& state) const
{
    Windows::Security::Credentials::WebAccount instance{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::IWebAccountFactory)->CreateWebAccount(get_abi(webAccountProvider), get_abi(userName), get_abi(state), put_abi(instance)));
    return instance;
}

template <typename D> hstring consume_Windows_Security_Credentials_IWebAccountProvider<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::IWebAccountProvider)->get_Id(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Credentials_IWebAccountProvider<D>::DisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::IWebAccountProvider)->get_DisplayName(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Uri consume_Windows_Security_Credentials_IWebAccountProvider<D>::IconUri() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::IWebAccountProvider)->get_IconUri(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Credentials_IWebAccountProvider2<D>::DisplayPurpose() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::IWebAccountProvider2)->get_DisplayPurpose(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Credentials_IWebAccountProvider2<D>::Authority() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::IWebAccountProvider2)->get_Authority(put_abi(value)));
    return value;
}

template <typename D> Windows::System::User consume_Windows_Security_Credentials_IWebAccountProvider3<D>::User() const
{
    Windows::System::User user{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::IWebAccountProvider3)->get_User(put_abi(user)));
    return user;
}

template <typename D> bool consume_Windows_Security_Credentials_IWebAccountProvider4<D>::IsSystemProvider() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::IWebAccountProvider4)->get_IsSystemProvider(&value));
    return value;
}

template <typename D> Windows::Security::Credentials::WebAccountProvider consume_Windows_Security_Credentials_IWebAccountProviderFactory<D>::CreateWebAccountProvider(param::hstring const& id, param::hstring const& displayName, Windows::Foundation::Uri const& iconUri) const
{
    Windows::Security::Credentials::WebAccountProvider instance{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::IWebAccountProviderFactory)->CreateWebAccountProvider(get_abi(id), get_abi(displayName), get_abi(iconUri), put_abi(instance)));
    return instance;
}

template <typename D>
struct produce<D, Windows::Security::Credentials::ICredentialFactory> : produce_base<D, Windows::Security::Credentials::ICredentialFactory>
{
    int32_t WINRT_CALL CreatePasswordCredential(void* resource, void* userName, void* password, void** credential) noexcept final
    {
        try
        {
            *credential = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreatePasswordCredential, WINRT_WRAP(Windows::Security::Credentials::PasswordCredential), hstring const&, hstring const&, hstring const&);
            *credential = detach_from<Windows::Security::Credentials::PasswordCredential>(this->shim().CreatePasswordCredential(*reinterpret_cast<hstring const*>(&resource), *reinterpret_cast<hstring const*>(&userName), *reinterpret_cast<hstring const*>(&password)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Credentials::IKeyCredential> : produce_base<D, Windows::Security::Credentials::IKeyCredential>
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

    int32_t WINRT_CALL RetrievePublicKeyWithDefaultBlobType(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RetrievePublicKey, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().RetrievePublicKey());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RetrievePublicKeyWithBlobType(Windows::Security::Cryptography::Core::CryptographicPublicKeyBlobType blobType, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RetrievePublicKey, WINRT_WRAP(Windows::Storage::Streams::IBuffer), Windows::Security::Cryptography::Core::CryptographicPublicKeyBlobType const&);
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().RetrievePublicKey(*reinterpret_cast<Windows::Security::Cryptography::Core::CryptographicPublicKeyBlobType const*>(&blobType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestSignAsync(void* data, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestSignAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::KeyCredentialOperationResult>), Windows::Storage::Streams::IBuffer const);
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::KeyCredentialOperationResult>>(this->shim().RequestSignAsync(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&data)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetAttestationAsync(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAttestationAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::KeyCredentialAttestationResult>));
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::KeyCredentialAttestationResult>>(this->shim().GetAttestationAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Credentials::IKeyCredentialAttestationResult> : produce_base<D, Windows::Security::Credentials::IKeyCredentialAttestationResult>
{
    int32_t WINRT_CALL get_CertificateChainBuffer(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CertificateChainBuffer, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().CertificateChainBuffer());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AttestationBuffer(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AttestationBuffer, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().AttestationBuffer());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Status(Windows::Security::Credentials::KeyCredentialAttestationStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Security::Credentials::KeyCredentialAttestationStatus));
            *value = detach_from<Windows::Security::Credentials::KeyCredentialAttestationStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Credentials::IKeyCredentialManagerStatics> : produce_base<D, Windows::Security::Credentials::IKeyCredentialManagerStatics>
{
    int32_t WINRT_CALL IsSupportedAsync(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSupportedAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>));
            *value = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().IsSupportedAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RenewAttestationAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RenewAttestationAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().RenewAttestationAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestCreateAsync(void* name, Windows::Security::Credentials::KeyCredentialCreationOption option, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestCreateAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::KeyCredentialRetrievalResult>), hstring const, Windows::Security::Credentials::KeyCredentialCreationOption const);
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::KeyCredentialRetrievalResult>>(this->shim().RequestCreateAsync(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<Windows::Security::Credentials::KeyCredentialCreationOption const*>(&option)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL OpenAsync(void* name, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OpenAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::KeyCredentialRetrievalResult>), hstring const);
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::KeyCredentialRetrievalResult>>(this->shim().OpenAsync(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DeleteAsync(void* name, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeleteAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().DeleteAsync(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Credentials::IKeyCredentialOperationResult> : produce_base<D, Windows::Security::Credentials::IKeyCredentialOperationResult>
{
    int32_t WINRT_CALL get_Result(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Result, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().Result());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Status(Windows::Security::Credentials::KeyCredentialStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Security::Credentials::KeyCredentialStatus));
            *value = detach_from<Windows::Security::Credentials::KeyCredentialStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Credentials::IKeyCredentialRetrievalResult> : produce_base<D, Windows::Security::Credentials::IKeyCredentialRetrievalResult>
{
    int32_t WINRT_CALL get_Credential(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Credential, WINRT_WRAP(Windows::Security::Credentials::KeyCredential));
            *value = detach_from<Windows::Security::Credentials::KeyCredential>(this->shim().Credential());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Status(Windows::Security::Credentials::KeyCredentialStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Security::Credentials::KeyCredentialStatus));
            *value = detach_from<Windows::Security::Credentials::KeyCredentialStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Credentials::IPasswordCredential> : produce_base<D, Windows::Security::Credentials::IPasswordCredential>
{
    int32_t WINRT_CALL get_Resource(void** resource) noexcept final
    {
        try
        {
            *resource = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Resource, WINRT_WRAP(hstring));
            *resource = detach_from<hstring>(this->shim().Resource());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Resource(void* resource) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Resource, WINRT_WRAP(void), hstring const&);
            this->shim().Resource(*reinterpret_cast<hstring const*>(&resource));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UserName(void** userName) noexcept final
    {
        try
        {
            *userName = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UserName, WINRT_WRAP(hstring));
            *userName = detach_from<hstring>(this->shim().UserName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_UserName(void* userName) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UserName, WINRT_WRAP(void), hstring const&);
            this->shim().UserName(*reinterpret_cast<hstring const*>(&userName));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Password(void** password) noexcept final
    {
        try
        {
            *password = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Password, WINRT_WRAP(hstring));
            *password = detach_from<hstring>(this->shim().Password());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Password(void* password) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Password, WINRT_WRAP(void), hstring const&);
            this->shim().Password(*reinterpret_cast<hstring const*>(&password));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RetrievePassword() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RetrievePassword, WINRT_WRAP(void));
            this->shim().RetrievePassword();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Properties(void** props) noexcept final
    {
        try
        {
            *props = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Properties, WINRT_WRAP(Windows::Foundation::Collections::IPropertySet));
            *props = detach_from<Windows::Foundation::Collections::IPropertySet>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Credentials::IPasswordVault> : produce_base<D, Windows::Security::Credentials::IPasswordVault>
{
    int32_t WINRT_CALL Add(void* credential) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Add, WINRT_WRAP(void), Windows::Security::Credentials::PasswordCredential const&);
            this->shim().Add(*reinterpret_cast<Windows::Security::Credentials::PasswordCredential const*>(&credential));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Remove(void* credential) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Remove, WINRT_WRAP(void), Windows::Security::Credentials::PasswordCredential const&);
            this->shim().Remove(*reinterpret_cast<Windows::Security::Credentials::PasswordCredential const*>(&credential));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Retrieve(void* resource, void* userName, void** credential) noexcept final
    {
        try
        {
            *credential = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Retrieve, WINRT_WRAP(Windows::Security::Credentials::PasswordCredential), hstring const&, hstring const&);
            *credential = detach_from<Windows::Security::Credentials::PasswordCredential>(this->shim().Retrieve(*reinterpret_cast<hstring const*>(&resource), *reinterpret_cast<hstring const*>(&userName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindAllByResource(void* resource, void** credentials) noexcept final
    {
        try
        {
            *credentials = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindAllByResource, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Security::Credentials::PasswordCredential>), hstring const&);
            *credentials = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Security::Credentials::PasswordCredential>>(this->shim().FindAllByResource(*reinterpret_cast<hstring const*>(&resource)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindAllByUserName(void* userName, void** credentials) noexcept final
    {
        try
        {
            *credentials = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindAllByUserName, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Security::Credentials::PasswordCredential>), hstring const&);
            *credentials = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Security::Credentials::PasswordCredential>>(this->shim().FindAllByUserName(*reinterpret_cast<hstring const*>(&userName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RetrieveAll(void** credentials) noexcept final
    {
        try
        {
            *credentials = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RetrieveAll, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Security::Credentials::PasswordCredential>));
            *credentials = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Security::Credentials::PasswordCredential>>(this->shim().RetrieveAll());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Credentials::IWebAccount> : produce_base<D, Windows::Security::Credentials::IWebAccount>
{
    int32_t WINRT_CALL get_WebAccountProvider(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WebAccountProvider, WINRT_WRAP(Windows::Security::Credentials::WebAccountProvider));
            *value = detach_from<Windows::Security::Credentials::WebAccountProvider>(this->shim().WebAccountProvider());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UserName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UserName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().UserName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_State(Windows::Security::Credentials::WebAccountState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(State, WINRT_WRAP(Windows::Security::Credentials::WebAccountState));
            *value = detach_from<Windows::Security::Credentials::WebAccountState>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Credentials::IWebAccount2> : produce_base<D, Windows::Security::Credentials::IWebAccount2>
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

    int32_t WINRT_CALL get_Properties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Properties, WINRT_WRAP(Windows::Foundation::Collections::IMapView<hstring, hstring>));
            *value = detach_from<Windows::Foundation::Collections::IMapView<hstring, hstring>>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetPictureAsync(Windows::Security::Credentials::WebAccountPictureSize desizedSize, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetPictureAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStream>), Windows::Security::Credentials::WebAccountPictureSize const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStream>>(this->shim().GetPictureAsync(*reinterpret_cast<Windows::Security::Credentials::WebAccountPictureSize const*>(&desizedSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SignOutAsync(void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SignOutAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *asyncInfo = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SignOutAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SignOutWithClientIdAsync(void* clientId, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SignOutAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), hstring const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SignOutAsync(*reinterpret_cast<hstring const*>(&clientId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Credentials::IWebAccountFactory> : produce_base<D, Windows::Security::Credentials::IWebAccountFactory>
{
    int32_t WINRT_CALL CreateWebAccount(void* webAccountProvider, void* userName, Windows::Security::Credentials::WebAccountState state, void** instance) noexcept final
    {
        try
        {
            *instance = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWebAccount, WINRT_WRAP(Windows::Security::Credentials::WebAccount), Windows::Security::Credentials::WebAccountProvider const&, hstring const&, Windows::Security::Credentials::WebAccountState const&);
            *instance = detach_from<Windows::Security::Credentials::WebAccount>(this->shim().CreateWebAccount(*reinterpret_cast<Windows::Security::Credentials::WebAccountProvider const*>(&webAccountProvider), *reinterpret_cast<hstring const*>(&userName), *reinterpret_cast<Windows::Security::Credentials::WebAccountState const*>(&state)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Credentials::IWebAccountProvider> : produce_base<D, Windows::Security::Credentials::IWebAccountProvider>
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

    int32_t WINRT_CALL get_IconUri(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IconUri, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().IconUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Credentials::IWebAccountProvider2> : produce_base<D, Windows::Security::Credentials::IWebAccountProvider2>
{
    int32_t WINRT_CALL get_DisplayPurpose(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayPurpose, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DisplayPurpose());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Authority(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Authority, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Authority());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Credentials::IWebAccountProvider3> : produce_base<D, Windows::Security::Credentials::IWebAccountProvider3>
{
    int32_t WINRT_CALL get_User(void** user) noexcept final
    {
        try
        {
            *user = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(User, WINRT_WRAP(Windows::System::User));
            *user = detach_from<Windows::System::User>(this->shim().User());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Credentials::IWebAccountProvider4> : produce_base<D, Windows::Security::Credentials::IWebAccountProvider4>
{
    int32_t WINRT_CALL get_IsSystemProvider(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSystemProvider, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsSystemProvider());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Credentials::IWebAccountProviderFactory> : produce_base<D, Windows::Security::Credentials::IWebAccountProviderFactory>
{
    int32_t WINRT_CALL CreateWebAccountProvider(void* id, void* displayName, void* iconUri, void** instance) noexcept final
    {
        try
        {
            *instance = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWebAccountProvider, WINRT_WRAP(Windows::Security::Credentials::WebAccountProvider), hstring const&, hstring const&, Windows::Foundation::Uri const&);
            *instance = detach_from<Windows::Security::Credentials::WebAccountProvider>(this->shim().CreateWebAccountProvider(*reinterpret_cast<hstring const*>(&id), *reinterpret_cast<hstring const*>(&displayName), *reinterpret_cast<Windows::Foundation::Uri const*>(&iconUri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Security::Credentials {

inline Windows::Foundation::IAsyncOperation<bool> KeyCredentialManager::IsSupportedAsync()
{
    return impl::call_factory<KeyCredentialManager, Windows::Security::Credentials::IKeyCredentialManagerStatics>([&](auto&& f) { return f.IsSupportedAsync(); });
}

inline Windows::Foundation::IAsyncAction KeyCredentialManager::RenewAttestationAsync()
{
    return impl::call_factory<KeyCredentialManager, Windows::Security::Credentials::IKeyCredentialManagerStatics>([&](auto&& f) { return f.RenewAttestationAsync(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::KeyCredentialRetrievalResult> KeyCredentialManager::RequestCreateAsync(param::hstring const& name, Windows::Security::Credentials::KeyCredentialCreationOption const& option)
{
    return impl::call_factory<KeyCredentialManager, Windows::Security::Credentials::IKeyCredentialManagerStatics>([&](auto&& f) { return f.RequestCreateAsync(name, option); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::KeyCredentialRetrievalResult> KeyCredentialManager::OpenAsync(param::hstring const& name)
{
    return impl::call_factory<KeyCredentialManager, Windows::Security::Credentials::IKeyCredentialManagerStatics>([&](auto&& f) { return f.OpenAsync(name); });
}

inline Windows::Foundation::IAsyncAction KeyCredentialManager::DeleteAsync(param::hstring const& name)
{
    return impl::call_factory<KeyCredentialManager, Windows::Security::Credentials::IKeyCredentialManagerStatics>([&](auto&& f) { return f.DeleteAsync(name); });
}

inline PasswordCredential::PasswordCredential() :
    PasswordCredential(impl::call_factory<PasswordCredential>([](auto&& f) { return f.template ActivateInstance<PasswordCredential>(); }))
{}

inline PasswordCredential::PasswordCredential(param::hstring const& resource, param::hstring const& userName, param::hstring const& password) :
    PasswordCredential(impl::call_factory<PasswordCredential, Windows::Security::Credentials::ICredentialFactory>([&](auto&& f) { return f.CreatePasswordCredential(resource, userName, password); }))
{}

inline PasswordCredentialPropertyStore::PasswordCredentialPropertyStore() :
    PasswordCredentialPropertyStore(impl::call_factory<PasswordCredentialPropertyStore>([](auto&& f) { return f.template ActivateInstance<PasswordCredentialPropertyStore>(); }))
{}

inline PasswordVault::PasswordVault() :
    PasswordVault(impl::call_factory<PasswordVault>([](auto&& f) { return f.template ActivateInstance<PasswordVault>(); }))
{}

inline WebAccount::WebAccount(Windows::Security::Credentials::WebAccountProvider const& webAccountProvider, param::hstring const& userName, Windows::Security::Credentials::WebAccountState const& state) :
    WebAccount(impl::call_factory<WebAccount, Windows::Security::Credentials::IWebAccountFactory>([&](auto&& f) { return f.CreateWebAccount(webAccountProvider, userName, state); }))
{}

inline WebAccountProvider::WebAccountProvider(param::hstring const& id, param::hstring const& displayName, Windows::Foundation::Uri const& iconUri) :
    WebAccountProvider(impl::call_factory<WebAccountProvider, Windows::Security::Credentials::IWebAccountProviderFactory>([&](auto&& f) { return f.CreateWebAccountProvider(id, displayName, iconUri); }))
{}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Security::Credentials::ICredentialFactory> : winrt::impl::hash_base<winrt::Windows::Security::Credentials::ICredentialFactory> {};
template<> struct hash<winrt::Windows::Security::Credentials::IKeyCredential> : winrt::impl::hash_base<winrt::Windows::Security::Credentials::IKeyCredential> {};
template<> struct hash<winrt::Windows::Security::Credentials::IKeyCredentialAttestationResult> : winrt::impl::hash_base<winrt::Windows::Security::Credentials::IKeyCredentialAttestationResult> {};
template<> struct hash<winrt::Windows::Security::Credentials::IKeyCredentialManagerStatics> : winrt::impl::hash_base<winrt::Windows::Security::Credentials::IKeyCredentialManagerStatics> {};
template<> struct hash<winrt::Windows::Security::Credentials::IKeyCredentialOperationResult> : winrt::impl::hash_base<winrt::Windows::Security::Credentials::IKeyCredentialOperationResult> {};
template<> struct hash<winrt::Windows::Security::Credentials::IKeyCredentialRetrievalResult> : winrt::impl::hash_base<winrt::Windows::Security::Credentials::IKeyCredentialRetrievalResult> {};
template<> struct hash<winrt::Windows::Security::Credentials::IPasswordCredential> : winrt::impl::hash_base<winrt::Windows::Security::Credentials::IPasswordCredential> {};
template<> struct hash<winrt::Windows::Security::Credentials::IPasswordVault> : winrt::impl::hash_base<winrt::Windows::Security::Credentials::IPasswordVault> {};
template<> struct hash<winrt::Windows::Security::Credentials::IWebAccount> : winrt::impl::hash_base<winrt::Windows::Security::Credentials::IWebAccount> {};
template<> struct hash<winrt::Windows::Security::Credentials::IWebAccount2> : winrt::impl::hash_base<winrt::Windows::Security::Credentials::IWebAccount2> {};
template<> struct hash<winrt::Windows::Security::Credentials::IWebAccountFactory> : winrt::impl::hash_base<winrt::Windows::Security::Credentials::IWebAccountFactory> {};
template<> struct hash<winrt::Windows::Security::Credentials::IWebAccountProvider> : winrt::impl::hash_base<winrt::Windows::Security::Credentials::IWebAccountProvider> {};
template<> struct hash<winrt::Windows::Security::Credentials::IWebAccountProvider2> : winrt::impl::hash_base<winrt::Windows::Security::Credentials::IWebAccountProvider2> {};
template<> struct hash<winrt::Windows::Security::Credentials::IWebAccountProvider3> : winrt::impl::hash_base<winrt::Windows::Security::Credentials::IWebAccountProvider3> {};
template<> struct hash<winrt::Windows::Security::Credentials::IWebAccountProvider4> : winrt::impl::hash_base<winrt::Windows::Security::Credentials::IWebAccountProvider4> {};
template<> struct hash<winrt::Windows::Security::Credentials::IWebAccountProviderFactory> : winrt::impl::hash_base<winrt::Windows::Security::Credentials::IWebAccountProviderFactory> {};
template<> struct hash<winrt::Windows::Security::Credentials::KeyCredential> : winrt::impl::hash_base<winrt::Windows::Security::Credentials::KeyCredential> {};
template<> struct hash<winrt::Windows::Security::Credentials::KeyCredentialAttestationResult> : winrt::impl::hash_base<winrt::Windows::Security::Credentials::KeyCredentialAttestationResult> {};
template<> struct hash<winrt::Windows::Security::Credentials::KeyCredentialManager> : winrt::impl::hash_base<winrt::Windows::Security::Credentials::KeyCredentialManager> {};
template<> struct hash<winrt::Windows::Security::Credentials::KeyCredentialOperationResult> : winrt::impl::hash_base<winrt::Windows::Security::Credentials::KeyCredentialOperationResult> {};
template<> struct hash<winrt::Windows::Security::Credentials::KeyCredentialRetrievalResult> : winrt::impl::hash_base<winrt::Windows::Security::Credentials::KeyCredentialRetrievalResult> {};
template<> struct hash<winrt::Windows::Security::Credentials::PasswordCredential> : winrt::impl::hash_base<winrt::Windows::Security::Credentials::PasswordCredential> {};
template<> struct hash<winrt::Windows::Security::Credentials::PasswordCredentialPropertyStore> : winrt::impl::hash_base<winrt::Windows::Security::Credentials::PasswordCredentialPropertyStore> {};
template<> struct hash<winrt::Windows::Security::Credentials::PasswordVault> : winrt::impl::hash_base<winrt::Windows::Security::Credentials::PasswordVault> {};
template<> struct hash<winrt::Windows::Security::Credentials::WebAccount> : winrt::impl::hash_base<winrt::Windows::Security::Credentials::WebAccount> {};
template<> struct hash<winrt::Windows::Security::Credentials::WebAccountProvider> : winrt::impl::hash_base<winrt::Windows::Security::Credentials::WebAccountProvider> {};

}
