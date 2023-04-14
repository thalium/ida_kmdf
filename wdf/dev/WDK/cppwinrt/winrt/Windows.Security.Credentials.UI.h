// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Security.Credentials.UI.2.h"
#include "winrt/Windows.Security.Credentials.h"

namespace winrt::impl {

template <typename D> void consume_Windows_Security_Credentials_UI_ICredentialPickerOptions<D>::Caption(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::UI::ICredentialPickerOptions)->put_Caption(get_abi(value)));
}

template <typename D> hstring consume_Windows_Security_Credentials_UI_ICredentialPickerOptions<D>::Caption() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::UI::ICredentialPickerOptions)->get_Caption(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Security_Credentials_UI_ICredentialPickerOptions<D>::Message(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::UI::ICredentialPickerOptions)->put_Message(get_abi(value)));
}

template <typename D> hstring consume_Windows_Security_Credentials_UI_ICredentialPickerOptions<D>::Message() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::UI::ICredentialPickerOptions)->get_Message(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Security_Credentials_UI_ICredentialPickerOptions<D>::ErrorCode(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::UI::ICredentialPickerOptions)->put_ErrorCode(value));
}

template <typename D> uint32_t consume_Windows_Security_Credentials_UI_ICredentialPickerOptions<D>::ErrorCode() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::UI::ICredentialPickerOptions)->get_ErrorCode(&value));
    return value;
}

template <typename D> void consume_Windows_Security_Credentials_UI_ICredentialPickerOptions<D>::TargetName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::UI::ICredentialPickerOptions)->put_TargetName(get_abi(value)));
}

template <typename D> hstring consume_Windows_Security_Credentials_UI_ICredentialPickerOptions<D>::TargetName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::UI::ICredentialPickerOptions)->get_TargetName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Security_Credentials_UI_ICredentialPickerOptions<D>::AuthenticationProtocol(Windows::Security::Credentials::UI::AuthenticationProtocol const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::UI::ICredentialPickerOptions)->put_AuthenticationProtocol(get_abi(value)));
}

template <typename D> Windows::Security::Credentials::UI::AuthenticationProtocol consume_Windows_Security_Credentials_UI_ICredentialPickerOptions<D>::AuthenticationProtocol() const
{
    Windows::Security::Credentials::UI::AuthenticationProtocol value{};
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::UI::ICredentialPickerOptions)->get_AuthenticationProtocol(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Security_Credentials_UI_ICredentialPickerOptions<D>::CustomAuthenticationProtocol(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::UI::ICredentialPickerOptions)->put_CustomAuthenticationProtocol(get_abi(value)));
}

template <typename D> hstring consume_Windows_Security_Credentials_UI_ICredentialPickerOptions<D>::CustomAuthenticationProtocol() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::UI::ICredentialPickerOptions)->get_CustomAuthenticationProtocol(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Security_Credentials_UI_ICredentialPickerOptions<D>::PreviousCredential(Windows::Storage::Streams::IBuffer const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::UI::ICredentialPickerOptions)->put_PreviousCredential(get_abi(value)));
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Security_Credentials_UI_ICredentialPickerOptions<D>::PreviousCredential() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::UI::ICredentialPickerOptions)->get_PreviousCredential(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Security_Credentials_UI_ICredentialPickerOptions<D>::AlwaysDisplayDialog(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::UI::ICredentialPickerOptions)->put_AlwaysDisplayDialog(value));
}

template <typename D> bool consume_Windows_Security_Credentials_UI_ICredentialPickerOptions<D>::AlwaysDisplayDialog() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::UI::ICredentialPickerOptions)->get_AlwaysDisplayDialog(&value));
    return value;
}

template <typename D> void consume_Windows_Security_Credentials_UI_ICredentialPickerOptions<D>::CallerSavesCredential(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::UI::ICredentialPickerOptions)->put_CallerSavesCredential(value));
}

template <typename D> bool consume_Windows_Security_Credentials_UI_ICredentialPickerOptions<D>::CallerSavesCredential() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::UI::ICredentialPickerOptions)->get_CallerSavesCredential(&value));
    return value;
}

template <typename D> void consume_Windows_Security_Credentials_UI_ICredentialPickerOptions<D>::CredentialSaveOption(Windows::Security::Credentials::UI::CredentialSaveOption const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::UI::ICredentialPickerOptions)->put_CredentialSaveOption(get_abi(value)));
}

template <typename D> Windows::Security::Credentials::UI::CredentialSaveOption consume_Windows_Security_Credentials_UI_ICredentialPickerOptions<D>::CredentialSaveOption() const
{
    Windows::Security::Credentials::UI::CredentialSaveOption value{};
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::UI::ICredentialPickerOptions)->get_CredentialSaveOption(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Security_Credentials_UI_ICredentialPickerResults<D>::ErrorCode() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::UI::ICredentialPickerResults)->get_ErrorCode(&value));
    return value;
}

template <typename D> Windows::Security::Credentials::UI::CredentialSaveOption consume_Windows_Security_Credentials_UI_ICredentialPickerResults<D>::CredentialSaveOption() const
{
    Windows::Security::Credentials::UI::CredentialSaveOption value{};
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::UI::ICredentialPickerResults)->get_CredentialSaveOption(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Security_Credentials_UI_ICredentialPickerResults<D>::CredentialSaved() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::UI::ICredentialPickerResults)->get_CredentialSaved(&value));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Security_Credentials_UI_ICredentialPickerResults<D>::Credential() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::UI::ICredentialPickerResults)->get_Credential(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Credentials_UI_ICredentialPickerResults<D>::CredentialDomainName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::UI::ICredentialPickerResults)->get_CredentialDomainName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Credentials_UI_ICredentialPickerResults<D>::CredentialUserName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::UI::ICredentialPickerResults)->get_CredentialUserName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Credentials_UI_ICredentialPickerResults<D>::CredentialPassword() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::UI::ICredentialPickerResults)->get_CredentialPassword(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::UI::CredentialPickerResults> consume_Windows_Security_Credentials_UI_ICredentialPickerStatics<D>::PickAsync(Windows::Security::Credentials::UI::CredentialPickerOptions const& options) const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::UI::CredentialPickerResults> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::UI::ICredentialPickerStatics)->PickWithOptionsAsync(get_abi(options), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::UI::CredentialPickerResults> consume_Windows_Security_Credentials_UI_ICredentialPickerStatics<D>::PickAsync(param::hstring const& targetName, param::hstring const& message) const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::UI::CredentialPickerResults> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::UI::ICredentialPickerStatics)->PickWithMessageAsync(get_abi(targetName), get_abi(message), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::UI::CredentialPickerResults> consume_Windows_Security_Credentials_UI_ICredentialPickerStatics<D>::PickAsync(param::hstring const& targetName, param::hstring const& message, param::hstring const& caption) const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::UI::CredentialPickerResults> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::UI::ICredentialPickerStatics)->PickWithCaptionAsync(get_abi(targetName), get_abi(message), get_abi(caption), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::UI::UserConsentVerifierAvailability> consume_Windows_Security_Credentials_UI_IUserConsentVerifierStatics<D>::CheckAvailabilityAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::UI::UserConsentVerifierAvailability> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::UI::IUserConsentVerifierStatics)->CheckAvailabilityAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::UI::UserConsentVerificationResult> consume_Windows_Security_Credentials_UI_IUserConsentVerifierStatics<D>::RequestVerificationAsync(param::hstring const& message) const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::UI::UserConsentVerificationResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Credentials::UI::IUserConsentVerifierStatics)->RequestVerificationAsync(get_abi(message), put_abi(result)));
    return result;
}

template <typename D>
struct produce<D, Windows::Security::Credentials::UI::ICredentialPickerOptions> : produce_base<D, Windows::Security::Credentials::UI::ICredentialPickerOptions>
{
    int32_t WINRT_CALL put_Caption(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Caption, WINRT_WRAP(void), hstring const&);
            this->shim().Caption(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Caption(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Caption, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Caption());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Message(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Message, WINRT_WRAP(void), hstring const&);
            this->shim().Message(*reinterpret_cast<hstring const*>(&value));
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
            WINRT_ASSERT_DECLARATION(Message, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Message());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ErrorCode(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ErrorCode, WINRT_WRAP(void), uint32_t);
            this->shim().ErrorCode(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ErrorCode(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ErrorCode, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().ErrorCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TargetName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetName, WINRT_WRAP(void), hstring const&);
            this->shim().TargetName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TargetName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().TargetName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AuthenticationProtocol(Windows::Security::Credentials::UI::AuthenticationProtocol value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AuthenticationProtocol, WINRT_WRAP(void), Windows::Security::Credentials::UI::AuthenticationProtocol const&);
            this->shim().AuthenticationProtocol(*reinterpret_cast<Windows::Security::Credentials::UI::AuthenticationProtocol const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AuthenticationProtocol(Windows::Security::Credentials::UI::AuthenticationProtocol* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AuthenticationProtocol, WINRT_WRAP(Windows::Security::Credentials::UI::AuthenticationProtocol));
            *value = detach_from<Windows::Security::Credentials::UI::AuthenticationProtocol>(this->shim().AuthenticationProtocol());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CustomAuthenticationProtocol(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CustomAuthenticationProtocol, WINRT_WRAP(void), hstring const&);
            this->shim().CustomAuthenticationProtocol(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CustomAuthenticationProtocol(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CustomAuthenticationProtocol, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().CustomAuthenticationProtocol());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PreviousCredential(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PreviousCredential, WINRT_WRAP(void), Windows::Storage::Streams::IBuffer const&);
            this->shim().PreviousCredential(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PreviousCredential(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PreviousCredential, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().PreviousCredential());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AlwaysDisplayDialog(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AlwaysDisplayDialog, WINRT_WRAP(void), bool);
            this->shim().AlwaysDisplayDialog(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AlwaysDisplayDialog(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AlwaysDisplayDialog, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AlwaysDisplayDialog());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CallerSavesCredential(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CallerSavesCredential, WINRT_WRAP(void), bool);
            this->shim().CallerSavesCredential(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CallerSavesCredential(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CallerSavesCredential, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CallerSavesCredential());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CredentialSaveOption(Windows::Security::Credentials::UI::CredentialSaveOption value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CredentialSaveOption, WINRT_WRAP(void), Windows::Security::Credentials::UI::CredentialSaveOption const&);
            this->shim().CredentialSaveOption(*reinterpret_cast<Windows::Security::Credentials::UI::CredentialSaveOption const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CredentialSaveOption(Windows::Security::Credentials::UI::CredentialSaveOption* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CredentialSaveOption, WINRT_WRAP(Windows::Security::Credentials::UI::CredentialSaveOption));
            *value = detach_from<Windows::Security::Credentials::UI::CredentialSaveOption>(this->shim().CredentialSaveOption());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Credentials::UI::ICredentialPickerResults> : produce_base<D, Windows::Security::Credentials::UI::ICredentialPickerResults>
{
    int32_t WINRT_CALL get_ErrorCode(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ErrorCode, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().ErrorCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CredentialSaveOption(Windows::Security::Credentials::UI::CredentialSaveOption* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CredentialSaveOption, WINRT_WRAP(Windows::Security::Credentials::UI::CredentialSaveOption));
            *value = detach_from<Windows::Security::Credentials::UI::CredentialSaveOption>(this->shim().CredentialSaveOption());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CredentialSaved(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CredentialSaved, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CredentialSaved());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Credential(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Credential, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().Credential());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CredentialDomainName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CredentialDomainName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().CredentialDomainName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CredentialUserName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CredentialUserName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().CredentialUserName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CredentialPassword(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CredentialPassword, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().CredentialPassword());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Credentials::UI::ICredentialPickerStatics> : produce_base<D, Windows::Security::Credentials::UI::ICredentialPickerStatics>
{
    int32_t WINRT_CALL PickWithOptionsAsync(void* options, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PickAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::UI::CredentialPickerResults>), Windows::Security::Credentials::UI::CredentialPickerOptions const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::UI::CredentialPickerResults>>(this->shim().PickAsync(*reinterpret_cast<Windows::Security::Credentials::UI::CredentialPickerOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PickWithMessageAsync(void* targetName, void* message, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PickAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::UI::CredentialPickerResults>), hstring const, hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::UI::CredentialPickerResults>>(this->shim().PickAsync(*reinterpret_cast<hstring const*>(&targetName), *reinterpret_cast<hstring const*>(&message)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PickWithCaptionAsync(void* targetName, void* message, void* caption, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PickAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::UI::CredentialPickerResults>), hstring const, hstring const, hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::UI::CredentialPickerResults>>(this->shim().PickAsync(*reinterpret_cast<hstring const*>(&targetName), *reinterpret_cast<hstring const*>(&message), *reinterpret_cast<hstring const*>(&caption)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Credentials::UI::IUserConsentVerifierStatics> : produce_base<D, Windows::Security::Credentials::UI::IUserConsentVerifierStatics>
{
    int32_t WINRT_CALL CheckAvailabilityAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CheckAvailabilityAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::UI::UserConsentVerifierAvailability>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::UI::UserConsentVerifierAvailability>>(this->shim().CheckAvailabilityAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestVerificationAsync(void* message, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestVerificationAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::UI::UserConsentVerificationResult>), hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::UI::UserConsentVerificationResult>>(this->shim().RequestVerificationAsync(*reinterpret_cast<hstring const*>(&message)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Security::Credentials::UI {

inline Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::UI::CredentialPickerResults> CredentialPicker::PickAsync(Windows::Security::Credentials::UI::CredentialPickerOptions const& options)
{
    return impl::call_factory<CredentialPicker, Windows::Security::Credentials::UI::ICredentialPickerStatics>([&](auto&& f) { return f.PickAsync(options); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::UI::CredentialPickerResults> CredentialPicker::PickAsync(param::hstring const& targetName, param::hstring const& message)
{
    return impl::call_factory<CredentialPicker, Windows::Security::Credentials::UI::ICredentialPickerStatics>([&](auto&& f) { return f.PickAsync(targetName, message); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::UI::CredentialPickerResults> CredentialPicker::PickAsync(param::hstring const& targetName, param::hstring const& message, param::hstring const& caption)
{
    return impl::call_factory<CredentialPicker, Windows::Security::Credentials::UI::ICredentialPickerStatics>([&](auto&& f) { return f.PickAsync(targetName, message, caption); });
}

inline CredentialPickerOptions::CredentialPickerOptions() :
    CredentialPickerOptions(impl::call_factory<CredentialPickerOptions>([](auto&& f) { return f.template ActivateInstance<CredentialPickerOptions>(); }))
{}

inline Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::UI::UserConsentVerifierAvailability> UserConsentVerifier::CheckAvailabilityAsync()
{
    return impl::call_factory<UserConsentVerifier, Windows::Security::Credentials::UI::IUserConsentVerifierStatics>([&](auto&& f) { return f.CheckAvailabilityAsync(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::UI::UserConsentVerificationResult> UserConsentVerifier::RequestVerificationAsync(param::hstring const& message)
{
    return impl::call_factory<UserConsentVerifier, Windows::Security::Credentials::UI::IUserConsentVerifierStatics>([&](auto&& f) { return f.RequestVerificationAsync(message); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Security::Credentials::UI::ICredentialPickerOptions> : winrt::impl::hash_base<winrt::Windows::Security::Credentials::UI::ICredentialPickerOptions> {};
template<> struct hash<winrt::Windows::Security::Credentials::UI::ICredentialPickerResults> : winrt::impl::hash_base<winrt::Windows::Security::Credentials::UI::ICredentialPickerResults> {};
template<> struct hash<winrt::Windows::Security::Credentials::UI::ICredentialPickerStatics> : winrt::impl::hash_base<winrt::Windows::Security::Credentials::UI::ICredentialPickerStatics> {};
template<> struct hash<winrt::Windows::Security::Credentials::UI::IUserConsentVerifierStatics> : winrt::impl::hash_base<winrt::Windows::Security::Credentials::UI::IUserConsentVerifierStatics> {};
template<> struct hash<winrt::Windows::Security::Credentials::UI::CredentialPicker> : winrt::impl::hash_base<winrt::Windows::Security::Credentials::UI::CredentialPicker> {};
template<> struct hash<winrt::Windows::Security::Credentials::UI::CredentialPickerOptions> : winrt::impl::hash_base<winrt::Windows::Security::Credentials::UI::CredentialPickerOptions> {};
template<> struct hash<winrt::Windows::Security::Credentials::UI::CredentialPickerResults> : winrt::impl::hash_base<winrt::Windows::Security::Credentials::UI::CredentialPickerResults> {};
template<> struct hash<winrt::Windows::Security::Credentials::UI::UserConsentVerifier> : winrt::impl::hash_base<winrt::Windows::Security::Credentials::UI::UserConsentVerifier> {};

}
