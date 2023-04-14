// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.Security.Authentication.OnlineId.2.h"

namespace winrt::impl {

template <typename D> Windows::Security::Authentication::OnlineId::UserAuthenticationOperation consume_Windows_Security_Authentication_OnlineId_IOnlineIdAuthenticator<D>::AuthenticateUserAsync(Windows::Security::Authentication::OnlineId::OnlineIdServiceTicketRequest const& request) const
{
    Windows::Security::Authentication::OnlineId::UserAuthenticationOperation authenticationOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::OnlineId::IOnlineIdAuthenticator)->AuthenticateUserAsync(get_abi(request), put_abi(authenticationOperation)));
    return authenticationOperation;
}

template <typename D> Windows::Security::Authentication::OnlineId::UserAuthenticationOperation consume_Windows_Security_Authentication_OnlineId_IOnlineIdAuthenticator<D>::AuthenticateUserAsync(param::async_iterable<Windows::Security::Authentication::OnlineId::OnlineIdServiceTicketRequest> const& requests, Windows::Security::Authentication::OnlineId::CredentialPromptType const& credentialPromptType) const
{
    Windows::Security::Authentication::OnlineId::UserAuthenticationOperation authenticationOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::OnlineId::IOnlineIdAuthenticator)->AuthenticateUserAsyncAdvanced(get_abi(requests), get_abi(credentialPromptType), put_abi(authenticationOperation)));
    return authenticationOperation;
}

template <typename D> Windows::Security::Authentication::OnlineId::SignOutUserOperation consume_Windows_Security_Authentication_OnlineId_IOnlineIdAuthenticator<D>::SignOutUserAsync() const
{
    Windows::Security::Authentication::OnlineId::SignOutUserOperation signOutUserOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::OnlineId::IOnlineIdAuthenticator)->SignOutUserAsync(put_abi(signOutUserOperation)));
    return signOutUserOperation;
}

template <typename D> void consume_Windows_Security_Authentication_OnlineId_IOnlineIdAuthenticator<D>::ApplicationId(winrt::guid const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::OnlineId::IOnlineIdAuthenticator)->put_ApplicationId(get_abi(value)));
}

template <typename D> winrt::guid consume_Windows_Security_Authentication_OnlineId_IOnlineIdAuthenticator<D>::ApplicationId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::OnlineId::IOnlineIdAuthenticator)->get_ApplicationId(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Security_Authentication_OnlineId_IOnlineIdAuthenticator<D>::CanSignOut() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::OnlineId::IOnlineIdAuthenticator)->get_CanSignOut(&value));
    return value;
}

template <typename D> hstring consume_Windows_Security_Authentication_OnlineId_IOnlineIdAuthenticator<D>::AuthenticatedSafeCustomerId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::OnlineId::IOnlineIdAuthenticator)->get_AuthenticatedSafeCustomerId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Authentication_OnlineId_IOnlineIdServiceTicket<D>::Value() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::OnlineId::IOnlineIdServiceTicket)->get_Value(put_abi(value)));
    return value;
}

template <typename D> Windows::Security::Authentication::OnlineId::OnlineIdServiceTicketRequest consume_Windows_Security_Authentication_OnlineId_IOnlineIdServiceTicket<D>::Request() const
{
    Windows::Security::Authentication::OnlineId::OnlineIdServiceTicketRequest value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::OnlineId::IOnlineIdServiceTicket)->get_Request(put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_Security_Authentication_OnlineId_IOnlineIdServiceTicket<D>::ErrorCode() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::OnlineId::IOnlineIdServiceTicket)->get_ErrorCode(&value));
    return value;
}

template <typename D> hstring consume_Windows_Security_Authentication_OnlineId_IOnlineIdServiceTicketRequest<D>::Service() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::OnlineId::IOnlineIdServiceTicketRequest)->get_Service(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Authentication_OnlineId_IOnlineIdServiceTicketRequest<D>::Policy() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::OnlineId::IOnlineIdServiceTicketRequest)->get_Policy(put_abi(value)));
    return value;
}

template <typename D> Windows::Security::Authentication::OnlineId::OnlineIdServiceTicketRequest consume_Windows_Security_Authentication_OnlineId_IOnlineIdServiceTicketRequestFactory<D>::CreateOnlineIdServiceTicketRequest(param::hstring const& service, param::hstring const& policy) const
{
    Windows::Security::Authentication::OnlineId::OnlineIdServiceTicketRequest onlineIdServiceTicketRequest{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::OnlineId::IOnlineIdServiceTicketRequestFactory)->CreateOnlineIdServiceTicketRequest(get_abi(service), get_abi(policy), put_abi(onlineIdServiceTicketRequest)));
    return onlineIdServiceTicketRequest;
}

template <typename D> Windows::Security::Authentication::OnlineId::OnlineIdServiceTicketRequest consume_Windows_Security_Authentication_OnlineId_IOnlineIdServiceTicketRequestFactory<D>::CreateOnlineIdServiceTicketRequestAdvanced(param::hstring const& service) const
{
    Windows::Security::Authentication::OnlineId::OnlineIdServiceTicketRequest onlineIdServiceTicketRequest{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::OnlineId::IOnlineIdServiceTicketRequestFactory)->CreateOnlineIdServiceTicketRequestAdvanced(get_abi(service), put_abi(onlineIdServiceTicketRequest)));
    return onlineIdServiceTicketRequest;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::OnlineId::OnlineIdSystemTicketResult> consume_Windows_Security_Authentication_OnlineId_IOnlineIdSystemAuthenticatorForUser<D>::GetTicketAsync(Windows::Security::Authentication::OnlineId::OnlineIdServiceTicketRequest const& request) const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::OnlineId::OnlineIdSystemTicketResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::OnlineId::IOnlineIdSystemAuthenticatorForUser)->GetTicketAsync(get_abi(request), put_abi(operation)));
    return operation;
}

template <typename D> void consume_Windows_Security_Authentication_OnlineId_IOnlineIdSystemAuthenticatorForUser<D>::ApplicationId(winrt::guid const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::OnlineId::IOnlineIdSystemAuthenticatorForUser)->put_ApplicationId(get_abi(value)));
}

template <typename D> winrt::guid consume_Windows_Security_Authentication_OnlineId_IOnlineIdSystemAuthenticatorForUser<D>::ApplicationId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::OnlineId::IOnlineIdSystemAuthenticatorForUser)->get_ApplicationId(put_abi(value)));
    return value;
}

template <typename D> Windows::System::User consume_Windows_Security_Authentication_OnlineId_IOnlineIdSystemAuthenticatorForUser<D>::User() const
{
    Windows::System::User user{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::OnlineId::IOnlineIdSystemAuthenticatorForUser)->get_User(put_abi(user)));
    return user;
}

template <typename D> Windows::Security::Authentication::OnlineId::OnlineIdSystemAuthenticatorForUser consume_Windows_Security_Authentication_OnlineId_IOnlineIdSystemAuthenticatorStatics<D>::Default() const
{
    Windows::Security::Authentication::OnlineId::OnlineIdSystemAuthenticatorForUser value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::OnlineId::IOnlineIdSystemAuthenticatorStatics)->get_Default(put_abi(value)));
    return value;
}

template <typename D> Windows::Security::Authentication::OnlineId::OnlineIdSystemAuthenticatorForUser consume_Windows_Security_Authentication_OnlineId_IOnlineIdSystemAuthenticatorStatics<D>::GetForUser(Windows::System::User const& user) const
{
    Windows::Security::Authentication::OnlineId::OnlineIdSystemAuthenticatorForUser value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::OnlineId::IOnlineIdSystemAuthenticatorStatics)->GetForUser(get_abi(user), put_abi(value)));
    return value;
}

template <typename D> Windows::Security::Authentication::OnlineId::OnlineIdServiceTicket consume_Windows_Security_Authentication_OnlineId_IOnlineIdSystemIdentity<D>::Ticket() const
{
    Windows::Security::Authentication::OnlineId::OnlineIdServiceTicket value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::OnlineId::IOnlineIdSystemIdentity)->get_Ticket(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Authentication_OnlineId_IOnlineIdSystemIdentity<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::OnlineId::IOnlineIdSystemIdentity)->get_Id(put_abi(value)));
    return value;
}

template <typename D> Windows::Security::Authentication::OnlineId::OnlineIdSystemIdentity consume_Windows_Security_Authentication_OnlineId_IOnlineIdSystemTicketResult<D>::Identity() const
{
    Windows::Security::Authentication::OnlineId::OnlineIdSystemIdentity value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::OnlineId::IOnlineIdSystemTicketResult)->get_Identity(put_abi(value)));
    return value;
}

template <typename D> Windows::Security::Authentication::OnlineId::OnlineIdSystemTicketStatus consume_Windows_Security_Authentication_OnlineId_IOnlineIdSystemTicketResult<D>::Status() const
{
    Windows::Security::Authentication::OnlineId::OnlineIdSystemTicketStatus value{};
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::OnlineId::IOnlineIdSystemTicketResult)->get_Status(put_abi(value)));
    return value;
}

template <typename D> winrt::hresult consume_Windows_Security_Authentication_OnlineId_IOnlineIdSystemTicketResult<D>::ExtendedError() const
{
    winrt::hresult value{};
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::OnlineId::IOnlineIdSystemTicketResult)->get_ExtendedError(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Security::Authentication::OnlineId::OnlineIdServiceTicket> consume_Windows_Security_Authentication_OnlineId_IUserIdentity<D>::Tickets() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Security::Authentication::OnlineId::OnlineIdServiceTicket> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::OnlineId::IUserIdentity)->get_Tickets(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Authentication_OnlineId_IUserIdentity<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::OnlineId::IUserIdentity)->get_Id(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Authentication_OnlineId_IUserIdentity<D>::SafeCustomerId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::OnlineId::IUserIdentity)->get_SafeCustomerId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Authentication_OnlineId_IUserIdentity<D>::SignInName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::OnlineId::IUserIdentity)->get_SignInName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Authentication_OnlineId_IUserIdentity<D>::FirstName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::OnlineId::IUserIdentity)->get_FirstName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Authentication_OnlineId_IUserIdentity<D>::LastName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::OnlineId::IUserIdentity)->get_LastName(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Security_Authentication_OnlineId_IUserIdentity<D>::IsBetaAccount() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::OnlineId::IUserIdentity)->get_IsBetaAccount(&value));
    return value;
}

template <typename D> bool consume_Windows_Security_Authentication_OnlineId_IUserIdentity<D>::IsConfirmedPC() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::OnlineId::IUserIdentity)->get_IsConfirmedPC(&value));
    return value;
}

template <typename D>
struct produce<D, Windows::Security::Authentication::OnlineId::IOnlineIdAuthenticator> : produce_base<D, Windows::Security::Authentication::OnlineId::IOnlineIdAuthenticator>
{
    int32_t WINRT_CALL AuthenticateUserAsync(void* request, void** authenticationOperation) noexcept final
    {
        try
        {
            *authenticationOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AuthenticateUserAsync, WINRT_WRAP(Windows::Security::Authentication::OnlineId::UserAuthenticationOperation), Windows::Security::Authentication::OnlineId::OnlineIdServiceTicketRequest const);
            *authenticationOperation = detach_from<Windows::Security::Authentication::OnlineId::UserAuthenticationOperation>(this->shim().AuthenticateUserAsync(*reinterpret_cast<Windows::Security::Authentication::OnlineId::OnlineIdServiceTicketRequest const*>(&request)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AuthenticateUserAsyncAdvanced(void* requests, Windows::Security::Authentication::OnlineId::CredentialPromptType credentialPromptType, void** authenticationOperation) noexcept final
    {
        try
        {
            *authenticationOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AuthenticateUserAsync, WINRT_WRAP(Windows::Security::Authentication::OnlineId::UserAuthenticationOperation), Windows::Foundation::Collections::IIterable<Windows::Security::Authentication::OnlineId::OnlineIdServiceTicketRequest> const, Windows::Security::Authentication::OnlineId::CredentialPromptType const);
            *authenticationOperation = detach_from<Windows::Security::Authentication::OnlineId::UserAuthenticationOperation>(this->shim().AuthenticateUserAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Security::Authentication::OnlineId::OnlineIdServiceTicketRequest> const*>(&requests), *reinterpret_cast<Windows::Security::Authentication::OnlineId::CredentialPromptType const*>(&credentialPromptType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SignOutUserAsync(void** signOutUserOperation) noexcept final
    {
        try
        {
            *signOutUserOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SignOutUserAsync, WINRT_WRAP(Windows::Security::Authentication::OnlineId::SignOutUserOperation));
            *signOutUserOperation = detach_from<Windows::Security::Authentication::OnlineId::SignOutUserOperation>(this->shim().SignOutUserAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ApplicationId(winrt::guid value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ApplicationId, WINRT_WRAP(void), winrt::guid const&);
            this->shim().ApplicationId(*reinterpret_cast<winrt::guid const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ApplicationId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ApplicationId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().ApplicationId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanSignOut(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanSignOut, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanSignOut());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AuthenticatedSafeCustomerId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AuthenticatedSafeCustomerId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AuthenticatedSafeCustomerId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Authentication::OnlineId::IOnlineIdServiceTicket> : produce_base<D, Windows::Security::Authentication::OnlineId::IOnlineIdServiceTicket>
{
    int32_t WINRT_CALL get_Value(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Value, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Value());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Request(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Request, WINRT_WRAP(Windows::Security::Authentication::OnlineId::OnlineIdServiceTicketRequest));
            *value = detach_from<Windows::Security::Authentication::OnlineId::OnlineIdServiceTicketRequest>(this->shim().Request());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ErrorCode(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ErrorCode, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().ErrorCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Authentication::OnlineId::IOnlineIdServiceTicketRequest> : produce_base<D, Windows::Security::Authentication::OnlineId::IOnlineIdServiceTicketRequest>
{
    int32_t WINRT_CALL get_Service(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Service, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Service());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Policy(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Policy, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Policy());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Authentication::OnlineId::IOnlineIdServiceTicketRequestFactory> : produce_base<D, Windows::Security::Authentication::OnlineId::IOnlineIdServiceTicketRequestFactory>
{
    int32_t WINRT_CALL CreateOnlineIdServiceTicketRequest(void* service, void* policy, void** onlineIdServiceTicketRequest) noexcept final
    {
        try
        {
            *onlineIdServiceTicketRequest = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateOnlineIdServiceTicketRequest, WINRT_WRAP(Windows::Security::Authentication::OnlineId::OnlineIdServiceTicketRequest), hstring const&, hstring const&);
            *onlineIdServiceTicketRequest = detach_from<Windows::Security::Authentication::OnlineId::OnlineIdServiceTicketRequest>(this->shim().CreateOnlineIdServiceTicketRequest(*reinterpret_cast<hstring const*>(&service), *reinterpret_cast<hstring const*>(&policy)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateOnlineIdServiceTicketRequestAdvanced(void* service, void** onlineIdServiceTicketRequest) noexcept final
    {
        try
        {
            *onlineIdServiceTicketRequest = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateOnlineIdServiceTicketRequestAdvanced, WINRT_WRAP(Windows::Security::Authentication::OnlineId::OnlineIdServiceTicketRequest), hstring const&);
            *onlineIdServiceTicketRequest = detach_from<Windows::Security::Authentication::OnlineId::OnlineIdServiceTicketRequest>(this->shim().CreateOnlineIdServiceTicketRequestAdvanced(*reinterpret_cast<hstring const*>(&service)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Authentication::OnlineId::IOnlineIdSystemAuthenticatorForUser> : produce_base<D, Windows::Security::Authentication::OnlineId::IOnlineIdSystemAuthenticatorForUser>
{
    int32_t WINRT_CALL GetTicketAsync(void* request, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetTicketAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::OnlineId::OnlineIdSystemTicketResult>), Windows::Security::Authentication::OnlineId::OnlineIdServiceTicketRequest const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::OnlineId::OnlineIdSystemTicketResult>>(this->shim().GetTicketAsync(*reinterpret_cast<Windows::Security::Authentication::OnlineId::OnlineIdServiceTicketRequest const*>(&request)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ApplicationId(winrt::guid value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ApplicationId, WINRT_WRAP(void), winrt::guid const&);
            this->shim().ApplicationId(*reinterpret_cast<winrt::guid const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ApplicationId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ApplicationId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().ApplicationId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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
struct produce<D, Windows::Security::Authentication::OnlineId::IOnlineIdSystemAuthenticatorStatics> : produce_base<D, Windows::Security::Authentication::OnlineId::IOnlineIdSystemAuthenticatorStatics>
{
    int32_t WINRT_CALL get_Default(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Default, WINRT_WRAP(Windows::Security::Authentication::OnlineId::OnlineIdSystemAuthenticatorForUser));
            *value = detach_from<Windows::Security::Authentication::OnlineId::OnlineIdSystemAuthenticatorForUser>(this->shim().Default());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetForUser(void* user, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForUser, WINRT_WRAP(Windows::Security::Authentication::OnlineId::OnlineIdSystemAuthenticatorForUser), Windows::System::User const&);
            *value = detach_from<Windows::Security::Authentication::OnlineId::OnlineIdSystemAuthenticatorForUser>(this->shim().GetForUser(*reinterpret_cast<Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Authentication::OnlineId::IOnlineIdSystemIdentity> : produce_base<D, Windows::Security::Authentication::OnlineId::IOnlineIdSystemIdentity>
{
    int32_t WINRT_CALL get_Ticket(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Ticket, WINRT_WRAP(Windows::Security::Authentication::OnlineId::OnlineIdServiceTicket));
            *value = detach_from<Windows::Security::Authentication::OnlineId::OnlineIdServiceTicket>(this->shim().Ticket());
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
};

template <typename D>
struct produce<D, Windows::Security::Authentication::OnlineId::IOnlineIdSystemTicketResult> : produce_base<D, Windows::Security::Authentication::OnlineId::IOnlineIdSystemTicketResult>
{
    int32_t WINRT_CALL get_Identity(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Identity, WINRT_WRAP(Windows::Security::Authentication::OnlineId::OnlineIdSystemIdentity));
            *value = detach_from<Windows::Security::Authentication::OnlineId::OnlineIdSystemIdentity>(this->shim().Identity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Status(Windows::Security::Authentication::OnlineId::OnlineIdSystemTicketStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Security::Authentication::OnlineId::OnlineIdSystemTicketStatus));
            *value = detach_from<Windows::Security::Authentication::OnlineId::OnlineIdSystemTicketStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExtendedError(winrt::hresult* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExtendedError, WINRT_WRAP(winrt::hresult));
            *value = detach_from<winrt::hresult>(this->shim().ExtendedError());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Authentication::OnlineId::IUserIdentity> : produce_base<D, Windows::Security::Authentication::OnlineId::IUserIdentity>
{
    int32_t WINRT_CALL get_Tickets(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Tickets, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Security::Authentication::OnlineId::OnlineIdServiceTicket>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Security::Authentication::OnlineId::OnlineIdServiceTicket>>(this->shim().Tickets());
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

    int32_t WINRT_CALL get_SafeCustomerId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SafeCustomerId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SafeCustomerId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SignInName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SignInName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SignInName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FirstName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FirstName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().FirstName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LastName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LastName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().LastName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsBetaAccount(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsBetaAccount, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsBetaAccount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsConfirmedPC(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsConfirmedPC, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsConfirmedPC());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Security::Authentication::OnlineId {

inline OnlineIdAuthenticator::OnlineIdAuthenticator() :
    OnlineIdAuthenticator(impl::call_factory<OnlineIdAuthenticator>([](auto&& f) { return f.template ActivateInstance<OnlineIdAuthenticator>(); }))
{}

inline OnlineIdServiceTicketRequest::OnlineIdServiceTicketRequest(param::hstring const& service, param::hstring const& policy) :
    OnlineIdServiceTicketRequest(impl::call_factory<OnlineIdServiceTicketRequest, Windows::Security::Authentication::OnlineId::IOnlineIdServiceTicketRequestFactory>([&](auto&& f) { return f.CreateOnlineIdServiceTicketRequest(service, policy); }))
{}

inline OnlineIdServiceTicketRequest::OnlineIdServiceTicketRequest(param::hstring const& service) :
    OnlineIdServiceTicketRequest(impl::call_factory<OnlineIdServiceTicketRequest, Windows::Security::Authentication::OnlineId::IOnlineIdServiceTicketRequestFactory>([&](auto&& f) { return f.CreateOnlineIdServiceTicketRequestAdvanced(service); }))
{}

inline Windows::Security::Authentication::OnlineId::OnlineIdSystemAuthenticatorForUser OnlineIdSystemAuthenticator::Default()
{
    return impl::call_factory<OnlineIdSystemAuthenticator, Windows::Security::Authentication::OnlineId::IOnlineIdSystemAuthenticatorStatics>([&](auto&& f) { return f.Default(); });
}

inline Windows::Security::Authentication::OnlineId::OnlineIdSystemAuthenticatorForUser OnlineIdSystemAuthenticator::GetForUser(Windows::System::User const& user)
{
    return impl::call_factory<OnlineIdSystemAuthenticator, Windows::Security::Authentication::OnlineId::IOnlineIdSystemAuthenticatorStatics>([&](auto&& f) { return f.GetForUser(user); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Security::Authentication::OnlineId::IOnlineIdAuthenticator> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::OnlineId::IOnlineIdAuthenticator> {};
template<> struct hash<winrt::Windows::Security::Authentication::OnlineId::IOnlineIdServiceTicket> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::OnlineId::IOnlineIdServiceTicket> {};
template<> struct hash<winrt::Windows::Security::Authentication::OnlineId::IOnlineIdServiceTicketRequest> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::OnlineId::IOnlineIdServiceTicketRequest> {};
template<> struct hash<winrt::Windows::Security::Authentication::OnlineId::IOnlineIdServiceTicketRequestFactory> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::OnlineId::IOnlineIdServiceTicketRequestFactory> {};
template<> struct hash<winrt::Windows::Security::Authentication::OnlineId::IOnlineIdSystemAuthenticatorForUser> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::OnlineId::IOnlineIdSystemAuthenticatorForUser> {};
template<> struct hash<winrt::Windows::Security::Authentication::OnlineId::IOnlineIdSystemAuthenticatorStatics> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::OnlineId::IOnlineIdSystemAuthenticatorStatics> {};
template<> struct hash<winrt::Windows::Security::Authentication::OnlineId::IOnlineIdSystemIdentity> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::OnlineId::IOnlineIdSystemIdentity> {};
template<> struct hash<winrt::Windows::Security::Authentication::OnlineId::IOnlineIdSystemTicketResult> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::OnlineId::IOnlineIdSystemTicketResult> {};
template<> struct hash<winrt::Windows::Security::Authentication::OnlineId::IUserIdentity> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::OnlineId::IUserIdentity> {};
template<> struct hash<winrt::Windows::Security::Authentication::OnlineId::OnlineIdAuthenticator> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::OnlineId::OnlineIdAuthenticator> {};
template<> struct hash<winrt::Windows::Security::Authentication::OnlineId::OnlineIdServiceTicket> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::OnlineId::OnlineIdServiceTicket> {};
template<> struct hash<winrt::Windows::Security::Authentication::OnlineId::OnlineIdServiceTicketRequest> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::OnlineId::OnlineIdServiceTicketRequest> {};
template<> struct hash<winrt::Windows::Security::Authentication::OnlineId::OnlineIdSystemAuthenticator> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::OnlineId::OnlineIdSystemAuthenticator> {};
template<> struct hash<winrt::Windows::Security::Authentication::OnlineId::OnlineIdSystemAuthenticatorForUser> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::OnlineId::OnlineIdSystemAuthenticatorForUser> {};
template<> struct hash<winrt::Windows::Security::Authentication::OnlineId::OnlineIdSystemIdentity> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::OnlineId::OnlineIdSystemIdentity> {};
template<> struct hash<winrt::Windows::Security::Authentication::OnlineId::OnlineIdSystemTicketResult> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::OnlineId::OnlineIdSystemTicketResult> {};
template<> struct hash<winrt::Windows::Security::Authentication::OnlineId::SignOutUserOperation> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::OnlineId::SignOutUserOperation> {};
template<> struct hash<winrt::Windows::Security::Authentication::OnlineId::UserAuthenticationOperation> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::OnlineId::UserAuthenticationOperation> {};
template<> struct hash<winrt::Windows::Security::Authentication::OnlineId::UserIdentity> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::OnlineId::UserIdentity> {};

}
