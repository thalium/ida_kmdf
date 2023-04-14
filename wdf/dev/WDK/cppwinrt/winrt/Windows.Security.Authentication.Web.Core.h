// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Security.Credentials.2.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.Security.Authentication.Web.Core.2.h"
#include "winrt/Windows.Security.Authentication.Web.h"

namespace winrt::impl {

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Security::Credentials::WebAccount> consume_Windows_Security_Authentication_Web_Core_IFindAllAccountsResult<D>::Accounts() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Security::Credentials::WebAccount> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Core::IFindAllAccountsResult)->get_Accounts(put_abi(value)));
    return value;
}

template <typename D> Windows::Security::Authentication::Web::Core::FindAllWebAccountsStatus consume_Windows_Security_Authentication_Web_Core_IFindAllAccountsResult<D>::Status() const
{
    Windows::Security::Authentication::Web::Core::FindAllWebAccountsStatus value{};
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Core::IFindAllAccountsResult)->get_Status(put_abi(value)));
    return value;
}

template <typename D> Windows::Security::Authentication::Web::Core::WebProviderError consume_Windows_Security_Authentication_Web_Core_IFindAllAccountsResult<D>::ProviderError() const
{
    Windows::Security::Authentication::Web::Core::WebProviderError value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Core::IFindAllAccountsResult)->get_ProviderError(put_abi(value)));
    return value;
}

template <typename D> Windows::Security::Credentials::WebAccount consume_Windows_Security_Authentication_Web_Core_IWebAccountEventArgs<D>::Account() const
{
    Windows::Security::Credentials::WebAccount value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Core::IWebAccountEventArgs)->get_Account(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Security_Authentication_Web_Core_IWebAccountMonitor<D>::Updated(Windows::Foundation::TypedEventHandler<Windows::Security::Authentication::Web::Core::WebAccountMonitor, Windows::Security::Authentication::Web::Core::WebAccountEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Core::IWebAccountMonitor)->add_Updated(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Security_Authentication_Web_Core_IWebAccountMonitor<D>::Updated_revoker consume_Windows_Security_Authentication_Web_Core_IWebAccountMonitor<D>::Updated(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Security::Authentication::Web::Core::WebAccountMonitor, Windows::Security::Authentication::Web::Core::WebAccountEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Updated_revoker>(this, Updated(handler));
}

template <typename D> void consume_Windows_Security_Authentication_Web_Core_IWebAccountMonitor<D>::Updated(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Security::Authentication::Web::Core::IWebAccountMonitor)->remove_Updated(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Security_Authentication_Web_Core_IWebAccountMonitor<D>::Removed(Windows::Foundation::TypedEventHandler<Windows::Security::Authentication::Web::Core::WebAccountMonitor, Windows::Security::Authentication::Web::Core::WebAccountEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Core::IWebAccountMonitor)->add_Removed(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Security_Authentication_Web_Core_IWebAccountMonitor<D>::Removed_revoker consume_Windows_Security_Authentication_Web_Core_IWebAccountMonitor<D>::Removed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Security::Authentication::Web::Core::WebAccountMonitor, Windows::Security::Authentication::Web::Core::WebAccountEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Removed_revoker>(this, Removed(handler));
}

template <typename D> void consume_Windows_Security_Authentication_Web_Core_IWebAccountMonitor<D>::Removed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Security::Authentication::Web::Core::IWebAccountMonitor)->remove_Removed(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Security_Authentication_Web_Core_IWebAccountMonitor<D>::DefaultSignInAccountChanged(Windows::Foundation::TypedEventHandler<Windows::Security::Authentication::Web::Core::WebAccountMonitor, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Core::IWebAccountMonitor)->add_DefaultSignInAccountChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Security_Authentication_Web_Core_IWebAccountMonitor<D>::DefaultSignInAccountChanged_revoker consume_Windows_Security_Authentication_Web_Core_IWebAccountMonitor<D>::DefaultSignInAccountChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Security::Authentication::Web::Core::WebAccountMonitor, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, DefaultSignInAccountChanged_revoker>(this, DefaultSignInAccountChanged(handler));
}

template <typename D> void consume_Windows_Security_Authentication_Web_Core_IWebAccountMonitor<D>::DefaultSignInAccountChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Security::Authentication::Web::Core::IWebAccountMonitor)->remove_DefaultSignInAccountChanged(get_abi(token)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Web::Core::WebTokenRequestResult> consume_Windows_Security_Authentication_Web_Core_IWebAuthenticationCoreManagerStatics<D>::GetTokenSilentlyAsync(Windows::Security::Authentication::Web::Core::WebTokenRequest const& request) const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Web::Core::WebTokenRequestResult> asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Core::IWebAuthenticationCoreManagerStatics)->GetTokenSilentlyAsync(get_abi(request), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Web::Core::WebTokenRequestResult> consume_Windows_Security_Authentication_Web_Core_IWebAuthenticationCoreManagerStatics<D>::GetTokenSilentlyAsync(Windows::Security::Authentication::Web::Core::WebTokenRequest const& request, Windows::Security::Credentials::WebAccount const& webAccount) const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Web::Core::WebTokenRequestResult> asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Core::IWebAuthenticationCoreManagerStatics)->GetTokenSilentlyWithWebAccountAsync(get_abi(request), get_abi(webAccount), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Web::Core::WebTokenRequestResult> consume_Windows_Security_Authentication_Web_Core_IWebAuthenticationCoreManagerStatics<D>::RequestTokenAsync(Windows::Security::Authentication::Web::Core::WebTokenRequest const& request) const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Web::Core::WebTokenRequestResult> asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Core::IWebAuthenticationCoreManagerStatics)->RequestTokenAsync(get_abi(request), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Web::Core::WebTokenRequestResult> consume_Windows_Security_Authentication_Web_Core_IWebAuthenticationCoreManagerStatics<D>::RequestTokenAsync(Windows::Security::Authentication::Web::Core::WebTokenRequest const& request, Windows::Security::Credentials::WebAccount const& webAccount) const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Web::Core::WebTokenRequestResult> asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Core::IWebAuthenticationCoreManagerStatics)->RequestTokenWithWebAccountAsync(get_abi(request), get_abi(webAccount), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::WebAccount> consume_Windows_Security_Authentication_Web_Core_IWebAuthenticationCoreManagerStatics<D>::FindAccountAsync(Windows::Security::Credentials::WebAccountProvider const& provider, param::hstring const& webAccountId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::WebAccount> asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Core::IWebAuthenticationCoreManagerStatics)->FindAccountAsync(get_abi(provider), get_abi(webAccountId), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::WebAccountProvider> consume_Windows_Security_Authentication_Web_Core_IWebAuthenticationCoreManagerStatics<D>::FindAccountProviderAsync(param::hstring const& webAccountProviderId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::WebAccountProvider> asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Core::IWebAuthenticationCoreManagerStatics)->FindAccountProviderAsync(get_abi(webAccountProviderId), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::WebAccountProvider> consume_Windows_Security_Authentication_Web_Core_IWebAuthenticationCoreManagerStatics<D>::FindAccountProviderAsync(param::hstring const& webAccountProviderId, param::hstring const& authority) const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::WebAccountProvider> asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Core::IWebAuthenticationCoreManagerStatics)->FindAccountProviderWithAuthorityAsync(get_abi(webAccountProviderId), get_abi(authority), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::WebAccountProvider> consume_Windows_Security_Authentication_Web_Core_IWebAuthenticationCoreManagerStatics2<D>::FindAccountProviderAsync(param::hstring const& webAccountProviderId, param::hstring const& authority, Windows::System::User const& user) const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::WebAccountProvider> asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Core::IWebAuthenticationCoreManagerStatics2)->FindAccountProviderWithAuthorityForUserAsync(get_abi(webAccountProviderId), get_abi(authority), get_abi(user), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Security::Authentication::Web::Core::WebAccountMonitor consume_Windows_Security_Authentication_Web_Core_IWebAuthenticationCoreManagerStatics3<D>::CreateWebAccountMonitor(param::iterable<Windows::Security::Credentials::WebAccount> const& webAccounts) const
{
    Windows::Security::Authentication::Web::Core::WebAccountMonitor result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Core::IWebAuthenticationCoreManagerStatics3)->CreateWebAccountMonitor(get_abi(webAccounts), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Web::Core::FindAllAccountsResult> consume_Windows_Security_Authentication_Web_Core_IWebAuthenticationCoreManagerStatics4<D>::FindAllAccountsAsync(Windows::Security::Credentials::WebAccountProvider const& provider) const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Web::Core::FindAllAccountsResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Core::IWebAuthenticationCoreManagerStatics4)->FindAllAccountsAsync(get_abi(provider), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Web::Core::FindAllAccountsResult> consume_Windows_Security_Authentication_Web_Core_IWebAuthenticationCoreManagerStatics4<D>::FindAllAccountsAsync(Windows::Security::Credentials::WebAccountProvider const& provider, param::hstring const& clientId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Web::Core::FindAllAccountsResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Core::IWebAuthenticationCoreManagerStatics4)->FindAllAccountsWithClientIdAsync(get_abi(provider), get_abi(clientId), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::WebAccountProvider> consume_Windows_Security_Authentication_Web_Core_IWebAuthenticationCoreManagerStatics4<D>::FindSystemAccountProviderAsync(param::hstring const& webAccountProviderId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::WebAccountProvider> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Core::IWebAuthenticationCoreManagerStatics4)->FindSystemAccountProviderAsync(get_abi(webAccountProviderId), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::WebAccountProvider> consume_Windows_Security_Authentication_Web_Core_IWebAuthenticationCoreManagerStatics4<D>::FindSystemAccountProviderAsync(param::hstring const& webAccountProviderId, param::hstring const& authority) const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::WebAccountProvider> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Core::IWebAuthenticationCoreManagerStatics4)->FindSystemAccountProviderWithAuthorityAsync(get_abi(webAccountProviderId), get_abi(authority), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::WebAccountProvider> consume_Windows_Security_Authentication_Web_Core_IWebAuthenticationCoreManagerStatics4<D>::FindSystemAccountProviderAsync(param::hstring const& webAccountProviderId, param::hstring const& authority, Windows::System::User const& user) const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::WebAccountProvider> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Core::IWebAuthenticationCoreManagerStatics4)->FindSystemAccountProviderWithAuthorityForUserAsync(get_abi(webAccountProviderId), get_abi(authority), get_abi(user), put_abi(operation)));
    return operation;
}

template <typename D> uint32_t consume_Windows_Security_Authentication_Web_Core_IWebProviderError<D>::ErrorCode() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Core::IWebProviderError)->get_ErrorCode(&value));
    return value;
}

template <typename D> hstring consume_Windows_Security_Authentication_Web_Core_IWebProviderError<D>::ErrorMessage() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Core::IWebProviderError)->get_ErrorMessage(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IMap<hstring, hstring> consume_Windows_Security_Authentication_Web_Core_IWebProviderError<D>::Properties() const
{
    Windows::Foundation::Collections::IMap<hstring, hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Core::IWebProviderError)->get_Properties(put_abi(value)));
    return value;
}

template <typename D> Windows::Security::Authentication::Web::Core::WebProviderError consume_Windows_Security_Authentication_Web_Core_IWebProviderErrorFactory<D>::Create(uint32_t errorCode, param::hstring const& errorMessage) const
{
    Windows::Security::Authentication::Web::Core::WebProviderError webProviderError{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Core::IWebProviderErrorFactory)->Create(errorCode, get_abi(errorMessage), put_abi(webProviderError)));
    return webProviderError;
}

template <typename D> Windows::Security::Credentials::WebAccountProvider consume_Windows_Security_Authentication_Web_Core_IWebTokenRequest<D>::WebAccountProvider() const
{
    Windows::Security::Credentials::WebAccountProvider value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Core::IWebTokenRequest)->get_WebAccountProvider(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Authentication_Web_Core_IWebTokenRequest<D>::Scope() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Core::IWebTokenRequest)->get_Scope(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Authentication_Web_Core_IWebTokenRequest<D>::ClientId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Core::IWebTokenRequest)->get_ClientId(put_abi(value)));
    return value;
}

template <typename D> Windows::Security::Authentication::Web::Core::WebTokenRequestPromptType consume_Windows_Security_Authentication_Web_Core_IWebTokenRequest<D>::PromptType() const
{
    Windows::Security::Authentication::Web::Core::WebTokenRequestPromptType value{};
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Core::IWebTokenRequest)->get_PromptType(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IMap<hstring, hstring> consume_Windows_Security_Authentication_Web_Core_IWebTokenRequest<D>::Properties() const
{
    Windows::Foundation::Collections::IMap<hstring, hstring> requestProperties{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Core::IWebTokenRequest)->get_Properties(put_abi(requestProperties)));
    return requestProperties;
}

template <typename D> Windows::Foundation::Collections::IMap<hstring, hstring> consume_Windows_Security_Authentication_Web_Core_IWebTokenRequest2<D>::AppProperties() const
{
    Windows::Foundation::Collections::IMap<hstring, hstring> requestProperties{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Core::IWebTokenRequest2)->get_AppProperties(put_abi(requestProperties)));
    return requestProperties;
}

template <typename D> hstring consume_Windows_Security_Authentication_Web_Core_IWebTokenRequest3<D>::CorrelationId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Core::IWebTokenRequest3)->get_CorrelationId(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Security_Authentication_Web_Core_IWebTokenRequest3<D>::CorrelationId(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Core::IWebTokenRequest3)->put_CorrelationId(get_abi(value)));
}

template <typename D> Windows::Security::Authentication::Web::Core::WebTokenRequest consume_Windows_Security_Authentication_Web_Core_IWebTokenRequestFactory<D>::Create(Windows::Security::Credentials::WebAccountProvider const& provider, param::hstring const& scope, param::hstring const& clientId) const
{
    Windows::Security::Authentication::Web::Core::WebTokenRequest webTokenRequest{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Core::IWebTokenRequestFactory)->Create(get_abi(provider), get_abi(scope), get_abi(clientId), put_abi(webTokenRequest)));
    return webTokenRequest;
}

template <typename D> Windows::Security::Authentication::Web::Core::WebTokenRequest consume_Windows_Security_Authentication_Web_Core_IWebTokenRequestFactory<D>::CreateWithPromptType(Windows::Security::Credentials::WebAccountProvider const& provider, param::hstring const& scope, param::hstring const& clientId, Windows::Security::Authentication::Web::Core::WebTokenRequestPromptType const& promptType) const
{
    Windows::Security::Authentication::Web::Core::WebTokenRequest webTokenRequest{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Core::IWebTokenRequestFactory)->CreateWithPromptType(get_abi(provider), get_abi(scope), get_abi(clientId), get_abi(promptType), put_abi(webTokenRequest)));
    return webTokenRequest;
}

template <typename D> Windows::Security::Authentication::Web::Core::WebTokenRequest consume_Windows_Security_Authentication_Web_Core_IWebTokenRequestFactory<D>::CreateWithProvider(Windows::Security::Credentials::WebAccountProvider const& provider) const
{
    Windows::Security::Authentication::Web::Core::WebTokenRequest webTokenRequest{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Core::IWebTokenRequestFactory)->CreateWithProvider(get_abi(provider), put_abi(webTokenRequest)));
    return webTokenRequest;
}

template <typename D> Windows::Security::Authentication::Web::Core::WebTokenRequest consume_Windows_Security_Authentication_Web_Core_IWebTokenRequestFactory<D>::CreateWithScope(Windows::Security::Credentials::WebAccountProvider const& provider, param::hstring const& scope) const
{
    Windows::Security::Authentication::Web::Core::WebTokenRequest webTokenRequest{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Core::IWebTokenRequestFactory)->CreateWithScope(get_abi(provider), get_abi(scope), put_abi(webTokenRequest)));
    return webTokenRequest;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Security::Authentication::Web::Core::WebTokenResponse> consume_Windows_Security_Authentication_Web_Core_IWebTokenRequestResult<D>::ResponseData() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Security::Authentication::Web::Core::WebTokenResponse> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Core::IWebTokenRequestResult)->get_ResponseData(put_abi(value)));
    return value;
}

template <typename D> Windows::Security::Authentication::Web::Core::WebTokenRequestStatus consume_Windows_Security_Authentication_Web_Core_IWebTokenRequestResult<D>::ResponseStatus() const
{
    Windows::Security::Authentication::Web::Core::WebTokenRequestStatus value{};
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Core::IWebTokenRequestResult)->get_ResponseStatus(put_abi(value)));
    return value;
}

template <typename D> Windows::Security::Authentication::Web::Core::WebProviderError consume_Windows_Security_Authentication_Web_Core_IWebTokenRequestResult<D>::ResponseError() const
{
    Windows::Security::Authentication::Web::Core::WebProviderError value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Core::IWebTokenRequestResult)->get_ResponseError(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Security_Authentication_Web_Core_IWebTokenRequestResult<D>::InvalidateCacheAsync() const
{
    Windows::Foundation::IAsyncAction asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Core::IWebTokenRequestResult)->InvalidateCacheAsync(put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> hstring consume_Windows_Security_Authentication_Web_Core_IWebTokenResponse<D>::Token() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Core::IWebTokenResponse)->get_Token(put_abi(value)));
    return value;
}

template <typename D> Windows::Security::Authentication::Web::Core::WebProviderError consume_Windows_Security_Authentication_Web_Core_IWebTokenResponse<D>::ProviderError() const
{
    Windows::Security::Authentication::Web::Core::WebProviderError value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Core::IWebTokenResponse)->get_ProviderError(put_abi(value)));
    return value;
}

template <typename D> Windows::Security::Credentials::WebAccount consume_Windows_Security_Authentication_Web_Core_IWebTokenResponse<D>::WebAccount() const
{
    Windows::Security::Credentials::WebAccount value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Core::IWebTokenResponse)->get_WebAccount(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IMap<hstring, hstring> consume_Windows_Security_Authentication_Web_Core_IWebTokenResponse<D>::Properties() const
{
    Windows::Foundation::Collections::IMap<hstring, hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Core::IWebTokenResponse)->get_Properties(put_abi(value)));
    return value;
}

template <typename D> Windows::Security::Authentication::Web::Core::WebTokenResponse consume_Windows_Security_Authentication_Web_Core_IWebTokenResponseFactory<D>::CreateWithToken(param::hstring const& token) const
{
    Windows::Security::Authentication::Web::Core::WebTokenResponse webTokenResponse{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Core::IWebTokenResponseFactory)->CreateWithToken(get_abi(token), put_abi(webTokenResponse)));
    return webTokenResponse;
}

template <typename D> Windows::Security::Authentication::Web::Core::WebTokenResponse consume_Windows_Security_Authentication_Web_Core_IWebTokenResponseFactory<D>::CreateWithTokenAndAccount(param::hstring const& token, Windows::Security::Credentials::WebAccount const& webAccount) const
{
    Windows::Security::Authentication::Web::Core::WebTokenResponse webTokenResponse{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Core::IWebTokenResponseFactory)->CreateWithTokenAndAccount(get_abi(token), get_abi(webAccount), put_abi(webTokenResponse)));
    return webTokenResponse;
}

template <typename D> Windows::Security::Authentication::Web::Core::WebTokenResponse consume_Windows_Security_Authentication_Web_Core_IWebTokenResponseFactory<D>::CreateWithTokenAccountAndError(param::hstring const& token, Windows::Security::Credentials::WebAccount const& webAccount, Windows::Security::Authentication::Web::Core::WebProviderError const& error) const
{
    Windows::Security::Authentication::Web::Core::WebTokenResponse webTokenResponse{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Core::IWebTokenResponseFactory)->CreateWithTokenAccountAndError(get_abi(token), get_abi(webAccount), get_abi(error), put_abi(webTokenResponse)));
    return webTokenResponse;
}

template <typename D>
struct produce<D, Windows::Security::Authentication::Web::Core::IFindAllAccountsResult> : produce_base<D, Windows::Security::Authentication::Web::Core::IFindAllAccountsResult>
{
    int32_t WINRT_CALL get_Accounts(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Accounts, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Security::Credentials::WebAccount>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Security::Credentials::WebAccount>>(this->shim().Accounts());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Status(Windows::Security::Authentication::Web::Core::FindAllWebAccountsStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Security::Authentication::Web::Core::FindAllWebAccountsStatus));
            *value = detach_from<Windows::Security::Authentication::Web::Core::FindAllWebAccountsStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProviderError(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProviderError, WINRT_WRAP(Windows::Security::Authentication::Web::Core::WebProviderError));
            *value = detach_from<Windows::Security::Authentication::Web::Core::WebProviderError>(this->shim().ProviderError());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Authentication::Web::Core::IWebAccountEventArgs> : produce_base<D, Windows::Security::Authentication::Web::Core::IWebAccountEventArgs>
{
    int32_t WINRT_CALL get_Account(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Account, WINRT_WRAP(Windows::Security::Credentials::WebAccount));
            *value = detach_from<Windows::Security::Credentials::WebAccount>(this->shim().Account());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Authentication::Web::Core::IWebAccountMonitor> : produce_base<D, Windows::Security::Authentication::Web::Core::IWebAccountMonitor>
{
    int32_t WINRT_CALL add_Updated(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Updated, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Security::Authentication::Web::Core::WebAccountMonitor, Windows::Security::Authentication::Web::Core::WebAccountEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Updated(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Security::Authentication::Web::Core::WebAccountMonitor, Windows::Security::Authentication::Web::Core::WebAccountEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Updated(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Updated, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Updated(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_Removed(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Removed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Security::Authentication::Web::Core::WebAccountMonitor, Windows::Security::Authentication::Web::Core::WebAccountEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Removed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Security::Authentication::Web::Core::WebAccountMonitor, Windows::Security::Authentication::Web::Core::WebAccountEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Removed(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Removed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Removed(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_DefaultSignInAccountChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DefaultSignInAccountChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Security::Authentication::Web::Core::WebAccountMonitor, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().DefaultSignInAccountChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Security::Authentication::Web::Core::WebAccountMonitor, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_DefaultSignInAccountChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(DefaultSignInAccountChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().DefaultSignInAccountChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Security::Authentication::Web::Core::IWebAuthenticationCoreManagerStatics> : produce_base<D, Windows::Security::Authentication::Web::Core::IWebAuthenticationCoreManagerStatics>
{
    int32_t WINRT_CALL GetTokenSilentlyAsync(void* request, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetTokenSilentlyAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Web::Core::WebTokenRequestResult>), Windows::Security::Authentication::Web::Core::WebTokenRequest const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Web::Core::WebTokenRequestResult>>(this->shim().GetTokenSilentlyAsync(*reinterpret_cast<Windows::Security::Authentication::Web::Core::WebTokenRequest const*>(&request)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetTokenSilentlyWithWebAccountAsync(void* request, void* webAccount, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetTokenSilentlyAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Web::Core::WebTokenRequestResult>), Windows::Security::Authentication::Web::Core::WebTokenRequest const, Windows::Security::Credentials::WebAccount const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Web::Core::WebTokenRequestResult>>(this->shim().GetTokenSilentlyAsync(*reinterpret_cast<Windows::Security::Authentication::Web::Core::WebTokenRequest const*>(&request), *reinterpret_cast<Windows::Security::Credentials::WebAccount const*>(&webAccount)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestTokenAsync(void* request, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestTokenAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Web::Core::WebTokenRequestResult>), Windows::Security::Authentication::Web::Core::WebTokenRequest const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Web::Core::WebTokenRequestResult>>(this->shim().RequestTokenAsync(*reinterpret_cast<Windows::Security::Authentication::Web::Core::WebTokenRequest const*>(&request)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestTokenWithWebAccountAsync(void* request, void* webAccount, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestTokenAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Web::Core::WebTokenRequestResult>), Windows::Security::Authentication::Web::Core::WebTokenRequest const, Windows::Security::Credentials::WebAccount const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Web::Core::WebTokenRequestResult>>(this->shim().RequestTokenAsync(*reinterpret_cast<Windows::Security::Authentication::Web::Core::WebTokenRequest const*>(&request), *reinterpret_cast<Windows::Security::Credentials::WebAccount const*>(&webAccount)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindAccountAsync(void* provider, void* webAccountId, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindAccountAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::WebAccount>), Windows::Security::Credentials::WebAccountProvider const, hstring const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::WebAccount>>(this->shim().FindAccountAsync(*reinterpret_cast<Windows::Security::Credentials::WebAccountProvider const*>(&provider), *reinterpret_cast<hstring const*>(&webAccountId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindAccountProviderAsync(void* webAccountProviderId, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindAccountProviderAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::WebAccountProvider>), hstring const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::WebAccountProvider>>(this->shim().FindAccountProviderAsync(*reinterpret_cast<hstring const*>(&webAccountProviderId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindAccountProviderWithAuthorityAsync(void* webAccountProviderId, void* authority, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindAccountProviderAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::WebAccountProvider>), hstring const, hstring const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::WebAccountProvider>>(this->shim().FindAccountProviderAsync(*reinterpret_cast<hstring const*>(&webAccountProviderId), *reinterpret_cast<hstring const*>(&authority)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Authentication::Web::Core::IWebAuthenticationCoreManagerStatics2> : produce_base<D, Windows::Security::Authentication::Web::Core::IWebAuthenticationCoreManagerStatics2>
{
    int32_t WINRT_CALL FindAccountProviderWithAuthorityForUserAsync(void* webAccountProviderId, void* authority, void* user, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindAccountProviderAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::WebAccountProvider>), hstring const, hstring const, Windows::System::User const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::WebAccountProvider>>(this->shim().FindAccountProviderAsync(*reinterpret_cast<hstring const*>(&webAccountProviderId), *reinterpret_cast<hstring const*>(&authority), *reinterpret_cast<Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Authentication::Web::Core::IWebAuthenticationCoreManagerStatics3> : produce_base<D, Windows::Security::Authentication::Web::Core::IWebAuthenticationCoreManagerStatics3>
{
    int32_t WINRT_CALL CreateWebAccountMonitor(void* webAccounts, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWebAccountMonitor, WINRT_WRAP(Windows::Security::Authentication::Web::Core::WebAccountMonitor), Windows::Foundation::Collections::IIterable<Windows::Security::Credentials::WebAccount> const&);
            *result = detach_from<Windows::Security::Authentication::Web::Core::WebAccountMonitor>(this->shim().CreateWebAccountMonitor(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Security::Credentials::WebAccount> const*>(&webAccounts)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Authentication::Web::Core::IWebAuthenticationCoreManagerStatics4> : produce_base<D, Windows::Security::Authentication::Web::Core::IWebAuthenticationCoreManagerStatics4>
{
    int32_t WINRT_CALL FindAllAccountsAsync(void* provider, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindAllAccountsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Web::Core::FindAllAccountsResult>), Windows::Security::Credentials::WebAccountProvider const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Web::Core::FindAllAccountsResult>>(this->shim().FindAllAccountsAsync(*reinterpret_cast<Windows::Security::Credentials::WebAccountProvider const*>(&provider)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindAllAccountsWithClientIdAsync(void* provider, void* clientId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindAllAccountsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Web::Core::FindAllAccountsResult>), Windows::Security::Credentials::WebAccountProvider const, hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Web::Core::FindAllAccountsResult>>(this->shim().FindAllAccountsAsync(*reinterpret_cast<Windows::Security::Credentials::WebAccountProvider const*>(&provider), *reinterpret_cast<hstring const*>(&clientId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindSystemAccountProviderAsync(void* webAccountProviderId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindSystemAccountProviderAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::WebAccountProvider>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::WebAccountProvider>>(this->shim().FindSystemAccountProviderAsync(*reinterpret_cast<hstring const*>(&webAccountProviderId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindSystemAccountProviderWithAuthorityAsync(void* webAccountProviderId, void* authority, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindSystemAccountProviderAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::WebAccountProvider>), hstring const, hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::WebAccountProvider>>(this->shim().FindSystemAccountProviderAsync(*reinterpret_cast<hstring const*>(&webAccountProviderId), *reinterpret_cast<hstring const*>(&authority)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindSystemAccountProviderWithAuthorityForUserAsync(void* webAccountProviderId, void* authority, void* user, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindSystemAccountProviderAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::WebAccountProvider>), hstring const, hstring const, Windows::System::User const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::WebAccountProvider>>(this->shim().FindSystemAccountProviderAsync(*reinterpret_cast<hstring const*>(&webAccountProviderId), *reinterpret_cast<hstring const*>(&authority), *reinterpret_cast<Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Authentication::Web::Core::IWebProviderError> : produce_base<D, Windows::Security::Authentication::Web::Core::IWebProviderError>
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

    int32_t WINRT_CALL get_ErrorMessage(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ErrorMessage, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ErrorMessage());
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
            WINRT_ASSERT_DECLARATION(Properties, WINRT_WRAP(Windows::Foundation::Collections::IMap<hstring, hstring>));
            *value = detach_from<Windows::Foundation::Collections::IMap<hstring, hstring>>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Authentication::Web::Core::IWebProviderErrorFactory> : produce_base<D, Windows::Security::Authentication::Web::Core::IWebProviderErrorFactory>
{
    int32_t WINRT_CALL Create(uint32_t errorCode, void* errorMessage, void** webProviderError) noexcept final
    {
        try
        {
            *webProviderError = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Security::Authentication::Web::Core::WebProviderError), uint32_t, hstring const&);
            *webProviderError = detach_from<Windows::Security::Authentication::Web::Core::WebProviderError>(this->shim().Create(errorCode, *reinterpret_cast<hstring const*>(&errorMessage)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Authentication::Web::Core::IWebTokenRequest> : produce_base<D, Windows::Security::Authentication::Web::Core::IWebTokenRequest>
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

    int32_t WINRT_CALL get_Scope(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Scope, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Scope());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ClientId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClientId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ClientId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PromptType(Windows::Security::Authentication::Web::Core::WebTokenRequestPromptType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PromptType, WINRT_WRAP(Windows::Security::Authentication::Web::Core::WebTokenRequestPromptType));
            *value = detach_from<Windows::Security::Authentication::Web::Core::WebTokenRequestPromptType>(this->shim().PromptType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Properties(void** requestProperties) noexcept final
    {
        try
        {
            *requestProperties = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Properties, WINRT_WRAP(Windows::Foundation::Collections::IMap<hstring, hstring>));
            *requestProperties = detach_from<Windows::Foundation::Collections::IMap<hstring, hstring>>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Authentication::Web::Core::IWebTokenRequest2> : produce_base<D, Windows::Security::Authentication::Web::Core::IWebTokenRequest2>
{
    int32_t WINRT_CALL get_AppProperties(void** requestProperties) noexcept final
    {
        try
        {
            *requestProperties = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppProperties, WINRT_WRAP(Windows::Foundation::Collections::IMap<hstring, hstring>));
            *requestProperties = detach_from<Windows::Foundation::Collections::IMap<hstring, hstring>>(this->shim().AppProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Authentication::Web::Core::IWebTokenRequest3> : produce_base<D, Windows::Security::Authentication::Web::Core::IWebTokenRequest3>
{
    int32_t WINRT_CALL get_CorrelationId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CorrelationId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().CorrelationId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CorrelationId(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CorrelationId, WINRT_WRAP(void), hstring const&);
            this->shim().CorrelationId(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Authentication::Web::Core::IWebTokenRequestFactory> : produce_base<D, Windows::Security::Authentication::Web::Core::IWebTokenRequestFactory>
{
    int32_t WINRT_CALL Create(void* provider, void* scope, void* clientId, void** webTokenRequest) noexcept final
    {
        try
        {
            *webTokenRequest = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Security::Authentication::Web::Core::WebTokenRequest), Windows::Security::Credentials::WebAccountProvider const&, hstring const&, hstring const&);
            *webTokenRequest = detach_from<Windows::Security::Authentication::Web::Core::WebTokenRequest>(this->shim().Create(*reinterpret_cast<Windows::Security::Credentials::WebAccountProvider const*>(&provider), *reinterpret_cast<hstring const*>(&scope), *reinterpret_cast<hstring const*>(&clientId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithPromptType(void* provider, void* scope, void* clientId, Windows::Security::Authentication::Web::Core::WebTokenRequestPromptType promptType, void** webTokenRequest) noexcept final
    {
        try
        {
            *webTokenRequest = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithPromptType, WINRT_WRAP(Windows::Security::Authentication::Web::Core::WebTokenRequest), Windows::Security::Credentials::WebAccountProvider const&, hstring const&, hstring const&, Windows::Security::Authentication::Web::Core::WebTokenRequestPromptType const&);
            *webTokenRequest = detach_from<Windows::Security::Authentication::Web::Core::WebTokenRequest>(this->shim().CreateWithPromptType(*reinterpret_cast<Windows::Security::Credentials::WebAccountProvider const*>(&provider), *reinterpret_cast<hstring const*>(&scope), *reinterpret_cast<hstring const*>(&clientId), *reinterpret_cast<Windows::Security::Authentication::Web::Core::WebTokenRequestPromptType const*>(&promptType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithProvider(void* provider, void** webTokenRequest) noexcept final
    {
        try
        {
            *webTokenRequest = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithProvider, WINRT_WRAP(Windows::Security::Authentication::Web::Core::WebTokenRequest), Windows::Security::Credentials::WebAccountProvider const&);
            *webTokenRequest = detach_from<Windows::Security::Authentication::Web::Core::WebTokenRequest>(this->shim().CreateWithProvider(*reinterpret_cast<Windows::Security::Credentials::WebAccountProvider const*>(&provider)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithScope(void* provider, void* scope, void** webTokenRequest) noexcept final
    {
        try
        {
            *webTokenRequest = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithScope, WINRT_WRAP(Windows::Security::Authentication::Web::Core::WebTokenRequest), Windows::Security::Credentials::WebAccountProvider const&, hstring const&);
            *webTokenRequest = detach_from<Windows::Security::Authentication::Web::Core::WebTokenRequest>(this->shim().CreateWithScope(*reinterpret_cast<Windows::Security::Credentials::WebAccountProvider const*>(&provider), *reinterpret_cast<hstring const*>(&scope)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Authentication::Web::Core::IWebTokenRequestResult> : produce_base<D, Windows::Security::Authentication::Web::Core::IWebTokenRequestResult>
{
    int32_t WINRT_CALL get_ResponseData(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResponseData, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Security::Authentication::Web::Core::WebTokenResponse>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Security::Authentication::Web::Core::WebTokenResponse>>(this->shim().ResponseData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ResponseStatus(Windows::Security::Authentication::Web::Core::WebTokenRequestStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResponseStatus, WINRT_WRAP(Windows::Security::Authentication::Web::Core::WebTokenRequestStatus));
            *value = detach_from<Windows::Security::Authentication::Web::Core::WebTokenRequestStatus>(this->shim().ResponseStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ResponseError(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResponseError, WINRT_WRAP(Windows::Security::Authentication::Web::Core::WebProviderError));
            *value = detach_from<Windows::Security::Authentication::Web::Core::WebProviderError>(this->shim().ResponseError());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL InvalidateCacheAsync(void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InvalidateCacheAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *asyncInfo = detach_from<Windows::Foundation::IAsyncAction>(this->shim().InvalidateCacheAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Authentication::Web::Core::IWebTokenResponse> : produce_base<D, Windows::Security::Authentication::Web::Core::IWebTokenResponse>
{
    int32_t WINRT_CALL get_Token(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Token, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Token());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProviderError(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProviderError, WINRT_WRAP(Windows::Security::Authentication::Web::Core::WebProviderError));
            *value = detach_from<Windows::Security::Authentication::Web::Core::WebProviderError>(this->shim().ProviderError());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WebAccount(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WebAccount, WINRT_WRAP(Windows::Security::Credentials::WebAccount));
            *value = detach_from<Windows::Security::Credentials::WebAccount>(this->shim().WebAccount());
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
            WINRT_ASSERT_DECLARATION(Properties, WINRT_WRAP(Windows::Foundation::Collections::IMap<hstring, hstring>));
            *value = detach_from<Windows::Foundation::Collections::IMap<hstring, hstring>>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Authentication::Web::Core::IWebTokenResponseFactory> : produce_base<D, Windows::Security::Authentication::Web::Core::IWebTokenResponseFactory>
{
    int32_t WINRT_CALL CreateWithToken(void* token, void** webTokenResponse) noexcept final
    {
        try
        {
            *webTokenResponse = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithToken, WINRT_WRAP(Windows::Security::Authentication::Web::Core::WebTokenResponse), hstring const&);
            *webTokenResponse = detach_from<Windows::Security::Authentication::Web::Core::WebTokenResponse>(this->shim().CreateWithToken(*reinterpret_cast<hstring const*>(&token)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithTokenAndAccount(void* token, void* webAccount, void** webTokenResponse) noexcept final
    {
        try
        {
            *webTokenResponse = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithTokenAndAccount, WINRT_WRAP(Windows::Security::Authentication::Web::Core::WebTokenResponse), hstring const&, Windows::Security::Credentials::WebAccount const&);
            *webTokenResponse = detach_from<Windows::Security::Authentication::Web::Core::WebTokenResponse>(this->shim().CreateWithTokenAndAccount(*reinterpret_cast<hstring const*>(&token), *reinterpret_cast<Windows::Security::Credentials::WebAccount const*>(&webAccount)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithTokenAccountAndError(void* token, void* webAccount, void* error, void** webTokenResponse) noexcept final
    {
        try
        {
            *webTokenResponse = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithTokenAccountAndError, WINRT_WRAP(Windows::Security::Authentication::Web::Core::WebTokenResponse), hstring const&, Windows::Security::Credentials::WebAccount const&, Windows::Security::Authentication::Web::Core::WebProviderError const&);
            *webTokenResponse = detach_from<Windows::Security::Authentication::Web::Core::WebTokenResponse>(this->shim().CreateWithTokenAccountAndError(*reinterpret_cast<hstring const*>(&token), *reinterpret_cast<Windows::Security::Credentials::WebAccount const*>(&webAccount), *reinterpret_cast<Windows::Security::Authentication::Web::Core::WebProviderError const*>(&error)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Security::Authentication::Web::Core {

inline Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Web::Core::WebTokenRequestResult> WebAuthenticationCoreManager::GetTokenSilentlyAsync(Windows::Security::Authentication::Web::Core::WebTokenRequest const& request)
{
    return impl::call_factory<WebAuthenticationCoreManager, Windows::Security::Authentication::Web::Core::IWebAuthenticationCoreManagerStatics>([&](auto&& f) { return f.GetTokenSilentlyAsync(request); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Web::Core::WebTokenRequestResult> WebAuthenticationCoreManager::GetTokenSilentlyAsync(Windows::Security::Authentication::Web::Core::WebTokenRequest const& request, Windows::Security::Credentials::WebAccount const& webAccount)
{
    return impl::call_factory<WebAuthenticationCoreManager, Windows::Security::Authentication::Web::Core::IWebAuthenticationCoreManagerStatics>([&](auto&& f) { return f.GetTokenSilentlyAsync(request, webAccount); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Web::Core::WebTokenRequestResult> WebAuthenticationCoreManager::RequestTokenAsync(Windows::Security::Authentication::Web::Core::WebTokenRequest const& request)
{
    return impl::call_factory<WebAuthenticationCoreManager, Windows::Security::Authentication::Web::Core::IWebAuthenticationCoreManagerStatics>([&](auto&& f) { return f.RequestTokenAsync(request); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Web::Core::WebTokenRequestResult> WebAuthenticationCoreManager::RequestTokenAsync(Windows::Security::Authentication::Web::Core::WebTokenRequest const& request, Windows::Security::Credentials::WebAccount const& webAccount)
{
    return impl::call_factory<WebAuthenticationCoreManager, Windows::Security::Authentication::Web::Core::IWebAuthenticationCoreManagerStatics>([&](auto&& f) { return f.RequestTokenAsync(request, webAccount); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::WebAccount> WebAuthenticationCoreManager::FindAccountAsync(Windows::Security::Credentials::WebAccountProvider const& provider, param::hstring const& webAccountId)
{
    return impl::call_factory<WebAuthenticationCoreManager, Windows::Security::Authentication::Web::Core::IWebAuthenticationCoreManagerStatics>([&](auto&& f) { return f.FindAccountAsync(provider, webAccountId); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::WebAccountProvider> WebAuthenticationCoreManager::FindAccountProviderAsync(param::hstring const& webAccountProviderId)
{
    return impl::call_factory<WebAuthenticationCoreManager, Windows::Security::Authentication::Web::Core::IWebAuthenticationCoreManagerStatics>([&](auto&& f) { return f.FindAccountProviderAsync(webAccountProviderId); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::WebAccountProvider> WebAuthenticationCoreManager::FindAccountProviderAsync(param::hstring const& webAccountProviderId, param::hstring const& authority)
{
    return impl::call_factory<WebAuthenticationCoreManager, Windows::Security::Authentication::Web::Core::IWebAuthenticationCoreManagerStatics>([&](auto&& f) { return f.FindAccountProviderAsync(webAccountProviderId, authority); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::WebAccountProvider> WebAuthenticationCoreManager::FindAccountProviderAsync(param::hstring const& webAccountProviderId, param::hstring const& authority, Windows::System::User const& user)
{
    return impl::call_factory<WebAuthenticationCoreManager, Windows::Security::Authentication::Web::Core::IWebAuthenticationCoreManagerStatics2>([&](auto&& f) { return f.FindAccountProviderAsync(webAccountProviderId, authority, user); });
}

inline Windows::Security::Authentication::Web::Core::WebAccountMonitor WebAuthenticationCoreManager::CreateWebAccountMonitor(param::iterable<Windows::Security::Credentials::WebAccount> const& webAccounts)
{
    return impl::call_factory<WebAuthenticationCoreManager, Windows::Security::Authentication::Web::Core::IWebAuthenticationCoreManagerStatics3>([&](auto&& f) { return f.CreateWebAccountMonitor(webAccounts); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Web::Core::FindAllAccountsResult> WebAuthenticationCoreManager::FindAllAccountsAsync(Windows::Security::Credentials::WebAccountProvider const& provider)
{
    return impl::call_factory<WebAuthenticationCoreManager, Windows::Security::Authentication::Web::Core::IWebAuthenticationCoreManagerStatics4>([&](auto&& f) { return f.FindAllAccountsAsync(provider); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Security::Authentication::Web::Core::FindAllAccountsResult> WebAuthenticationCoreManager::FindAllAccountsAsync(Windows::Security::Credentials::WebAccountProvider const& provider, param::hstring const& clientId)
{
    return impl::call_factory<WebAuthenticationCoreManager, Windows::Security::Authentication::Web::Core::IWebAuthenticationCoreManagerStatics4>([&](auto&& f) { return f.FindAllAccountsAsync(provider, clientId); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::WebAccountProvider> WebAuthenticationCoreManager::FindSystemAccountProviderAsync(param::hstring const& webAccountProviderId)
{
    return impl::call_factory<WebAuthenticationCoreManager, Windows::Security::Authentication::Web::Core::IWebAuthenticationCoreManagerStatics4>([&](auto&& f) { return f.FindSystemAccountProviderAsync(webAccountProviderId); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::WebAccountProvider> WebAuthenticationCoreManager::FindSystemAccountProviderAsync(param::hstring const& webAccountProviderId, param::hstring const& authority)
{
    return impl::call_factory<WebAuthenticationCoreManager, Windows::Security::Authentication::Web::Core::IWebAuthenticationCoreManagerStatics4>([&](auto&& f) { return f.FindSystemAccountProviderAsync(webAccountProviderId, authority); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::WebAccountProvider> WebAuthenticationCoreManager::FindSystemAccountProviderAsync(param::hstring const& webAccountProviderId, param::hstring const& authority, Windows::System::User const& user)
{
    return impl::call_factory<WebAuthenticationCoreManager, Windows::Security::Authentication::Web::Core::IWebAuthenticationCoreManagerStatics4>([&](auto&& f) { return f.FindSystemAccountProviderAsync(webAccountProviderId, authority, user); });
}

inline WebProviderError::WebProviderError(uint32_t errorCode, param::hstring const& errorMessage) :
    WebProviderError(impl::call_factory<WebProviderError, Windows::Security::Authentication::Web::Core::IWebProviderErrorFactory>([&](auto&& f) { return f.Create(errorCode, errorMessage); }))
{}

inline WebTokenRequest::WebTokenRequest(Windows::Security::Credentials::WebAccountProvider const& provider, param::hstring const& scope, param::hstring const& clientId) :
    WebTokenRequest(impl::call_factory<WebTokenRequest, Windows::Security::Authentication::Web::Core::IWebTokenRequestFactory>([&](auto&& f) { return f.Create(provider, scope, clientId); }))
{}

inline WebTokenRequest::WebTokenRequest(Windows::Security::Credentials::WebAccountProvider const& provider, param::hstring const& scope, param::hstring const& clientId, Windows::Security::Authentication::Web::Core::WebTokenRequestPromptType const& promptType) :
    WebTokenRequest(impl::call_factory<WebTokenRequest, Windows::Security::Authentication::Web::Core::IWebTokenRequestFactory>([&](auto&& f) { return f.CreateWithPromptType(provider, scope, clientId, promptType); }))
{}

inline WebTokenRequest::WebTokenRequest(Windows::Security::Credentials::WebAccountProvider const& provider) :
    WebTokenRequest(impl::call_factory<WebTokenRequest, Windows::Security::Authentication::Web::Core::IWebTokenRequestFactory>([&](auto&& f) { return f.CreateWithProvider(provider); }))
{}

inline WebTokenRequest::WebTokenRequest(Windows::Security::Credentials::WebAccountProvider const& provider, param::hstring const& scope) :
    WebTokenRequest(impl::call_factory<WebTokenRequest, Windows::Security::Authentication::Web::Core::IWebTokenRequestFactory>([&](auto&& f) { return f.CreateWithScope(provider, scope); }))
{}

inline WebTokenResponse::WebTokenResponse() :
    WebTokenResponse(impl::call_factory<WebTokenResponse>([](auto&& f) { return f.template ActivateInstance<WebTokenResponse>(); }))
{}

inline WebTokenResponse::WebTokenResponse(param::hstring const& token) :
    WebTokenResponse(impl::call_factory<WebTokenResponse, Windows::Security::Authentication::Web::Core::IWebTokenResponseFactory>([&](auto&& f) { return f.CreateWithToken(token); }))
{}

inline WebTokenResponse::WebTokenResponse(param::hstring const& token, Windows::Security::Credentials::WebAccount const& webAccount) :
    WebTokenResponse(impl::call_factory<WebTokenResponse, Windows::Security::Authentication::Web::Core::IWebTokenResponseFactory>([&](auto&& f) { return f.CreateWithTokenAndAccount(token, webAccount); }))
{}

inline WebTokenResponse::WebTokenResponse(param::hstring const& token, Windows::Security::Credentials::WebAccount const& webAccount, Windows::Security::Authentication::Web::Core::WebProviderError const& error) :
    WebTokenResponse(impl::call_factory<WebTokenResponse, Windows::Security::Authentication::Web::Core::IWebTokenResponseFactory>([&](auto&& f) { return f.CreateWithTokenAccountAndError(token, webAccount, error); }))
{}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Security::Authentication::Web::Core::IFindAllAccountsResult> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Web::Core::IFindAllAccountsResult> {};
template<> struct hash<winrt::Windows::Security::Authentication::Web::Core::IWebAccountEventArgs> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Web::Core::IWebAccountEventArgs> {};
template<> struct hash<winrt::Windows::Security::Authentication::Web::Core::IWebAccountMonitor> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Web::Core::IWebAccountMonitor> {};
template<> struct hash<winrt::Windows::Security::Authentication::Web::Core::IWebAuthenticationCoreManagerStatics> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Web::Core::IWebAuthenticationCoreManagerStatics> {};
template<> struct hash<winrt::Windows::Security::Authentication::Web::Core::IWebAuthenticationCoreManagerStatics2> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Web::Core::IWebAuthenticationCoreManagerStatics2> {};
template<> struct hash<winrt::Windows::Security::Authentication::Web::Core::IWebAuthenticationCoreManagerStatics3> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Web::Core::IWebAuthenticationCoreManagerStatics3> {};
template<> struct hash<winrt::Windows::Security::Authentication::Web::Core::IWebAuthenticationCoreManagerStatics4> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Web::Core::IWebAuthenticationCoreManagerStatics4> {};
template<> struct hash<winrt::Windows::Security::Authentication::Web::Core::IWebProviderError> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Web::Core::IWebProviderError> {};
template<> struct hash<winrt::Windows::Security::Authentication::Web::Core::IWebProviderErrorFactory> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Web::Core::IWebProviderErrorFactory> {};
template<> struct hash<winrt::Windows::Security::Authentication::Web::Core::IWebTokenRequest> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Web::Core::IWebTokenRequest> {};
template<> struct hash<winrt::Windows::Security::Authentication::Web::Core::IWebTokenRequest2> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Web::Core::IWebTokenRequest2> {};
template<> struct hash<winrt::Windows::Security::Authentication::Web::Core::IWebTokenRequest3> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Web::Core::IWebTokenRequest3> {};
template<> struct hash<winrt::Windows::Security::Authentication::Web::Core::IWebTokenRequestFactory> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Web::Core::IWebTokenRequestFactory> {};
template<> struct hash<winrt::Windows::Security::Authentication::Web::Core::IWebTokenRequestResult> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Web::Core::IWebTokenRequestResult> {};
template<> struct hash<winrt::Windows::Security::Authentication::Web::Core::IWebTokenResponse> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Web::Core::IWebTokenResponse> {};
template<> struct hash<winrt::Windows::Security::Authentication::Web::Core::IWebTokenResponseFactory> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Web::Core::IWebTokenResponseFactory> {};
template<> struct hash<winrt::Windows::Security::Authentication::Web::Core::FindAllAccountsResult> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Web::Core::FindAllAccountsResult> {};
template<> struct hash<winrt::Windows::Security::Authentication::Web::Core::WebAccountEventArgs> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Web::Core::WebAccountEventArgs> {};
template<> struct hash<winrt::Windows::Security::Authentication::Web::Core::WebAccountMonitor> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Web::Core::WebAccountMonitor> {};
template<> struct hash<winrt::Windows::Security::Authentication::Web::Core::WebAuthenticationCoreManager> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Web::Core::WebAuthenticationCoreManager> {};
template<> struct hash<winrt::Windows::Security::Authentication::Web::Core::WebProviderError> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Web::Core::WebProviderError> {};
template<> struct hash<winrt::Windows::Security::Authentication::Web::Core::WebTokenRequest> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Web::Core::WebTokenRequest> {};
template<> struct hash<winrt::Windows::Security::Authentication::Web::Core::WebTokenRequestResult> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Web::Core::WebTokenRequestResult> {};
template<> struct hash<winrt::Windows::Security::Authentication::Web::Core::WebTokenResponse> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Web::Core::WebTokenResponse> {};

}
