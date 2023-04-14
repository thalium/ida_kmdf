// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Security.Authentication.Web.2.h"
#include "winrt/impl/Windows.Security.Authentication.Web.Core.2.h"
#include "winrt/impl/Windows.Security.Credentials.2.h"
#include "winrt/impl/Windows.Security.Cryptography.Core.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.Web.Http.2.h"
#include "winrt/impl/Windows.Security.Authentication.Web.Provider.2.h"
#include "winrt/Windows.Security.Authentication.Web.h"

namespace winrt::impl {

template <typename D> Windows::Foundation::Uri consume_Windows_Security_Authentication_Web_Provider_IWebAccountClientView<D>::ApplicationCallbackUri() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Provider::IWebAccountClientView)->get_ApplicationCallbackUri(put_abi(value)));
    return value;
}

template <typename D> Windows::Security::Authentication::Web::Provider::WebAccountClientViewType consume_Windows_Security_Authentication_Web_Provider_IWebAccountClientView<D>::Type() const
{
    Windows::Security::Authentication::Web::Provider::WebAccountClientViewType value{};
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Provider::IWebAccountClientView)->get_Type(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Authentication_Web_Provider_IWebAccountClientView<D>::AccountPairwiseId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Provider::IWebAccountClientView)->get_AccountPairwiseId(put_abi(value)));
    return value;
}

template <typename D> Windows::Security::Authentication::Web::Provider::WebAccountClientView consume_Windows_Security_Authentication_Web_Provider_IWebAccountClientViewFactory<D>::Create(Windows::Security::Authentication::Web::Provider::WebAccountClientViewType const& viewType, Windows::Foundation::Uri const& applicationCallbackUri) const
{
    Windows::Security::Authentication::Web::Provider::WebAccountClientView view{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Provider::IWebAccountClientViewFactory)->Create(get_abi(viewType), get_abi(applicationCallbackUri), put_abi(view)));
    return view;
}

template <typename D> Windows::Security::Authentication::Web::Provider::WebAccountClientView consume_Windows_Security_Authentication_Web_Provider_IWebAccountClientViewFactory<D>::CreateWithPairwiseId(Windows::Security::Authentication::Web::Provider::WebAccountClientViewType const& viewType, Windows::Foundation::Uri const& applicationCallbackUri, param::hstring const& accountPairwiseId) const
{
    Windows::Security::Authentication::Web::Provider::WebAccountClientView view{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Provider::IWebAccountClientViewFactory)->CreateWithPairwiseId(get_abi(viewType), get_abi(applicationCallbackUri), get_abi(accountPairwiseId), put_abi(view)));
    return view;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Security_Authentication_Web_Provider_IWebAccountManagerStatics<D>::UpdateWebAccountPropertiesAsync(Windows::Security::Credentials::WebAccount const& webAccount, param::hstring const& webAccountUserName, param::async_map_view<hstring, hstring> const& additionalProperties) const
{
    Windows::Foundation::IAsyncAction asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Provider::IWebAccountManagerStatics)->UpdateWebAccountPropertiesAsync(get_abi(webAccount), get_abi(webAccountUserName), get_abi(additionalProperties), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::WebAccount> consume_Windows_Security_Authentication_Web_Provider_IWebAccountManagerStatics<D>::AddWebAccountAsync(param::hstring const& webAccountId, param::hstring const& webAccountUserName, param::async_map_view<hstring, hstring> const& props) const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::WebAccount> asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Provider::IWebAccountManagerStatics)->AddWebAccountAsync(get_abi(webAccountId), get_abi(webAccountUserName), get_abi(props), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Security_Authentication_Web_Provider_IWebAccountManagerStatics<D>::DeleteWebAccountAsync(Windows::Security::Credentials::WebAccount const& webAccount) const
{
    Windows::Foundation::IAsyncAction asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Provider::IWebAccountManagerStatics)->DeleteWebAccountAsync(get_abi(webAccount), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Security::Credentials::WebAccount>> consume_Windows_Security_Authentication_Web_Provider_IWebAccountManagerStatics<D>::FindAllProviderWebAccountsAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Security::Credentials::WebAccount>> asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Provider::IWebAccountManagerStatics)->FindAllProviderWebAccountsAsync(put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Security_Authentication_Web_Provider_IWebAccountManagerStatics<D>::PushCookiesAsync(Windows::Foundation::Uri const& uri, param::async_vector_view<Windows::Web::Http::HttpCookie> const& cookies) const
{
    Windows::Foundation::IAsyncAction asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Provider::IWebAccountManagerStatics)->PushCookiesAsync(get_abi(uri), get_abi(cookies), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Security_Authentication_Web_Provider_IWebAccountManagerStatics<D>::SetViewAsync(Windows::Security::Credentials::WebAccount const& webAccount, Windows::Security::Authentication::Web::Provider::WebAccountClientView const& view) const
{
    Windows::Foundation::IAsyncAction asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Provider::IWebAccountManagerStatics)->SetViewAsync(get_abi(webAccount), get_abi(view), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Security_Authentication_Web_Provider_IWebAccountManagerStatics<D>::ClearViewAsync(Windows::Security::Credentials::WebAccount const& webAccount, Windows::Foundation::Uri const& applicationCallbackUri) const
{
    Windows::Foundation::IAsyncAction asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Provider::IWebAccountManagerStatics)->ClearViewAsync(get_abi(webAccount), get_abi(applicationCallbackUri), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Security::Authentication::Web::Provider::WebAccountClientView>> consume_Windows_Security_Authentication_Web_Provider_IWebAccountManagerStatics<D>::GetViewsAsync(Windows::Security::Credentials::WebAccount const& webAccount) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Security::Authentication::Web::Provider::WebAccountClientView>> asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Provider::IWebAccountManagerStatics)->GetViewsAsync(get_abi(webAccount), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Security_Authentication_Web_Provider_IWebAccountManagerStatics<D>::SetWebAccountPictureAsync(Windows::Security::Credentials::WebAccount const& webAccount, Windows::Storage::Streams::IRandomAccessStream const& webAccountPicture) const
{
    Windows::Foundation::IAsyncAction asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Provider::IWebAccountManagerStatics)->SetWebAccountPictureAsync(get_abi(webAccount), get_abi(webAccountPicture), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Security_Authentication_Web_Provider_IWebAccountManagerStatics<D>::ClearWebAccountPictureAsync(Windows::Security::Credentials::WebAccount const& webAccount) const
{
    Windows::Foundation::IAsyncAction asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Provider::IWebAccountManagerStatics)->ClearWebAccountPictureAsync(get_abi(webAccount), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Security_Authentication_Web_Provider_IWebAccountManagerStatics2<D>::PullCookiesAsync(param::hstring const& uriString, param::hstring const& callerPFN) const
{
    Windows::Foundation::IAsyncAction asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Provider::IWebAccountManagerStatics2)->PullCookiesAsync(get_abi(uriString), get_abi(callerPFN), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Security::Credentials::WebAccount>> consume_Windows_Security_Authentication_Web_Provider_IWebAccountManagerStatics3<D>::FindAllProviderWebAccountsForUserAsync(Windows::System::User const& user) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Security::Credentials::WebAccount>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Provider::IWebAccountManagerStatics3)->FindAllProviderWebAccountsForUserAsync(get_abi(user), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::WebAccount> consume_Windows_Security_Authentication_Web_Provider_IWebAccountManagerStatics3<D>::AddWebAccountForUserAsync(Windows::System::User const& user, param::hstring const& webAccountId, param::hstring const& webAccountUserName, param::async_map_view<hstring, hstring> const& props) const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::WebAccount> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Provider::IWebAccountManagerStatics3)->AddWebAccountForUserAsync(get_abi(user), get_abi(webAccountId), get_abi(webAccountUserName), get_abi(props), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::WebAccount> consume_Windows_Security_Authentication_Web_Provider_IWebAccountManagerStatics3<D>::AddWebAccountForUserAsync(Windows::System::User const& user, param::hstring const& webAccountId, param::hstring const& webAccountUserName, param::async_map_view<hstring, hstring> const& props, Windows::Security::Authentication::Web::Provider::WebAccountScope const& scope) const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::WebAccount> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Provider::IWebAccountManagerStatics3)->AddWebAccountWithScopeForUserAsync(get_abi(user), get_abi(webAccountId), get_abi(webAccountUserName), get_abi(props), get_abi(scope), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::WebAccount> consume_Windows_Security_Authentication_Web_Provider_IWebAccountManagerStatics3<D>::AddWebAccountForUserAsync(Windows::System::User const& user, param::hstring const& webAccountId, param::hstring const& webAccountUserName, param::async_map_view<hstring, hstring> const& props, Windows::Security::Authentication::Web::Provider::WebAccountScope const& scope, param::hstring const& perUserWebAccountId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::WebAccount> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Provider::IWebAccountManagerStatics3)->AddWebAccountWithScopeAndMapForUserAsync(get_abi(user), get_abi(webAccountId), get_abi(webAccountUserName), get_abi(props), get_abi(scope), get_abi(perUserWebAccountId), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Security_Authentication_Web_Provider_IWebAccountManagerStatics4<D>::InvalidateAppCacheForAllAccountsAsync() const
{
    Windows::Foundation::IAsyncAction asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Provider::IWebAccountManagerStatics4)->InvalidateAppCacheForAllAccountsAsync(put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Security_Authentication_Web_Provider_IWebAccountManagerStatics4<D>::InvalidateAppCacheForAccountAsync(Windows::Security::Credentials::WebAccount const& webAccount) const
{
    Windows::Foundation::IAsyncAction asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Provider::IWebAccountManagerStatics4)->InvalidateAppCacheForAccountAsync(get_abi(webAccount), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::WebAccount> consume_Windows_Security_Authentication_Web_Provider_IWebAccountMapManagerStatics<D>::AddWebAccountAsync(param::hstring const& webAccountId, param::hstring const& webAccountUserName, param::async_map_view<hstring, hstring> const& props, Windows::Security::Authentication::Web::Provider::WebAccountScope const& scope, param::hstring const& perUserWebAccountId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::WebAccount> asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Provider::IWebAccountMapManagerStatics)->AddWebAccountWithScopeAndMapAsync(get_abi(webAccountId), get_abi(webAccountUserName), get_abi(props), get_abi(scope), get_abi(perUserWebAccountId), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Security_Authentication_Web_Provider_IWebAccountMapManagerStatics<D>::SetPerAppToPerUserAccountAsync(Windows::Security::Credentials::WebAccount const& perAppAccount, param::hstring const& perUserWebAccountId) const
{
    Windows::Foundation::IAsyncAction asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Provider::IWebAccountMapManagerStatics)->SetPerAppToPerUserAccountAsync(get_abi(perAppAccount), get_abi(perUserWebAccountId), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::WebAccount> consume_Windows_Security_Authentication_Web_Provider_IWebAccountMapManagerStatics<D>::GetPerUserFromPerAppAccountAsync(Windows::Security::Credentials::WebAccount const& perAppAccount) const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::WebAccount> asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Provider::IWebAccountMapManagerStatics)->GetPerUserFromPerAppAccountAsync(get_abi(perAppAccount), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Security_Authentication_Web_Provider_IWebAccountMapManagerStatics<D>::ClearPerUserFromPerAppAccountAsync(Windows::Security::Credentials::WebAccount const& perAppAccount) const
{
    Windows::Foundation::IAsyncAction asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Provider::IWebAccountMapManagerStatics)->ClearPerUserFromPerAppAccountAsync(get_abi(perAppAccount), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> void consume_Windows_Security_Authentication_Web_Provider_IWebAccountProviderAddAccountOperation<D>::ReportCompleted() const
{
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Provider::IWebAccountProviderAddAccountOperation)->ReportCompleted());
}

template <typename D> void consume_Windows_Security_Authentication_Web_Provider_IWebAccountProviderBaseReportOperation<D>::ReportCompleted() const
{
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Provider::IWebAccountProviderBaseReportOperation)->ReportCompleted());
}

template <typename D> void consume_Windows_Security_Authentication_Web_Provider_IWebAccountProviderBaseReportOperation<D>::ReportError(Windows::Security::Authentication::Web::Core::WebProviderError const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Provider::IWebAccountProviderBaseReportOperation)->ReportError(get_abi(value)));
}

template <typename D> Windows::Security::Credentials::WebAccount consume_Windows_Security_Authentication_Web_Provider_IWebAccountProviderDeleteAccountOperation<D>::WebAccount() const
{
    Windows::Security::Credentials::WebAccount value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Provider::IWebAccountProviderDeleteAccountOperation)->get_WebAccount(put_abi(value)));
    return value;
}

template <typename D> Windows::Security::Credentials::WebAccount consume_Windows_Security_Authentication_Web_Provider_IWebAccountProviderManageAccountOperation<D>::WebAccount() const
{
    Windows::Security::Credentials::WebAccount value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Provider::IWebAccountProviderManageAccountOperation)->get_WebAccount(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Security_Authentication_Web_Provider_IWebAccountProviderManageAccountOperation<D>::ReportCompleted() const
{
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Provider::IWebAccountProviderManageAccountOperation)->ReportCompleted());
}

template <typename D> Windows::Security::Authentication::Web::Provider::WebAccountProviderOperationKind consume_Windows_Security_Authentication_Web_Provider_IWebAccountProviderOperation<D>::Kind() const
{
    Windows::Security::Authentication::Web::Provider::WebAccountProviderOperationKind value{};
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Provider::IWebAccountProviderOperation)->get_Kind(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Uri consume_Windows_Security_Authentication_Web_Provider_IWebAccountProviderRetrieveCookiesOperation<D>::Context() const
{
    Windows::Foundation::Uri webCookieRequestContext{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Provider::IWebAccountProviderRetrieveCookiesOperation)->get_Context(put_abi(webCookieRequestContext)));
    return webCookieRequestContext;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::Web::Http::HttpCookie> consume_Windows_Security_Authentication_Web_Provider_IWebAccountProviderRetrieveCookiesOperation<D>::Cookies() const
{
    Windows::Foundation::Collections::IVector<Windows::Web::Http::HttpCookie> cookies{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Provider::IWebAccountProviderRetrieveCookiesOperation)->get_Cookies(put_abi(cookies)));
    return cookies;
}

template <typename D> void consume_Windows_Security_Authentication_Web_Provider_IWebAccountProviderRetrieveCookiesOperation<D>::Uri(Windows::Foundation::Uri const& uri) const
{
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Provider::IWebAccountProviderRetrieveCookiesOperation)->put_Uri(get_abi(uri)));
}

template <typename D> Windows::Foundation::Uri consume_Windows_Security_Authentication_Web_Provider_IWebAccountProviderRetrieveCookiesOperation<D>::Uri() const
{
    Windows::Foundation::Uri uri{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Provider::IWebAccountProviderRetrieveCookiesOperation)->get_Uri(put_abi(uri)));
    return uri;
}

template <typename D> Windows::Foundation::Uri consume_Windows_Security_Authentication_Web_Provider_IWebAccountProviderRetrieveCookiesOperation<D>::ApplicationCallbackUri() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Provider::IWebAccountProviderRetrieveCookiesOperation)->get_ApplicationCallbackUri(put_abi(value)));
    return value;
}

template <typename D> Windows::Security::Credentials::WebAccount consume_Windows_Security_Authentication_Web_Provider_IWebAccountProviderSignOutAccountOperation<D>::WebAccount() const
{
    Windows::Security::Credentials::WebAccount value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Provider::IWebAccountProviderSignOutAccountOperation)->get_WebAccount(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Uri consume_Windows_Security_Authentication_Web_Provider_IWebAccountProviderSignOutAccountOperation<D>::ApplicationCallbackUri() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Provider::IWebAccountProviderSignOutAccountOperation)->get_ApplicationCallbackUri(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Authentication_Web_Provider_IWebAccountProviderSignOutAccountOperation<D>::ClientId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Provider::IWebAccountProviderSignOutAccountOperation)->get_ClientId(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Security_Authentication_Web_Provider_IWebAccountProviderSilentReportOperation<D>::ReportUserInteractionRequired() const
{
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Provider::IWebAccountProviderSilentReportOperation)->ReportUserInteractionRequired());
}

template <typename D> void consume_Windows_Security_Authentication_Web_Provider_IWebAccountProviderSilentReportOperation<D>::ReportUserInteractionRequired(Windows::Security::Authentication::Web::Core::WebProviderError const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Provider::IWebAccountProviderSilentReportOperation)->ReportUserInteractionRequiredWithError(get_abi(value)));
}

template <typename D> Windows::Security::Authentication::Web::Provider::IWebAccountProviderOperation consume_Windows_Security_Authentication_Web_Provider_IWebAccountProviderTokenObjects<D>::Operation() const
{
    Windows::Security::Authentication::Web::Provider::IWebAccountProviderOperation value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Provider::IWebAccountProviderTokenObjects)->get_Operation(put_abi(value)));
    return value;
}

template <typename D> Windows::System::User consume_Windows_Security_Authentication_Web_Provider_IWebAccountProviderTokenObjects2<D>::User() const
{
    Windows::System::User value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Provider::IWebAccountProviderTokenObjects2)->get_User(put_abi(value)));
    return value;
}

template <typename D> Windows::Security::Authentication::Web::Provider::WebProviderTokenRequest consume_Windows_Security_Authentication_Web_Provider_IWebAccountProviderTokenOperation<D>::ProviderRequest() const
{
    Windows::Security::Authentication::Web::Provider::WebProviderTokenRequest webTokenRequest{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Provider::IWebAccountProviderTokenOperation)->get_ProviderRequest(put_abi(webTokenRequest)));
    return webTokenRequest;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::Security::Authentication::Web::Provider::WebProviderTokenResponse> consume_Windows_Security_Authentication_Web_Provider_IWebAccountProviderTokenOperation<D>::ProviderResponses() const
{
    Windows::Foundation::Collections::IVector<Windows::Security::Authentication::Web::Provider::WebProviderTokenResponse> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Provider::IWebAccountProviderTokenOperation)->get_ProviderResponses(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Security_Authentication_Web_Provider_IWebAccountProviderTokenOperation<D>::CacheExpirationTime(Windows::Foundation::DateTime const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Provider::IWebAccountProviderTokenOperation)->put_CacheExpirationTime(get_abi(value)));
}

template <typename D> Windows::Foundation::DateTime consume_Windows_Security_Authentication_Web_Provider_IWebAccountProviderTokenOperation<D>::CacheExpirationTime() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Provider::IWebAccountProviderTokenOperation)->get_CacheExpirationTime(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Security_Authentication_Web_Provider_IWebAccountProviderUIReportOperation<D>::ReportUserCanceled() const
{
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Provider::IWebAccountProviderUIReportOperation)->ReportUserCanceled());
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::WebAccount> consume_Windows_Security_Authentication_Web_Provider_IWebAccountScopeManagerStatics<D>::AddWebAccountAsync(param::hstring const& webAccountId, param::hstring const& webAccountUserName, param::async_map_view<hstring, hstring> const& props, Windows::Security::Authentication::Web::Provider::WebAccountScope const& scope) const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::WebAccount> asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Provider::IWebAccountScopeManagerStatics)->AddWebAccountWithScopeAsync(get_abi(webAccountId), get_abi(webAccountUserName), get_abi(props), get_abi(scope), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Security_Authentication_Web_Provider_IWebAccountScopeManagerStatics<D>::SetScopeAsync(Windows::Security::Credentials::WebAccount const& webAccount, Windows::Security::Authentication::Web::Provider::WebAccountScope const& scope) const
{
    Windows::Foundation::IAsyncAction asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Provider::IWebAccountScopeManagerStatics)->SetScopeAsync(get_abi(webAccount), get_abi(scope), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Security::Authentication::Web::Provider::WebAccountScope consume_Windows_Security_Authentication_Web_Provider_IWebAccountScopeManagerStatics<D>::GetScope(Windows::Security::Credentials::WebAccount const& webAccount) const
{
    Windows::Security::Authentication::Web::Provider::WebAccountScope scope{};
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Provider::IWebAccountScopeManagerStatics)->GetScope(get_abi(webAccount), put_abi(scope)));
    return scope;
}

template <typename D> Windows::Security::Authentication::Web::Core::WebTokenRequest consume_Windows_Security_Authentication_Web_Provider_IWebProviderTokenRequest<D>::ClientRequest() const
{
    Windows::Security::Authentication::Web::Core::WebTokenRequest value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Provider::IWebProviderTokenRequest)->get_ClientRequest(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Security::Credentials::WebAccount> consume_Windows_Security_Authentication_Web_Provider_IWebProviderTokenRequest<D>::WebAccounts() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Security::Credentials::WebAccount> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Provider::IWebProviderTokenRequest)->get_WebAccounts(put_abi(value)));
    return value;
}

template <typename D> Windows::Security::Authentication::Web::Provider::WebAccountSelectionOptions consume_Windows_Security_Authentication_Web_Provider_IWebProviderTokenRequest<D>::WebAccountSelectionOptions() const
{
    Windows::Security::Authentication::Web::Provider::WebAccountSelectionOptions value{};
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Provider::IWebProviderTokenRequest)->get_WebAccountSelectionOptions(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Uri consume_Windows_Security_Authentication_Web_Provider_IWebProviderTokenRequest<D>::ApplicationCallbackUri() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Provider::IWebProviderTokenRequest)->get_ApplicationCallbackUri(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Security::Cryptography::Core::CryptographicKey> consume_Windows_Security_Authentication_Web_Provider_IWebProviderTokenRequest<D>::GetApplicationTokenBindingKeyAsync(Windows::Security::Authentication::Web::TokenBindingKeyType const& keyType, Windows::Foundation::Uri const& target) const
{
    Windows::Foundation::IAsyncOperation<Windows::Security::Cryptography::Core::CryptographicKey> asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Provider::IWebProviderTokenRequest)->GetApplicationTokenBindingKeyAsync(get_abi(keyType), get_abi(target), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer> consume_Windows_Security_Authentication_Web_Provider_IWebProviderTokenRequest2<D>::GetApplicationTokenBindingKeyIdAsync(Windows::Security::Authentication::Web::TokenBindingKeyType const& keyType, Windows::Foundation::Uri const& target) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer> asyncInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Provider::IWebProviderTokenRequest2)->GetApplicationTokenBindingKeyIdAsync(get_abi(keyType), get_abi(target), put_abi(asyncInfo)));
    return asyncInfo;
}

template <typename D> hstring consume_Windows_Security_Authentication_Web_Provider_IWebProviderTokenRequest3<D>::ApplicationPackageFamilyName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Provider::IWebProviderTokenRequest3)->get_ApplicationPackageFamilyName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Security_Authentication_Web_Provider_IWebProviderTokenRequest3<D>::ApplicationProcessName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Provider::IWebProviderTokenRequest3)->get_ApplicationProcessName(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Security_Authentication_Web_Provider_IWebProviderTokenRequest3<D>::CheckApplicationForCapabilityAsync(param::hstring const& capabilityName) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Provider::IWebProviderTokenRequest3)->CheckApplicationForCapabilityAsync(get_abi(capabilityName), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Security::Authentication::Web::Core::WebTokenResponse consume_Windows_Security_Authentication_Web_Provider_IWebProviderTokenResponse<D>::ClientResponse() const
{
    Windows::Security::Authentication::Web::Core::WebTokenResponse value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Provider::IWebProviderTokenResponse)->get_ClientResponse(put_abi(value)));
    return value;
}

template <typename D> Windows::Security::Authentication::Web::Provider::WebProviderTokenResponse consume_Windows_Security_Authentication_Web_Provider_IWebProviderTokenResponseFactory<D>::Create(Windows::Security::Authentication::Web::Core::WebTokenResponse const& webTokenResponse) const
{
    Windows::Security::Authentication::Web::Provider::WebProviderTokenResponse webProviderTokenResponse{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Security::Authentication::Web::Provider::IWebProviderTokenResponseFactory)->Create(get_abi(webTokenResponse), put_abi(webProviderTokenResponse)));
    return webProviderTokenResponse;
}

template <typename D>
struct produce<D, Windows::Security::Authentication::Web::Provider::IWebAccountClientView> : produce_base<D, Windows::Security::Authentication::Web::Provider::IWebAccountClientView>
{
    int32_t WINRT_CALL get_ApplicationCallbackUri(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ApplicationCallbackUri, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().ApplicationCallbackUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Type(Windows::Security::Authentication::Web::Provider::WebAccountClientViewType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Type, WINRT_WRAP(Windows::Security::Authentication::Web::Provider::WebAccountClientViewType));
            *value = detach_from<Windows::Security::Authentication::Web::Provider::WebAccountClientViewType>(this->shim().Type());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AccountPairwiseId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AccountPairwiseId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AccountPairwiseId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Authentication::Web::Provider::IWebAccountClientViewFactory> : produce_base<D, Windows::Security::Authentication::Web::Provider::IWebAccountClientViewFactory>
{
    int32_t WINRT_CALL Create(Windows::Security::Authentication::Web::Provider::WebAccountClientViewType viewType, void* applicationCallbackUri, void** view) noexcept final
    {
        try
        {
            *view = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Security::Authentication::Web::Provider::WebAccountClientView), Windows::Security::Authentication::Web::Provider::WebAccountClientViewType const&, Windows::Foundation::Uri const&);
            *view = detach_from<Windows::Security::Authentication::Web::Provider::WebAccountClientView>(this->shim().Create(*reinterpret_cast<Windows::Security::Authentication::Web::Provider::WebAccountClientViewType const*>(&viewType), *reinterpret_cast<Windows::Foundation::Uri const*>(&applicationCallbackUri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithPairwiseId(Windows::Security::Authentication::Web::Provider::WebAccountClientViewType viewType, void* applicationCallbackUri, void* accountPairwiseId, void** view) noexcept final
    {
        try
        {
            *view = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithPairwiseId, WINRT_WRAP(Windows::Security::Authentication::Web::Provider::WebAccountClientView), Windows::Security::Authentication::Web::Provider::WebAccountClientViewType const&, Windows::Foundation::Uri const&, hstring const&);
            *view = detach_from<Windows::Security::Authentication::Web::Provider::WebAccountClientView>(this->shim().CreateWithPairwiseId(*reinterpret_cast<Windows::Security::Authentication::Web::Provider::WebAccountClientViewType const*>(&viewType), *reinterpret_cast<Windows::Foundation::Uri const*>(&applicationCallbackUri), *reinterpret_cast<hstring const*>(&accountPairwiseId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Authentication::Web::Provider::IWebAccountManagerStatics> : produce_base<D, Windows::Security::Authentication::Web::Provider::IWebAccountManagerStatics>
{
    int32_t WINRT_CALL UpdateWebAccountPropertiesAsync(void* webAccount, void* webAccountUserName, void* additionalProperties, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpdateWebAccountPropertiesAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Security::Credentials::WebAccount const, hstring const, Windows::Foundation::Collections::IMapView<hstring, hstring> const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncAction>(this->shim().UpdateWebAccountPropertiesAsync(*reinterpret_cast<Windows::Security::Credentials::WebAccount const*>(&webAccount), *reinterpret_cast<hstring const*>(&webAccountUserName), *reinterpret_cast<Windows::Foundation::Collections::IMapView<hstring, hstring> const*>(&additionalProperties)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AddWebAccountAsync(void* webAccountId, void* webAccountUserName, void* props, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddWebAccountAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::WebAccount>), hstring const, hstring const, Windows::Foundation::Collections::IMapView<hstring, hstring> const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::WebAccount>>(this->shim().AddWebAccountAsync(*reinterpret_cast<hstring const*>(&webAccountId), *reinterpret_cast<hstring const*>(&webAccountUserName), *reinterpret_cast<Windows::Foundation::Collections::IMapView<hstring, hstring> const*>(&props)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DeleteWebAccountAsync(void* webAccount, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeleteWebAccountAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Security::Credentials::WebAccount const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncAction>(this->shim().DeleteWebAccountAsync(*reinterpret_cast<Windows::Security::Credentials::WebAccount const*>(&webAccount)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindAllProviderWebAccountsAsync(void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindAllProviderWebAccountsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Security::Credentials::WebAccount>>));
            *asyncInfo = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Security::Credentials::WebAccount>>>(this->shim().FindAllProviderWebAccountsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PushCookiesAsync(void* uri, void* cookies, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PushCookiesAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Foundation::Uri const, Windows::Foundation::Collections::IVectorView<Windows::Web::Http::HttpCookie> const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncAction>(this->shim().PushCookiesAsync(*reinterpret_cast<Windows::Foundation::Uri const*>(&uri), *reinterpret_cast<Windows::Foundation::Collections::IVectorView<Windows::Web::Http::HttpCookie> const*>(&cookies)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetViewAsync(void* webAccount, void* view, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetViewAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Security::Credentials::WebAccount const, Windows::Security::Authentication::Web::Provider::WebAccountClientView const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SetViewAsync(*reinterpret_cast<Windows::Security::Credentials::WebAccount const*>(&webAccount), *reinterpret_cast<Windows::Security::Authentication::Web::Provider::WebAccountClientView const*>(&view)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ClearViewAsync(void* webAccount, void* applicationCallbackUri, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClearViewAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Security::Credentials::WebAccount const, Windows::Foundation::Uri const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ClearViewAsync(*reinterpret_cast<Windows::Security::Credentials::WebAccount const*>(&webAccount), *reinterpret_cast<Windows::Foundation::Uri const*>(&applicationCallbackUri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetViewsAsync(void* webAccount, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetViewsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Security::Authentication::Web::Provider::WebAccountClientView>>), Windows::Security::Credentials::WebAccount const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Security::Authentication::Web::Provider::WebAccountClientView>>>(this->shim().GetViewsAsync(*reinterpret_cast<Windows::Security::Credentials::WebAccount const*>(&webAccount)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetWebAccountPictureAsync(void* webAccount, void* webAccountPicture, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetWebAccountPictureAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Security::Credentials::WebAccount const, Windows::Storage::Streams::IRandomAccessStream const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SetWebAccountPictureAsync(*reinterpret_cast<Windows::Security::Credentials::WebAccount const*>(&webAccount), *reinterpret_cast<Windows::Storage::Streams::IRandomAccessStream const*>(&webAccountPicture)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ClearWebAccountPictureAsync(void* webAccount, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClearWebAccountPictureAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Security::Credentials::WebAccount const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ClearWebAccountPictureAsync(*reinterpret_cast<Windows::Security::Credentials::WebAccount const*>(&webAccount)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Authentication::Web::Provider::IWebAccountManagerStatics2> : produce_base<D, Windows::Security::Authentication::Web::Provider::IWebAccountManagerStatics2>
{
    int32_t WINRT_CALL PullCookiesAsync(void* uriString, void* callerPFN, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PullCookiesAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), hstring const, hstring const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncAction>(this->shim().PullCookiesAsync(*reinterpret_cast<hstring const*>(&uriString), *reinterpret_cast<hstring const*>(&callerPFN)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Authentication::Web::Provider::IWebAccountManagerStatics3> : produce_base<D, Windows::Security::Authentication::Web::Provider::IWebAccountManagerStatics3>
{
    int32_t WINRT_CALL FindAllProviderWebAccountsForUserAsync(void* user, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindAllProviderWebAccountsForUserAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Security::Credentials::WebAccount>>), Windows::System::User const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Security::Credentials::WebAccount>>>(this->shim().FindAllProviderWebAccountsForUserAsync(*reinterpret_cast<Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AddWebAccountForUserAsync(void* user, void* webAccountId, void* webAccountUserName, void* props, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddWebAccountForUserAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::WebAccount>), Windows::System::User const, hstring const, hstring const, Windows::Foundation::Collections::IMapView<hstring, hstring> const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::WebAccount>>(this->shim().AddWebAccountForUserAsync(*reinterpret_cast<Windows::System::User const*>(&user), *reinterpret_cast<hstring const*>(&webAccountId), *reinterpret_cast<hstring const*>(&webAccountUserName), *reinterpret_cast<Windows::Foundation::Collections::IMapView<hstring, hstring> const*>(&props)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AddWebAccountWithScopeForUserAsync(void* user, void* webAccountId, void* webAccountUserName, void* props, Windows::Security::Authentication::Web::Provider::WebAccountScope scope, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddWebAccountForUserAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::WebAccount>), Windows::System::User const, hstring const, hstring const, Windows::Foundation::Collections::IMapView<hstring, hstring> const, Windows::Security::Authentication::Web::Provider::WebAccountScope const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::WebAccount>>(this->shim().AddWebAccountForUserAsync(*reinterpret_cast<Windows::System::User const*>(&user), *reinterpret_cast<hstring const*>(&webAccountId), *reinterpret_cast<hstring const*>(&webAccountUserName), *reinterpret_cast<Windows::Foundation::Collections::IMapView<hstring, hstring> const*>(&props), *reinterpret_cast<Windows::Security::Authentication::Web::Provider::WebAccountScope const*>(&scope)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AddWebAccountWithScopeAndMapForUserAsync(void* user, void* webAccountId, void* webAccountUserName, void* props, Windows::Security::Authentication::Web::Provider::WebAccountScope scope, void* perUserWebAccountId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddWebAccountForUserAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::WebAccount>), Windows::System::User const, hstring const, hstring const, Windows::Foundation::Collections::IMapView<hstring, hstring> const, Windows::Security::Authentication::Web::Provider::WebAccountScope const, hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::WebAccount>>(this->shim().AddWebAccountForUserAsync(*reinterpret_cast<Windows::System::User const*>(&user), *reinterpret_cast<hstring const*>(&webAccountId), *reinterpret_cast<hstring const*>(&webAccountUserName), *reinterpret_cast<Windows::Foundation::Collections::IMapView<hstring, hstring> const*>(&props), *reinterpret_cast<Windows::Security::Authentication::Web::Provider::WebAccountScope const*>(&scope), *reinterpret_cast<hstring const*>(&perUserWebAccountId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Authentication::Web::Provider::IWebAccountManagerStatics4> : produce_base<D, Windows::Security::Authentication::Web::Provider::IWebAccountManagerStatics4>
{
    int32_t WINRT_CALL InvalidateAppCacheForAllAccountsAsync(void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InvalidateAppCacheForAllAccountsAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *asyncInfo = detach_from<Windows::Foundation::IAsyncAction>(this->shim().InvalidateAppCacheForAllAccountsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL InvalidateAppCacheForAccountAsync(void* webAccount, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InvalidateAppCacheForAccountAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Security::Credentials::WebAccount const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncAction>(this->shim().InvalidateAppCacheForAccountAsync(*reinterpret_cast<Windows::Security::Credentials::WebAccount const*>(&webAccount)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Authentication::Web::Provider::IWebAccountMapManagerStatics> : produce_base<D, Windows::Security::Authentication::Web::Provider::IWebAccountMapManagerStatics>
{
    int32_t WINRT_CALL AddWebAccountWithScopeAndMapAsync(void* webAccountId, void* webAccountUserName, void* props, Windows::Security::Authentication::Web::Provider::WebAccountScope scope, void* perUserWebAccountId, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddWebAccountAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::WebAccount>), hstring const, hstring const, Windows::Foundation::Collections::IMapView<hstring, hstring> const, Windows::Security::Authentication::Web::Provider::WebAccountScope const, hstring const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::WebAccount>>(this->shim().AddWebAccountAsync(*reinterpret_cast<hstring const*>(&webAccountId), *reinterpret_cast<hstring const*>(&webAccountUserName), *reinterpret_cast<Windows::Foundation::Collections::IMapView<hstring, hstring> const*>(&props), *reinterpret_cast<Windows::Security::Authentication::Web::Provider::WebAccountScope const*>(&scope), *reinterpret_cast<hstring const*>(&perUserWebAccountId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetPerAppToPerUserAccountAsync(void* perAppAccount, void* perUserWebAccountId, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetPerAppToPerUserAccountAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Security::Credentials::WebAccount const, hstring const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SetPerAppToPerUserAccountAsync(*reinterpret_cast<Windows::Security::Credentials::WebAccount const*>(&perAppAccount), *reinterpret_cast<hstring const*>(&perUserWebAccountId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetPerUserFromPerAppAccountAsync(void* perAppAccount, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetPerUserFromPerAppAccountAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::WebAccount>), Windows::Security::Credentials::WebAccount const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::WebAccount>>(this->shim().GetPerUserFromPerAppAccountAsync(*reinterpret_cast<Windows::Security::Credentials::WebAccount const*>(&perAppAccount)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ClearPerUserFromPerAppAccountAsync(void* perAppAccount, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClearPerUserFromPerAppAccountAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Security::Credentials::WebAccount const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ClearPerUserFromPerAppAccountAsync(*reinterpret_cast<Windows::Security::Credentials::WebAccount const*>(&perAppAccount)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Authentication::Web::Provider::IWebAccountProviderAddAccountOperation> : produce_base<D, Windows::Security::Authentication::Web::Provider::IWebAccountProviderAddAccountOperation>
{
    int32_t WINRT_CALL ReportCompleted() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportCompleted, WINRT_WRAP(void));
            this->shim().ReportCompleted();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Authentication::Web::Provider::IWebAccountProviderBaseReportOperation> : produce_base<D, Windows::Security::Authentication::Web::Provider::IWebAccountProviderBaseReportOperation>
{
    int32_t WINRT_CALL ReportCompleted() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportCompleted, WINRT_WRAP(void));
            this->shim().ReportCompleted();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReportError(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportError, WINRT_WRAP(void), Windows::Security::Authentication::Web::Core::WebProviderError const&);
            this->shim().ReportError(*reinterpret_cast<Windows::Security::Authentication::Web::Core::WebProviderError const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Authentication::Web::Provider::IWebAccountProviderDeleteAccountOperation> : produce_base<D, Windows::Security::Authentication::Web::Provider::IWebAccountProviderDeleteAccountOperation>
{
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
};

template <typename D>
struct produce<D, Windows::Security::Authentication::Web::Provider::IWebAccountProviderManageAccountOperation> : produce_base<D, Windows::Security::Authentication::Web::Provider::IWebAccountProviderManageAccountOperation>
{
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

    int32_t WINRT_CALL ReportCompleted() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportCompleted, WINRT_WRAP(void));
            this->shim().ReportCompleted();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Authentication::Web::Provider::IWebAccountProviderOperation> : produce_base<D, Windows::Security::Authentication::Web::Provider::IWebAccountProviderOperation>
{
    int32_t WINRT_CALL get_Kind(Windows::Security::Authentication::Web::Provider::WebAccountProviderOperationKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Kind, WINRT_WRAP(Windows::Security::Authentication::Web::Provider::WebAccountProviderOperationKind));
            *value = detach_from<Windows::Security::Authentication::Web::Provider::WebAccountProviderOperationKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Authentication::Web::Provider::IWebAccountProviderRetrieveCookiesOperation> : produce_base<D, Windows::Security::Authentication::Web::Provider::IWebAccountProviderRetrieveCookiesOperation>
{
    int32_t WINRT_CALL get_Context(void** webCookieRequestContext) noexcept final
    {
        try
        {
            *webCookieRequestContext = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Context, WINRT_WRAP(Windows::Foundation::Uri));
            *webCookieRequestContext = detach_from<Windows::Foundation::Uri>(this->shim().Context());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Cookies(void** cookies) noexcept final
    {
        try
        {
            *cookies = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Cookies, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::Web::Http::HttpCookie>));
            *cookies = detach_from<Windows::Foundation::Collections::IVector<Windows::Web::Http::HttpCookie>>(this->shim().Cookies());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Uri(void* uri) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Uri, WINRT_WRAP(void), Windows::Foundation::Uri const&);
            this->shim().Uri(*reinterpret_cast<Windows::Foundation::Uri const*>(&uri));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Uri(void** uri) noexcept final
    {
        try
        {
            *uri = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Uri, WINRT_WRAP(Windows::Foundation::Uri));
            *uri = detach_from<Windows::Foundation::Uri>(this->shim().Uri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ApplicationCallbackUri(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ApplicationCallbackUri, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().ApplicationCallbackUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Authentication::Web::Provider::IWebAccountProviderSignOutAccountOperation> : produce_base<D, Windows::Security::Authentication::Web::Provider::IWebAccountProviderSignOutAccountOperation>
{
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

    int32_t WINRT_CALL get_ApplicationCallbackUri(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ApplicationCallbackUri, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().ApplicationCallbackUri());
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
};

template <typename D>
struct produce<D, Windows::Security::Authentication::Web::Provider::IWebAccountProviderSilentReportOperation> : produce_base<D, Windows::Security::Authentication::Web::Provider::IWebAccountProviderSilentReportOperation>
{
    int32_t WINRT_CALL ReportUserInteractionRequired() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportUserInteractionRequired, WINRT_WRAP(void));
            this->shim().ReportUserInteractionRequired();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReportUserInteractionRequiredWithError(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportUserInteractionRequired, WINRT_WRAP(void), Windows::Security::Authentication::Web::Core::WebProviderError const&);
            this->shim().ReportUserInteractionRequired(*reinterpret_cast<Windows::Security::Authentication::Web::Core::WebProviderError const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Authentication::Web::Provider::IWebAccountProviderTokenObjects> : produce_base<D, Windows::Security::Authentication::Web::Provider::IWebAccountProviderTokenObjects>
{
    int32_t WINRT_CALL get_Operation(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Operation, WINRT_WRAP(Windows::Security::Authentication::Web::Provider::IWebAccountProviderOperation));
            *value = detach_from<Windows::Security::Authentication::Web::Provider::IWebAccountProviderOperation>(this->shim().Operation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Authentication::Web::Provider::IWebAccountProviderTokenObjects2> : produce_base<D, Windows::Security::Authentication::Web::Provider::IWebAccountProviderTokenObjects2>
{
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
struct produce<D, Windows::Security::Authentication::Web::Provider::IWebAccountProviderTokenOperation> : produce_base<D, Windows::Security::Authentication::Web::Provider::IWebAccountProviderTokenOperation>
{
    int32_t WINRT_CALL get_ProviderRequest(void** webTokenRequest) noexcept final
    {
        try
        {
            *webTokenRequest = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProviderRequest, WINRT_WRAP(Windows::Security::Authentication::Web::Provider::WebProviderTokenRequest));
            *webTokenRequest = detach_from<Windows::Security::Authentication::Web::Provider::WebProviderTokenRequest>(this->shim().ProviderRequest());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProviderResponses(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProviderResponses, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::Security::Authentication::Web::Provider::WebProviderTokenResponse>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::Security::Authentication::Web::Provider::WebProviderTokenResponse>>(this->shim().ProviderResponses());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CacheExpirationTime(Windows::Foundation::DateTime value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CacheExpirationTime, WINRT_WRAP(void), Windows::Foundation::DateTime const&);
            this->shim().CacheExpirationTime(*reinterpret_cast<Windows::Foundation::DateTime const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CacheExpirationTime(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CacheExpirationTime, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().CacheExpirationTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Authentication::Web::Provider::IWebAccountProviderUIReportOperation> : produce_base<D, Windows::Security::Authentication::Web::Provider::IWebAccountProviderUIReportOperation>
{
    int32_t WINRT_CALL ReportUserCanceled() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportUserCanceled, WINRT_WRAP(void));
            this->shim().ReportUserCanceled();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Authentication::Web::Provider::IWebAccountScopeManagerStatics> : produce_base<D, Windows::Security::Authentication::Web::Provider::IWebAccountScopeManagerStatics>
{
    int32_t WINRT_CALL AddWebAccountWithScopeAsync(void* webAccountId, void* webAccountUserName, void* props, Windows::Security::Authentication::Web::Provider::WebAccountScope scope, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddWebAccountAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::WebAccount>), hstring const, hstring const, Windows::Foundation::Collections::IMapView<hstring, hstring> const, Windows::Security::Authentication::Web::Provider::WebAccountScope const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::WebAccount>>(this->shim().AddWebAccountAsync(*reinterpret_cast<hstring const*>(&webAccountId), *reinterpret_cast<hstring const*>(&webAccountUserName), *reinterpret_cast<Windows::Foundation::Collections::IMapView<hstring, hstring> const*>(&props), *reinterpret_cast<Windows::Security::Authentication::Web::Provider::WebAccountScope const*>(&scope)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetScopeAsync(void* webAccount, Windows::Security::Authentication::Web::Provider::WebAccountScope scope, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetScopeAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Security::Credentials::WebAccount const, Windows::Security::Authentication::Web::Provider::WebAccountScope const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SetScopeAsync(*reinterpret_cast<Windows::Security::Credentials::WebAccount const*>(&webAccount), *reinterpret_cast<Windows::Security::Authentication::Web::Provider::WebAccountScope const*>(&scope)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetScope(void* webAccount, Windows::Security::Authentication::Web::Provider::WebAccountScope* scope) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetScope, WINRT_WRAP(Windows::Security::Authentication::Web::Provider::WebAccountScope), Windows::Security::Credentials::WebAccount const&);
            *scope = detach_from<Windows::Security::Authentication::Web::Provider::WebAccountScope>(this->shim().GetScope(*reinterpret_cast<Windows::Security::Credentials::WebAccount const*>(&webAccount)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Authentication::Web::Provider::IWebProviderTokenRequest> : produce_base<D, Windows::Security::Authentication::Web::Provider::IWebProviderTokenRequest>
{
    int32_t WINRT_CALL get_ClientRequest(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClientRequest, WINRT_WRAP(Windows::Security::Authentication::Web::Core::WebTokenRequest));
            *value = detach_from<Windows::Security::Authentication::Web::Core::WebTokenRequest>(this->shim().ClientRequest());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WebAccounts(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WebAccounts, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Security::Credentials::WebAccount>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Security::Credentials::WebAccount>>(this->shim().WebAccounts());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WebAccountSelectionOptions(Windows::Security::Authentication::Web::Provider::WebAccountSelectionOptions* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WebAccountSelectionOptions, WINRT_WRAP(Windows::Security::Authentication::Web::Provider::WebAccountSelectionOptions));
            *value = detach_from<Windows::Security::Authentication::Web::Provider::WebAccountSelectionOptions>(this->shim().WebAccountSelectionOptions());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ApplicationCallbackUri(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ApplicationCallbackUri, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().ApplicationCallbackUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetApplicationTokenBindingKeyAsync(Windows::Security::Authentication::Web::TokenBindingKeyType keyType, void* target, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetApplicationTokenBindingKeyAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Security::Cryptography::Core::CryptographicKey>), Windows::Security::Authentication::Web::TokenBindingKeyType const, Windows::Foundation::Uri const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncOperation<Windows::Security::Cryptography::Core::CryptographicKey>>(this->shim().GetApplicationTokenBindingKeyAsync(*reinterpret_cast<Windows::Security::Authentication::Web::TokenBindingKeyType const*>(&keyType), *reinterpret_cast<Windows::Foundation::Uri const*>(&target)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Authentication::Web::Provider::IWebProviderTokenRequest2> : produce_base<D, Windows::Security::Authentication::Web::Provider::IWebProviderTokenRequest2>
{
    int32_t WINRT_CALL GetApplicationTokenBindingKeyIdAsync(Windows::Security::Authentication::Web::TokenBindingKeyType keyType, void* target, void** asyncInfo) noexcept final
    {
        try
        {
            *asyncInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetApplicationTokenBindingKeyIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer>), Windows::Security::Authentication::Web::TokenBindingKeyType const, Windows::Foundation::Uri const);
            *asyncInfo = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer>>(this->shim().GetApplicationTokenBindingKeyIdAsync(*reinterpret_cast<Windows::Security::Authentication::Web::TokenBindingKeyType const*>(&keyType), *reinterpret_cast<Windows::Foundation::Uri const*>(&target)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Authentication::Web::Provider::IWebProviderTokenRequest3> : produce_base<D, Windows::Security::Authentication::Web::Provider::IWebProviderTokenRequest3>
{
    int32_t WINRT_CALL get_ApplicationPackageFamilyName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ApplicationPackageFamilyName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ApplicationPackageFamilyName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ApplicationProcessName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ApplicationProcessName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ApplicationProcessName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CheckApplicationForCapabilityAsync(void* capabilityName, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CheckApplicationForCapabilityAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().CheckApplicationForCapabilityAsync(*reinterpret_cast<hstring const*>(&capabilityName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Authentication::Web::Provider::IWebProviderTokenResponse> : produce_base<D, Windows::Security::Authentication::Web::Provider::IWebProviderTokenResponse>
{
    int32_t WINRT_CALL get_ClientResponse(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClientResponse, WINRT_WRAP(Windows::Security::Authentication::Web::Core::WebTokenResponse));
            *value = detach_from<Windows::Security::Authentication::Web::Core::WebTokenResponse>(this->shim().ClientResponse());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Security::Authentication::Web::Provider::IWebProviderTokenResponseFactory> : produce_base<D, Windows::Security::Authentication::Web::Provider::IWebProviderTokenResponseFactory>
{
    int32_t WINRT_CALL Create(void* webTokenResponse, void** webProviderTokenResponse) noexcept final
    {
        try
        {
            *webProviderTokenResponse = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Security::Authentication::Web::Provider::WebProviderTokenResponse), Windows::Security::Authentication::Web::Core::WebTokenResponse const&);
            *webProviderTokenResponse = detach_from<Windows::Security::Authentication::Web::Provider::WebProviderTokenResponse>(this->shim().Create(*reinterpret_cast<Windows::Security::Authentication::Web::Core::WebTokenResponse const*>(&webTokenResponse)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Security::Authentication::Web::Provider {

inline WebAccountClientView::WebAccountClientView(Windows::Security::Authentication::Web::Provider::WebAccountClientViewType const& viewType, Windows::Foundation::Uri const& applicationCallbackUri) :
    WebAccountClientView(impl::call_factory<WebAccountClientView, Windows::Security::Authentication::Web::Provider::IWebAccountClientViewFactory>([&](auto&& f) { return f.Create(viewType, applicationCallbackUri); }))
{}

inline WebAccountClientView::WebAccountClientView(Windows::Security::Authentication::Web::Provider::WebAccountClientViewType const& viewType, Windows::Foundation::Uri const& applicationCallbackUri, param::hstring const& accountPairwiseId) :
    WebAccountClientView(impl::call_factory<WebAccountClientView, Windows::Security::Authentication::Web::Provider::IWebAccountClientViewFactory>([&](auto&& f) { return f.CreateWithPairwiseId(viewType, applicationCallbackUri, accountPairwiseId); }))
{}

inline Windows::Foundation::IAsyncAction WebAccountManager::UpdateWebAccountPropertiesAsync(Windows::Security::Credentials::WebAccount const& webAccount, param::hstring const& webAccountUserName, param::async_map_view<hstring, hstring> const& additionalProperties)
{
    return impl::call_factory<WebAccountManager, Windows::Security::Authentication::Web::Provider::IWebAccountManagerStatics>([&](auto&& f) { return f.UpdateWebAccountPropertiesAsync(webAccount, webAccountUserName, additionalProperties); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::WebAccount> WebAccountManager::AddWebAccountAsync(param::hstring const& webAccountId, param::hstring const& webAccountUserName, param::async_map_view<hstring, hstring> const& props)
{
    return impl::call_factory<WebAccountManager, Windows::Security::Authentication::Web::Provider::IWebAccountManagerStatics>([&](auto&& f) { return f.AddWebAccountAsync(webAccountId, webAccountUserName, props); });
}

inline Windows::Foundation::IAsyncAction WebAccountManager::DeleteWebAccountAsync(Windows::Security::Credentials::WebAccount const& webAccount)
{
    return impl::call_factory<WebAccountManager, Windows::Security::Authentication::Web::Provider::IWebAccountManagerStatics>([&](auto&& f) { return f.DeleteWebAccountAsync(webAccount); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Security::Credentials::WebAccount>> WebAccountManager::FindAllProviderWebAccountsAsync()
{
    return impl::call_factory<WebAccountManager, Windows::Security::Authentication::Web::Provider::IWebAccountManagerStatics>([&](auto&& f) { return f.FindAllProviderWebAccountsAsync(); });
}

inline Windows::Foundation::IAsyncAction WebAccountManager::PushCookiesAsync(Windows::Foundation::Uri const& uri, param::async_vector_view<Windows::Web::Http::HttpCookie> const& cookies)
{
    return impl::call_factory<WebAccountManager, Windows::Security::Authentication::Web::Provider::IWebAccountManagerStatics>([&](auto&& f) { return f.PushCookiesAsync(uri, cookies); });
}

inline Windows::Foundation::IAsyncAction WebAccountManager::SetViewAsync(Windows::Security::Credentials::WebAccount const& webAccount, Windows::Security::Authentication::Web::Provider::WebAccountClientView const& view)
{
    return impl::call_factory<WebAccountManager, Windows::Security::Authentication::Web::Provider::IWebAccountManagerStatics>([&](auto&& f) { return f.SetViewAsync(webAccount, view); });
}

inline Windows::Foundation::IAsyncAction WebAccountManager::ClearViewAsync(Windows::Security::Credentials::WebAccount const& webAccount, Windows::Foundation::Uri const& applicationCallbackUri)
{
    return impl::call_factory<WebAccountManager, Windows::Security::Authentication::Web::Provider::IWebAccountManagerStatics>([&](auto&& f) { return f.ClearViewAsync(webAccount, applicationCallbackUri); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Security::Authentication::Web::Provider::WebAccountClientView>> WebAccountManager::GetViewsAsync(Windows::Security::Credentials::WebAccount const& webAccount)
{
    return impl::call_factory<WebAccountManager, Windows::Security::Authentication::Web::Provider::IWebAccountManagerStatics>([&](auto&& f) { return f.GetViewsAsync(webAccount); });
}

inline Windows::Foundation::IAsyncAction WebAccountManager::SetWebAccountPictureAsync(Windows::Security::Credentials::WebAccount const& webAccount, Windows::Storage::Streams::IRandomAccessStream const& webAccountPicture)
{
    return impl::call_factory<WebAccountManager, Windows::Security::Authentication::Web::Provider::IWebAccountManagerStatics>([&](auto&& f) { return f.SetWebAccountPictureAsync(webAccount, webAccountPicture); });
}

inline Windows::Foundation::IAsyncAction WebAccountManager::ClearWebAccountPictureAsync(Windows::Security::Credentials::WebAccount const& webAccount)
{
    return impl::call_factory<WebAccountManager, Windows::Security::Authentication::Web::Provider::IWebAccountManagerStatics>([&](auto&& f) { return f.ClearWebAccountPictureAsync(webAccount); });
}

inline Windows::Foundation::IAsyncAction WebAccountManager::PullCookiesAsync(param::hstring const& uriString, param::hstring const& callerPFN)
{
    return impl::call_factory<WebAccountManager, Windows::Security::Authentication::Web::Provider::IWebAccountManagerStatics2>([&](auto&& f) { return f.PullCookiesAsync(uriString, callerPFN); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Security::Credentials::WebAccount>> WebAccountManager::FindAllProviderWebAccountsForUserAsync(Windows::System::User const& user)
{
    return impl::call_factory<WebAccountManager, Windows::Security::Authentication::Web::Provider::IWebAccountManagerStatics3>([&](auto&& f) { return f.FindAllProviderWebAccountsForUserAsync(user); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::WebAccount> WebAccountManager::AddWebAccountForUserAsync(Windows::System::User const& user, param::hstring const& webAccountId, param::hstring const& webAccountUserName, param::async_map_view<hstring, hstring> const& props)
{
    return impl::call_factory<WebAccountManager, Windows::Security::Authentication::Web::Provider::IWebAccountManagerStatics3>([&](auto&& f) { return f.AddWebAccountForUserAsync(user, webAccountId, webAccountUserName, props); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::WebAccount> WebAccountManager::AddWebAccountForUserAsync(Windows::System::User const& user, param::hstring const& webAccountId, param::hstring const& webAccountUserName, param::async_map_view<hstring, hstring> const& props, Windows::Security::Authentication::Web::Provider::WebAccountScope const& scope)
{
    return impl::call_factory<WebAccountManager, Windows::Security::Authentication::Web::Provider::IWebAccountManagerStatics3>([&](auto&& f) { return f.AddWebAccountForUserAsync(user, webAccountId, webAccountUserName, props, scope); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::WebAccount> WebAccountManager::AddWebAccountForUserAsync(Windows::System::User const& user, param::hstring const& webAccountId, param::hstring const& webAccountUserName, param::async_map_view<hstring, hstring> const& props, Windows::Security::Authentication::Web::Provider::WebAccountScope const& scope, param::hstring const& perUserWebAccountId)
{
    return impl::call_factory<WebAccountManager, Windows::Security::Authentication::Web::Provider::IWebAccountManagerStatics3>([&](auto&& f) { return f.AddWebAccountForUserAsync(user, webAccountId, webAccountUserName, props, scope, perUserWebAccountId); });
}

inline Windows::Foundation::IAsyncAction WebAccountManager::InvalidateAppCacheForAllAccountsAsync()
{
    return impl::call_factory<WebAccountManager, Windows::Security::Authentication::Web::Provider::IWebAccountManagerStatics4>([&](auto&& f) { return f.InvalidateAppCacheForAllAccountsAsync(); });
}

inline Windows::Foundation::IAsyncAction WebAccountManager::InvalidateAppCacheForAccountAsync(Windows::Security::Credentials::WebAccount const& webAccount)
{
    return impl::call_factory<WebAccountManager, Windows::Security::Authentication::Web::Provider::IWebAccountManagerStatics4>([&](auto&& f) { return f.InvalidateAppCacheForAccountAsync(webAccount); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::WebAccount> WebAccountManager::AddWebAccountAsync(param::hstring const& webAccountId, param::hstring const& webAccountUserName, param::async_map_view<hstring, hstring> const& props, Windows::Security::Authentication::Web::Provider::WebAccountScope const& scope, param::hstring const& perUserWebAccountId)
{
    return impl::call_factory<WebAccountManager, Windows::Security::Authentication::Web::Provider::IWebAccountMapManagerStatics>([&](auto&& f) { return f.AddWebAccountAsync(webAccountId, webAccountUserName, props, scope, perUserWebAccountId); });
}

inline Windows::Foundation::IAsyncAction WebAccountManager::SetPerAppToPerUserAccountAsync(Windows::Security::Credentials::WebAccount const& perAppAccount, param::hstring const& perUserWebAccountId)
{
    return impl::call_factory<WebAccountManager, Windows::Security::Authentication::Web::Provider::IWebAccountMapManagerStatics>([&](auto&& f) { return f.SetPerAppToPerUserAccountAsync(perAppAccount, perUserWebAccountId); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::WebAccount> WebAccountManager::GetPerUserFromPerAppAccountAsync(Windows::Security::Credentials::WebAccount const& perAppAccount)
{
    return impl::call_factory<WebAccountManager, Windows::Security::Authentication::Web::Provider::IWebAccountMapManagerStatics>([&](auto&& f) { return f.GetPerUserFromPerAppAccountAsync(perAppAccount); });
}

inline Windows::Foundation::IAsyncAction WebAccountManager::ClearPerUserFromPerAppAccountAsync(Windows::Security::Credentials::WebAccount const& perAppAccount)
{
    return impl::call_factory<WebAccountManager, Windows::Security::Authentication::Web::Provider::IWebAccountMapManagerStatics>([&](auto&& f) { return f.ClearPerUserFromPerAppAccountAsync(perAppAccount); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Security::Credentials::WebAccount> WebAccountManager::AddWebAccountAsync(param::hstring const& webAccountId, param::hstring const& webAccountUserName, param::async_map_view<hstring, hstring> const& props, Windows::Security::Authentication::Web::Provider::WebAccountScope const& scope)
{
    return impl::call_factory<WebAccountManager, Windows::Security::Authentication::Web::Provider::IWebAccountScopeManagerStatics>([&](auto&& f) { return f.AddWebAccountAsync(webAccountId, webAccountUserName, props, scope); });
}

inline Windows::Foundation::IAsyncAction WebAccountManager::SetScopeAsync(Windows::Security::Credentials::WebAccount const& webAccount, Windows::Security::Authentication::Web::Provider::WebAccountScope const& scope)
{
    return impl::call_factory<WebAccountManager, Windows::Security::Authentication::Web::Provider::IWebAccountScopeManagerStatics>([&](auto&& f) { return f.SetScopeAsync(webAccount, scope); });
}

inline Windows::Security::Authentication::Web::Provider::WebAccountScope WebAccountManager::GetScope(Windows::Security::Credentials::WebAccount const& webAccount)
{
    return impl::call_factory<WebAccountManager, Windows::Security::Authentication::Web::Provider::IWebAccountScopeManagerStatics>([&](auto&& f) { return f.GetScope(webAccount); });
}

inline WebProviderTokenResponse::WebProviderTokenResponse(Windows::Security::Authentication::Web::Core::WebTokenResponse const& webTokenResponse) :
    WebProviderTokenResponse(impl::call_factory<WebProviderTokenResponse, Windows::Security::Authentication::Web::Provider::IWebProviderTokenResponseFactory>([&](auto&& f) { return f.Create(webTokenResponse); }))
{}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountClientView> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountClientView> {};
template<> struct hash<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountClientViewFactory> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountClientViewFactory> {};
template<> struct hash<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountManagerStatics> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountManagerStatics> {};
template<> struct hash<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountManagerStatics2> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountManagerStatics2> {};
template<> struct hash<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountManagerStatics3> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountManagerStatics3> {};
template<> struct hash<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountManagerStatics4> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountManagerStatics4> {};
template<> struct hash<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountMapManagerStatics> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountMapManagerStatics> {};
template<> struct hash<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderAddAccountOperation> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderAddAccountOperation> {};
template<> struct hash<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderBaseReportOperation> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderBaseReportOperation> {};
template<> struct hash<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderDeleteAccountOperation> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderDeleteAccountOperation> {};
template<> struct hash<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderManageAccountOperation> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderManageAccountOperation> {};
template<> struct hash<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderOperation> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderOperation> {};
template<> struct hash<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderRetrieveCookiesOperation> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderRetrieveCookiesOperation> {};
template<> struct hash<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderSignOutAccountOperation> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderSignOutAccountOperation> {};
template<> struct hash<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderSilentReportOperation> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderSilentReportOperation> {};
template<> struct hash<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderTokenObjects> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderTokenObjects> {};
template<> struct hash<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderTokenObjects2> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderTokenObjects2> {};
template<> struct hash<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderTokenOperation> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderTokenOperation> {};
template<> struct hash<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderUIReportOperation> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountProviderUIReportOperation> {};
template<> struct hash<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountScopeManagerStatics> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Web::Provider::IWebAccountScopeManagerStatics> {};
template<> struct hash<winrt::Windows::Security::Authentication::Web::Provider::IWebProviderTokenRequest> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Web::Provider::IWebProviderTokenRequest> {};
template<> struct hash<winrt::Windows::Security::Authentication::Web::Provider::IWebProviderTokenRequest2> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Web::Provider::IWebProviderTokenRequest2> {};
template<> struct hash<winrt::Windows::Security::Authentication::Web::Provider::IWebProviderTokenRequest3> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Web::Provider::IWebProviderTokenRequest3> {};
template<> struct hash<winrt::Windows::Security::Authentication::Web::Provider::IWebProviderTokenResponse> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Web::Provider::IWebProviderTokenResponse> {};
template<> struct hash<winrt::Windows::Security::Authentication::Web::Provider::IWebProviderTokenResponseFactory> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Web::Provider::IWebProviderTokenResponseFactory> {};
template<> struct hash<winrt::Windows::Security::Authentication::Web::Provider::WebAccountClientView> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Web::Provider::WebAccountClientView> {};
template<> struct hash<winrt::Windows::Security::Authentication::Web::Provider::WebAccountManager> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Web::Provider::WebAccountManager> {};
template<> struct hash<winrt::Windows::Security::Authentication::Web::Provider::WebAccountProviderAddAccountOperation> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Web::Provider::WebAccountProviderAddAccountOperation> {};
template<> struct hash<winrt::Windows::Security::Authentication::Web::Provider::WebAccountProviderDeleteAccountOperation> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Web::Provider::WebAccountProviderDeleteAccountOperation> {};
template<> struct hash<winrt::Windows::Security::Authentication::Web::Provider::WebAccountProviderGetTokenSilentOperation> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Web::Provider::WebAccountProviderGetTokenSilentOperation> {};
template<> struct hash<winrt::Windows::Security::Authentication::Web::Provider::WebAccountProviderManageAccountOperation> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Web::Provider::WebAccountProviderManageAccountOperation> {};
template<> struct hash<winrt::Windows::Security::Authentication::Web::Provider::WebAccountProviderRequestTokenOperation> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Web::Provider::WebAccountProviderRequestTokenOperation> {};
template<> struct hash<winrt::Windows::Security::Authentication::Web::Provider::WebAccountProviderRetrieveCookiesOperation> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Web::Provider::WebAccountProviderRetrieveCookiesOperation> {};
template<> struct hash<winrt::Windows::Security::Authentication::Web::Provider::WebAccountProviderSignOutAccountOperation> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Web::Provider::WebAccountProviderSignOutAccountOperation> {};
template<> struct hash<winrt::Windows::Security::Authentication::Web::Provider::WebAccountProviderTriggerDetails> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Web::Provider::WebAccountProviderTriggerDetails> {};
template<> struct hash<winrt::Windows::Security::Authentication::Web::Provider::WebProviderTokenRequest> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Web::Provider::WebProviderTokenRequest> {};
template<> struct hash<winrt::Windows::Security::Authentication::Web::Provider::WebProviderTokenResponse> : winrt::impl::hash_base<winrt::Windows::Security::Authentication::Web::Provider::WebProviderTokenResponse> {};

}
