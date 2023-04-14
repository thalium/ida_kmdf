// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Networking.Sockets.2.h"
#include "winrt/impl/Windows.Security.Cryptography.Certificates.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Web.Http.Filters.2.h"
#include "winrt/impl/Windows.Web.Http.Headers.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Web.Http.2.h"
#include "winrt/Windows.Web.h"

namespace winrt::impl {

template <typename D> Windows::Web::Http::HttpBufferContent consume_Windows_Web_Http_IHttpBufferContentFactory<D>::CreateFromBuffer(Windows::Storage::Streams::IBuffer const& content) const
{
    Windows::Web::Http::HttpBufferContent value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpBufferContentFactory)->CreateFromBuffer(get_abi(content), put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::HttpBufferContent consume_Windows_Web_Http_IHttpBufferContentFactory<D>::CreateFromBufferWithOffset(Windows::Storage::Streams::IBuffer const& content, uint32_t offset, uint32_t count) const
{
    Windows::Web::Http::HttpBufferContent value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpBufferContentFactory)->CreateFromBufferWithOffset(get_abi(content), offset, count, put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpResponseMessage, Windows::Web::Http::HttpProgress> consume_Windows_Web_Http_IHttpClient<D>::DeleteAsync(Windows::Foundation::Uri const& uri) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpResponseMessage, Windows::Web::Http::HttpProgress> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpClient)->DeleteAsync(get_abi(uri), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpResponseMessage, Windows::Web::Http::HttpProgress> consume_Windows_Web_Http_IHttpClient<D>::GetAsync(Windows::Foundation::Uri const& uri) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpResponseMessage, Windows::Web::Http::HttpProgress> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpClient)->GetAsync(get_abi(uri), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpResponseMessage, Windows::Web::Http::HttpProgress> consume_Windows_Web_Http_IHttpClient<D>::GetAsync(Windows::Foundation::Uri const& uri, Windows::Web::Http::HttpCompletionOption const& completionOption) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpResponseMessage, Windows::Web::Http::HttpProgress> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpClient)->GetWithOptionAsync(get_abi(uri), get_abi(completionOption), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Storage::Streams::IBuffer, Windows::Web::Http::HttpProgress> consume_Windows_Web_Http_IHttpClient<D>::GetBufferAsync(Windows::Foundation::Uri const& uri) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Storage::Streams::IBuffer, Windows::Web::Http::HttpProgress> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpClient)->GetBufferAsync(get_abi(uri), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Storage::Streams::IInputStream, Windows::Web::Http::HttpProgress> consume_Windows_Web_Http_IHttpClient<D>::GetInputStreamAsync(Windows::Foundation::Uri const& uri) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Storage::Streams::IInputStream, Windows::Web::Http::HttpProgress> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpClient)->GetInputStreamAsync(get_abi(uri), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<hstring, Windows::Web::Http::HttpProgress> consume_Windows_Web_Http_IHttpClient<D>::GetStringAsync(Windows::Foundation::Uri const& uri) const
{
    Windows::Foundation::IAsyncOperationWithProgress<hstring, Windows::Web::Http::HttpProgress> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpClient)->GetStringAsync(get_abi(uri), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpResponseMessage, Windows::Web::Http::HttpProgress> consume_Windows_Web_Http_IHttpClient<D>::PostAsync(Windows::Foundation::Uri const& uri, Windows::Web::Http::IHttpContent const& content) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpResponseMessage, Windows::Web::Http::HttpProgress> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpClient)->PostAsync(get_abi(uri), get_abi(content), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpResponseMessage, Windows::Web::Http::HttpProgress> consume_Windows_Web_Http_IHttpClient<D>::PutAsync(Windows::Foundation::Uri const& uri, Windows::Web::Http::IHttpContent const& content) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpResponseMessage, Windows::Web::Http::HttpProgress> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpClient)->PutAsync(get_abi(uri), get_abi(content), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpResponseMessage, Windows::Web::Http::HttpProgress> consume_Windows_Web_Http_IHttpClient<D>::SendRequestAsync(Windows::Web::Http::HttpRequestMessage const& request) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpResponseMessage, Windows::Web::Http::HttpProgress> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpClient)->SendRequestAsync(get_abi(request), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpResponseMessage, Windows::Web::Http::HttpProgress> consume_Windows_Web_Http_IHttpClient<D>::SendRequestAsync(Windows::Web::Http::HttpRequestMessage const& request, Windows::Web::Http::HttpCompletionOption const& completionOption) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpResponseMessage, Windows::Web::Http::HttpProgress> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpClient)->SendRequestWithOptionAsync(get_abi(request), get_abi(completionOption), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Web::Http::Headers::HttpRequestHeaderCollection consume_Windows_Web_Http_IHttpClient<D>::DefaultRequestHeaders() const
{
    Windows::Web::Http::Headers::HttpRequestHeaderCollection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpClient)->get_DefaultRequestHeaders(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpRequestResult, Windows::Web::Http::HttpProgress> consume_Windows_Web_Http_IHttpClient2<D>::TryDeleteAsync(Windows::Foundation::Uri const& uri) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpRequestResult, Windows::Web::Http::HttpProgress> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpClient2)->TryDeleteAsync(get_abi(uri), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpRequestResult, Windows::Web::Http::HttpProgress> consume_Windows_Web_Http_IHttpClient2<D>::TryGetAsync(Windows::Foundation::Uri const& uri) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpRequestResult, Windows::Web::Http::HttpProgress> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpClient2)->TryGetAsync(get_abi(uri), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpRequestResult, Windows::Web::Http::HttpProgress> consume_Windows_Web_Http_IHttpClient2<D>::TryGetAsync(Windows::Foundation::Uri const& uri, Windows::Web::Http::HttpCompletionOption const& completionOption) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpRequestResult, Windows::Web::Http::HttpProgress> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpClient2)->TryGetAsync2(get_abi(uri), get_abi(completionOption), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpGetBufferResult, Windows::Web::Http::HttpProgress> consume_Windows_Web_Http_IHttpClient2<D>::TryGetBufferAsync(Windows::Foundation::Uri const& uri) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpGetBufferResult, Windows::Web::Http::HttpProgress> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpClient2)->TryGetBufferAsync(get_abi(uri), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpGetInputStreamResult, Windows::Web::Http::HttpProgress> consume_Windows_Web_Http_IHttpClient2<D>::TryGetInputStreamAsync(Windows::Foundation::Uri const& uri) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpGetInputStreamResult, Windows::Web::Http::HttpProgress> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpClient2)->TryGetInputStreamAsync(get_abi(uri), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpGetStringResult, Windows::Web::Http::HttpProgress> consume_Windows_Web_Http_IHttpClient2<D>::TryGetStringAsync(Windows::Foundation::Uri const& uri) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpGetStringResult, Windows::Web::Http::HttpProgress> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpClient2)->TryGetStringAsync(get_abi(uri), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpRequestResult, Windows::Web::Http::HttpProgress> consume_Windows_Web_Http_IHttpClient2<D>::TryPostAsync(Windows::Foundation::Uri const& uri, Windows::Web::Http::IHttpContent const& content) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpRequestResult, Windows::Web::Http::HttpProgress> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpClient2)->TryPostAsync(get_abi(uri), get_abi(content), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpRequestResult, Windows::Web::Http::HttpProgress> consume_Windows_Web_Http_IHttpClient2<D>::TryPutAsync(Windows::Foundation::Uri const& uri, Windows::Web::Http::IHttpContent const& content) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpRequestResult, Windows::Web::Http::HttpProgress> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpClient2)->TryPutAsync(get_abi(uri), get_abi(content), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpRequestResult, Windows::Web::Http::HttpProgress> consume_Windows_Web_Http_IHttpClient2<D>::TrySendRequestAsync(Windows::Web::Http::HttpRequestMessage const& request) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpRequestResult, Windows::Web::Http::HttpProgress> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpClient2)->TrySendRequestAsync(get_abi(request), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpRequestResult, Windows::Web::Http::HttpProgress> consume_Windows_Web_Http_IHttpClient2<D>::TrySendRequestAsync(Windows::Web::Http::HttpRequestMessage const& request, Windows::Web::Http::HttpCompletionOption const& completionOption) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpRequestResult, Windows::Web::Http::HttpProgress> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpClient2)->TrySendRequestAsync2(get_abi(request), get_abi(completionOption), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Web::Http::HttpClient consume_Windows_Web_Http_IHttpClientFactory<D>::Create(Windows::Web::Http::Filters::IHttpFilter const& filter) const
{
    Windows::Web::Http::HttpClient value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpClientFactory)->Create(get_abi(filter), put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::Headers::HttpContentHeaderCollection consume_Windows_Web_Http_IHttpContent<D>::Headers() const
{
    Windows::Web::Http::Headers::HttpContentHeaderCollection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpContent)->get_Headers(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<uint64_t, uint64_t> consume_Windows_Web_Http_IHttpContent<D>::BufferAllAsync() const
{
    Windows::Foundation::IAsyncOperationWithProgress<uint64_t, uint64_t> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpContent)->BufferAllAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Storage::Streams::IBuffer, uint64_t> consume_Windows_Web_Http_IHttpContent<D>::ReadAsBufferAsync() const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Storage::Streams::IBuffer, uint64_t> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpContent)->ReadAsBufferAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Storage::Streams::IInputStream, uint64_t> consume_Windows_Web_Http_IHttpContent<D>::ReadAsInputStreamAsync() const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Storage::Streams::IInputStream, uint64_t> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpContent)->ReadAsInputStreamAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<hstring, uint64_t> consume_Windows_Web_Http_IHttpContent<D>::ReadAsStringAsync() const
{
    Windows::Foundation::IAsyncOperationWithProgress<hstring, uint64_t> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpContent)->ReadAsStringAsync(put_abi(operation)));
    return operation;
}

template <typename D> bool consume_Windows_Web_Http_IHttpContent<D>::TryComputeLength(uint64_t& length) const
{
    bool succeeded{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpContent)->TryComputeLength(&length, &succeeded));
    return succeeded;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<uint64_t, uint64_t> consume_Windows_Web_Http_IHttpContent<D>::WriteToStreamAsync(Windows::Storage::Streams::IOutputStream const& outputStream) const
{
    Windows::Foundation::IAsyncOperationWithProgress<uint64_t, uint64_t> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpContent)->WriteToStreamAsync(get_abi(outputStream), put_abi(operation)));
    return operation;
}

template <typename D> hstring consume_Windows_Web_Http_IHttpCookie<D>::Name() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpCookie)->get_Name(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Web_Http_IHttpCookie<D>::Domain() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpCookie)->get_Domain(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Web_Http_IHttpCookie<D>::Path() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpCookie)->get_Path(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::DateTime> consume_Windows_Web_Http_IHttpCookie<D>::Expires() const
{
    Windows::Foundation::IReference<Windows::Foundation::DateTime> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpCookie)->get_Expires(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_Http_IHttpCookie<D>::Expires(optional<Windows::Foundation::DateTime> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpCookie)->put_Expires(get_abi(value)));
}

template <typename D> bool consume_Windows_Web_Http_IHttpCookie<D>::HttpOnly() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpCookie)->get_HttpOnly(&value));
    return value;
}

template <typename D> void consume_Windows_Web_Http_IHttpCookie<D>::HttpOnly(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpCookie)->put_HttpOnly(value));
}

template <typename D> bool consume_Windows_Web_Http_IHttpCookie<D>::Secure() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpCookie)->get_Secure(&value));
    return value;
}

template <typename D> void consume_Windows_Web_Http_IHttpCookie<D>::Secure(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpCookie)->put_Secure(value));
}

template <typename D> hstring consume_Windows_Web_Http_IHttpCookie<D>::Value() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpCookie)->get_Value(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_Http_IHttpCookie<D>::Value(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpCookie)->put_Value(get_abi(value)));
}

template <typename D> Windows::Web::Http::HttpCookie consume_Windows_Web_Http_IHttpCookieFactory<D>::Create(param::hstring const& name, param::hstring const& domain, param::hstring const& path) const
{
    Windows::Web::Http::HttpCookie value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpCookieFactory)->Create(get_abi(name), get_abi(domain), get_abi(path), put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Web_Http_IHttpCookieManager<D>::SetCookie(Windows::Web::Http::HttpCookie const& cookie) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpCookieManager)->SetCookie(get_abi(cookie), &result));
    return result;
}

template <typename D> bool consume_Windows_Web_Http_IHttpCookieManager<D>::SetCookie(Windows::Web::Http::HttpCookie const& cookie, bool thirdParty) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpCookieManager)->SetCookieWithThirdParty(get_abi(cookie), thirdParty, &result));
    return result;
}

template <typename D> void consume_Windows_Web_Http_IHttpCookieManager<D>::DeleteCookie(Windows::Web::Http::HttpCookie const& cookie) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpCookieManager)->DeleteCookie(get_abi(cookie)));
}

template <typename D> Windows::Web::Http::HttpCookieCollection consume_Windows_Web_Http_IHttpCookieManager<D>::GetCookies(Windows::Foundation::Uri const& uri) const
{
    Windows::Web::Http::HttpCookieCollection result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpCookieManager)->GetCookies(get_abi(uri), put_abi(result)));
    return result;
}

template <typename D> Windows::Web::Http::HttpFormUrlEncodedContent consume_Windows_Web_Http_IHttpFormUrlEncodedContentFactory<D>::Create(param::iterable<Windows::Foundation::Collections::IKeyValuePair<hstring, hstring>> const& content) const
{
    Windows::Web::Http::HttpFormUrlEncodedContent value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpFormUrlEncodedContentFactory)->Create(get_abi(content), put_abi(value)));
    return value;
}

template <typename D> winrt::hresult consume_Windows_Web_Http_IHttpGetBufferResult<D>::ExtendedError() const
{
    winrt::hresult value{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpGetBufferResult)->get_ExtendedError(put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::HttpRequestMessage consume_Windows_Web_Http_IHttpGetBufferResult<D>::RequestMessage() const
{
    Windows::Web::Http::HttpRequestMessage value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpGetBufferResult)->get_RequestMessage(put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::HttpResponseMessage consume_Windows_Web_Http_IHttpGetBufferResult<D>::ResponseMessage() const
{
    Windows::Web::Http::HttpResponseMessage value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpGetBufferResult)->get_ResponseMessage(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Web_Http_IHttpGetBufferResult<D>::Succeeded() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpGetBufferResult)->get_Succeeded(&value));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Web_Http_IHttpGetBufferResult<D>::Value() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpGetBufferResult)->get_Value(put_abi(value)));
    return value;
}

template <typename D> winrt::hresult consume_Windows_Web_Http_IHttpGetInputStreamResult<D>::ExtendedError() const
{
    winrt::hresult value{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpGetInputStreamResult)->get_ExtendedError(put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::HttpRequestMessage consume_Windows_Web_Http_IHttpGetInputStreamResult<D>::RequestMessage() const
{
    Windows::Web::Http::HttpRequestMessage value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpGetInputStreamResult)->get_RequestMessage(put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::HttpResponseMessage consume_Windows_Web_Http_IHttpGetInputStreamResult<D>::ResponseMessage() const
{
    Windows::Web::Http::HttpResponseMessage value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpGetInputStreamResult)->get_ResponseMessage(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Web_Http_IHttpGetInputStreamResult<D>::Succeeded() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpGetInputStreamResult)->get_Succeeded(&value));
    return value;
}

template <typename D> Windows::Storage::Streams::IInputStream consume_Windows_Web_Http_IHttpGetInputStreamResult<D>::Value() const
{
    Windows::Storage::Streams::IInputStream value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpGetInputStreamResult)->get_Value(put_abi(value)));
    return value;
}

template <typename D> winrt::hresult consume_Windows_Web_Http_IHttpGetStringResult<D>::ExtendedError() const
{
    winrt::hresult value{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpGetStringResult)->get_ExtendedError(put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::HttpRequestMessage consume_Windows_Web_Http_IHttpGetStringResult<D>::RequestMessage() const
{
    Windows::Web::Http::HttpRequestMessage value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpGetStringResult)->get_RequestMessage(put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::HttpResponseMessage consume_Windows_Web_Http_IHttpGetStringResult<D>::ResponseMessage() const
{
    Windows::Web::Http::HttpResponseMessage value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpGetStringResult)->get_ResponseMessage(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Web_Http_IHttpGetStringResult<D>::Succeeded() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpGetStringResult)->get_Succeeded(&value));
    return value;
}

template <typename D> hstring consume_Windows_Web_Http_IHttpGetStringResult<D>::Value() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpGetStringResult)->get_Value(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Web_Http_IHttpMethod<D>::Method() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpMethod)->get_Method(put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::HttpMethod consume_Windows_Web_Http_IHttpMethodFactory<D>::Create(param::hstring const& method) const
{
    Windows::Web::Http::HttpMethod value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpMethodFactory)->Create(get_abi(method), put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::HttpMethod consume_Windows_Web_Http_IHttpMethodStatics<D>::Delete() const
{
    Windows::Web::Http::HttpMethod value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpMethodStatics)->get_Delete(put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::HttpMethod consume_Windows_Web_Http_IHttpMethodStatics<D>::Get() const
{
    Windows::Web::Http::HttpMethod value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpMethodStatics)->get_Get(put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::HttpMethod consume_Windows_Web_Http_IHttpMethodStatics<D>::Head() const
{
    Windows::Web::Http::HttpMethod value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpMethodStatics)->get_Head(put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::HttpMethod consume_Windows_Web_Http_IHttpMethodStatics<D>::Options() const
{
    Windows::Web::Http::HttpMethod value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpMethodStatics)->get_Options(put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::HttpMethod consume_Windows_Web_Http_IHttpMethodStatics<D>::Patch() const
{
    Windows::Web::Http::HttpMethod value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpMethodStatics)->get_Patch(put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::HttpMethod consume_Windows_Web_Http_IHttpMethodStatics<D>::Post() const
{
    Windows::Web::Http::HttpMethod value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpMethodStatics)->get_Post(put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::HttpMethod consume_Windows_Web_Http_IHttpMethodStatics<D>::Put() const
{
    Windows::Web::Http::HttpMethod value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpMethodStatics)->get_Put(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_Http_IHttpMultipartContent<D>::Add(Windows::Web::Http::IHttpContent const& content) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpMultipartContent)->Add(get_abi(content)));
}

template <typename D> Windows::Web::Http::HttpMultipartContent consume_Windows_Web_Http_IHttpMultipartContentFactory<D>::CreateWithSubtype(param::hstring const& subtype) const
{
    Windows::Web::Http::HttpMultipartContent value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpMultipartContentFactory)->CreateWithSubtype(get_abi(subtype), put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::HttpMultipartContent consume_Windows_Web_Http_IHttpMultipartContentFactory<D>::CreateWithSubtypeAndBoundary(param::hstring const& subtype, param::hstring const& boundary) const
{
    Windows::Web::Http::HttpMultipartContent value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpMultipartContentFactory)->CreateWithSubtypeAndBoundary(get_abi(subtype), get_abi(boundary), put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_Http_IHttpMultipartFormDataContent<D>::Add(Windows::Web::Http::IHttpContent const& content) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpMultipartFormDataContent)->Add(get_abi(content)));
}

template <typename D> void consume_Windows_Web_Http_IHttpMultipartFormDataContent<D>::Add(Windows::Web::Http::IHttpContent const& content, param::hstring const& name) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpMultipartFormDataContent)->AddWithName(get_abi(content), get_abi(name)));
}

template <typename D> void consume_Windows_Web_Http_IHttpMultipartFormDataContent<D>::Add(Windows::Web::Http::IHttpContent const& content, param::hstring const& name, param::hstring const& fileName) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpMultipartFormDataContent)->AddWithNameAndFileName(get_abi(content), get_abi(name), get_abi(fileName)));
}

template <typename D> Windows::Web::Http::HttpMultipartFormDataContent consume_Windows_Web_Http_IHttpMultipartFormDataContentFactory<D>::CreateWithBoundary(param::hstring const& boundary) const
{
    Windows::Web::Http::HttpMultipartFormDataContent value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpMultipartFormDataContentFactory)->CreateWithBoundary(get_abi(boundary), put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::IHttpContent consume_Windows_Web_Http_IHttpRequestMessage<D>::Content() const
{
    Windows::Web::Http::IHttpContent value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpRequestMessage)->get_Content(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_Http_IHttpRequestMessage<D>::Content(Windows::Web::Http::IHttpContent const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpRequestMessage)->put_Content(get_abi(value)));
}

template <typename D> Windows::Web::Http::Headers::HttpRequestHeaderCollection consume_Windows_Web_Http_IHttpRequestMessage<D>::Headers() const
{
    Windows::Web::Http::Headers::HttpRequestHeaderCollection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpRequestMessage)->get_Headers(put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::HttpMethod consume_Windows_Web_Http_IHttpRequestMessage<D>::Method() const
{
    Windows::Web::Http::HttpMethod value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpRequestMessage)->get_Method(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_Http_IHttpRequestMessage<D>::Method(Windows::Web::Http::HttpMethod const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpRequestMessage)->put_Method(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IMap<hstring, Windows::Foundation::IInspectable> consume_Windows_Web_Http_IHttpRequestMessage<D>::Properties() const
{
    Windows::Foundation::Collections::IMap<hstring, Windows::Foundation::IInspectable> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpRequestMessage)->get_Properties(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Uri consume_Windows_Web_Http_IHttpRequestMessage<D>::RequestUri() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpRequestMessage)->get_RequestUri(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_Http_IHttpRequestMessage<D>::RequestUri(Windows::Foundation::Uri const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpRequestMessage)->put_RequestUri(get_abi(value)));
}

template <typename D> Windows::Web::Http::HttpTransportInformation consume_Windows_Web_Http_IHttpRequestMessage<D>::TransportInformation() const
{
    Windows::Web::Http::HttpTransportInformation value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpRequestMessage)->get_TransportInformation(put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::HttpRequestMessage consume_Windows_Web_Http_IHttpRequestMessageFactory<D>::Create(Windows::Web::Http::HttpMethod const& method, Windows::Foundation::Uri const& uri) const
{
    Windows::Web::Http::HttpRequestMessage value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpRequestMessageFactory)->Create(get_abi(method), get_abi(uri), put_abi(value)));
    return value;
}

template <typename D> winrt::hresult consume_Windows_Web_Http_IHttpRequestResult<D>::ExtendedError() const
{
    winrt::hresult value{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpRequestResult)->get_ExtendedError(put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::HttpRequestMessage consume_Windows_Web_Http_IHttpRequestResult<D>::RequestMessage() const
{
    Windows::Web::Http::HttpRequestMessage value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpRequestResult)->get_RequestMessage(put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::HttpResponseMessage consume_Windows_Web_Http_IHttpRequestResult<D>::ResponseMessage() const
{
    Windows::Web::Http::HttpResponseMessage value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpRequestResult)->get_ResponseMessage(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Web_Http_IHttpRequestResult<D>::Succeeded() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpRequestResult)->get_Succeeded(&value));
    return value;
}

template <typename D> Windows::Web::Http::IHttpContent consume_Windows_Web_Http_IHttpResponseMessage<D>::Content() const
{
    Windows::Web::Http::IHttpContent value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpResponseMessage)->get_Content(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_Http_IHttpResponseMessage<D>::Content(Windows::Web::Http::IHttpContent const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpResponseMessage)->put_Content(get_abi(value)));
}

template <typename D> Windows::Web::Http::Headers::HttpResponseHeaderCollection consume_Windows_Web_Http_IHttpResponseMessage<D>::Headers() const
{
    Windows::Web::Http::Headers::HttpResponseHeaderCollection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpResponseMessage)->get_Headers(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Web_Http_IHttpResponseMessage<D>::IsSuccessStatusCode() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpResponseMessage)->get_IsSuccessStatusCode(&value));
    return value;
}

template <typename D> hstring consume_Windows_Web_Http_IHttpResponseMessage<D>::ReasonPhrase() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpResponseMessage)->get_ReasonPhrase(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_Http_IHttpResponseMessage<D>::ReasonPhrase(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpResponseMessage)->put_ReasonPhrase(get_abi(value)));
}

template <typename D> Windows::Web::Http::HttpRequestMessage consume_Windows_Web_Http_IHttpResponseMessage<D>::RequestMessage() const
{
    Windows::Web::Http::HttpRequestMessage value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpResponseMessage)->get_RequestMessage(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_Http_IHttpResponseMessage<D>::RequestMessage(Windows::Web::Http::HttpRequestMessage const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpResponseMessage)->put_RequestMessage(get_abi(value)));
}

template <typename D> Windows::Web::Http::HttpResponseMessageSource consume_Windows_Web_Http_IHttpResponseMessage<D>::Source() const
{
    Windows::Web::Http::HttpResponseMessageSource value{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpResponseMessage)->get_Source(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_Http_IHttpResponseMessage<D>::Source(Windows::Web::Http::HttpResponseMessageSource const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpResponseMessage)->put_Source(get_abi(value)));
}

template <typename D> Windows::Web::Http::HttpStatusCode consume_Windows_Web_Http_IHttpResponseMessage<D>::StatusCode() const
{
    Windows::Web::Http::HttpStatusCode value{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpResponseMessage)->get_StatusCode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_Http_IHttpResponseMessage<D>::StatusCode(Windows::Web::Http::HttpStatusCode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpResponseMessage)->put_StatusCode(get_abi(value)));
}

template <typename D> Windows::Web::Http::HttpVersion consume_Windows_Web_Http_IHttpResponseMessage<D>::Version() const
{
    Windows::Web::Http::HttpVersion value{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpResponseMessage)->get_Version(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_Http_IHttpResponseMessage<D>::Version(Windows::Web::Http::HttpVersion const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpResponseMessage)->put_Version(get_abi(value)));
}

template <typename D> Windows::Web::Http::HttpResponseMessage consume_Windows_Web_Http_IHttpResponseMessage<D>::EnsureSuccessStatusCode() const
{
    Windows::Web::Http::HttpResponseMessage result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpResponseMessage)->EnsureSuccessStatusCode(put_abi(result)));
    return result;
}

template <typename D> Windows::Web::Http::HttpResponseMessage consume_Windows_Web_Http_IHttpResponseMessageFactory<D>::Create(Windows::Web::Http::HttpStatusCode const& statusCode) const
{
    Windows::Web::Http::HttpResponseMessage value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpResponseMessageFactory)->Create(get_abi(statusCode), put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::HttpStreamContent consume_Windows_Web_Http_IHttpStreamContentFactory<D>::CreateFromInputStream(Windows::Storage::Streams::IInputStream const& content) const
{
    Windows::Web::Http::HttpStreamContent value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpStreamContentFactory)->CreateFromInputStream(get_abi(content), put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::HttpStringContent consume_Windows_Web_Http_IHttpStringContentFactory<D>::CreateFromString(param::hstring const& content) const
{
    Windows::Web::Http::HttpStringContent value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpStringContentFactory)->CreateFromString(get_abi(content), put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::HttpStringContent consume_Windows_Web_Http_IHttpStringContentFactory<D>::CreateFromStringWithEncoding(param::hstring const& content, Windows::Storage::Streams::UnicodeEncoding const& encoding) const
{
    Windows::Web::Http::HttpStringContent value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpStringContentFactory)->CreateFromStringWithEncoding(get_abi(content), get_abi(encoding), put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::HttpStringContent consume_Windows_Web_Http_IHttpStringContentFactory<D>::CreateFromStringWithEncodingAndMediaType(param::hstring const& content, Windows::Storage::Streams::UnicodeEncoding const& encoding, param::hstring const& mediaType) const
{
    Windows::Web::Http::HttpStringContent value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpStringContentFactory)->CreateFromStringWithEncodingAndMediaType(get_abi(content), get_abi(encoding), get_abi(mediaType), put_abi(value)));
    return value;
}

template <typename D> Windows::Security::Cryptography::Certificates::Certificate consume_Windows_Web_Http_IHttpTransportInformation<D>::ServerCertificate() const
{
    Windows::Security::Cryptography::Certificates::Certificate value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpTransportInformation)->get_ServerCertificate(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::Sockets::SocketSslErrorSeverity consume_Windows_Web_Http_IHttpTransportInformation<D>::ServerCertificateErrorSeverity() const
{
    Windows::Networking::Sockets::SocketSslErrorSeverity value{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpTransportInformation)->get_ServerCertificateErrorSeverity(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Security::Cryptography::Certificates::ChainValidationResult> consume_Windows_Web_Http_IHttpTransportInformation<D>::ServerCertificateErrors() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Security::Cryptography::Certificates::ChainValidationResult> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpTransportInformation)->get_ServerCertificateErrors(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Security::Cryptography::Certificates::Certificate> consume_Windows_Web_Http_IHttpTransportInformation<D>::ServerIntermediateCertificates() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Security::Cryptography::Certificates::Certificate> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::IHttpTransportInformation)->get_ServerIntermediateCertificates(put_abi(value)));
    return value;
}

template <typename D>
struct produce<D, Windows::Web::Http::IHttpBufferContentFactory> : produce_base<D, Windows::Web::Http::IHttpBufferContentFactory>
{
    int32_t WINRT_CALL CreateFromBuffer(void* content, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromBuffer, WINRT_WRAP(Windows::Web::Http::HttpBufferContent), Windows::Storage::Streams::IBuffer const&);
            *value = detach_from<Windows::Web::Http::HttpBufferContent>(this->shim().CreateFromBuffer(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&content)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromBufferWithOffset(void* content, uint32_t offset, uint32_t count, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromBufferWithOffset, WINRT_WRAP(Windows::Web::Http::HttpBufferContent), Windows::Storage::Streams::IBuffer const&, uint32_t, uint32_t);
            *value = detach_from<Windows::Web::Http::HttpBufferContent>(this->shim().CreateFromBufferWithOffset(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&content), offset, count));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::IHttpClient> : produce_base<D, Windows::Web::Http::IHttpClient>
{
    int32_t WINRT_CALL DeleteAsync(void* uri, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeleteAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpResponseMessage, Windows::Web::Http::HttpProgress>), Windows::Foundation::Uri const);
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpResponseMessage, Windows::Web::Http::HttpProgress>>(this->shim().DeleteAsync(*reinterpret_cast<Windows::Foundation::Uri const*>(&uri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetAsync(void* uri, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpResponseMessage, Windows::Web::Http::HttpProgress>), Windows::Foundation::Uri const);
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpResponseMessage, Windows::Web::Http::HttpProgress>>(this->shim().GetAsync(*reinterpret_cast<Windows::Foundation::Uri const*>(&uri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetWithOptionAsync(void* uri, Windows::Web::Http::HttpCompletionOption completionOption, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpResponseMessage, Windows::Web::Http::HttpProgress>), Windows::Foundation::Uri const, Windows::Web::Http::HttpCompletionOption const);
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpResponseMessage, Windows::Web::Http::HttpProgress>>(this->shim().GetAsync(*reinterpret_cast<Windows::Foundation::Uri const*>(&uri), *reinterpret_cast<Windows::Web::Http::HttpCompletionOption const*>(&completionOption)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetBufferAsync(void* uri, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetBufferAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Storage::Streams::IBuffer, Windows::Web::Http::HttpProgress>), Windows::Foundation::Uri const);
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Storage::Streams::IBuffer, Windows::Web::Http::HttpProgress>>(this->shim().GetBufferAsync(*reinterpret_cast<Windows::Foundation::Uri const*>(&uri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetInputStreamAsync(void* uri, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetInputStreamAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Storage::Streams::IInputStream, Windows::Web::Http::HttpProgress>), Windows::Foundation::Uri const);
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Storage::Streams::IInputStream, Windows::Web::Http::HttpProgress>>(this->shim().GetInputStreamAsync(*reinterpret_cast<Windows::Foundation::Uri const*>(&uri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetStringAsync(void* uri, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetStringAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<hstring, Windows::Web::Http::HttpProgress>), Windows::Foundation::Uri const);
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<hstring, Windows::Web::Http::HttpProgress>>(this->shim().GetStringAsync(*reinterpret_cast<Windows::Foundation::Uri const*>(&uri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PostAsync(void* uri, void* content, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PostAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpResponseMessage, Windows::Web::Http::HttpProgress>), Windows::Foundation::Uri const, Windows::Web::Http::IHttpContent const);
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpResponseMessage, Windows::Web::Http::HttpProgress>>(this->shim().PostAsync(*reinterpret_cast<Windows::Foundation::Uri const*>(&uri), *reinterpret_cast<Windows::Web::Http::IHttpContent const*>(&content)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PutAsync(void* uri, void* content, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PutAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpResponseMessage, Windows::Web::Http::HttpProgress>), Windows::Foundation::Uri const, Windows::Web::Http::IHttpContent const);
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpResponseMessage, Windows::Web::Http::HttpProgress>>(this->shim().PutAsync(*reinterpret_cast<Windows::Foundation::Uri const*>(&uri), *reinterpret_cast<Windows::Web::Http::IHttpContent const*>(&content)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SendRequestAsync(void* request, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SendRequestAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpResponseMessage, Windows::Web::Http::HttpProgress>), Windows::Web::Http::HttpRequestMessage const);
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpResponseMessage, Windows::Web::Http::HttpProgress>>(this->shim().SendRequestAsync(*reinterpret_cast<Windows::Web::Http::HttpRequestMessage const*>(&request)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SendRequestWithOptionAsync(void* request, Windows::Web::Http::HttpCompletionOption completionOption, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SendRequestAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpResponseMessage, Windows::Web::Http::HttpProgress>), Windows::Web::Http::HttpRequestMessage const, Windows::Web::Http::HttpCompletionOption const);
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpResponseMessage, Windows::Web::Http::HttpProgress>>(this->shim().SendRequestAsync(*reinterpret_cast<Windows::Web::Http::HttpRequestMessage const*>(&request), *reinterpret_cast<Windows::Web::Http::HttpCompletionOption const*>(&completionOption)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DefaultRequestHeaders(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DefaultRequestHeaders, WINRT_WRAP(Windows::Web::Http::Headers::HttpRequestHeaderCollection));
            *value = detach_from<Windows::Web::Http::Headers::HttpRequestHeaderCollection>(this->shim().DefaultRequestHeaders());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::IHttpClient2> : produce_base<D, Windows::Web::Http::IHttpClient2>
{
    int32_t WINRT_CALL TryDeleteAsync(void* uri, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryDeleteAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpRequestResult, Windows::Web::Http::HttpProgress>), Windows::Foundation::Uri const);
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpRequestResult, Windows::Web::Http::HttpProgress>>(this->shim().TryDeleteAsync(*reinterpret_cast<Windows::Foundation::Uri const*>(&uri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryGetAsync(void* uri, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryGetAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpRequestResult, Windows::Web::Http::HttpProgress>), Windows::Foundation::Uri const);
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpRequestResult, Windows::Web::Http::HttpProgress>>(this->shim().TryGetAsync(*reinterpret_cast<Windows::Foundation::Uri const*>(&uri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryGetAsync2(void* uri, Windows::Web::Http::HttpCompletionOption completionOption, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryGetAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpRequestResult, Windows::Web::Http::HttpProgress>), Windows::Foundation::Uri const, Windows::Web::Http::HttpCompletionOption const);
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpRequestResult, Windows::Web::Http::HttpProgress>>(this->shim().TryGetAsync(*reinterpret_cast<Windows::Foundation::Uri const*>(&uri), *reinterpret_cast<Windows::Web::Http::HttpCompletionOption const*>(&completionOption)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryGetBufferAsync(void* uri, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryGetBufferAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpGetBufferResult, Windows::Web::Http::HttpProgress>), Windows::Foundation::Uri const);
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpGetBufferResult, Windows::Web::Http::HttpProgress>>(this->shim().TryGetBufferAsync(*reinterpret_cast<Windows::Foundation::Uri const*>(&uri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryGetInputStreamAsync(void* uri, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryGetInputStreamAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpGetInputStreamResult, Windows::Web::Http::HttpProgress>), Windows::Foundation::Uri const);
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpGetInputStreamResult, Windows::Web::Http::HttpProgress>>(this->shim().TryGetInputStreamAsync(*reinterpret_cast<Windows::Foundation::Uri const*>(&uri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryGetStringAsync(void* uri, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryGetStringAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpGetStringResult, Windows::Web::Http::HttpProgress>), Windows::Foundation::Uri const);
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpGetStringResult, Windows::Web::Http::HttpProgress>>(this->shim().TryGetStringAsync(*reinterpret_cast<Windows::Foundation::Uri const*>(&uri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryPostAsync(void* uri, void* content, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryPostAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpRequestResult, Windows::Web::Http::HttpProgress>), Windows::Foundation::Uri const, Windows::Web::Http::IHttpContent const);
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpRequestResult, Windows::Web::Http::HttpProgress>>(this->shim().TryPostAsync(*reinterpret_cast<Windows::Foundation::Uri const*>(&uri), *reinterpret_cast<Windows::Web::Http::IHttpContent const*>(&content)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryPutAsync(void* uri, void* content, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryPutAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpRequestResult, Windows::Web::Http::HttpProgress>), Windows::Foundation::Uri const, Windows::Web::Http::IHttpContent const);
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpRequestResult, Windows::Web::Http::HttpProgress>>(this->shim().TryPutAsync(*reinterpret_cast<Windows::Foundation::Uri const*>(&uri), *reinterpret_cast<Windows::Web::Http::IHttpContent const*>(&content)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TrySendRequestAsync(void* request, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrySendRequestAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpRequestResult, Windows::Web::Http::HttpProgress>), Windows::Web::Http::HttpRequestMessage const);
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpRequestResult, Windows::Web::Http::HttpProgress>>(this->shim().TrySendRequestAsync(*reinterpret_cast<Windows::Web::Http::HttpRequestMessage const*>(&request)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TrySendRequestAsync2(void* request, Windows::Web::Http::HttpCompletionOption completionOption, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrySendRequestAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpRequestResult, Windows::Web::Http::HttpProgress>), Windows::Web::Http::HttpRequestMessage const, Windows::Web::Http::HttpCompletionOption const);
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpRequestResult, Windows::Web::Http::HttpProgress>>(this->shim().TrySendRequestAsync(*reinterpret_cast<Windows::Web::Http::HttpRequestMessage const*>(&request), *reinterpret_cast<Windows::Web::Http::HttpCompletionOption const*>(&completionOption)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::IHttpClientFactory> : produce_base<D, Windows::Web::Http::IHttpClientFactory>
{
    int32_t WINRT_CALL Create(void* filter, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Web::Http::HttpClient), Windows::Web::Http::Filters::IHttpFilter const&);
            *value = detach_from<Windows::Web::Http::HttpClient>(this->shim().Create(*reinterpret_cast<Windows::Web::Http::Filters::IHttpFilter const*>(&filter)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::IHttpContent> : produce_base<D, Windows::Web::Http::IHttpContent>
{
    int32_t WINRT_CALL get_Headers(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Headers, WINRT_WRAP(Windows::Web::Http::Headers::HttpContentHeaderCollection));
            *value = detach_from<Windows::Web::Http::Headers::HttpContentHeaderCollection>(this->shim().Headers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL BufferAllAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BufferAllAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<uint64_t, uint64_t>));
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<uint64_t, uint64_t>>(this->shim().BufferAllAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReadAsBufferAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadAsBufferAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Storage::Streams::IBuffer, uint64_t>));
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Storage::Streams::IBuffer, uint64_t>>(this->shim().ReadAsBufferAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReadAsInputStreamAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadAsInputStreamAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Storage::Streams::IInputStream, uint64_t>));
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Storage::Streams::IInputStream, uint64_t>>(this->shim().ReadAsInputStreamAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReadAsStringAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadAsStringAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<hstring, uint64_t>));
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<hstring, uint64_t>>(this->shim().ReadAsStringAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryComputeLength(uint64_t* length, bool* succeeded) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryComputeLength, WINRT_WRAP(bool), uint64_t&);
            *succeeded = detach_from<bool>(this->shim().TryComputeLength(*length));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL WriteToStreamAsync(void* outputStream, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WriteToStreamAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<uint64_t, uint64_t>), Windows::Storage::Streams::IOutputStream const);
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<uint64_t, uint64_t>>(this->shim().WriteToStreamAsync(*reinterpret_cast<Windows::Storage::Streams::IOutputStream const*>(&outputStream)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::IHttpCookie> : produce_base<D, Windows::Web::Http::IHttpCookie>
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

    int32_t WINRT_CALL get_Path(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Path, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Path());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Expires(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Expires, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::DateTime>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::DateTime>>(this->shim().Expires());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Expires(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Expires, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Foundation::DateTime> const&);
            this->shim().Expires(*reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::DateTime> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HttpOnly(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HttpOnly, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().HttpOnly());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_HttpOnly(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HttpOnly, WINRT_WRAP(void), bool);
            this->shim().HttpOnly(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Secure(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Secure, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Secure());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Secure(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Secure, WINRT_WRAP(void), bool);
            this->shim().Secure(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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

    int32_t WINRT_CALL put_Value(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Value, WINRT_WRAP(void), hstring const&);
            this->shim().Value(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::IHttpCookieFactory> : produce_base<D, Windows::Web::Http::IHttpCookieFactory>
{
    int32_t WINRT_CALL Create(void* name, void* domain, void* path, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Web::Http::HttpCookie), hstring const&, hstring const&, hstring const&);
            *value = detach_from<Windows::Web::Http::HttpCookie>(this->shim().Create(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<hstring const*>(&domain), *reinterpret_cast<hstring const*>(&path)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::IHttpCookieManager> : produce_base<D, Windows::Web::Http::IHttpCookieManager>
{
    int32_t WINRT_CALL SetCookie(void* cookie, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetCookie, WINRT_WRAP(bool), Windows::Web::Http::HttpCookie const&);
            *result = detach_from<bool>(this->shim().SetCookie(*reinterpret_cast<Windows::Web::Http::HttpCookie const*>(&cookie)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetCookieWithThirdParty(void* cookie, bool thirdParty, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetCookie, WINRT_WRAP(bool), Windows::Web::Http::HttpCookie const&, bool);
            *result = detach_from<bool>(this->shim().SetCookie(*reinterpret_cast<Windows::Web::Http::HttpCookie const*>(&cookie), thirdParty));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DeleteCookie(void* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeleteCookie, WINRT_WRAP(void), Windows::Web::Http::HttpCookie const&);
            this->shim().DeleteCookie(*reinterpret_cast<Windows::Web::Http::HttpCookie const*>(&cookie));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetCookies(void* uri, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCookies, WINRT_WRAP(Windows::Web::Http::HttpCookieCollection), Windows::Foundation::Uri const&);
            *result = detach_from<Windows::Web::Http::HttpCookieCollection>(this->shim().GetCookies(*reinterpret_cast<Windows::Foundation::Uri const*>(&uri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::IHttpFormUrlEncodedContentFactory> : produce_base<D, Windows::Web::Http::IHttpFormUrlEncodedContentFactory>
{
    int32_t WINRT_CALL Create(void* content, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Web::Http::HttpFormUrlEncodedContent), Windows::Foundation::Collections::IIterable<Windows::Foundation::Collections::IKeyValuePair<hstring, hstring>> const&);
            *value = detach_from<Windows::Web::Http::HttpFormUrlEncodedContent>(this->shim().Create(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Foundation::Collections::IKeyValuePair<hstring, hstring>> const*>(&content)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::IHttpGetBufferResult> : produce_base<D, Windows::Web::Http::IHttpGetBufferResult>
{
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

    int32_t WINRT_CALL get_RequestMessage(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestMessage, WINRT_WRAP(Windows::Web::Http::HttpRequestMessage));
            *value = detach_from<Windows::Web::Http::HttpRequestMessage>(this->shim().RequestMessage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ResponseMessage(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResponseMessage, WINRT_WRAP(Windows::Web::Http::HttpResponseMessage));
            *value = detach_from<Windows::Web::Http::HttpResponseMessage>(this->shim().ResponseMessage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Succeeded(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Succeeded, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Succeeded());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Value(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Value, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().Value());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::IHttpGetInputStreamResult> : produce_base<D, Windows::Web::Http::IHttpGetInputStreamResult>
{
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

    int32_t WINRT_CALL get_RequestMessage(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestMessage, WINRT_WRAP(Windows::Web::Http::HttpRequestMessage));
            *value = detach_from<Windows::Web::Http::HttpRequestMessage>(this->shim().RequestMessage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ResponseMessage(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResponseMessage, WINRT_WRAP(Windows::Web::Http::HttpResponseMessage));
            *value = detach_from<Windows::Web::Http::HttpResponseMessage>(this->shim().ResponseMessage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Succeeded(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Succeeded, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Succeeded());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Value(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Value, WINRT_WRAP(Windows::Storage::Streams::IInputStream));
            *value = detach_from<Windows::Storage::Streams::IInputStream>(this->shim().Value());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::IHttpGetStringResult> : produce_base<D, Windows::Web::Http::IHttpGetStringResult>
{
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

    int32_t WINRT_CALL get_RequestMessage(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestMessage, WINRT_WRAP(Windows::Web::Http::HttpRequestMessage));
            *value = detach_from<Windows::Web::Http::HttpRequestMessage>(this->shim().RequestMessage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ResponseMessage(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResponseMessage, WINRT_WRAP(Windows::Web::Http::HttpResponseMessage));
            *value = detach_from<Windows::Web::Http::HttpResponseMessage>(this->shim().ResponseMessage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Succeeded(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Succeeded, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Succeeded());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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
};

template <typename D>
struct produce<D, Windows::Web::Http::IHttpMethod> : produce_base<D, Windows::Web::Http::IHttpMethod>
{
    int32_t WINRT_CALL get_Method(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Method, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Method());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::IHttpMethodFactory> : produce_base<D, Windows::Web::Http::IHttpMethodFactory>
{
    int32_t WINRT_CALL Create(void* method, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Web::Http::HttpMethod), hstring const&);
            *value = detach_from<Windows::Web::Http::HttpMethod>(this->shim().Create(*reinterpret_cast<hstring const*>(&method)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::IHttpMethodStatics> : produce_base<D, Windows::Web::Http::IHttpMethodStatics>
{
    int32_t WINRT_CALL get_Delete(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Delete, WINRT_WRAP(Windows::Web::Http::HttpMethod));
            *value = detach_from<Windows::Web::Http::HttpMethod>(this->shim().Delete());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Get(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Get, WINRT_WRAP(Windows::Web::Http::HttpMethod));
            *value = detach_from<Windows::Web::Http::HttpMethod>(this->shim().Get());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Head(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Head, WINRT_WRAP(Windows::Web::Http::HttpMethod));
            *value = detach_from<Windows::Web::Http::HttpMethod>(this->shim().Head());
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
            WINRT_ASSERT_DECLARATION(Options, WINRT_WRAP(Windows::Web::Http::HttpMethod));
            *value = detach_from<Windows::Web::Http::HttpMethod>(this->shim().Options());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Patch(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Patch, WINRT_WRAP(Windows::Web::Http::HttpMethod));
            *value = detach_from<Windows::Web::Http::HttpMethod>(this->shim().Patch());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Post(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Post, WINRT_WRAP(Windows::Web::Http::HttpMethod));
            *value = detach_from<Windows::Web::Http::HttpMethod>(this->shim().Post());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Put(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Put, WINRT_WRAP(Windows::Web::Http::HttpMethod));
            *value = detach_from<Windows::Web::Http::HttpMethod>(this->shim().Put());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::IHttpMultipartContent> : produce_base<D, Windows::Web::Http::IHttpMultipartContent>
{
    int32_t WINRT_CALL Add(void* content) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Add, WINRT_WRAP(void), Windows::Web::Http::IHttpContent const&);
            this->shim().Add(*reinterpret_cast<Windows::Web::Http::IHttpContent const*>(&content));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::IHttpMultipartContentFactory> : produce_base<D, Windows::Web::Http::IHttpMultipartContentFactory>
{
    int32_t WINRT_CALL CreateWithSubtype(void* subtype, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithSubtype, WINRT_WRAP(Windows::Web::Http::HttpMultipartContent), hstring const&);
            *value = detach_from<Windows::Web::Http::HttpMultipartContent>(this->shim().CreateWithSubtype(*reinterpret_cast<hstring const*>(&subtype)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithSubtypeAndBoundary(void* subtype, void* boundary, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithSubtypeAndBoundary, WINRT_WRAP(Windows::Web::Http::HttpMultipartContent), hstring const&, hstring const&);
            *value = detach_from<Windows::Web::Http::HttpMultipartContent>(this->shim().CreateWithSubtypeAndBoundary(*reinterpret_cast<hstring const*>(&subtype), *reinterpret_cast<hstring const*>(&boundary)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::IHttpMultipartFormDataContent> : produce_base<D, Windows::Web::Http::IHttpMultipartFormDataContent>
{
    int32_t WINRT_CALL Add(void* content) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Add, WINRT_WRAP(void), Windows::Web::Http::IHttpContent const&);
            this->shim().Add(*reinterpret_cast<Windows::Web::Http::IHttpContent const*>(&content));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AddWithName(void* content, void* name) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Add, WINRT_WRAP(void), Windows::Web::Http::IHttpContent const&, hstring const&);
            this->shim().Add(*reinterpret_cast<Windows::Web::Http::IHttpContent const*>(&content), *reinterpret_cast<hstring const*>(&name));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AddWithNameAndFileName(void* content, void* name, void* fileName) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Add, WINRT_WRAP(void), Windows::Web::Http::IHttpContent const&, hstring const&, hstring const&);
            this->shim().Add(*reinterpret_cast<Windows::Web::Http::IHttpContent const*>(&content), *reinterpret_cast<hstring const*>(&name), *reinterpret_cast<hstring const*>(&fileName));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::IHttpMultipartFormDataContentFactory> : produce_base<D, Windows::Web::Http::IHttpMultipartFormDataContentFactory>
{
    int32_t WINRT_CALL CreateWithBoundary(void* boundary, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithBoundary, WINRT_WRAP(Windows::Web::Http::HttpMultipartFormDataContent), hstring const&);
            *value = detach_from<Windows::Web::Http::HttpMultipartFormDataContent>(this->shim().CreateWithBoundary(*reinterpret_cast<hstring const*>(&boundary)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::IHttpRequestMessage> : produce_base<D, Windows::Web::Http::IHttpRequestMessage>
{
    int32_t WINRT_CALL get_Content(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Content, WINRT_WRAP(Windows::Web::Http::IHttpContent));
            *value = detach_from<Windows::Web::Http::IHttpContent>(this->shim().Content());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Content(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Content, WINRT_WRAP(void), Windows::Web::Http::IHttpContent const&);
            this->shim().Content(*reinterpret_cast<Windows::Web::Http::IHttpContent const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Headers(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Headers, WINRT_WRAP(Windows::Web::Http::Headers::HttpRequestHeaderCollection));
            *value = detach_from<Windows::Web::Http::Headers::HttpRequestHeaderCollection>(this->shim().Headers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Method(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Method, WINRT_WRAP(Windows::Web::Http::HttpMethod));
            *value = detach_from<Windows::Web::Http::HttpMethod>(this->shim().Method());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Method(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Method, WINRT_WRAP(void), Windows::Web::Http::HttpMethod const&);
            this->shim().Method(*reinterpret_cast<Windows::Web::Http::HttpMethod const*>(&value));
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
            WINRT_ASSERT_DECLARATION(Properties, WINRT_WRAP(Windows::Foundation::Collections::IMap<hstring, Windows::Foundation::IInspectable>));
            *value = detach_from<Windows::Foundation::Collections::IMap<hstring, Windows::Foundation::IInspectable>>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RequestUri(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestUri, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().RequestUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RequestUri(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestUri, WINRT_WRAP(void), Windows::Foundation::Uri const&);
            this->shim().RequestUri(*reinterpret_cast<Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TransportInformation(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransportInformation, WINRT_WRAP(Windows::Web::Http::HttpTransportInformation));
            *value = detach_from<Windows::Web::Http::HttpTransportInformation>(this->shim().TransportInformation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::IHttpRequestMessageFactory> : produce_base<D, Windows::Web::Http::IHttpRequestMessageFactory>
{
    int32_t WINRT_CALL Create(void* method, void* uri, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Web::Http::HttpRequestMessage), Windows::Web::Http::HttpMethod const&, Windows::Foundation::Uri const&);
            *value = detach_from<Windows::Web::Http::HttpRequestMessage>(this->shim().Create(*reinterpret_cast<Windows::Web::Http::HttpMethod const*>(&method), *reinterpret_cast<Windows::Foundation::Uri const*>(&uri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::IHttpRequestResult> : produce_base<D, Windows::Web::Http::IHttpRequestResult>
{
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

    int32_t WINRT_CALL get_RequestMessage(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestMessage, WINRT_WRAP(Windows::Web::Http::HttpRequestMessage));
            *value = detach_from<Windows::Web::Http::HttpRequestMessage>(this->shim().RequestMessage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ResponseMessage(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResponseMessage, WINRT_WRAP(Windows::Web::Http::HttpResponseMessage));
            *value = detach_from<Windows::Web::Http::HttpResponseMessage>(this->shim().ResponseMessage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Succeeded(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Succeeded, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Succeeded());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::IHttpResponseMessage> : produce_base<D, Windows::Web::Http::IHttpResponseMessage>
{
    int32_t WINRT_CALL get_Content(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Content, WINRT_WRAP(Windows::Web::Http::IHttpContent));
            *value = detach_from<Windows::Web::Http::IHttpContent>(this->shim().Content());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Content(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Content, WINRT_WRAP(void), Windows::Web::Http::IHttpContent const&);
            this->shim().Content(*reinterpret_cast<Windows::Web::Http::IHttpContent const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Headers(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Headers, WINRT_WRAP(Windows::Web::Http::Headers::HttpResponseHeaderCollection));
            *value = detach_from<Windows::Web::Http::Headers::HttpResponseHeaderCollection>(this->shim().Headers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsSuccessStatusCode(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSuccessStatusCode, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsSuccessStatusCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ReasonPhrase(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReasonPhrase, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ReasonPhrase());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ReasonPhrase(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReasonPhrase, WINRT_WRAP(void), hstring const&);
            this->shim().ReasonPhrase(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RequestMessage(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestMessage, WINRT_WRAP(Windows::Web::Http::HttpRequestMessage));
            *value = detach_from<Windows::Web::Http::HttpRequestMessage>(this->shim().RequestMessage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RequestMessage(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestMessage, WINRT_WRAP(void), Windows::Web::Http::HttpRequestMessage const&);
            this->shim().RequestMessage(*reinterpret_cast<Windows::Web::Http::HttpRequestMessage const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Source(Windows::Web::Http::HttpResponseMessageSource* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Source, WINRT_WRAP(Windows::Web::Http::HttpResponseMessageSource));
            *value = detach_from<Windows::Web::Http::HttpResponseMessageSource>(this->shim().Source());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Source(Windows::Web::Http::HttpResponseMessageSource value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Source, WINRT_WRAP(void), Windows::Web::Http::HttpResponseMessageSource const&);
            this->shim().Source(*reinterpret_cast<Windows::Web::Http::HttpResponseMessageSource const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StatusCode(Windows::Web::Http::HttpStatusCode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StatusCode, WINRT_WRAP(Windows::Web::Http::HttpStatusCode));
            *value = detach_from<Windows::Web::Http::HttpStatusCode>(this->shim().StatusCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_StatusCode(Windows::Web::Http::HttpStatusCode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StatusCode, WINRT_WRAP(void), Windows::Web::Http::HttpStatusCode const&);
            this->shim().StatusCode(*reinterpret_cast<Windows::Web::Http::HttpStatusCode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Version(Windows::Web::Http::HttpVersion* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Version, WINRT_WRAP(Windows::Web::Http::HttpVersion));
            *value = detach_from<Windows::Web::Http::HttpVersion>(this->shim().Version());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Version(Windows::Web::Http::HttpVersion value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Version, WINRT_WRAP(void), Windows::Web::Http::HttpVersion const&);
            this->shim().Version(*reinterpret_cast<Windows::Web::Http::HttpVersion const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL EnsureSuccessStatusCode(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnsureSuccessStatusCode, WINRT_WRAP(Windows::Web::Http::HttpResponseMessage));
            *result = detach_from<Windows::Web::Http::HttpResponseMessage>(this->shim().EnsureSuccessStatusCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::IHttpResponseMessageFactory> : produce_base<D, Windows::Web::Http::IHttpResponseMessageFactory>
{
    int32_t WINRT_CALL Create(Windows::Web::Http::HttpStatusCode statusCode, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Web::Http::HttpResponseMessage), Windows::Web::Http::HttpStatusCode const&);
            *value = detach_from<Windows::Web::Http::HttpResponseMessage>(this->shim().Create(*reinterpret_cast<Windows::Web::Http::HttpStatusCode const*>(&statusCode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::IHttpStreamContentFactory> : produce_base<D, Windows::Web::Http::IHttpStreamContentFactory>
{
    int32_t WINRT_CALL CreateFromInputStream(void* content, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromInputStream, WINRT_WRAP(Windows::Web::Http::HttpStreamContent), Windows::Storage::Streams::IInputStream const&);
            *value = detach_from<Windows::Web::Http::HttpStreamContent>(this->shim().CreateFromInputStream(*reinterpret_cast<Windows::Storage::Streams::IInputStream const*>(&content)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::IHttpStringContentFactory> : produce_base<D, Windows::Web::Http::IHttpStringContentFactory>
{
    int32_t WINRT_CALL CreateFromString(void* content, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromString, WINRT_WRAP(Windows::Web::Http::HttpStringContent), hstring const&);
            *value = detach_from<Windows::Web::Http::HttpStringContent>(this->shim().CreateFromString(*reinterpret_cast<hstring const*>(&content)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromStringWithEncoding(void* content, Windows::Storage::Streams::UnicodeEncoding encoding, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromStringWithEncoding, WINRT_WRAP(Windows::Web::Http::HttpStringContent), hstring const&, Windows::Storage::Streams::UnicodeEncoding const&);
            *value = detach_from<Windows::Web::Http::HttpStringContent>(this->shim().CreateFromStringWithEncoding(*reinterpret_cast<hstring const*>(&content), *reinterpret_cast<Windows::Storage::Streams::UnicodeEncoding const*>(&encoding)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromStringWithEncodingAndMediaType(void* content, Windows::Storage::Streams::UnicodeEncoding encoding, void* mediaType, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromStringWithEncodingAndMediaType, WINRT_WRAP(Windows::Web::Http::HttpStringContent), hstring const&, Windows::Storage::Streams::UnicodeEncoding const&, hstring const&);
            *value = detach_from<Windows::Web::Http::HttpStringContent>(this->shim().CreateFromStringWithEncodingAndMediaType(*reinterpret_cast<hstring const*>(&content), *reinterpret_cast<Windows::Storage::Streams::UnicodeEncoding const*>(&encoding), *reinterpret_cast<hstring const*>(&mediaType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::IHttpTransportInformation> : produce_base<D, Windows::Web::Http::IHttpTransportInformation>
{
    int32_t WINRT_CALL get_ServerCertificate(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServerCertificate, WINRT_WRAP(Windows::Security::Cryptography::Certificates::Certificate));
            *value = detach_from<Windows::Security::Cryptography::Certificates::Certificate>(this->shim().ServerCertificate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ServerCertificateErrorSeverity(Windows::Networking::Sockets::SocketSslErrorSeverity* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServerCertificateErrorSeverity, WINRT_WRAP(Windows::Networking::Sockets::SocketSslErrorSeverity));
            *value = detach_from<Windows::Networking::Sockets::SocketSslErrorSeverity>(this->shim().ServerCertificateErrorSeverity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ServerCertificateErrors(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServerCertificateErrors, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Security::Cryptography::Certificates::ChainValidationResult>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Security::Cryptography::Certificates::ChainValidationResult>>(this->shim().ServerCertificateErrors());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ServerIntermediateCertificates(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServerIntermediateCertificates, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Security::Cryptography::Certificates::Certificate>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Security::Cryptography::Certificates::Certificate>>(this->shim().ServerIntermediateCertificates());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Web::Http {

inline HttpBufferContent::HttpBufferContent(Windows::Storage::Streams::IBuffer const& content) :
    HttpBufferContent(impl::call_factory<HttpBufferContent, Windows::Web::Http::IHttpBufferContentFactory>([&](auto&& f) { return f.CreateFromBuffer(content); }))
{}

inline HttpBufferContent::HttpBufferContent(Windows::Storage::Streams::IBuffer const& content, uint32_t offset, uint32_t count) :
    HttpBufferContent(impl::call_factory<HttpBufferContent, Windows::Web::Http::IHttpBufferContentFactory>([&](auto&& f) { return f.CreateFromBufferWithOffset(content, offset, count); }))
{}

inline HttpClient::HttpClient() :
    HttpClient(impl::call_factory<HttpClient>([](auto&& f) { return f.template ActivateInstance<HttpClient>(); }))
{}

inline HttpClient::HttpClient(Windows::Web::Http::Filters::IHttpFilter const& filter) :
    HttpClient(impl::call_factory<HttpClient, Windows::Web::Http::IHttpClientFactory>([&](auto&& f) { return f.Create(filter); }))
{}

inline HttpCookie::HttpCookie(param::hstring const& name, param::hstring const& domain, param::hstring const& path) :
    HttpCookie(impl::call_factory<HttpCookie, Windows::Web::Http::IHttpCookieFactory>([&](auto&& f) { return f.Create(name, domain, path); }))
{}

inline HttpFormUrlEncodedContent::HttpFormUrlEncodedContent(param::iterable<Windows::Foundation::Collections::IKeyValuePair<hstring, hstring>> const& content) :
    HttpFormUrlEncodedContent(impl::call_factory<HttpFormUrlEncodedContent, Windows::Web::Http::IHttpFormUrlEncodedContentFactory>([&](auto&& f) { return f.Create(content); }))
{}

inline HttpMethod::HttpMethod(param::hstring const& method) :
    HttpMethod(impl::call_factory<HttpMethod, Windows::Web::Http::IHttpMethodFactory>([&](auto&& f) { return f.Create(method); }))
{}

inline Windows::Web::Http::HttpMethod HttpMethod::Delete()
{
    return impl::call_factory<HttpMethod, Windows::Web::Http::IHttpMethodStatics>([&](auto&& f) { return f.Delete(); });
}

inline Windows::Web::Http::HttpMethod HttpMethod::Get()
{
    return impl::call_factory<HttpMethod, Windows::Web::Http::IHttpMethodStatics>([&](auto&& f) { return f.Get(); });
}

inline Windows::Web::Http::HttpMethod HttpMethod::Head()
{
    return impl::call_factory<HttpMethod, Windows::Web::Http::IHttpMethodStatics>([&](auto&& f) { return f.Head(); });
}

inline Windows::Web::Http::HttpMethod HttpMethod::Options()
{
    return impl::call_factory<HttpMethod, Windows::Web::Http::IHttpMethodStatics>([&](auto&& f) { return f.Options(); });
}

inline Windows::Web::Http::HttpMethod HttpMethod::Patch()
{
    return impl::call_factory<HttpMethod, Windows::Web::Http::IHttpMethodStatics>([&](auto&& f) { return f.Patch(); });
}

inline Windows::Web::Http::HttpMethod HttpMethod::Post()
{
    return impl::call_factory<HttpMethod, Windows::Web::Http::IHttpMethodStatics>([&](auto&& f) { return f.Post(); });
}

inline Windows::Web::Http::HttpMethod HttpMethod::Put()
{
    return impl::call_factory<HttpMethod, Windows::Web::Http::IHttpMethodStatics>([&](auto&& f) { return f.Put(); });
}

inline HttpMultipartContent::HttpMultipartContent() :
    HttpMultipartContent(impl::call_factory<HttpMultipartContent>([](auto&& f) { return f.template ActivateInstance<HttpMultipartContent>(); }))
{}

inline HttpMultipartContent::HttpMultipartContent(param::hstring const& subtype) :
    HttpMultipartContent(impl::call_factory<HttpMultipartContent, Windows::Web::Http::IHttpMultipartContentFactory>([&](auto&& f) { return f.CreateWithSubtype(subtype); }))
{}

inline HttpMultipartContent::HttpMultipartContent(param::hstring const& subtype, param::hstring const& boundary) :
    HttpMultipartContent(impl::call_factory<HttpMultipartContent, Windows::Web::Http::IHttpMultipartContentFactory>([&](auto&& f) { return f.CreateWithSubtypeAndBoundary(subtype, boundary); }))
{}

inline HttpMultipartFormDataContent::HttpMultipartFormDataContent() :
    HttpMultipartFormDataContent(impl::call_factory<HttpMultipartFormDataContent>([](auto&& f) { return f.template ActivateInstance<HttpMultipartFormDataContent>(); }))
{}

inline HttpMultipartFormDataContent::HttpMultipartFormDataContent(param::hstring const& boundary) :
    HttpMultipartFormDataContent(impl::call_factory<HttpMultipartFormDataContent, Windows::Web::Http::IHttpMultipartFormDataContentFactory>([&](auto&& f) { return f.CreateWithBoundary(boundary); }))
{}

inline HttpRequestMessage::HttpRequestMessage() :
    HttpRequestMessage(impl::call_factory<HttpRequestMessage>([](auto&& f) { return f.template ActivateInstance<HttpRequestMessage>(); }))
{}

inline HttpRequestMessage::HttpRequestMessage(Windows::Web::Http::HttpMethod const& method, Windows::Foundation::Uri const& uri) :
    HttpRequestMessage(impl::call_factory<HttpRequestMessage, Windows::Web::Http::IHttpRequestMessageFactory>([&](auto&& f) { return f.Create(method, uri); }))
{}

inline HttpResponseMessage::HttpResponseMessage() :
    HttpResponseMessage(impl::call_factory<HttpResponseMessage>([](auto&& f) { return f.template ActivateInstance<HttpResponseMessage>(); }))
{}

inline HttpResponseMessage::HttpResponseMessage(Windows::Web::Http::HttpStatusCode const& statusCode) :
    HttpResponseMessage(impl::call_factory<HttpResponseMessage, Windows::Web::Http::IHttpResponseMessageFactory>([&](auto&& f) { return f.Create(statusCode); }))
{}

inline HttpStreamContent::HttpStreamContent(Windows::Storage::Streams::IInputStream const& content) :
    HttpStreamContent(impl::call_factory<HttpStreamContent, Windows::Web::Http::IHttpStreamContentFactory>([&](auto&& f) { return f.CreateFromInputStream(content); }))
{}

inline HttpStringContent::HttpStringContent(param::hstring const& content) :
    HttpStringContent(impl::call_factory<HttpStringContent, Windows::Web::Http::IHttpStringContentFactory>([&](auto&& f) { return f.CreateFromString(content); }))
{}

inline HttpStringContent::HttpStringContent(param::hstring const& content, Windows::Storage::Streams::UnicodeEncoding const& encoding) :
    HttpStringContent(impl::call_factory<HttpStringContent, Windows::Web::Http::IHttpStringContentFactory>([&](auto&& f) { return f.CreateFromStringWithEncoding(content, encoding); }))
{}

inline HttpStringContent::HttpStringContent(param::hstring const& content, Windows::Storage::Streams::UnicodeEncoding const& encoding, param::hstring const& mediaType) :
    HttpStringContent(impl::call_factory<HttpStringContent, Windows::Web::Http::IHttpStringContentFactory>([&](auto&& f) { return f.CreateFromStringWithEncodingAndMediaType(content, encoding, mediaType); }))
{}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Web::Http::IHttpBufferContentFactory> : winrt::impl::hash_base<winrt::Windows::Web::Http::IHttpBufferContentFactory> {};
template<> struct hash<winrt::Windows::Web::Http::IHttpClient> : winrt::impl::hash_base<winrt::Windows::Web::Http::IHttpClient> {};
template<> struct hash<winrt::Windows::Web::Http::IHttpClient2> : winrt::impl::hash_base<winrt::Windows::Web::Http::IHttpClient2> {};
template<> struct hash<winrt::Windows::Web::Http::IHttpClientFactory> : winrt::impl::hash_base<winrt::Windows::Web::Http::IHttpClientFactory> {};
template<> struct hash<winrt::Windows::Web::Http::IHttpContent> : winrt::impl::hash_base<winrt::Windows::Web::Http::IHttpContent> {};
template<> struct hash<winrt::Windows::Web::Http::IHttpCookie> : winrt::impl::hash_base<winrt::Windows::Web::Http::IHttpCookie> {};
template<> struct hash<winrt::Windows::Web::Http::IHttpCookieFactory> : winrt::impl::hash_base<winrt::Windows::Web::Http::IHttpCookieFactory> {};
template<> struct hash<winrt::Windows::Web::Http::IHttpCookieManager> : winrt::impl::hash_base<winrt::Windows::Web::Http::IHttpCookieManager> {};
template<> struct hash<winrt::Windows::Web::Http::IHttpFormUrlEncodedContentFactory> : winrt::impl::hash_base<winrt::Windows::Web::Http::IHttpFormUrlEncodedContentFactory> {};
template<> struct hash<winrt::Windows::Web::Http::IHttpGetBufferResult> : winrt::impl::hash_base<winrt::Windows::Web::Http::IHttpGetBufferResult> {};
template<> struct hash<winrt::Windows::Web::Http::IHttpGetInputStreamResult> : winrt::impl::hash_base<winrt::Windows::Web::Http::IHttpGetInputStreamResult> {};
template<> struct hash<winrt::Windows::Web::Http::IHttpGetStringResult> : winrt::impl::hash_base<winrt::Windows::Web::Http::IHttpGetStringResult> {};
template<> struct hash<winrt::Windows::Web::Http::IHttpMethod> : winrt::impl::hash_base<winrt::Windows::Web::Http::IHttpMethod> {};
template<> struct hash<winrt::Windows::Web::Http::IHttpMethodFactory> : winrt::impl::hash_base<winrt::Windows::Web::Http::IHttpMethodFactory> {};
template<> struct hash<winrt::Windows::Web::Http::IHttpMethodStatics> : winrt::impl::hash_base<winrt::Windows::Web::Http::IHttpMethodStatics> {};
template<> struct hash<winrt::Windows::Web::Http::IHttpMultipartContent> : winrt::impl::hash_base<winrt::Windows::Web::Http::IHttpMultipartContent> {};
template<> struct hash<winrt::Windows::Web::Http::IHttpMultipartContentFactory> : winrt::impl::hash_base<winrt::Windows::Web::Http::IHttpMultipartContentFactory> {};
template<> struct hash<winrt::Windows::Web::Http::IHttpMultipartFormDataContent> : winrt::impl::hash_base<winrt::Windows::Web::Http::IHttpMultipartFormDataContent> {};
template<> struct hash<winrt::Windows::Web::Http::IHttpMultipartFormDataContentFactory> : winrt::impl::hash_base<winrt::Windows::Web::Http::IHttpMultipartFormDataContentFactory> {};
template<> struct hash<winrt::Windows::Web::Http::IHttpRequestMessage> : winrt::impl::hash_base<winrt::Windows::Web::Http::IHttpRequestMessage> {};
template<> struct hash<winrt::Windows::Web::Http::IHttpRequestMessageFactory> : winrt::impl::hash_base<winrt::Windows::Web::Http::IHttpRequestMessageFactory> {};
template<> struct hash<winrt::Windows::Web::Http::IHttpRequestResult> : winrt::impl::hash_base<winrt::Windows::Web::Http::IHttpRequestResult> {};
template<> struct hash<winrt::Windows::Web::Http::IHttpResponseMessage> : winrt::impl::hash_base<winrt::Windows::Web::Http::IHttpResponseMessage> {};
template<> struct hash<winrt::Windows::Web::Http::IHttpResponseMessageFactory> : winrt::impl::hash_base<winrt::Windows::Web::Http::IHttpResponseMessageFactory> {};
template<> struct hash<winrt::Windows::Web::Http::IHttpStreamContentFactory> : winrt::impl::hash_base<winrt::Windows::Web::Http::IHttpStreamContentFactory> {};
template<> struct hash<winrt::Windows::Web::Http::IHttpStringContentFactory> : winrt::impl::hash_base<winrt::Windows::Web::Http::IHttpStringContentFactory> {};
template<> struct hash<winrt::Windows::Web::Http::IHttpTransportInformation> : winrt::impl::hash_base<winrt::Windows::Web::Http::IHttpTransportInformation> {};
template<> struct hash<winrt::Windows::Web::Http::HttpBufferContent> : winrt::impl::hash_base<winrt::Windows::Web::Http::HttpBufferContent> {};
template<> struct hash<winrt::Windows::Web::Http::HttpClient> : winrt::impl::hash_base<winrt::Windows::Web::Http::HttpClient> {};
template<> struct hash<winrt::Windows::Web::Http::HttpCookie> : winrt::impl::hash_base<winrt::Windows::Web::Http::HttpCookie> {};
template<> struct hash<winrt::Windows::Web::Http::HttpCookieCollection> : winrt::impl::hash_base<winrt::Windows::Web::Http::HttpCookieCollection> {};
template<> struct hash<winrt::Windows::Web::Http::HttpCookieManager> : winrt::impl::hash_base<winrt::Windows::Web::Http::HttpCookieManager> {};
template<> struct hash<winrt::Windows::Web::Http::HttpFormUrlEncodedContent> : winrt::impl::hash_base<winrt::Windows::Web::Http::HttpFormUrlEncodedContent> {};
template<> struct hash<winrt::Windows::Web::Http::HttpGetBufferResult> : winrt::impl::hash_base<winrt::Windows::Web::Http::HttpGetBufferResult> {};
template<> struct hash<winrt::Windows::Web::Http::HttpGetInputStreamResult> : winrt::impl::hash_base<winrt::Windows::Web::Http::HttpGetInputStreamResult> {};
template<> struct hash<winrt::Windows::Web::Http::HttpGetStringResult> : winrt::impl::hash_base<winrt::Windows::Web::Http::HttpGetStringResult> {};
template<> struct hash<winrt::Windows::Web::Http::HttpMethod> : winrt::impl::hash_base<winrt::Windows::Web::Http::HttpMethod> {};
template<> struct hash<winrt::Windows::Web::Http::HttpMultipartContent> : winrt::impl::hash_base<winrt::Windows::Web::Http::HttpMultipartContent> {};
template<> struct hash<winrt::Windows::Web::Http::HttpMultipartFormDataContent> : winrt::impl::hash_base<winrt::Windows::Web::Http::HttpMultipartFormDataContent> {};
template<> struct hash<winrt::Windows::Web::Http::HttpRequestMessage> : winrt::impl::hash_base<winrt::Windows::Web::Http::HttpRequestMessage> {};
template<> struct hash<winrt::Windows::Web::Http::HttpRequestResult> : winrt::impl::hash_base<winrt::Windows::Web::Http::HttpRequestResult> {};
template<> struct hash<winrt::Windows::Web::Http::HttpResponseMessage> : winrt::impl::hash_base<winrt::Windows::Web::Http::HttpResponseMessage> {};
template<> struct hash<winrt::Windows::Web::Http::HttpStreamContent> : winrt::impl::hash_base<winrt::Windows::Web::Http::HttpStreamContent> {};
template<> struct hash<winrt::Windows::Web::Http::HttpStringContent> : winrt::impl::hash_base<winrt::Windows::Web::Http::HttpStringContent> {};
template<> struct hash<winrt::Windows::Web::Http::HttpTransportInformation> : winrt::impl::hash_base<winrt::Windows::Web::Http::HttpTransportInformation> {};

}
