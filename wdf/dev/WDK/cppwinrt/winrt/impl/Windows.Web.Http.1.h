// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Foundation.0.h"
#include "winrt/impl/Windows.Networking.Sockets.0.h"
#include "winrt/impl/Windows.Security.Cryptography.Certificates.0.h"
#include "winrt/impl/Windows.Storage.Streams.0.h"
#include "winrt/impl/Windows.Web.Http.Filters.0.h"
#include "winrt/impl/Windows.Web.Http.Headers.0.h"
#include "winrt/impl/Windows.Foundation.Collections.0.h"
#include "winrt/impl/Windows.Web.Http.0.h"

WINRT_EXPORT namespace winrt::Windows::Web::Http {

struct WINRT_EBO IHttpBufferContentFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpBufferContentFactory>
{
    IHttpBufferContentFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpClient :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpClient>
{
    IHttpClient(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpClient2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpClient2>
{
    IHttpClient2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpClientFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpClientFactory>
{
    IHttpClientFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpContent :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpContent>,
    impl::require<IHttpContent, Windows::Foundation::IClosable>
{
    IHttpContent(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpCookie :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpCookie>
{
    IHttpCookie(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpCookieFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpCookieFactory>
{
    IHttpCookieFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpCookieManager :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpCookieManager>
{
    IHttpCookieManager(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpFormUrlEncodedContentFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpFormUrlEncodedContentFactory>
{
    IHttpFormUrlEncodedContentFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpGetBufferResult :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpGetBufferResult>
{
    IHttpGetBufferResult(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpGetInputStreamResult :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpGetInputStreamResult>
{
    IHttpGetInputStreamResult(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpGetStringResult :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpGetStringResult>
{
    IHttpGetStringResult(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpMethod :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpMethod>
{
    IHttpMethod(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpMethodFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpMethodFactory>
{
    IHttpMethodFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpMethodStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpMethodStatics>
{
    IHttpMethodStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpMultipartContent :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpMultipartContent>
{
    IHttpMultipartContent(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpMultipartContentFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpMultipartContentFactory>
{
    IHttpMultipartContentFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpMultipartFormDataContent :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpMultipartFormDataContent>
{
    IHttpMultipartFormDataContent(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpMultipartFormDataContentFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpMultipartFormDataContentFactory>
{
    IHttpMultipartFormDataContentFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpRequestMessage :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpRequestMessage>
{
    IHttpRequestMessage(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpRequestMessageFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpRequestMessageFactory>
{
    IHttpRequestMessageFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpRequestResult :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpRequestResult>
{
    IHttpRequestResult(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpResponseMessage :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpResponseMessage>
{
    IHttpResponseMessage(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpResponseMessageFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpResponseMessageFactory>
{
    IHttpResponseMessageFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpStreamContentFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpStreamContentFactory>
{
    IHttpStreamContentFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpStringContentFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpStringContentFactory>
{
    IHttpStringContentFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpTransportInformation :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpTransportInformation>
{
    IHttpTransportInformation(std::nullptr_t = nullptr) noexcept {}
};

}
