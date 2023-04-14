// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Foundation.0.h"
#include "winrt/impl/Windows.Globalization.0.h"
#include "winrt/impl/Windows.Networking.0.h"
#include "winrt/impl/Windows.Storage.Streams.0.h"
#include "winrt/impl/Windows.Web.Http.0.h"
#include "winrt/impl/Windows.Foundation.Collections.0.h"
#include "winrt/impl/Windows.Web.Http.Headers.0.h"

WINRT_EXPORT namespace winrt::Windows::Web::Http::Headers {

struct WINRT_EBO IHttpCacheDirectiveHeaderValueCollection :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpCacheDirectiveHeaderValueCollection>
{
    IHttpCacheDirectiveHeaderValueCollection(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpChallengeHeaderValue :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpChallengeHeaderValue>
{
    IHttpChallengeHeaderValue(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpChallengeHeaderValueCollection :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpChallengeHeaderValueCollection>
{
    IHttpChallengeHeaderValueCollection(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpChallengeHeaderValueFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpChallengeHeaderValueFactory>
{
    IHttpChallengeHeaderValueFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpChallengeHeaderValueStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpChallengeHeaderValueStatics>
{
    IHttpChallengeHeaderValueStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpConnectionOptionHeaderValue :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpConnectionOptionHeaderValue>
{
    IHttpConnectionOptionHeaderValue(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpConnectionOptionHeaderValueCollection :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpConnectionOptionHeaderValueCollection>
{
    IHttpConnectionOptionHeaderValueCollection(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpConnectionOptionHeaderValueFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpConnectionOptionHeaderValueFactory>
{
    IHttpConnectionOptionHeaderValueFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpConnectionOptionHeaderValueStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpConnectionOptionHeaderValueStatics>
{
    IHttpConnectionOptionHeaderValueStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpContentCodingHeaderValue :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpContentCodingHeaderValue>
{
    IHttpContentCodingHeaderValue(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpContentCodingHeaderValueCollection :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpContentCodingHeaderValueCollection>
{
    IHttpContentCodingHeaderValueCollection(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpContentCodingHeaderValueFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpContentCodingHeaderValueFactory>
{
    IHttpContentCodingHeaderValueFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpContentCodingHeaderValueStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpContentCodingHeaderValueStatics>
{
    IHttpContentCodingHeaderValueStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpContentCodingWithQualityHeaderValue :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpContentCodingWithQualityHeaderValue>
{
    IHttpContentCodingWithQualityHeaderValue(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpContentCodingWithQualityHeaderValueCollection :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpContentCodingWithQualityHeaderValueCollection>
{
    IHttpContentCodingWithQualityHeaderValueCollection(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpContentCodingWithQualityHeaderValueFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpContentCodingWithQualityHeaderValueFactory>
{
    IHttpContentCodingWithQualityHeaderValueFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpContentCodingWithQualityHeaderValueStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpContentCodingWithQualityHeaderValueStatics>
{
    IHttpContentCodingWithQualityHeaderValueStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpContentDispositionHeaderValue :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpContentDispositionHeaderValue>
{
    IHttpContentDispositionHeaderValue(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpContentDispositionHeaderValueFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpContentDispositionHeaderValueFactory>
{
    IHttpContentDispositionHeaderValueFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpContentDispositionHeaderValueStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpContentDispositionHeaderValueStatics>
{
    IHttpContentDispositionHeaderValueStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpContentHeaderCollection :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpContentHeaderCollection>
{
    IHttpContentHeaderCollection(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpContentRangeHeaderValue :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpContentRangeHeaderValue>
{
    IHttpContentRangeHeaderValue(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpContentRangeHeaderValueFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpContentRangeHeaderValueFactory>
{
    IHttpContentRangeHeaderValueFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpContentRangeHeaderValueStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpContentRangeHeaderValueStatics>
{
    IHttpContentRangeHeaderValueStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpCookiePairHeaderValue :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpCookiePairHeaderValue>
{
    IHttpCookiePairHeaderValue(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpCookiePairHeaderValueCollection :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpCookiePairHeaderValueCollection>
{
    IHttpCookiePairHeaderValueCollection(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpCookiePairHeaderValueFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpCookiePairHeaderValueFactory>
{
    IHttpCookiePairHeaderValueFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpCookiePairHeaderValueStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpCookiePairHeaderValueStatics>
{
    IHttpCookiePairHeaderValueStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpCredentialsHeaderValue :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpCredentialsHeaderValue>
{
    IHttpCredentialsHeaderValue(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpCredentialsHeaderValueFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpCredentialsHeaderValueFactory>
{
    IHttpCredentialsHeaderValueFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpCredentialsHeaderValueStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpCredentialsHeaderValueStatics>
{
    IHttpCredentialsHeaderValueStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpDateOrDeltaHeaderValue :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpDateOrDeltaHeaderValue>
{
    IHttpDateOrDeltaHeaderValue(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpDateOrDeltaHeaderValueStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpDateOrDeltaHeaderValueStatics>
{
    IHttpDateOrDeltaHeaderValueStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpExpectationHeaderValue :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpExpectationHeaderValue>
{
    IHttpExpectationHeaderValue(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpExpectationHeaderValueCollection :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpExpectationHeaderValueCollection>
{
    IHttpExpectationHeaderValueCollection(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpExpectationHeaderValueFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpExpectationHeaderValueFactory>
{
    IHttpExpectationHeaderValueFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpExpectationHeaderValueStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpExpectationHeaderValueStatics>
{
    IHttpExpectationHeaderValueStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpLanguageHeaderValueCollection :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpLanguageHeaderValueCollection>
{
    IHttpLanguageHeaderValueCollection(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpLanguageRangeWithQualityHeaderValue :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpLanguageRangeWithQualityHeaderValue>
{
    IHttpLanguageRangeWithQualityHeaderValue(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpLanguageRangeWithQualityHeaderValueCollection :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpLanguageRangeWithQualityHeaderValueCollection>
{
    IHttpLanguageRangeWithQualityHeaderValueCollection(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpLanguageRangeWithQualityHeaderValueFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpLanguageRangeWithQualityHeaderValueFactory>
{
    IHttpLanguageRangeWithQualityHeaderValueFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpLanguageRangeWithQualityHeaderValueStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpLanguageRangeWithQualityHeaderValueStatics>
{
    IHttpLanguageRangeWithQualityHeaderValueStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpMediaTypeHeaderValue :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpMediaTypeHeaderValue>
{
    IHttpMediaTypeHeaderValue(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpMediaTypeHeaderValueFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpMediaTypeHeaderValueFactory>
{
    IHttpMediaTypeHeaderValueFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpMediaTypeHeaderValueStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpMediaTypeHeaderValueStatics>
{
    IHttpMediaTypeHeaderValueStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpMediaTypeWithQualityHeaderValue :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpMediaTypeWithQualityHeaderValue>
{
    IHttpMediaTypeWithQualityHeaderValue(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpMediaTypeWithQualityHeaderValueCollection :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpMediaTypeWithQualityHeaderValueCollection>
{
    IHttpMediaTypeWithQualityHeaderValueCollection(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpMediaTypeWithQualityHeaderValueFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpMediaTypeWithQualityHeaderValueFactory>
{
    IHttpMediaTypeWithQualityHeaderValueFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpMediaTypeWithQualityHeaderValueStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpMediaTypeWithQualityHeaderValueStatics>
{
    IHttpMediaTypeWithQualityHeaderValueStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpMethodHeaderValueCollection :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpMethodHeaderValueCollection>
{
    IHttpMethodHeaderValueCollection(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpNameValueHeaderValue :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpNameValueHeaderValue>
{
    IHttpNameValueHeaderValue(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpNameValueHeaderValueFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpNameValueHeaderValueFactory>
{
    IHttpNameValueHeaderValueFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpNameValueHeaderValueStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpNameValueHeaderValueStatics>
{
    IHttpNameValueHeaderValueStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpProductHeaderValue :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpProductHeaderValue>
{
    IHttpProductHeaderValue(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpProductHeaderValueFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpProductHeaderValueFactory>
{
    IHttpProductHeaderValueFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpProductHeaderValueStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpProductHeaderValueStatics>
{
    IHttpProductHeaderValueStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpProductInfoHeaderValue :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpProductInfoHeaderValue>
{
    IHttpProductInfoHeaderValue(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpProductInfoHeaderValueCollection :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpProductInfoHeaderValueCollection>
{
    IHttpProductInfoHeaderValueCollection(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpProductInfoHeaderValueFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpProductInfoHeaderValueFactory>
{
    IHttpProductInfoHeaderValueFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpProductInfoHeaderValueStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpProductInfoHeaderValueStatics>
{
    IHttpProductInfoHeaderValueStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpRequestHeaderCollection :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpRequestHeaderCollection>
{
    IHttpRequestHeaderCollection(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpResponseHeaderCollection :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpResponseHeaderCollection>
{
    IHttpResponseHeaderCollection(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpTransferCodingHeaderValue :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpTransferCodingHeaderValue>
{
    IHttpTransferCodingHeaderValue(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpTransferCodingHeaderValueCollection :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpTransferCodingHeaderValueCollection>
{
    IHttpTransferCodingHeaderValueCollection(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpTransferCodingHeaderValueFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpTransferCodingHeaderValueFactory>
{
    IHttpTransferCodingHeaderValueFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpTransferCodingHeaderValueStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpTransferCodingHeaderValueStatics>
{
    IHttpTransferCodingHeaderValueStatics(std::nullptr_t = nullptr) noexcept {}
};

}
