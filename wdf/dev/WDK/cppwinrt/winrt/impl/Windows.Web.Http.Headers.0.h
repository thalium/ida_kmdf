// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Foundation {

struct Uri;

}

WINRT_EXPORT namespace winrt::Windows::Globalization {

struct Language;

}

WINRT_EXPORT namespace winrt::Windows::Networking {

struct HostName;

}

WINRT_EXPORT namespace winrt::Windows::Storage::Streams {

struct IBuffer;

}

WINRT_EXPORT namespace winrt::Windows::Web::Http {

struct HttpMethod;

}

WINRT_EXPORT namespace winrt::Windows::Web::Http::Headers {

struct IHttpCacheDirectiveHeaderValueCollection;
struct IHttpChallengeHeaderValue;
struct IHttpChallengeHeaderValueCollection;
struct IHttpChallengeHeaderValueFactory;
struct IHttpChallengeHeaderValueStatics;
struct IHttpConnectionOptionHeaderValue;
struct IHttpConnectionOptionHeaderValueCollection;
struct IHttpConnectionOptionHeaderValueFactory;
struct IHttpConnectionOptionHeaderValueStatics;
struct IHttpContentCodingHeaderValue;
struct IHttpContentCodingHeaderValueCollection;
struct IHttpContentCodingHeaderValueFactory;
struct IHttpContentCodingHeaderValueStatics;
struct IHttpContentCodingWithQualityHeaderValue;
struct IHttpContentCodingWithQualityHeaderValueCollection;
struct IHttpContentCodingWithQualityHeaderValueFactory;
struct IHttpContentCodingWithQualityHeaderValueStatics;
struct IHttpContentDispositionHeaderValue;
struct IHttpContentDispositionHeaderValueFactory;
struct IHttpContentDispositionHeaderValueStatics;
struct IHttpContentHeaderCollection;
struct IHttpContentRangeHeaderValue;
struct IHttpContentRangeHeaderValueFactory;
struct IHttpContentRangeHeaderValueStatics;
struct IHttpCookiePairHeaderValue;
struct IHttpCookiePairHeaderValueCollection;
struct IHttpCookiePairHeaderValueFactory;
struct IHttpCookiePairHeaderValueStatics;
struct IHttpCredentialsHeaderValue;
struct IHttpCredentialsHeaderValueFactory;
struct IHttpCredentialsHeaderValueStatics;
struct IHttpDateOrDeltaHeaderValue;
struct IHttpDateOrDeltaHeaderValueStatics;
struct IHttpExpectationHeaderValue;
struct IHttpExpectationHeaderValueCollection;
struct IHttpExpectationHeaderValueFactory;
struct IHttpExpectationHeaderValueStatics;
struct IHttpLanguageHeaderValueCollection;
struct IHttpLanguageRangeWithQualityHeaderValue;
struct IHttpLanguageRangeWithQualityHeaderValueCollection;
struct IHttpLanguageRangeWithQualityHeaderValueFactory;
struct IHttpLanguageRangeWithQualityHeaderValueStatics;
struct IHttpMediaTypeHeaderValue;
struct IHttpMediaTypeHeaderValueFactory;
struct IHttpMediaTypeHeaderValueStatics;
struct IHttpMediaTypeWithQualityHeaderValue;
struct IHttpMediaTypeWithQualityHeaderValueCollection;
struct IHttpMediaTypeWithQualityHeaderValueFactory;
struct IHttpMediaTypeWithQualityHeaderValueStatics;
struct IHttpMethodHeaderValueCollection;
struct IHttpNameValueHeaderValue;
struct IHttpNameValueHeaderValueFactory;
struct IHttpNameValueHeaderValueStatics;
struct IHttpProductHeaderValue;
struct IHttpProductHeaderValueFactory;
struct IHttpProductHeaderValueStatics;
struct IHttpProductInfoHeaderValue;
struct IHttpProductInfoHeaderValueCollection;
struct IHttpProductInfoHeaderValueFactory;
struct IHttpProductInfoHeaderValueStatics;
struct IHttpRequestHeaderCollection;
struct IHttpResponseHeaderCollection;
struct IHttpTransferCodingHeaderValue;
struct IHttpTransferCodingHeaderValueCollection;
struct IHttpTransferCodingHeaderValueFactory;
struct IHttpTransferCodingHeaderValueStatics;
struct HttpCacheDirectiveHeaderValueCollection;
struct HttpChallengeHeaderValue;
struct HttpChallengeHeaderValueCollection;
struct HttpConnectionOptionHeaderValue;
struct HttpConnectionOptionHeaderValueCollection;
struct HttpContentCodingHeaderValue;
struct HttpContentCodingHeaderValueCollection;
struct HttpContentCodingWithQualityHeaderValue;
struct HttpContentCodingWithQualityHeaderValueCollection;
struct HttpContentDispositionHeaderValue;
struct HttpContentHeaderCollection;
struct HttpContentRangeHeaderValue;
struct HttpCookiePairHeaderValue;
struct HttpCookiePairHeaderValueCollection;
struct HttpCredentialsHeaderValue;
struct HttpDateOrDeltaHeaderValue;
struct HttpExpectationHeaderValue;
struct HttpExpectationHeaderValueCollection;
struct HttpLanguageHeaderValueCollection;
struct HttpLanguageRangeWithQualityHeaderValue;
struct HttpLanguageRangeWithQualityHeaderValueCollection;
struct HttpMediaTypeHeaderValue;
struct HttpMediaTypeWithQualityHeaderValue;
struct HttpMediaTypeWithQualityHeaderValueCollection;
struct HttpMethodHeaderValueCollection;
struct HttpNameValueHeaderValue;
struct HttpProductHeaderValue;
struct HttpProductInfoHeaderValue;
struct HttpProductInfoHeaderValueCollection;
struct HttpRequestHeaderCollection;
struct HttpResponseHeaderCollection;
struct HttpTransferCodingHeaderValue;
struct HttpTransferCodingHeaderValueCollection;

}

namespace winrt::impl {

template <> struct category<Windows::Web::Http::Headers::IHttpCacheDirectiveHeaderValueCollection>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Headers::IHttpChallengeHeaderValue>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Headers::IHttpChallengeHeaderValueCollection>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Headers::IHttpChallengeHeaderValueFactory>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Headers::IHttpChallengeHeaderValueStatics>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Headers::IHttpConnectionOptionHeaderValue>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Headers::IHttpConnectionOptionHeaderValueCollection>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Headers::IHttpConnectionOptionHeaderValueFactory>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Headers::IHttpConnectionOptionHeaderValueStatics>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Headers::IHttpContentCodingHeaderValue>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Headers::IHttpContentCodingHeaderValueCollection>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Headers::IHttpContentCodingHeaderValueFactory>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Headers::IHttpContentCodingHeaderValueStatics>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Headers::IHttpContentCodingWithQualityHeaderValue>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Headers::IHttpContentCodingWithQualityHeaderValueCollection>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Headers::IHttpContentCodingWithQualityHeaderValueFactory>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Headers::IHttpContentCodingWithQualityHeaderValueStatics>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Headers::IHttpContentDispositionHeaderValue>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Headers::IHttpContentDispositionHeaderValueFactory>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Headers::IHttpContentDispositionHeaderValueStatics>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Headers::IHttpContentHeaderCollection>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Headers::IHttpContentRangeHeaderValue>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Headers::IHttpContentRangeHeaderValueFactory>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Headers::IHttpContentRangeHeaderValueStatics>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Headers::IHttpCookiePairHeaderValue>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Headers::IHttpCookiePairHeaderValueCollection>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Headers::IHttpCookiePairHeaderValueFactory>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Headers::IHttpCookiePairHeaderValueStatics>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Headers::IHttpCredentialsHeaderValue>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Headers::IHttpCredentialsHeaderValueFactory>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Headers::IHttpCredentialsHeaderValueStatics>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Headers::IHttpDateOrDeltaHeaderValue>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Headers::IHttpDateOrDeltaHeaderValueStatics>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Headers::IHttpExpectationHeaderValue>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Headers::IHttpExpectationHeaderValueCollection>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Headers::IHttpExpectationHeaderValueFactory>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Headers::IHttpExpectationHeaderValueStatics>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Headers::IHttpLanguageHeaderValueCollection>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Headers::IHttpLanguageRangeWithQualityHeaderValue>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Headers::IHttpLanguageRangeWithQualityHeaderValueCollection>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Headers::IHttpLanguageRangeWithQualityHeaderValueFactory>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Headers::IHttpLanguageRangeWithQualityHeaderValueStatics>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Headers::IHttpMediaTypeHeaderValue>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Headers::IHttpMediaTypeHeaderValueFactory>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Headers::IHttpMediaTypeHeaderValueStatics>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Headers::IHttpMediaTypeWithQualityHeaderValue>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Headers::IHttpMediaTypeWithQualityHeaderValueCollection>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Headers::IHttpMediaTypeWithQualityHeaderValueFactory>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Headers::IHttpMediaTypeWithQualityHeaderValueStatics>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Headers::IHttpMethodHeaderValueCollection>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Headers::IHttpNameValueHeaderValue>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Headers::IHttpNameValueHeaderValueFactory>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Headers::IHttpNameValueHeaderValueStatics>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Headers::IHttpProductHeaderValue>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Headers::IHttpProductHeaderValueFactory>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Headers::IHttpProductHeaderValueStatics>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Headers::IHttpProductInfoHeaderValue>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Headers::IHttpProductInfoHeaderValueCollection>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Headers::IHttpProductInfoHeaderValueFactory>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Headers::IHttpProductInfoHeaderValueStatics>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Headers::IHttpRequestHeaderCollection>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Headers::IHttpResponseHeaderCollection>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Headers::IHttpTransferCodingHeaderValue>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Headers::IHttpTransferCodingHeaderValueCollection>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Headers::IHttpTransferCodingHeaderValueFactory>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Headers::IHttpTransferCodingHeaderValueStatics>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Headers::HttpCacheDirectiveHeaderValueCollection>{ using type = class_category; };
template <> struct category<Windows::Web::Http::Headers::HttpChallengeHeaderValue>{ using type = class_category; };
template <> struct category<Windows::Web::Http::Headers::HttpChallengeHeaderValueCollection>{ using type = class_category; };
template <> struct category<Windows::Web::Http::Headers::HttpConnectionOptionHeaderValue>{ using type = class_category; };
template <> struct category<Windows::Web::Http::Headers::HttpConnectionOptionHeaderValueCollection>{ using type = class_category; };
template <> struct category<Windows::Web::Http::Headers::HttpContentCodingHeaderValue>{ using type = class_category; };
template <> struct category<Windows::Web::Http::Headers::HttpContentCodingHeaderValueCollection>{ using type = class_category; };
template <> struct category<Windows::Web::Http::Headers::HttpContentCodingWithQualityHeaderValue>{ using type = class_category; };
template <> struct category<Windows::Web::Http::Headers::HttpContentCodingWithQualityHeaderValueCollection>{ using type = class_category; };
template <> struct category<Windows::Web::Http::Headers::HttpContentDispositionHeaderValue>{ using type = class_category; };
template <> struct category<Windows::Web::Http::Headers::HttpContentHeaderCollection>{ using type = class_category; };
template <> struct category<Windows::Web::Http::Headers::HttpContentRangeHeaderValue>{ using type = class_category; };
template <> struct category<Windows::Web::Http::Headers::HttpCookiePairHeaderValue>{ using type = class_category; };
template <> struct category<Windows::Web::Http::Headers::HttpCookiePairHeaderValueCollection>{ using type = class_category; };
template <> struct category<Windows::Web::Http::Headers::HttpCredentialsHeaderValue>{ using type = class_category; };
template <> struct category<Windows::Web::Http::Headers::HttpDateOrDeltaHeaderValue>{ using type = class_category; };
template <> struct category<Windows::Web::Http::Headers::HttpExpectationHeaderValue>{ using type = class_category; };
template <> struct category<Windows::Web::Http::Headers::HttpExpectationHeaderValueCollection>{ using type = class_category; };
template <> struct category<Windows::Web::Http::Headers::HttpLanguageHeaderValueCollection>{ using type = class_category; };
template <> struct category<Windows::Web::Http::Headers::HttpLanguageRangeWithQualityHeaderValue>{ using type = class_category; };
template <> struct category<Windows::Web::Http::Headers::HttpLanguageRangeWithQualityHeaderValueCollection>{ using type = class_category; };
template <> struct category<Windows::Web::Http::Headers::HttpMediaTypeHeaderValue>{ using type = class_category; };
template <> struct category<Windows::Web::Http::Headers::HttpMediaTypeWithQualityHeaderValue>{ using type = class_category; };
template <> struct category<Windows::Web::Http::Headers::HttpMediaTypeWithQualityHeaderValueCollection>{ using type = class_category; };
template <> struct category<Windows::Web::Http::Headers::HttpMethodHeaderValueCollection>{ using type = class_category; };
template <> struct category<Windows::Web::Http::Headers::HttpNameValueHeaderValue>{ using type = class_category; };
template <> struct category<Windows::Web::Http::Headers::HttpProductHeaderValue>{ using type = class_category; };
template <> struct category<Windows::Web::Http::Headers::HttpProductInfoHeaderValue>{ using type = class_category; };
template <> struct category<Windows::Web::Http::Headers::HttpProductInfoHeaderValueCollection>{ using type = class_category; };
template <> struct category<Windows::Web::Http::Headers::HttpRequestHeaderCollection>{ using type = class_category; };
template <> struct category<Windows::Web::Http::Headers::HttpResponseHeaderCollection>{ using type = class_category; };
template <> struct category<Windows::Web::Http::Headers::HttpTransferCodingHeaderValue>{ using type = class_category; };
template <> struct category<Windows::Web::Http::Headers::HttpTransferCodingHeaderValueCollection>{ using type = class_category; };
template <> struct name<Windows::Web::Http::Headers::IHttpCacheDirectiveHeaderValueCollection>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.IHttpCacheDirectiveHeaderValueCollection" }; };
template <> struct name<Windows::Web::Http::Headers::IHttpChallengeHeaderValue>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.IHttpChallengeHeaderValue" }; };
template <> struct name<Windows::Web::Http::Headers::IHttpChallengeHeaderValueCollection>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.IHttpChallengeHeaderValueCollection" }; };
template <> struct name<Windows::Web::Http::Headers::IHttpChallengeHeaderValueFactory>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.IHttpChallengeHeaderValueFactory" }; };
template <> struct name<Windows::Web::Http::Headers::IHttpChallengeHeaderValueStatics>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.IHttpChallengeHeaderValueStatics" }; };
template <> struct name<Windows::Web::Http::Headers::IHttpConnectionOptionHeaderValue>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.IHttpConnectionOptionHeaderValue" }; };
template <> struct name<Windows::Web::Http::Headers::IHttpConnectionOptionHeaderValueCollection>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.IHttpConnectionOptionHeaderValueCollection" }; };
template <> struct name<Windows::Web::Http::Headers::IHttpConnectionOptionHeaderValueFactory>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.IHttpConnectionOptionHeaderValueFactory" }; };
template <> struct name<Windows::Web::Http::Headers::IHttpConnectionOptionHeaderValueStatics>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.IHttpConnectionOptionHeaderValueStatics" }; };
template <> struct name<Windows::Web::Http::Headers::IHttpContentCodingHeaderValue>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.IHttpContentCodingHeaderValue" }; };
template <> struct name<Windows::Web::Http::Headers::IHttpContentCodingHeaderValueCollection>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.IHttpContentCodingHeaderValueCollection" }; };
template <> struct name<Windows::Web::Http::Headers::IHttpContentCodingHeaderValueFactory>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.IHttpContentCodingHeaderValueFactory" }; };
template <> struct name<Windows::Web::Http::Headers::IHttpContentCodingHeaderValueStatics>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.IHttpContentCodingHeaderValueStatics" }; };
template <> struct name<Windows::Web::Http::Headers::IHttpContentCodingWithQualityHeaderValue>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.IHttpContentCodingWithQualityHeaderValue" }; };
template <> struct name<Windows::Web::Http::Headers::IHttpContentCodingWithQualityHeaderValueCollection>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.IHttpContentCodingWithQualityHeaderValueCollection" }; };
template <> struct name<Windows::Web::Http::Headers::IHttpContentCodingWithQualityHeaderValueFactory>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.IHttpContentCodingWithQualityHeaderValueFactory" }; };
template <> struct name<Windows::Web::Http::Headers::IHttpContentCodingWithQualityHeaderValueStatics>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.IHttpContentCodingWithQualityHeaderValueStatics" }; };
template <> struct name<Windows::Web::Http::Headers::IHttpContentDispositionHeaderValue>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.IHttpContentDispositionHeaderValue" }; };
template <> struct name<Windows::Web::Http::Headers::IHttpContentDispositionHeaderValueFactory>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.IHttpContentDispositionHeaderValueFactory" }; };
template <> struct name<Windows::Web::Http::Headers::IHttpContentDispositionHeaderValueStatics>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.IHttpContentDispositionHeaderValueStatics" }; };
template <> struct name<Windows::Web::Http::Headers::IHttpContentHeaderCollection>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.IHttpContentHeaderCollection" }; };
template <> struct name<Windows::Web::Http::Headers::IHttpContentRangeHeaderValue>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.IHttpContentRangeHeaderValue" }; };
template <> struct name<Windows::Web::Http::Headers::IHttpContentRangeHeaderValueFactory>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.IHttpContentRangeHeaderValueFactory" }; };
template <> struct name<Windows::Web::Http::Headers::IHttpContentRangeHeaderValueStatics>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.IHttpContentRangeHeaderValueStatics" }; };
template <> struct name<Windows::Web::Http::Headers::IHttpCookiePairHeaderValue>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.IHttpCookiePairHeaderValue" }; };
template <> struct name<Windows::Web::Http::Headers::IHttpCookiePairHeaderValueCollection>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.IHttpCookiePairHeaderValueCollection" }; };
template <> struct name<Windows::Web::Http::Headers::IHttpCookiePairHeaderValueFactory>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.IHttpCookiePairHeaderValueFactory" }; };
template <> struct name<Windows::Web::Http::Headers::IHttpCookiePairHeaderValueStatics>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.IHttpCookiePairHeaderValueStatics" }; };
template <> struct name<Windows::Web::Http::Headers::IHttpCredentialsHeaderValue>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.IHttpCredentialsHeaderValue" }; };
template <> struct name<Windows::Web::Http::Headers::IHttpCredentialsHeaderValueFactory>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.IHttpCredentialsHeaderValueFactory" }; };
template <> struct name<Windows::Web::Http::Headers::IHttpCredentialsHeaderValueStatics>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.IHttpCredentialsHeaderValueStatics" }; };
template <> struct name<Windows::Web::Http::Headers::IHttpDateOrDeltaHeaderValue>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.IHttpDateOrDeltaHeaderValue" }; };
template <> struct name<Windows::Web::Http::Headers::IHttpDateOrDeltaHeaderValueStatics>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.IHttpDateOrDeltaHeaderValueStatics" }; };
template <> struct name<Windows::Web::Http::Headers::IHttpExpectationHeaderValue>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.IHttpExpectationHeaderValue" }; };
template <> struct name<Windows::Web::Http::Headers::IHttpExpectationHeaderValueCollection>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.IHttpExpectationHeaderValueCollection" }; };
template <> struct name<Windows::Web::Http::Headers::IHttpExpectationHeaderValueFactory>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.IHttpExpectationHeaderValueFactory" }; };
template <> struct name<Windows::Web::Http::Headers::IHttpExpectationHeaderValueStatics>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.IHttpExpectationHeaderValueStatics" }; };
template <> struct name<Windows::Web::Http::Headers::IHttpLanguageHeaderValueCollection>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.IHttpLanguageHeaderValueCollection" }; };
template <> struct name<Windows::Web::Http::Headers::IHttpLanguageRangeWithQualityHeaderValue>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.IHttpLanguageRangeWithQualityHeaderValue" }; };
template <> struct name<Windows::Web::Http::Headers::IHttpLanguageRangeWithQualityHeaderValueCollection>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.IHttpLanguageRangeWithQualityHeaderValueCollection" }; };
template <> struct name<Windows::Web::Http::Headers::IHttpLanguageRangeWithQualityHeaderValueFactory>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.IHttpLanguageRangeWithQualityHeaderValueFactory" }; };
template <> struct name<Windows::Web::Http::Headers::IHttpLanguageRangeWithQualityHeaderValueStatics>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.IHttpLanguageRangeWithQualityHeaderValueStatics" }; };
template <> struct name<Windows::Web::Http::Headers::IHttpMediaTypeHeaderValue>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.IHttpMediaTypeHeaderValue" }; };
template <> struct name<Windows::Web::Http::Headers::IHttpMediaTypeHeaderValueFactory>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.IHttpMediaTypeHeaderValueFactory" }; };
template <> struct name<Windows::Web::Http::Headers::IHttpMediaTypeHeaderValueStatics>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.IHttpMediaTypeHeaderValueStatics" }; };
template <> struct name<Windows::Web::Http::Headers::IHttpMediaTypeWithQualityHeaderValue>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.IHttpMediaTypeWithQualityHeaderValue" }; };
template <> struct name<Windows::Web::Http::Headers::IHttpMediaTypeWithQualityHeaderValueCollection>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.IHttpMediaTypeWithQualityHeaderValueCollection" }; };
template <> struct name<Windows::Web::Http::Headers::IHttpMediaTypeWithQualityHeaderValueFactory>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.IHttpMediaTypeWithQualityHeaderValueFactory" }; };
template <> struct name<Windows::Web::Http::Headers::IHttpMediaTypeWithQualityHeaderValueStatics>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.IHttpMediaTypeWithQualityHeaderValueStatics" }; };
template <> struct name<Windows::Web::Http::Headers::IHttpMethodHeaderValueCollection>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.IHttpMethodHeaderValueCollection" }; };
template <> struct name<Windows::Web::Http::Headers::IHttpNameValueHeaderValue>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.IHttpNameValueHeaderValue" }; };
template <> struct name<Windows::Web::Http::Headers::IHttpNameValueHeaderValueFactory>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.IHttpNameValueHeaderValueFactory" }; };
template <> struct name<Windows::Web::Http::Headers::IHttpNameValueHeaderValueStatics>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.IHttpNameValueHeaderValueStatics" }; };
template <> struct name<Windows::Web::Http::Headers::IHttpProductHeaderValue>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.IHttpProductHeaderValue" }; };
template <> struct name<Windows::Web::Http::Headers::IHttpProductHeaderValueFactory>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.IHttpProductHeaderValueFactory" }; };
template <> struct name<Windows::Web::Http::Headers::IHttpProductHeaderValueStatics>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.IHttpProductHeaderValueStatics" }; };
template <> struct name<Windows::Web::Http::Headers::IHttpProductInfoHeaderValue>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.IHttpProductInfoHeaderValue" }; };
template <> struct name<Windows::Web::Http::Headers::IHttpProductInfoHeaderValueCollection>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.IHttpProductInfoHeaderValueCollection" }; };
template <> struct name<Windows::Web::Http::Headers::IHttpProductInfoHeaderValueFactory>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.IHttpProductInfoHeaderValueFactory" }; };
template <> struct name<Windows::Web::Http::Headers::IHttpProductInfoHeaderValueStatics>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.IHttpProductInfoHeaderValueStatics" }; };
template <> struct name<Windows::Web::Http::Headers::IHttpRequestHeaderCollection>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.IHttpRequestHeaderCollection" }; };
template <> struct name<Windows::Web::Http::Headers::IHttpResponseHeaderCollection>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.IHttpResponseHeaderCollection" }; };
template <> struct name<Windows::Web::Http::Headers::IHttpTransferCodingHeaderValue>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.IHttpTransferCodingHeaderValue" }; };
template <> struct name<Windows::Web::Http::Headers::IHttpTransferCodingHeaderValueCollection>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.IHttpTransferCodingHeaderValueCollection" }; };
template <> struct name<Windows::Web::Http::Headers::IHttpTransferCodingHeaderValueFactory>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.IHttpTransferCodingHeaderValueFactory" }; };
template <> struct name<Windows::Web::Http::Headers::IHttpTransferCodingHeaderValueStatics>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.IHttpTransferCodingHeaderValueStatics" }; };
template <> struct name<Windows::Web::Http::Headers::HttpCacheDirectiveHeaderValueCollection>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.HttpCacheDirectiveHeaderValueCollection" }; };
template <> struct name<Windows::Web::Http::Headers::HttpChallengeHeaderValue>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.HttpChallengeHeaderValue" }; };
template <> struct name<Windows::Web::Http::Headers::HttpChallengeHeaderValueCollection>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.HttpChallengeHeaderValueCollection" }; };
template <> struct name<Windows::Web::Http::Headers::HttpConnectionOptionHeaderValue>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.HttpConnectionOptionHeaderValue" }; };
template <> struct name<Windows::Web::Http::Headers::HttpConnectionOptionHeaderValueCollection>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.HttpConnectionOptionHeaderValueCollection" }; };
template <> struct name<Windows::Web::Http::Headers::HttpContentCodingHeaderValue>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.HttpContentCodingHeaderValue" }; };
template <> struct name<Windows::Web::Http::Headers::HttpContentCodingHeaderValueCollection>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.HttpContentCodingHeaderValueCollection" }; };
template <> struct name<Windows::Web::Http::Headers::HttpContentCodingWithQualityHeaderValue>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.HttpContentCodingWithQualityHeaderValue" }; };
template <> struct name<Windows::Web::Http::Headers::HttpContentCodingWithQualityHeaderValueCollection>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.HttpContentCodingWithQualityHeaderValueCollection" }; };
template <> struct name<Windows::Web::Http::Headers::HttpContentDispositionHeaderValue>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.HttpContentDispositionHeaderValue" }; };
template <> struct name<Windows::Web::Http::Headers::HttpContentHeaderCollection>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.HttpContentHeaderCollection" }; };
template <> struct name<Windows::Web::Http::Headers::HttpContentRangeHeaderValue>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.HttpContentRangeHeaderValue" }; };
template <> struct name<Windows::Web::Http::Headers::HttpCookiePairHeaderValue>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.HttpCookiePairHeaderValue" }; };
template <> struct name<Windows::Web::Http::Headers::HttpCookiePairHeaderValueCollection>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.HttpCookiePairHeaderValueCollection" }; };
template <> struct name<Windows::Web::Http::Headers::HttpCredentialsHeaderValue>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.HttpCredentialsHeaderValue" }; };
template <> struct name<Windows::Web::Http::Headers::HttpDateOrDeltaHeaderValue>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.HttpDateOrDeltaHeaderValue" }; };
template <> struct name<Windows::Web::Http::Headers::HttpExpectationHeaderValue>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.HttpExpectationHeaderValue" }; };
template <> struct name<Windows::Web::Http::Headers::HttpExpectationHeaderValueCollection>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.HttpExpectationHeaderValueCollection" }; };
template <> struct name<Windows::Web::Http::Headers::HttpLanguageHeaderValueCollection>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.HttpLanguageHeaderValueCollection" }; };
template <> struct name<Windows::Web::Http::Headers::HttpLanguageRangeWithQualityHeaderValue>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.HttpLanguageRangeWithQualityHeaderValue" }; };
template <> struct name<Windows::Web::Http::Headers::HttpLanguageRangeWithQualityHeaderValueCollection>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.HttpLanguageRangeWithQualityHeaderValueCollection" }; };
template <> struct name<Windows::Web::Http::Headers::HttpMediaTypeHeaderValue>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.HttpMediaTypeHeaderValue" }; };
template <> struct name<Windows::Web::Http::Headers::HttpMediaTypeWithQualityHeaderValue>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.HttpMediaTypeWithQualityHeaderValue" }; };
template <> struct name<Windows::Web::Http::Headers::HttpMediaTypeWithQualityHeaderValueCollection>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.HttpMediaTypeWithQualityHeaderValueCollection" }; };
template <> struct name<Windows::Web::Http::Headers::HttpMethodHeaderValueCollection>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.HttpMethodHeaderValueCollection" }; };
template <> struct name<Windows::Web::Http::Headers::HttpNameValueHeaderValue>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.HttpNameValueHeaderValue" }; };
template <> struct name<Windows::Web::Http::Headers::HttpProductHeaderValue>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.HttpProductHeaderValue" }; };
template <> struct name<Windows::Web::Http::Headers::HttpProductInfoHeaderValue>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.HttpProductInfoHeaderValue" }; };
template <> struct name<Windows::Web::Http::Headers::HttpProductInfoHeaderValueCollection>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.HttpProductInfoHeaderValueCollection" }; };
template <> struct name<Windows::Web::Http::Headers::HttpRequestHeaderCollection>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.HttpRequestHeaderCollection" }; };
template <> struct name<Windows::Web::Http::Headers::HttpResponseHeaderCollection>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.HttpResponseHeaderCollection" }; };
template <> struct name<Windows::Web::Http::Headers::HttpTransferCodingHeaderValue>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.HttpTransferCodingHeaderValue" }; };
template <> struct name<Windows::Web::Http::Headers::HttpTransferCodingHeaderValueCollection>{ static constexpr auto & value{ L"Windows.Web.Http.Headers.HttpTransferCodingHeaderValueCollection" }; };
template <> struct guid_storage<Windows::Web::Http::Headers::IHttpCacheDirectiveHeaderValueCollection>{ static constexpr guid value{ 0x9A586B89,0xD5D0,0x4FBE,{ 0xBD,0x9D,0xB5,0xB3,0x63,0x68,0x11,0xB4 } }; };
template <> struct guid_storage<Windows::Web::Http::Headers::IHttpChallengeHeaderValue>{ static constexpr guid value{ 0x393361AF,0x0F7D,0x4820,{ 0x9F,0xDD,0xA2,0xB9,0x56,0xEE,0xAE,0xAB } }; };
template <> struct guid_storage<Windows::Web::Http::Headers::IHttpChallengeHeaderValueCollection>{ static constexpr guid value{ 0xCA9E5F81,0xAEE0,0x4353,{ 0xA1,0x0B,0xE6,0x25,0xBA,0xBD,0x64,0xC2 } }; };
template <> struct guid_storage<Windows::Web::Http::Headers::IHttpChallengeHeaderValueFactory>{ static constexpr guid value{ 0xC452C451,0xD99C,0x40AA,{ 0x93,0x99,0x90,0xEE,0xB9,0x8F,0xC6,0x13 } }; };
template <> struct guid_storage<Windows::Web::Http::Headers::IHttpChallengeHeaderValueStatics>{ static constexpr guid value{ 0xF3D38A72,0xFC01,0x4D01,{ 0xA0,0x08,0xFC,0xB7,0xC4,0x59,0xD6,0x35 } }; };
template <> struct guid_storage<Windows::Web::Http::Headers::IHttpConnectionOptionHeaderValue>{ static constexpr guid value{ 0xCB4AF27A,0x4E90,0x45EB,{ 0x8D,0xCD,0xFD,0x14,0x08,0xF4,0xC4,0x4F } }; };
template <> struct guid_storage<Windows::Web::Http::Headers::IHttpConnectionOptionHeaderValueCollection>{ static constexpr guid value{ 0xE4F56C1D,0x5142,0x4E00,{ 0x8E,0x0F,0x01,0x95,0x09,0x33,0x76,0x29 } }; };
template <> struct guid_storage<Windows::Web::Http::Headers::IHttpConnectionOptionHeaderValueFactory>{ static constexpr guid value{ 0xD93CCC1E,0x0B7D,0x4C3F,{ 0xA5,0x8D,0xA2,0xA1,0xBD,0xEA,0xBC,0x0A } }; };
template <> struct guid_storage<Windows::Web::Http::Headers::IHttpConnectionOptionHeaderValueStatics>{ static constexpr guid value{ 0xAAA75D37,0xA946,0x4B1F,{ 0x85,0xAF,0x48,0xB6,0x8B,0x3C,0x50,0xBD } }; };
template <> struct guid_storage<Windows::Web::Http::Headers::IHttpContentCodingHeaderValue>{ static constexpr guid value{ 0xBCF7F92A,0x9376,0x4D85,{ 0xBC,0xCC,0x9F,0x4F,0x9A,0xCA,0xB4,0x34 } }; };
template <> struct guid_storage<Windows::Web::Http::Headers::IHttpContentCodingHeaderValueCollection>{ static constexpr guid value{ 0x7D221721,0xA6DB,0x436E,{ 0x8E,0x83,0x91,0x59,0x61,0x92,0x81,0x9C } }; };
template <> struct guid_storage<Windows::Web::Http::Headers::IHttpContentCodingHeaderValueFactory>{ static constexpr guid value{ 0xC53D2BD7,0x332B,0x4350,{ 0x85,0x10,0x2E,0x67,0xA2,0x28,0x9A,0x5A } }; };
template <> struct guid_storage<Windows::Web::Http::Headers::IHttpContentCodingHeaderValueStatics>{ static constexpr guid value{ 0x94D8602E,0xF9BF,0x42F7,{ 0xAA,0x46,0xED,0x27,0x2A,0x41,0xE2,0x12 } }; };
template <> struct guid_storage<Windows::Web::Http::Headers::IHttpContentCodingWithQualityHeaderValue>{ static constexpr guid value{ 0x94531CD5,0x8B13,0x4D73,{ 0x86,0x51,0xF7,0x6B,0x38,0xF8,0x84,0x95 } }; };
template <> struct guid_storage<Windows::Web::Http::Headers::IHttpContentCodingWithQualityHeaderValueCollection>{ static constexpr guid value{ 0x7C0D753E,0xE899,0x4378,{ 0xB5,0xC8,0x41,0x2D,0x82,0x07,0x11,0xCC } }; };
template <> struct guid_storage<Windows::Web::Http::Headers::IHttpContentCodingWithQualityHeaderValueFactory>{ static constexpr guid value{ 0xC45EEE1A,0xC553,0x46FC,{ 0xAD,0xE2,0xD7,0x5C,0x1D,0x53,0xDF,0x7B } }; };
template <> struct guid_storage<Windows::Web::Http::Headers::IHttpContentCodingWithQualityHeaderValueStatics>{ static constexpr guid value{ 0xE8C9357C,0x8F89,0x4801,{ 0x8E,0x75,0x4C,0x9A,0xBF,0xC3,0xDE,0x71 } }; };
template <> struct guid_storage<Windows::Web::Http::Headers::IHttpContentDispositionHeaderValue>{ static constexpr guid value{ 0xF2A2EEDC,0x2629,0x4B49,{ 0x99,0x08,0x96,0xA1,0x68,0xE9,0x36,0x5E } }; };
template <> struct guid_storage<Windows::Web::Http::Headers::IHttpContentDispositionHeaderValueFactory>{ static constexpr guid value{ 0x9915BBC4,0x456C,0x4E81,{ 0x82,0x95,0xB2,0xAB,0x3C,0xBC,0xF5,0x45 } }; };
template <> struct guid_storage<Windows::Web::Http::Headers::IHttpContentDispositionHeaderValueStatics>{ static constexpr guid value{ 0x29C56067,0x5A37,0x46E4,{ 0xB0,0x74,0xC5,0x17,0x7D,0x69,0xCA,0x66 } }; };
template <> struct guid_storage<Windows::Web::Http::Headers::IHttpContentHeaderCollection>{ static constexpr guid value{ 0x40612A44,0x47AE,0x4B7E,{ 0x91,0x24,0x69,0x62,0x8B,0x64,0xAA,0x18 } }; };
template <> struct guid_storage<Windows::Web::Http::Headers::IHttpContentRangeHeaderValue>{ static constexpr guid value{ 0x04D967D3,0xA4F6,0x495C,{ 0x95,0x30,0x85,0x79,0xFC,0xBA,0x8A,0xA9 } }; };
template <> struct guid_storage<Windows::Web::Http::Headers::IHttpContentRangeHeaderValueFactory>{ static constexpr guid value{ 0x3F5BD691,0xA03C,0x4456,{ 0x9A,0x6F,0xEF,0x27,0xEC,0xD0,0x3C,0xAE } }; };
template <> struct guid_storage<Windows::Web::Http::Headers::IHttpContentRangeHeaderValueStatics>{ static constexpr guid value{ 0x80A346CA,0x174C,0x4FAE,{ 0x82,0x1C,0x13,0x4C,0xD2,0x94,0xAA,0x38 } }; };
template <> struct guid_storage<Windows::Web::Http::Headers::IHttpCookiePairHeaderValue>{ static constexpr guid value{ 0xCBD46217,0x4B29,0x412B,{ 0xBD,0x90,0xB3,0xD8,0x14,0xAB,0x8E,0x1B } }; };
template <> struct guid_storage<Windows::Web::Http::Headers::IHttpCookiePairHeaderValueCollection>{ static constexpr guid value{ 0xF3F44350,0x581E,0x4ECC,{ 0x9F,0x59,0xE5,0x07,0xD0,0x4F,0x06,0xE6 } }; };
template <> struct guid_storage<Windows::Web::Http::Headers::IHttpCookiePairHeaderValueFactory>{ static constexpr guid value{ 0x635E326F,0x146F,0x4F56,{ 0xAA,0x21,0x2C,0xB7,0xD6,0xD5,0x8B,0x1E } }; };
template <> struct guid_storage<Windows::Web::Http::Headers::IHttpCookiePairHeaderValueStatics>{ static constexpr guid value{ 0x6E866D48,0x06AF,0x4462,{ 0x81,0x58,0x99,0x38,0x8D,0x5D,0xCA,0x81 } }; };
template <> struct guid_storage<Windows::Web::Http::Headers::IHttpCredentialsHeaderValue>{ static constexpr guid value{ 0xC34CC3CB,0x542E,0x4177,{ 0xA6,0xC7,0xB6,0x74,0xCE,0x19,0x3F,0xBF } }; };
template <> struct guid_storage<Windows::Web::Http::Headers::IHttpCredentialsHeaderValueFactory>{ static constexpr guid value{ 0xF21D9E91,0x4D1C,0x4182,{ 0xBF,0xD1,0x34,0x47,0x0A,0x62,0xF9,0x50 } }; };
template <> struct guid_storage<Windows::Web::Http::Headers::IHttpCredentialsHeaderValueStatics>{ static constexpr guid value{ 0xA69B2BE6,0xCE8C,0x4443,{ 0xA3,0x5A,0x1B,0x72,0x7B,0x13,0x10,0x36 } }; };
template <> struct guid_storage<Windows::Web::Http::Headers::IHttpDateOrDeltaHeaderValue>{ static constexpr guid value{ 0xEAFCAA6A,0xC4DC,0x49E2,{ 0xA2,0x7D,0x04,0x3A,0xDF,0x58,0x67,0xA3 } }; };
template <> struct guid_storage<Windows::Web::Http::Headers::IHttpDateOrDeltaHeaderValueStatics>{ static constexpr guid value{ 0x7C2659A8,0x6672,0x4E90,{ 0x9A,0x9A,0xF3,0x97,0x66,0xF7,0xF5,0x76 } }; };
template <> struct guid_storage<Windows::Web::Http::Headers::IHttpExpectationHeaderValue>{ static constexpr guid value{ 0x4CE585CD,0x3A99,0x43AF,{ 0xA2,0xE6,0xEC,0x23,0x2F,0xEA,0x96,0x58 } }; };
template <> struct guid_storage<Windows::Web::Http::Headers::IHttpExpectationHeaderValueCollection>{ static constexpr guid value{ 0xE78521B3,0xA0E2,0x4AC4,{ 0x9E,0x66,0x79,0x70,0x6C,0xB9,0xFD,0x58 } }; };
template <> struct guid_storage<Windows::Web::Http::Headers::IHttpExpectationHeaderValueFactory>{ static constexpr guid value{ 0x4EA275CB,0xD53E,0x4868,{ 0x88,0x56,0x1E,0x21,0xA5,0x03,0x0D,0xC0 } }; };
template <> struct guid_storage<Windows::Web::Http::Headers::IHttpExpectationHeaderValueStatics>{ static constexpr guid value{ 0x3019ABE2,0xCFE5,0x473B,{ 0xA5,0x7F,0xFB,0xA5,0xB1,0x4E,0xB2,0x57 } }; };
template <> struct guid_storage<Windows::Web::Http::Headers::IHttpLanguageHeaderValueCollection>{ static constexpr guid value{ 0x9EBD7CA3,0x8219,0x44F6,{ 0x99,0x02,0x8C,0x56,0xDF,0xD3,0x34,0x0C } }; };
template <> struct guid_storage<Windows::Web::Http::Headers::IHttpLanguageRangeWithQualityHeaderValue>{ static constexpr guid value{ 0x7256E102,0x0080,0x4DB4,{ 0xA0,0x83,0x7D,0xE7,0xB2,0xE5,0xBA,0x4C } }; };
template <> struct guid_storage<Windows::Web::Http::Headers::IHttpLanguageRangeWithQualityHeaderValueCollection>{ static constexpr guid value{ 0x885D5ABD,0x4B4F,0x480A,{ 0x89,0xCE,0x8A,0xED,0xCE,0xE6,0xE3,0xA0 } }; };
template <> struct guid_storage<Windows::Web::Http::Headers::IHttpLanguageRangeWithQualityHeaderValueFactory>{ static constexpr guid value{ 0x7BB83970,0x780F,0x4C83,{ 0x9F,0xE4,0xDC,0x30,0x87,0xF6,0xBD,0x55 } }; };
template <> struct guid_storage<Windows::Web::Http::Headers::IHttpLanguageRangeWithQualityHeaderValueStatics>{ static constexpr guid value{ 0x2541E146,0xF308,0x46F5,{ 0xB6,0x95,0x42,0xF5,0x40,0x24,0xEC,0x68 } }; };
template <> struct guid_storage<Windows::Web::Http::Headers::IHttpMediaTypeHeaderValue>{ static constexpr guid value{ 0x16B28533,0xE728,0x4FCB,{ 0xBD,0xB0,0x08,0xA4,0x31,0xA1,0x48,0x44 } }; };
template <> struct guid_storage<Windows::Web::Http::Headers::IHttpMediaTypeHeaderValueFactory>{ static constexpr guid value{ 0xBED747A8,0xCD17,0x42DD,{ 0x93,0x67,0xAB,0x9C,0x5B,0x56,0xDD,0x7D } }; };
template <> struct guid_storage<Windows::Web::Http::Headers::IHttpMediaTypeHeaderValueStatics>{ static constexpr guid value{ 0xE04D83DF,0x1D41,0x4D8C,{ 0xA2,0xDE,0x6F,0xD2,0xED,0x87,0x39,0x9B } }; };
template <> struct guid_storage<Windows::Web::Http::Headers::IHttpMediaTypeWithQualityHeaderValue>{ static constexpr guid value{ 0x188D5E32,0x76BE,0x44A0,{ 0xB1,0xCD,0x20,0x74,0xBD,0xED,0x2D,0xDE } }; };
template <> struct guid_storage<Windows::Web::Http::Headers::IHttpMediaTypeWithQualityHeaderValueCollection>{ static constexpr guid value{ 0x3C0C6B73,0x1342,0x4587,{ 0xA0,0x56,0x18,0xD0,0x2F,0xF6,0x71,0x65 } }; };
template <> struct guid_storage<Windows::Web::Http::Headers::IHttpMediaTypeWithQualityHeaderValueFactory>{ static constexpr guid value{ 0x4C6D20F4,0x9457,0x44E6,{ 0xA3,0x23,0xD1,0x22,0xB9,0x58,0x78,0x0B } }; };
template <> struct guid_storage<Windows::Web::Http::Headers::IHttpMediaTypeWithQualityHeaderValueStatics>{ static constexpr guid value{ 0x5B070CD9,0xB560,0x4FC8,{ 0x98,0x35,0x7E,0x6C,0x0A,0x65,0x7B,0x24 } }; };
template <> struct guid_storage<Windows::Web::Http::Headers::IHttpMethodHeaderValueCollection>{ static constexpr guid value{ 0x43BC3FF4,0x6119,0x4ADF,{ 0x93,0x8C,0x34,0xBF,0xFF,0xCF,0x92,0xED } }; };
template <> struct guid_storage<Windows::Web::Http::Headers::IHttpNameValueHeaderValue>{ static constexpr guid value{ 0xD8BA7463,0x5B9A,0x4D1B,{ 0x93,0xF9,0xAA,0x5B,0x44,0xEC,0xFD,0xDF } }; };
template <> struct guid_storage<Windows::Web::Http::Headers::IHttpNameValueHeaderValueFactory>{ static constexpr guid value{ 0x770E2267,0xCBF8,0x4736,{ 0xA9,0x25,0x93,0xFB,0xE1,0x0C,0x7C,0xA8 } }; };
template <> struct guid_storage<Windows::Web::Http::Headers::IHttpNameValueHeaderValueStatics>{ static constexpr guid value{ 0xFFD4030F,0x1130,0x4152,{ 0x86,0x59,0x25,0x69,0x09,0xA9,0xD1,0x15 } }; };
template <> struct guid_storage<Windows::Web::Http::Headers::IHttpProductHeaderValue>{ static constexpr guid value{ 0xF4FEEE03,0xEBD4,0x4160,{ 0xB9,0xFF,0x80,0x7C,0x51,0x83,0xB6,0xE6 } }; };
template <> struct guid_storage<Windows::Web::Http::Headers::IHttpProductHeaderValueFactory>{ static constexpr guid value{ 0x611AA4F5,0x82BC,0x42FB,{ 0x97,0x7B,0xDC,0x00,0x53,0x6E,0x5E,0x86 } }; };
template <> struct guid_storage<Windows::Web::Http::Headers::IHttpProductHeaderValueStatics>{ static constexpr guid value{ 0x90C33E29,0xBEFC,0x4337,{ 0xBE,0x62,0x49,0xF0,0x97,0x97,0x5F,0x53 } }; };
template <> struct guid_storage<Windows::Web::Http::Headers::IHttpProductInfoHeaderValue>{ static constexpr guid value{ 0x1B1A8732,0x4C35,0x486A,{ 0x96,0x6F,0x64,0x64,0x89,0x19,0x8E,0x4D } }; };
template <> struct guid_storage<Windows::Web::Http::Headers::IHttpProductInfoHeaderValueCollection>{ static constexpr guid value{ 0x877DF74A,0xD69B,0x44F8,{ 0xAD,0x4F,0x45,0x3A,0xF9,0xC4,0x2E,0xD0 } }; };
template <> struct guid_storage<Windows::Web::Http::Headers::IHttpProductInfoHeaderValueFactory>{ static constexpr guid value{ 0x24220FBE,0xEABE,0x4464,{ 0xB4,0x60,0xEC,0x01,0x0B,0x7C,0x41,0xE2 } }; };
template <> struct guid_storage<Windows::Web::Http::Headers::IHttpProductInfoHeaderValueStatics>{ static constexpr guid value{ 0xDB7FD857,0x327A,0x4E73,{ 0x81,0xE5,0x70,0x59,0xA3,0x02,0xB0,0x42 } }; };
template <> struct guid_storage<Windows::Web::Http::Headers::IHttpRequestHeaderCollection>{ static constexpr guid value{ 0xAF40329B,0xB544,0x469B,{ 0x86,0xB9,0xAC,0x3D,0x46,0x6F,0xEA,0x36 } }; };
template <> struct guid_storage<Windows::Web::Http::Headers::IHttpResponseHeaderCollection>{ static constexpr guid value{ 0x7A990969,0xFA3F,0x41ED,{ 0xAA,0xC6,0xBF,0x95,0x79,0x75,0xC1,0x6B } }; };
template <> struct guid_storage<Windows::Web::Http::Headers::IHttpTransferCodingHeaderValue>{ static constexpr guid value{ 0x436F32F9,0x3DED,0x42BD,{ 0xB3,0x8A,0x54,0x96,0xA2,0x51,0x1C,0xE6 } }; };
template <> struct guid_storage<Windows::Web::Http::Headers::IHttpTransferCodingHeaderValueCollection>{ static constexpr guid value{ 0x202C8C34,0x2C03,0x49B8,{ 0x96,0x65,0x73,0xE2,0x7C,0xB2,0xFC,0x79 } }; };
template <> struct guid_storage<Windows::Web::Http::Headers::IHttpTransferCodingHeaderValueFactory>{ static constexpr guid value{ 0xBB62DFFC,0xE361,0x4F08,{ 0x8E,0x4F,0xC9,0xE7,0x23,0xDE,0x70,0x3B } }; };
template <> struct guid_storage<Windows::Web::Http::Headers::IHttpTransferCodingHeaderValueStatics>{ static constexpr guid value{ 0x6AB8892A,0x1A98,0x4D32,{ 0xA9,0x06,0x74,0x70,0xA9,0x87,0x5C,0xE5 } }; };
template <> struct default_interface<Windows::Web::Http::Headers::HttpCacheDirectiveHeaderValueCollection>{ using type = Windows::Web::Http::Headers::IHttpCacheDirectiveHeaderValueCollection; };
template <> struct default_interface<Windows::Web::Http::Headers::HttpChallengeHeaderValue>{ using type = Windows::Web::Http::Headers::IHttpChallengeHeaderValue; };
template <> struct default_interface<Windows::Web::Http::Headers::HttpChallengeHeaderValueCollection>{ using type = Windows::Web::Http::Headers::IHttpChallengeHeaderValueCollection; };
template <> struct default_interface<Windows::Web::Http::Headers::HttpConnectionOptionHeaderValue>{ using type = Windows::Web::Http::Headers::IHttpConnectionOptionHeaderValue; };
template <> struct default_interface<Windows::Web::Http::Headers::HttpConnectionOptionHeaderValueCollection>{ using type = Windows::Web::Http::Headers::IHttpConnectionOptionHeaderValueCollection; };
template <> struct default_interface<Windows::Web::Http::Headers::HttpContentCodingHeaderValue>{ using type = Windows::Web::Http::Headers::IHttpContentCodingHeaderValue; };
template <> struct default_interface<Windows::Web::Http::Headers::HttpContentCodingHeaderValueCollection>{ using type = Windows::Web::Http::Headers::IHttpContentCodingHeaderValueCollection; };
template <> struct default_interface<Windows::Web::Http::Headers::HttpContentCodingWithQualityHeaderValue>{ using type = Windows::Web::Http::Headers::IHttpContentCodingWithQualityHeaderValue; };
template <> struct default_interface<Windows::Web::Http::Headers::HttpContentCodingWithQualityHeaderValueCollection>{ using type = Windows::Web::Http::Headers::IHttpContentCodingWithQualityHeaderValueCollection; };
template <> struct default_interface<Windows::Web::Http::Headers::HttpContentDispositionHeaderValue>{ using type = Windows::Web::Http::Headers::IHttpContentDispositionHeaderValue; };
template <> struct default_interface<Windows::Web::Http::Headers::HttpContentHeaderCollection>{ using type = Windows::Web::Http::Headers::IHttpContentHeaderCollection; };
template <> struct default_interface<Windows::Web::Http::Headers::HttpContentRangeHeaderValue>{ using type = Windows::Web::Http::Headers::IHttpContentRangeHeaderValue; };
template <> struct default_interface<Windows::Web::Http::Headers::HttpCookiePairHeaderValue>{ using type = Windows::Web::Http::Headers::IHttpCookiePairHeaderValue; };
template <> struct default_interface<Windows::Web::Http::Headers::HttpCookiePairHeaderValueCollection>{ using type = Windows::Web::Http::Headers::IHttpCookiePairHeaderValueCollection; };
template <> struct default_interface<Windows::Web::Http::Headers::HttpCredentialsHeaderValue>{ using type = Windows::Web::Http::Headers::IHttpCredentialsHeaderValue; };
template <> struct default_interface<Windows::Web::Http::Headers::HttpDateOrDeltaHeaderValue>{ using type = Windows::Web::Http::Headers::IHttpDateOrDeltaHeaderValue; };
template <> struct default_interface<Windows::Web::Http::Headers::HttpExpectationHeaderValue>{ using type = Windows::Web::Http::Headers::IHttpExpectationHeaderValue; };
template <> struct default_interface<Windows::Web::Http::Headers::HttpExpectationHeaderValueCollection>{ using type = Windows::Web::Http::Headers::IHttpExpectationHeaderValueCollection; };
template <> struct default_interface<Windows::Web::Http::Headers::HttpLanguageHeaderValueCollection>{ using type = Windows::Web::Http::Headers::IHttpLanguageHeaderValueCollection; };
template <> struct default_interface<Windows::Web::Http::Headers::HttpLanguageRangeWithQualityHeaderValue>{ using type = Windows::Web::Http::Headers::IHttpLanguageRangeWithQualityHeaderValue; };
template <> struct default_interface<Windows::Web::Http::Headers::HttpLanguageRangeWithQualityHeaderValueCollection>{ using type = Windows::Web::Http::Headers::IHttpLanguageRangeWithQualityHeaderValueCollection; };
template <> struct default_interface<Windows::Web::Http::Headers::HttpMediaTypeHeaderValue>{ using type = Windows::Web::Http::Headers::IHttpMediaTypeHeaderValue; };
template <> struct default_interface<Windows::Web::Http::Headers::HttpMediaTypeWithQualityHeaderValue>{ using type = Windows::Web::Http::Headers::IHttpMediaTypeWithQualityHeaderValue; };
template <> struct default_interface<Windows::Web::Http::Headers::HttpMediaTypeWithQualityHeaderValueCollection>{ using type = Windows::Web::Http::Headers::IHttpMediaTypeWithQualityHeaderValueCollection; };
template <> struct default_interface<Windows::Web::Http::Headers::HttpMethodHeaderValueCollection>{ using type = Windows::Web::Http::Headers::IHttpMethodHeaderValueCollection; };
template <> struct default_interface<Windows::Web::Http::Headers::HttpNameValueHeaderValue>{ using type = Windows::Web::Http::Headers::IHttpNameValueHeaderValue; };
template <> struct default_interface<Windows::Web::Http::Headers::HttpProductHeaderValue>{ using type = Windows::Web::Http::Headers::IHttpProductHeaderValue; };
template <> struct default_interface<Windows::Web::Http::Headers::HttpProductInfoHeaderValue>{ using type = Windows::Web::Http::Headers::IHttpProductInfoHeaderValue; };
template <> struct default_interface<Windows::Web::Http::Headers::HttpProductInfoHeaderValueCollection>{ using type = Windows::Web::Http::Headers::IHttpProductInfoHeaderValueCollection; };
template <> struct default_interface<Windows::Web::Http::Headers::HttpRequestHeaderCollection>{ using type = Windows::Web::Http::Headers::IHttpRequestHeaderCollection; };
template <> struct default_interface<Windows::Web::Http::Headers::HttpResponseHeaderCollection>{ using type = Windows::Web::Http::Headers::IHttpResponseHeaderCollection; };
template <> struct default_interface<Windows::Web::Http::Headers::HttpTransferCodingHeaderValue>{ using type = Windows::Web::Http::Headers::IHttpTransferCodingHeaderValue; };
template <> struct default_interface<Windows::Web::Http::Headers::HttpTransferCodingHeaderValueCollection>{ using type = Windows::Web::Http::Headers::IHttpTransferCodingHeaderValueCollection; };

template <> struct abi<Windows::Web::Http::Headers::IHttpCacheDirectiveHeaderValueCollection>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_MaxAge(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_MaxAge(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MaxStale(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_MaxStale(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MinFresh(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_MinFresh(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SharedMaxAge(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_SharedMaxAge(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL ParseAdd(void* input) noexcept = 0;
    virtual int32_t WINRT_CALL TryParseAdd(void* input, bool* result) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Headers::IHttpChallengeHeaderValue>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Parameters(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Scheme(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Token(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Headers::IHttpChallengeHeaderValueCollection>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL ParseAdd(void* input) noexcept = 0;
    virtual int32_t WINRT_CALL TryParseAdd(void* input, bool* result) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Headers::IHttpChallengeHeaderValueFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateFromScheme(void* scheme, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateFromSchemeWithToken(void* scheme, void* token, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Headers::IHttpChallengeHeaderValueStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Parse(void* input, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL TryParse(void* input, void** challengeHeaderValue, bool* succeeded) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Headers::IHttpConnectionOptionHeaderValue>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Token(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Headers::IHttpConnectionOptionHeaderValueCollection>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL ParseAdd(void* input) noexcept = 0;
    virtual int32_t WINRT_CALL TryParseAdd(void* input, bool* result) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Headers::IHttpConnectionOptionHeaderValueFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Create(void* token, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Headers::IHttpConnectionOptionHeaderValueStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Parse(void* input, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL TryParse(void* input, void** connectionOptionHeaderValue, bool* succeeded) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Headers::IHttpContentCodingHeaderValue>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ContentCoding(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Headers::IHttpContentCodingHeaderValueCollection>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL ParseAdd(void* input) noexcept = 0;
    virtual int32_t WINRT_CALL TryParseAdd(void* input, bool* result) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Headers::IHttpContentCodingHeaderValueFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Create(void* contentCoding, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Headers::IHttpContentCodingHeaderValueStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Parse(void* input, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL TryParse(void* input, void** contentCodingHeaderValue, bool* succeeded) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Headers::IHttpContentCodingWithQualityHeaderValue>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ContentCoding(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Quality(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Headers::IHttpContentCodingWithQualityHeaderValueCollection>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL ParseAdd(void* input) noexcept = 0;
    virtual int32_t WINRT_CALL TryParseAdd(void* input, bool* result) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Headers::IHttpContentCodingWithQualityHeaderValueFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateFromValue(void* contentCoding, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateFromValueWithQuality(void* contentCoding, double quality, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Headers::IHttpContentCodingWithQualityHeaderValueStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Parse(void* input, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL TryParse(void* input, void** contentCodingWithQualityHeaderValue, bool* succeeded) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Headers::IHttpContentDispositionHeaderValue>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_DispositionType(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_DispositionType(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_FileName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_FileName(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_FileNameStar(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_FileNameStar(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Name(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Name(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Parameters(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Size(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Size(void* value) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Headers::IHttpContentDispositionHeaderValueFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Create(void* dispositionType, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Headers::IHttpContentDispositionHeaderValueStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Parse(void* input, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL TryParse(void* input, void** contentDispositionHeaderValue, bool* succeeded) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Headers::IHttpContentHeaderCollection>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ContentDisposition(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ContentDisposition(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ContentEncoding(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ContentLanguage(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ContentLength(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ContentLength(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ContentLocation(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ContentLocation(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ContentMD5(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ContentMD5(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ContentRange(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ContentRange(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ContentType(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ContentType(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Expires(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Expires(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LastModified(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_LastModified(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL Append(void* name, void* value) noexcept = 0;
    virtual int32_t WINRT_CALL TryAppendWithoutValidation(void* name, void* value, bool* result) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Headers::IHttpContentRangeHeaderValue>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_FirstBytePosition(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LastBytePosition(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Length(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Unit(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Unit(void* value) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Headers::IHttpContentRangeHeaderValueFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateFromLength(uint64_t length, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateFromRange(uint64_t from, uint64_t to, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateFromRangeWithLength(uint64_t from, uint64_t to, uint64_t length, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Headers::IHttpContentRangeHeaderValueStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Parse(void* input, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL TryParse(void* input, void** contentRangeHeaderValue, bool* succeeded) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Headers::IHttpCookiePairHeaderValue>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Name(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Value(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Value(void* value) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Headers::IHttpCookiePairHeaderValueCollection>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL ParseAdd(void* input) noexcept = 0;
    virtual int32_t WINRT_CALL TryParseAdd(void* input, bool* result) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Headers::IHttpCookiePairHeaderValueFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateFromName(void* name, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateFromNameWithValue(void* name, void* value, void** cookiePairHeaderValue) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Headers::IHttpCookiePairHeaderValueStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Parse(void* input, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL TryParse(void* input, void** cookiePairHeaderValue, bool* succeeded) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Headers::IHttpCredentialsHeaderValue>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Parameters(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Scheme(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Token(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Headers::IHttpCredentialsHeaderValueFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateFromScheme(void* scheme, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateFromSchemeWithToken(void* scheme, void* token, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Headers::IHttpCredentialsHeaderValueStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Parse(void* input, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL TryParse(void* input, void** credentialsHeaderValue, bool* succeeded) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Headers::IHttpDateOrDeltaHeaderValue>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Date(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Delta(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Headers::IHttpDateOrDeltaHeaderValueStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Parse(void* input, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL TryParse(void* input, void** dateOrDeltaHeaderValue, bool* succeeded) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Headers::IHttpExpectationHeaderValue>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Name(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Value(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Value(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Parameters(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Headers::IHttpExpectationHeaderValueCollection>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL ParseAdd(void* input) noexcept = 0;
    virtual int32_t WINRT_CALL TryParseAdd(void* input, bool* result) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Headers::IHttpExpectationHeaderValueFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateFromName(void* name, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateFromNameWithValue(void* name, void* value, void** expectationHeaderValue) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Headers::IHttpExpectationHeaderValueStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Parse(void* input, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL TryParse(void* input, void** expectationHeaderValue, bool* succeeded) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Headers::IHttpLanguageHeaderValueCollection>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL ParseAdd(void* input) noexcept = 0;
    virtual int32_t WINRT_CALL TryParseAdd(void* input, bool* result) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Headers::IHttpLanguageRangeWithQualityHeaderValue>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_LanguageRange(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Quality(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Headers::IHttpLanguageRangeWithQualityHeaderValueCollection>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL ParseAdd(void* input) noexcept = 0;
    virtual int32_t WINRT_CALL TryParseAdd(void* input, bool* result) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Headers::IHttpLanguageRangeWithQualityHeaderValueFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateFromLanguageRange(void* languageRange, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateFromLanguageRangeWithQuality(void* languageRange, double quality, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Headers::IHttpLanguageRangeWithQualityHeaderValueStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Parse(void* input, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL TryParse(void* input, void** languageRangeWithQualityHeaderValue, bool* succeeded) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Headers::IHttpMediaTypeHeaderValue>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_CharSet(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_CharSet(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MediaType(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_MediaType(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Parameters(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Headers::IHttpMediaTypeHeaderValueFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Create(void* mediaType, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Headers::IHttpMediaTypeHeaderValueStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Parse(void* input, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL TryParse(void* input, void** mediaTypeHeaderValue, bool* succeeded) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Headers::IHttpMediaTypeWithQualityHeaderValue>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_CharSet(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_CharSet(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MediaType(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_MediaType(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Parameters(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Quality(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Quality(void* value) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Headers::IHttpMediaTypeWithQualityHeaderValueCollection>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL ParseAdd(void* input) noexcept = 0;
    virtual int32_t WINRT_CALL TryParseAdd(void* input, bool* result) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Headers::IHttpMediaTypeWithQualityHeaderValueFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateFromMediaType(void* mediaType, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateFromMediaTypeWithQuality(void* mediaType, double quality, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Headers::IHttpMediaTypeWithQualityHeaderValueStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Parse(void* input, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL TryParse(void* input, void** mediaTypeWithQualityHeaderValue, bool* succeeded) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Headers::IHttpMethodHeaderValueCollection>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL ParseAdd(void* input) noexcept = 0;
    virtual int32_t WINRT_CALL TryParseAdd(void* input, bool* result) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Headers::IHttpNameValueHeaderValue>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Name(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Value(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Value(void* value) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Headers::IHttpNameValueHeaderValueFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateFromName(void* name, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateFromNameWithValue(void* name, void* value, void** nameValueHeaderValue) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Headers::IHttpNameValueHeaderValueStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Parse(void* input, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL TryParse(void* input, void** nameValueHeaderValue, bool* succeeded) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Headers::IHttpProductHeaderValue>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Name(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Version(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Headers::IHttpProductHeaderValueFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateFromName(void* productName, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateFromNameWithVersion(void* productName, void* productVersion, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Headers::IHttpProductHeaderValueStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Parse(void* input, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL TryParse(void* input, void** productHeaderValue, bool* succeeded) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Headers::IHttpProductInfoHeaderValue>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Product(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Comment(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Headers::IHttpProductInfoHeaderValueCollection>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL ParseAdd(void* input) noexcept = 0;
    virtual int32_t WINRT_CALL TryParseAdd(void* input, bool* result) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Headers::IHttpProductInfoHeaderValueFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateFromComment(void* productComment, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateFromNameWithVersion(void* productName, void* productVersion, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Headers::IHttpProductInfoHeaderValueStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Parse(void* input, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL TryParse(void* input, void** productInfoHeaderValue, bool* succeeded) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Headers::IHttpRequestHeaderCollection>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Accept(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AcceptEncoding(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AcceptLanguage(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Authorization(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Authorization(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CacheControl(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Connection(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Cookie(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Date(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Date(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Expect(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_From(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_From(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Host(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Host(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IfModifiedSince(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IfModifiedSince(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IfUnmodifiedSince(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IfUnmodifiedSince(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MaxForwards(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_MaxForwards(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ProxyAuthorization(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ProxyAuthorization(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Referer(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Referer(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TransferEncoding(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_UserAgent(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL Append(void* name, void* value) noexcept = 0;
    virtual int32_t WINRT_CALL TryAppendWithoutValidation(void* name, void* value, bool* result) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Headers::IHttpResponseHeaderCollection>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Age(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Age(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Allow(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CacheControl(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Connection(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Date(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Date(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Location(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Location(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ProxyAuthenticate(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RetryAfter(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_RetryAfter(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TransferEncoding(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_WwwAuthenticate(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL Append(void* name, void* value) noexcept = 0;
    virtual int32_t WINRT_CALL TryAppendWithoutValidation(void* name, void* value, bool* result) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Headers::IHttpTransferCodingHeaderValue>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Parameters(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Value(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Headers::IHttpTransferCodingHeaderValueCollection>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL ParseAdd(void* input) noexcept = 0;
    virtual int32_t WINRT_CALL TryParseAdd(void* input, bool* result) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Headers::IHttpTransferCodingHeaderValueFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Create(void* input, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Headers::IHttpTransferCodingHeaderValueStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Parse(void* input, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL TryParse(void* input, void** transferCodingHeaderValue, bool* succeeded) noexcept = 0;
};};

template <typename D>
struct consume_Windows_Web_Http_Headers_IHttpCacheDirectiveHeaderValueCollection
{
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> MaxAge() const;
    void MaxAge(optional<Windows::Foundation::TimeSpan> const& value) const;
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> MaxStale() const;
    void MaxStale(optional<Windows::Foundation::TimeSpan> const& value) const;
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> MinFresh() const;
    void MinFresh(optional<Windows::Foundation::TimeSpan> const& value) const;
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> SharedMaxAge() const;
    void SharedMaxAge(optional<Windows::Foundation::TimeSpan> const& value) const;
    void ParseAdd(param::hstring const& input) const;
    bool TryParseAdd(param::hstring const& input) const;
};
template <> struct consume<Windows::Web::Http::Headers::IHttpCacheDirectiveHeaderValueCollection> { template <typename D> using type = consume_Windows_Web_Http_Headers_IHttpCacheDirectiveHeaderValueCollection<D>; };

template <typename D>
struct consume_Windows_Web_Http_Headers_IHttpChallengeHeaderValue
{
    Windows::Foundation::Collections::IVector<Windows::Web::Http::Headers::HttpNameValueHeaderValue> Parameters() const;
    hstring Scheme() const;
    hstring Token() const;
};
template <> struct consume<Windows::Web::Http::Headers::IHttpChallengeHeaderValue> { template <typename D> using type = consume_Windows_Web_Http_Headers_IHttpChallengeHeaderValue<D>; };

template <typename D>
struct consume_Windows_Web_Http_Headers_IHttpChallengeHeaderValueCollection
{
    void ParseAdd(param::hstring const& input) const;
    bool TryParseAdd(param::hstring const& input) const;
};
template <> struct consume<Windows::Web::Http::Headers::IHttpChallengeHeaderValueCollection> { template <typename D> using type = consume_Windows_Web_Http_Headers_IHttpChallengeHeaderValueCollection<D>; };

template <typename D>
struct consume_Windows_Web_Http_Headers_IHttpChallengeHeaderValueFactory
{
    Windows::Web::Http::Headers::HttpChallengeHeaderValue CreateFromScheme(param::hstring const& scheme) const;
    Windows::Web::Http::Headers::HttpChallengeHeaderValue CreateFromSchemeWithToken(param::hstring const& scheme, param::hstring const& token) const;
};
template <> struct consume<Windows::Web::Http::Headers::IHttpChallengeHeaderValueFactory> { template <typename D> using type = consume_Windows_Web_Http_Headers_IHttpChallengeHeaderValueFactory<D>; };

template <typename D>
struct consume_Windows_Web_Http_Headers_IHttpChallengeHeaderValueStatics
{
    Windows::Web::Http::Headers::HttpChallengeHeaderValue Parse(param::hstring const& input) const;
    bool TryParse(param::hstring const& input, Windows::Web::Http::Headers::HttpChallengeHeaderValue& challengeHeaderValue) const;
};
template <> struct consume<Windows::Web::Http::Headers::IHttpChallengeHeaderValueStatics> { template <typename D> using type = consume_Windows_Web_Http_Headers_IHttpChallengeHeaderValueStatics<D>; };

template <typename D>
struct consume_Windows_Web_Http_Headers_IHttpConnectionOptionHeaderValue
{
    hstring Token() const;
};
template <> struct consume<Windows::Web::Http::Headers::IHttpConnectionOptionHeaderValue> { template <typename D> using type = consume_Windows_Web_Http_Headers_IHttpConnectionOptionHeaderValue<D>; };

template <typename D>
struct consume_Windows_Web_Http_Headers_IHttpConnectionOptionHeaderValueCollection
{
    void ParseAdd(param::hstring const& input) const;
    bool TryParseAdd(param::hstring const& input) const;
};
template <> struct consume<Windows::Web::Http::Headers::IHttpConnectionOptionHeaderValueCollection> { template <typename D> using type = consume_Windows_Web_Http_Headers_IHttpConnectionOptionHeaderValueCollection<D>; };

template <typename D>
struct consume_Windows_Web_Http_Headers_IHttpConnectionOptionHeaderValueFactory
{
    Windows::Web::Http::Headers::HttpConnectionOptionHeaderValue Create(param::hstring const& token) const;
};
template <> struct consume<Windows::Web::Http::Headers::IHttpConnectionOptionHeaderValueFactory> { template <typename D> using type = consume_Windows_Web_Http_Headers_IHttpConnectionOptionHeaderValueFactory<D>; };

template <typename D>
struct consume_Windows_Web_Http_Headers_IHttpConnectionOptionHeaderValueStatics
{
    Windows::Web::Http::Headers::HttpConnectionOptionHeaderValue Parse(param::hstring const& input) const;
    bool TryParse(param::hstring const& input, Windows::Web::Http::Headers::HttpConnectionOptionHeaderValue& connectionOptionHeaderValue) const;
};
template <> struct consume<Windows::Web::Http::Headers::IHttpConnectionOptionHeaderValueStatics> { template <typename D> using type = consume_Windows_Web_Http_Headers_IHttpConnectionOptionHeaderValueStatics<D>; };

template <typename D>
struct consume_Windows_Web_Http_Headers_IHttpContentCodingHeaderValue
{
    hstring ContentCoding() const;
};
template <> struct consume<Windows::Web::Http::Headers::IHttpContentCodingHeaderValue> { template <typename D> using type = consume_Windows_Web_Http_Headers_IHttpContentCodingHeaderValue<D>; };

template <typename D>
struct consume_Windows_Web_Http_Headers_IHttpContentCodingHeaderValueCollection
{
    void ParseAdd(param::hstring const& input) const;
    bool TryParseAdd(param::hstring const& input) const;
};
template <> struct consume<Windows::Web::Http::Headers::IHttpContentCodingHeaderValueCollection> { template <typename D> using type = consume_Windows_Web_Http_Headers_IHttpContentCodingHeaderValueCollection<D>; };

template <typename D>
struct consume_Windows_Web_Http_Headers_IHttpContentCodingHeaderValueFactory
{
    Windows::Web::Http::Headers::HttpContentCodingHeaderValue Create(param::hstring const& contentCoding) const;
};
template <> struct consume<Windows::Web::Http::Headers::IHttpContentCodingHeaderValueFactory> { template <typename D> using type = consume_Windows_Web_Http_Headers_IHttpContentCodingHeaderValueFactory<D>; };

template <typename D>
struct consume_Windows_Web_Http_Headers_IHttpContentCodingHeaderValueStatics
{
    Windows::Web::Http::Headers::HttpContentCodingHeaderValue Parse(param::hstring const& input) const;
    bool TryParse(param::hstring const& input, Windows::Web::Http::Headers::HttpContentCodingHeaderValue& contentCodingHeaderValue) const;
};
template <> struct consume<Windows::Web::Http::Headers::IHttpContentCodingHeaderValueStatics> { template <typename D> using type = consume_Windows_Web_Http_Headers_IHttpContentCodingHeaderValueStatics<D>; };

template <typename D>
struct consume_Windows_Web_Http_Headers_IHttpContentCodingWithQualityHeaderValue
{
    hstring ContentCoding() const;
    Windows::Foundation::IReference<double> Quality() const;
};
template <> struct consume<Windows::Web::Http::Headers::IHttpContentCodingWithQualityHeaderValue> { template <typename D> using type = consume_Windows_Web_Http_Headers_IHttpContentCodingWithQualityHeaderValue<D>; };

template <typename D>
struct consume_Windows_Web_Http_Headers_IHttpContentCodingWithQualityHeaderValueCollection
{
    void ParseAdd(param::hstring const& input) const;
    bool TryParseAdd(param::hstring const& input) const;
};
template <> struct consume<Windows::Web::Http::Headers::IHttpContentCodingWithQualityHeaderValueCollection> { template <typename D> using type = consume_Windows_Web_Http_Headers_IHttpContentCodingWithQualityHeaderValueCollection<D>; };

template <typename D>
struct consume_Windows_Web_Http_Headers_IHttpContentCodingWithQualityHeaderValueFactory
{
    Windows::Web::Http::Headers::HttpContentCodingWithQualityHeaderValue CreateFromValue(param::hstring const& contentCoding) const;
    Windows::Web::Http::Headers::HttpContentCodingWithQualityHeaderValue CreateFromValueWithQuality(param::hstring const& contentCoding, double quality) const;
};
template <> struct consume<Windows::Web::Http::Headers::IHttpContentCodingWithQualityHeaderValueFactory> { template <typename D> using type = consume_Windows_Web_Http_Headers_IHttpContentCodingWithQualityHeaderValueFactory<D>; };

template <typename D>
struct consume_Windows_Web_Http_Headers_IHttpContentCodingWithQualityHeaderValueStatics
{
    Windows::Web::Http::Headers::HttpContentCodingWithQualityHeaderValue Parse(param::hstring const& input) const;
    bool TryParse(param::hstring const& input, Windows::Web::Http::Headers::HttpContentCodingWithQualityHeaderValue& contentCodingWithQualityHeaderValue) const;
};
template <> struct consume<Windows::Web::Http::Headers::IHttpContentCodingWithQualityHeaderValueStatics> { template <typename D> using type = consume_Windows_Web_Http_Headers_IHttpContentCodingWithQualityHeaderValueStatics<D>; };

template <typename D>
struct consume_Windows_Web_Http_Headers_IHttpContentDispositionHeaderValue
{
    hstring DispositionType() const;
    void DispositionType(param::hstring const& value) const;
    hstring FileName() const;
    void FileName(param::hstring const& value) const;
    hstring FileNameStar() const;
    void FileNameStar(param::hstring const& value) const;
    hstring Name() const;
    void Name(param::hstring const& value) const;
    Windows::Foundation::Collections::IVector<Windows::Web::Http::Headers::HttpNameValueHeaderValue> Parameters() const;
    Windows::Foundation::IReference<uint64_t> Size() const;
    void Size(optional<uint64_t> const& value) const;
};
template <> struct consume<Windows::Web::Http::Headers::IHttpContentDispositionHeaderValue> { template <typename D> using type = consume_Windows_Web_Http_Headers_IHttpContentDispositionHeaderValue<D>; };

template <typename D>
struct consume_Windows_Web_Http_Headers_IHttpContentDispositionHeaderValueFactory
{
    Windows::Web::Http::Headers::HttpContentDispositionHeaderValue Create(param::hstring const& dispositionType) const;
};
template <> struct consume<Windows::Web::Http::Headers::IHttpContentDispositionHeaderValueFactory> { template <typename D> using type = consume_Windows_Web_Http_Headers_IHttpContentDispositionHeaderValueFactory<D>; };

template <typename D>
struct consume_Windows_Web_Http_Headers_IHttpContentDispositionHeaderValueStatics
{
    Windows::Web::Http::Headers::HttpContentDispositionHeaderValue Parse(param::hstring const& input) const;
    bool TryParse(param::hstring const& input, Windows::Web::Http::Headers::HttpContentDispositionHeaderValue& contentDispositionHeaderValue) const;
};
template <> struct consume<Windows::Web::Http::Headers::IHttpContentDispositionHeaderValueStatics> { template <typename D> using type = consume_Windows_Web_Http_Headers_IHttpContentDispositionHeaderValueStatics<D>; };

template <typename D>
struct consume_Windows_Web_Http_Headers_IHttpContentHeaderCollection
{
    Windows::Web::Http::Headers::HttpContentDispositionHeaderValue ContentDisposition() const;
    void ContentDisposition(Windows::Web::Http::Headers::HttpContentDispositionHeaderValue const& value) const;
    Windows::Web::Http::Headers::HttpContentCodingHeaderValueCollection ContentEncoding() const;
    Windows::Web::Http::Headers::HttpLanguageHeaderValueCollection ContentLanguage() const;
    Windows::Foundation::IReference<uint64_t> ContentLength() const;
    void ContentLength(optional<uint64_t> const& value) const;
    Windows::Foundation::Uri ContentLocation() const;
    void ContentLocation(Windows::Foundation::Uri const& value) const;
    Windows::Storage::Streams::IBuffer ContentMD5() const;
    void ContentMD5(Windows::Storage::Streams::IBuffer const& value) const;
    Windows::Web::Http::Headers::HttpContentRangeHeaderValue ContentRange() const;
    void ContentRange(Windows::Web::Http::Headers::HttpContentRangeHeaderValue const& value) const;
    Windows::Web::Http::Headers::HttpMediaTypeHeaderValue ContentType() const;
    void ContentType(Windows::Web::Http::Headers::HttpMediaTypeHeaderValue const& value) const;
    Windows::Foundation::IReference<Windows::Foundation::DateTime> Expires() const;
    void Expires(optional<Windows::Foundation::DateTime> const& value) const;
    Windows::Foundation::IReference<Windows::Foundation::DateTime> LastModified() const;
    void LastModified(optional<Windows::Foundation::DateTime> const& value) const;
    void Append(param::hstring const& name, param::hstring const& value) const;
    bool TryAppendWithoutValidation(param::hstring const& name, param::hstring const& value) const;
};
template <> struct consume<Windows::Web::Http::Headers::IHttpContentHeaderCollection> { template <typename D> using type = consume_Windows_Web_Http_Headers_IHttpContentHeaderCollection<D>; };

template <typename D>
struct consume_Windows_Web_Http_Headers_IHttpContentRangeHeaderValue
{
    Windows::Foundation::IReference<uint64_t> FirstBytePosition() const;
    Windows::Foundation::IReference<uint64_t> LastBytePosition() const;
    Windows::Foundation::IReference<uint64_t> Length() const;
    hstring Unit() const;
    void Unit(param::hstring const& value) const;
};
template <> struct consume<Windows::Web::Http::Headers::IHttpContentRangeHeaderValue> { template <typename D> using type = consume_Windows_Web_Http_Headers_IHttpContentRangeHeaderValue<D>; };

template <typename D>
struct consume_Windows_Web_Http_Headers_IHttpContentRangeHeaderValueFactory
{
    Windows::Web::Http::Headers::HttpContentRangeHeaderValue CreateFromLength(uint64_t length) const;
    Windows::Web::Http::Headers::HttpContentRangeHeaderValue CreateFromRange(uint64_t from, uint64_t to) const;
    Windows::Web::Http::Headers::HttpContentRangeHeaderValue CreateFromRangeWithLength(uint64_t from, uint64_t to, uint64_t length) const;
};
template <> struct consume<Windows::Web::Http::Headers::IHttpContentRangeHeaderValueFactory> { template <typename D> using type = consume_Windows_Web_Http_Headers_IHttpContentRangeHeaderValueFactory<D>; };

template <typename D>
struct consume_Windows_Web_Http_Headers_IHttpContentRangeHeaderValueStatics
{
    Windows::Web::Http::Headers::HttpContentRangeHeaderValue Parse(param::hstring const& input) const;
    bool TryParse(param::hstring const& input, Windows::Web::Http::Headers::HttpContentRangeHeaderValue& contentRangeHeaderValue) const;
};
template <> struct consume<Windows::Web::Http::Headers::IHttpContentRangeHeaderValueStatics> { template <typename D> using type = consume_Windows_Web_Http_Headers_IHttpContentRangeHeaderValueStatics<D>; };

template <typename D>
struct consume_Windows_Web_Http_Headers_IHttpCookiePairHeaderValue
{
    hstring Name() const;
    hstring Value() const;
    void Value(param::hstring const& value) const;
};
template <> struct consume<Windows::Web::Http::Headers::IHttpCookiePairHeaderValue> { template <typename D> using type = consume_Windows_Web_Http_Headers_IHttpCookiePairHeaderValue<D>; };

template <typename D>
struct consume_Windows_Web_Http_Headers_IHttpCookiePairHeaderValueCollection
{
    void ParseAdd(param::hstring const& input) const;
    bool TryParseAdd(param::hstring const& input) const;
};
template <> struct consume<Windows::Web::Http::Headers::IHttpCookiePairHeaderValueCollection> { template <typename D> using type = consume_Windows_Web_Http_Headers_IHttpCookiePairHeaderValueCollection<D>; };

template <typename D>
struct consume_Windows_Web_Http_Headers_IHttpCookiePairHeaderValueFactory
{
    Windows::Web::Http::Headers::HttpCookiePairHeaderValue CreateFromName(param::hstring const& name) const;
    Windows::Web::Http::Headers::HttpCookiePairHeaderValue CreateFromNameWithValue(param::hstring const& name, param::hstring const& value) const;
};
template <> struct consume<Windows::Web::Http::Headers::IHttpCookiePairHeaderValueFactory> { template <typename D> using type = consume_Windows_Web_Http_Headers_IHttpCookiePairHeaderValueFactory<D>; };

template <typename D>
struct consume_Windows_Web_Http_Headers_IHttpCookiePairHeaderValueStatics
{
    Windows::Web::Http::Headers::HttpCookiePairHeaderValue Parse(param::hstring const& input) const;
    bool TryParse(param::hstring const& input, Windows::Web::Http::Headers::HttpCookiePairHeaderValue& cookiePairHeaderValue) const;
};
template <> struct consume<Windows::Web::Http::Headers::IHttpCookiePairHeaderValueStatics> { template <typename D> using type = consume_Windows_Web_Http_Headers_IHttpCookiePairHeaderValueStatics<D>; };

template <typename D>
struct consume_Windows_Web_Http_Headers_IHttpCredentialsHeaderValue
{
    Windows::Foundation::Collections::IVector<Windows::Web::Http::Headers::HttpNameValueHeaderValue> Parameters() const;
    hstring Scheme() const;
    hstring Token() const;
};
template <> struct consume<Windows::Web::Http::Headers::IHttpCredentialsHeaderValue> { template <typename D> using type = consume_Windows_Web_Http_Headers_IHttpCredentialsHeaderValue<D>; };

template <typename D>
struct consume_Windows_Web_Http_Headers_IHttpCredentialsHeaderValueFactory
{
    Windows::Web::Http::Headers::HttpCredentialsHeaderValue CreateFromScheme(param::hstring const& scheme) const;
    Windows::Web::Http::Headers::HttpCredentialsHeaderValue CreateFromSchemeWithToken(param::hstring const& scheme, param::hstring const& token) const;
};
template <> struct consume<Windows::Web::Http::Headers::IHttpCredentialsHeaderValueFactory> { template <typename D> using type = consume_Windows_Web_Http_Headers_IHttpCredentialsHeaderValueFactory<D>; };

template <typename D>
struct consume_Windows_Web_Http_Headers_IHttpCredentialsHeaderValueStatics
{
    Windows::Web::Http::Headers::HttpCredentialsHeaderValue Parse(param::hstring const& input) const;
    bool TryParse(param::hstring const& input, Windows::Web::Http::Headers::HttpCredentialsHeaderValue& credentialsHeaderValue) const;
};
template <> struct consume<Windows::Web::Http::Headers::IHttpCredentialsHeaderValueStatics> { template <typename D> using type = consume_Windows_Web_Http_Headers_IHttpCredentialsHeaderValueStatics<D>; };

template <typename D>
struct consume_Windows_Web_Http_Headers_IHttpDateOrDeltaHeaderValue
{
    Windows::Foundation::IReference<Windows::Foundation::DateTime> Date() const;
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> Delta() const;
};
template <> struct consume<Windows::Web::Http::Headers::IHttpDateOrDeltaHeaderValue> { template <typename D> using type = consume_Windows_Web_Http_Headers_IHttpDateOrDeltaHeaderValue<D>; };

template <typename D>
struct consume_Windows_Web_Http_Headers_IHttpDateOrDeltaHeaderValueStatics
{
    Windows::Web::Http::Headers::HttpDateOrDeltaHeaderValue Parse(param::hstring const& input) const;
    bool TryParse(param::hstring const& input, Windows::Web::Http::Headers::HttpDateOrDeltaHeaderValue& dateOrDeltaHeaderValue) const;
};
template <> struct consume<Windows::Web::Http::Headers::IHttpDateOrDeltaHeaderValueStatics> { template <typename D> using type = consume_Windows_Web_Http_Headers_IHttpDateOrDeltaHeaderValueStatics<D>; };

template <typename D>
struct consume_Windows_Web_Http_Headers_IHttpExpectationHeaderValue
{
    hstring Name() const;
    hstring Value() const;
    void Value(param::hstring const& value) const;
    Windows::Foundation::Collections::IVector<Windows::Web::Http::Headers::HttpNameValueHeaderValue> Parameters() const;
};
template <> struct consume<Windows::Web::Http::Headers::IHttpExpectationHeaderValue> { template <typename D> using type = consume_Windows_Web_Http_Headers_IHttpExpectationHeaderValue<D>; };

template <typename D>
struct consume_Windows_Web_Http_Headers_IHttpExpectationHeaderValueCollection
{
    void ParseAdd(param::hstring const& input) const;
    bool TryParseAdd(param::hstring const& input) const;
};
template <> struct consume<Windows::Web::Http::Headers::IHttpExpectationHeaderValueCollection> { template <typename D> using type = consume_Windows_Web_Http_Headers_IHttpExpectationHeaderValueCollection<D>; };

template <typename D>
struct consume_Windows_Web_Http_Headers_IHttpExpectationHeaderValueFactory
{
    Windows::Web::Http::Headers::HttpExpectationHeaderValue CreateFromName(param::hstring const& name) const;
    Windows::Web::Http::Headers::HttpExpectationHeaderValue CreateFromNameWithValue(param::hstring const& name, param::hstring const& value) const;
};
template <> struct consume<Windows::Web::Http::Headers::IHttpExpectationHeaderValueFactory> { template <typename D> using type = consume_Windows_Web_Http_Headers_IHttpExpectationHeaderValueFactory<D>; };

template <typename D>
struct consume_Windows_Web_Http_Headers_IHttpExpectationHeaderValueStatics
{
    Windows::Web::Http::Headers::HttpExpectationHeaderValue Parse(param::hstring const& input) const;
    bool TryParse(param::hstring const& input, Windows::Web::Http::Headers::HttpExpectationHeaderValue& expectationHeaderValue) const;
};
template <> struct consume<Windows::Web::Http::Headers::IHttpExpectationHeaderValueStatics> { template <typename D> using type = consume_Windows_Web_Http_Headers_IHttpExpectationHeaderValueStatics<D>; };

template <typename D>
struct consume_Windows_Web_Http_Headers_IHttpLanguageHeaderValueCollection
{
    void ParseAdd(param::hstring const& input) const;
    bool TryParseAdd(param::hstring const& input) const;
};
template <> struct consume<Windows::Web::Http::Headers::IHttpLanguageHeaderValueCollection> { template <typename D> using type = consume_Windows_Web_Http_Headers_IHttpLanguageHeaderValueCollection<D>; };

template <typename D>
struct consume_Windows_Web_Http_Headers_IHttpLanguageRangeWithQualityHeaderValue
{
    hstring LanguageRange() const;
    Windows::Foundation::IReference<double> Quality() const;
};
template <> struct consume<Windows::Web::Http::Headers::IHttpLanguageRangeWithQualityHeaderValue> { template <typename D> using type = consume_Windows_Web_Http_Headers_IHttpLanguageRangeWithQualityHeaderValue<D>; };

template <typename D>
struct consume_Windows_Web_Http_Headers_IHttpLanguageRangeWithQualityHeaderValueCollection
{
    void ParseAdd(param::hstring const& input) const;
    bool TryParseAdd(param::hstring const& input) const;
};
template <> struct consume<Windows::Web::Http::Headers::IHttpLanguageRangeWithQualityHeaderValueCollection> { template <typename D> using type = consume_Windows_Web_Http_Headers_IHttpLanguageRangeWithQualityHeaderValueCollection<D>; };

template <typename D>
struct consume_Windows_Web_Http_Headers_IHttpLanguageRangeWithQualityHeaderValueFactory
{
    Windows::Web::Http::Headers::HttpLanguageRangeWithQualityHeaderValue CreateFromLanguageRange(param::hstring const& languageRange) const;
    Windows::Web::Http::Headers::HttpLanguageRangeWithQualityHeaderValue CreateFromLanguageRangeWithQuality(param::hstring const& languageRange, double quality) const;
};
template <> struct consume<Windows::Web::Http::Headers::IHttpLanguageRangeWithQualityHeaderValueFactory> { template <typename D> using type = consume_Windows_Web_Http_Headers_IHttpLanguageRangeWithQualityHeaderValueFactory<D>; };

template <typename D>
struct consume_Windows_Web_Http_Headers_IHttpLanguageRangeWithQualityHeaderValueStatics
{
    Windows::Web::Http::Headers::HttpLanguageRangeWithQualityHeaderValue Parse(param::hstring const& input) const;
    bool TryParse(param::hstring const& input, Windows::Web::Http::Headers::HttpLanguageRangeWithQualityHeaderValue& languageRangeWithQualityHeaderValue) const;
};
template <> struct consume<Windows::Web::Http::Headers::IHttpLanguageRangeWithQualityHeaderValueStatics> { template <typename D> using type = consume_Windows_Web_Http_Headers_IHttpLanguageRangeWithQualityHeaderValueStatics<D>; };

template <typename D>
struct consume_Windows_Web_Http_Headers_IHttpMediaTypeHeaderValue
{
    hstring CharSet() const;
    void CharSet(param::hstring const& value) const;
    hstring MediaType() const;
    void MediaType(param::hstring const& value) const;
    Windows::Foundation::Collections::IVector<Windows::Web::Http::Headers::HttpNameValueHeaderValue> Parameters() const;
};
template <> struct consume<Windows::Web::Http::Headers::IHttpMediaTypeHeaderValue> { template <typename D> using type = consume_Windows_Web_Http_Headers_IHttpMediaTypeHeaderValue<D>; };

template <typename D>
struct consume_Windows_Web_Http_Headers_IHttpMediaTypeHeaderValueFactory
{
    Windows::Web::Http::Headers::HttpMediaTypeHeaderValue Create(param::hstring const& mediaType) const;
};
template <> struct consume<Windows::Web::Http::Headers::IHttpMediaTypeHeaderValueFactory> { template <typename D> using type = consume_Windows_Web_Http_Headers_IHttpMediaTypeHeaderValueFactory<D>; };

template <typename D>
struct consume_Windows_Web_Http_Headers_IHttpMediaTypeHeaderValueStatics
{
    Windows::Web::Http::Headers::HttpMediaTypeHeaderValue Parse(param::hstring const& input) const;
    bool TryParse(param::hstring const& input, Windows::Web::Http::Headers::HttpMediaTypeHeaderValue& mediaTypeHeaderValue) const;
};
template <> struct consume<Windows::Web::Http::Headers::IHttpMediaTypeHeaderValueStatics> { template <typename D> using type = consume_Windows_Web_Http_Headers_IHttpMediaTypeHeaderValueStatics<D>; };

template <typename D>
struct consume_Windows_Web_Http_Headers_IHttpMediaTypeWithQualityHeaderValue
{
    hstring CharSet() const;
    void CharSet(param::hstring const& value) const;
    hstring MediaType() const;
    void MediaType(param::hstring const& value) const;
    Windows::Foundation::Collections::IVector<Windows::Web::Http::Headers::HttpNameValueHeaderValue> Parameters() const;
    Windows::Foundation::IReference<double> Quality() const;
    void Quality(optional<double> const& value) const;
};
template <> struct consume<Windows::Web::Http::Headers::IHttpMediaTypeWithQualityHeaderValue> { template <typename D> using type = consume_Windows_Web_Http_Headers_IHttpMediaTypeWithQualityHeaderValue<D>; };

template <typename D>
struct consume_Windows_Web_Http_Headers_IHttpMediaTypeWithQualityHeaderValueCollection
{
    void ParseAdd(param::hstring const& input) const;
    bool TryParseAdd(param::hstring const& input) const;
};
template <> struct consume<Windows::Web::Http::Headers::IHttpMediaTypeWithQualityHeaderValueCollection> { template <typename D> using type = consume_Windows_Web_Http_Headers_IHttpMediaTypeWithQualityHeaderValueCollection<D>; };

template <typename D>
struct consume_Windows_Web_Http_Headers_IHttpMediaTypeWithQualityHeaderValueFactory
{
    Windows::Web::Http::Headers::HttpMediaTypeWithQualityHeaderValue CreateFromMediaType(param::hstring const& mediaType) const;
    Windows::Web::Http::Headers::HttpMediaTypeWithQualityHeaderValue CreateFromMediaTypeWithQuality(param::hstring const& mediaType, double quality) const;
};
template <> struct consume<Windows::Web::Http::Headers::IHttpMediaTypeWithQualityHeaderValueFactory> { template <typename D> using type = consume_Windows_Web_Http_Headers_IHttpMediaTypeWithQualityHeaderValueFactory<D>; };

template <typename D>
struct consume_Windows_Web_Http_Headers_IHttpMediaTypeWithQualityHeaderValueStatics
{
    Windows::Web::Http::Headers::HttpMediaTypeWithQualityHeaderValue Parse(param::hstring const& input) const;
    bool TryParse(param::hstring const& input, Windows::Web::Http::Headers::HttpMediaTypeWithQualityHeaderValue& mediaTypeWithQualityHeaderValue) const;
};
template <> struct consume<Windows::Web::Http::Headers::IHttpMediaTypeWithQualityHeaderValueStatics> { template <typename D> using type = consume_Windows_Web_Http_Headers_IHttpMediaTypeWithQualityHeaderValueStatics<D>; };

template <typename D>
struct consume_Windows_Web_Http_Headers_IHttpMethodHeaderValueCollection
{
    void ParseAdd(param::hstring const& input) const;
    bool TryParseAdd(param::hstring const& input) const;
};
template <> struct consume<Windows::Web::Http::Headers::IHttpMethodHeaderValueCollection> { template <typename D> using type = consume_Windows_Web_Http_Headers_IHttpMethodHeaderValueCollection<D>; };

template <typename D>
struct consume_Windows_Web_Http_Headers_IHttpNameValueHeaderValue
{
    hstring Name() const;
    hstring Value() const;
    void Value(param::hstring const& value) const;
};
template <> struct consume<Windows::Web::Http::Headers::IHttpNameValueHeaderValue> { template <typename D> using type = consume_Windows_Web_Http_Headers_IHttpNameValueHeaderValue<D>; };

template <typename D>
struct consume_Windows_Web_Http_Headers_IHttpNameValueHeaderValueFactory
{
    Windows::Web::Http::Headers::HttpNameValueHeaderValue CreateFromName(param::hstring const& name) const;
    Windows::Web::Http::Headers::HttpNameValueHeaderValue CreateFromNameWithValue(param::hstring const& name, param::hstring const& value) const;
};
template <> struct consume<Windows::Web::Http::Headers::IHttpNameValueHeaderValueFactory> { template <typename D> using type = consume_Windows_Web_Http_Headers_IHttpNameValueHeaderValueFactory<D>; };

template <typename D>
struct consume_Windows_Web_Http_Headers_IHttpNameValueHeaderValueStatics
{
    Windows::Web::Http::Headers::HttpNameValueHeaderValue Parse(param::hstring const& input) const;
    bool TryParse(param::hstring const& input, Windows::Web::Http::Headers::HttpNameValueHeaderValue& nameValueHeaderValue) const;
};
template <> struct consume<Windows::Web::Http::Headers::IHttpNameValueHeaderValueStatics> { template <typename D> using type = consume_Windows_Web_Http_Headers_IHttpNameValueHeaderValueStatics<D>; };

template <typename D>
struct consume_Windows_Web_Http_Headers_IHttpProductHeaderValue
{
    hstring Name() const;
    hstring Version() const;
};
template <> struct consume<Windows::Web::Http::Headers::IHttpProductHeaderValue> { template <typename D> using type = consume_Windows_Web_Http_Headers_IHttpProductHeaderValue<D>; };

template <typename D>
struct consume_Windows_Web_Http_Headers_IHttpProductHeaderValueFactory
{
    Windows::Web::Http::Headers::HttpProductHeaderValue CreateFromName(param::hstring const& productName) const;
    Windows::Web::Http::Headers::HttpProductHeaderValue CreateFromNameWithVersion(param::hstring const& productName, param::hstring const& productVersion) const;
};
template <> struct consume<Windows::Web::Http::Headers::IHttpProductHeaderValueFactory> { template <typename D> using type = consume_Windows_Web_Http_Headers_IHttpProductHeaderValueFactory<D>; };

template <typename D>
struct consume_Windows_Web_Http_Headers_IHttpProductHeaderValueStatics
{
    Windows::Web::Http::Headers::HttpProductHeaderValue Parse(param::hstring const& input) const;
    bool TryParse(param::hstring const& input, Windows::Web::Http::Headers::HttpProductHeaderValue& productHeaderValue) const;
};
template <> struct consume<Windows::Web::Http::Headers::IHttpProductHeaderValueStatics> { template <typename D> using type = consume_Windows_Web_Http_Headers_IHttpProductHeaderValueStatics<D>; };

template <typename D>
struct consume_Windows_Web_Http_Headers_IHttpProductInfoHeaderValue
{
    Windows::Web::Http::Headers::HttpProductHeaderValue Product() const;
    hstring Comment() const;
};
template <> struct consume<Windows::Web::Http::Headers::IHttpProductInfoHeaderValue> { template <typename D> using type = consume_Windows_Web_Http_Headers_IHttpProductInfoHeaderValue<D>; };

template <typename D>
struct consume_Windows_Web_Http_Headers_IHttpProductInfoHeaderValueCollection
{
    void ParseAdd(param::hstring const& input) const;
    bool TryParseAdd(param::hstring const& input) const;
};
template <> struct consume<Windows::Web::Http::Headers::IHttpProductInfoHeaderValueCollection> { template <typename D> using type = consume_Windows_Web_Http_Headers_IHttpProductInfoHeaderValueCollection<D>; };

template <typename D>
struct consume_Windows_Web_Http_Headers_IHttpProductInfoHeaderValueFactory
{
    Windows::Web::Http::Headers::HttpProductInfoHeaderValue CreateFromComment(param::hstring const& productComment) const;
    Windows::Web::Http::Headers::HttpProductInfoHeaderValue CreateFromNameWithVersion(param::hstring const& productName, param::hstring const& productVersion) const;
};
template <> struct consume<Windows::Web::Http::Headers::IHttpProductInfoHeaderValueFactory> { template <typename D> using type = consume_Windows_Web_Http_Headers_IHttpProductInfoHeaderValueFactory<D>; };

template <typename D>
struct consume_Windows_Web_Http_Headers_IHttpProductInfoHeaderValueStatics
{
    Windows::Web::Http::Headers::HttpProductInfoHeaderValue Parse(param::hstring const& input) const;
    bool TryParse(param::hstring const& input, Windows::Web::Http::Headers::HttpProductInfoHeaderValue& productInfoHeaderValue) const;
};
template <> struct consume<Windows::Web::Http::Headers::IHttpProductInfoHeaderValueStatics> { template <typename D> using type = consume_Windows_Web_Http_Headers_IHttpProductInfoHeaderValueStatics<D>; };

template <typename D>
struct consume_Windows_Web_Http_Headers_IHttpRequestHeaderCollection
{
    Windows::Web::Http::Headers::HttpMediaTypeWithQualityHeaderValueCollection Accept() const;
    Windows::Web::Http::Headers::HttpContentCodingWithQualityHeaderValueCollection AcceptEncoding() const;
    Windows::Web::Http::Headers::HttpLanguageRangeWithQualityHeaderValueCollection AcceptLanguage() const;
    Windows::Web::Http::Headers::HttpCredentialsHeaderValue Authorization() const;
    void Authorization(Windows::Web::Http::Headers::HttpCredentialsHeaderValue const& value) const;
    Windows::Web::Http::Headers::HttpCacheDirectiveHeaderValueCollection CacheControl() const;
    Windows::Web::Http::Headers::HttpConnectionOptionHeaderValueCollection Connection() const;
    Windows::Web::Http::Headers::HttpCookiePairHeaderValueCollection Cookie() const;
    Windows::Foundation::IReference<Windows::Foundation::DateTime> Date() const;
    void Date(optional<Windows::Foundation::DateTime> const& value) const;
    Windows::Web::Http::Headers::HttpExpectationHeaderValueCollection Expect() const;
    hstring From() const;
    void From(param::hstring const& value) const;
    Windows::Networking::HostName Host() const;
    void Host(Windows::Networking::HostName const& value) const;
    Windows::Foundation::IReference<Windows::Foundation::DateTime> IfModifiedSince() const;
    void IfModifiedSince(optional<Windows::Foundation::DateTime> const& value) const;
    Windows::Foundation::IReference<Windows::Foundation::DateTime> IfUnmodifiedSince() const;
    void IfUnmodifiedSince(optional<Windows::Foundation::DateTime> const& value) const;
    Windows::Foundation::IReference<uint32_t> MaxForwards() const;
    void MaxForwards(optional<uint32_t> const& value) const;
    Windows::Web::Http::Headers::HttpCredentialsHeaderValue ProxyAuthorization() const;
    void ProxyAuthorization(Windows::Web::Http::Headers::HttpCredentialsHeaderValue const& value) const;
    Windows::Foundation::Uri Referer() const;
    void Referer(Windows::Foundation::Uri const& value) const;
    Windows::Web::Http::Headers::HttpTransferCodingHeaderValueCollection TransferEncoding() const;
    Windows::Web::Http::Headers::HttpProductInfoHeaderValueCollection UserAgent() const;
    void Append(param::hstring const& name, param::hstring const& value) const;
    bool TryAppendWithoutValidation(param::hstring const& name, param::hstring const& value) const;
};
template <> struct consume<Windows::Web::Http::Headers::IHttpRequestHeaderCollection> { template <typename D> using type = consume_Windows_Web_Http_Headers_IHttpRequestHeaderCollection<D>; };

template <typename D>
struct consume_Windows_Web_Http_Headers_IHttpResponseHeaderCollection
{
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> Age() const;
    void Age(optional<Windows::Foundation::TimeSpan> const& value) const;
    Windows::Web::Http::Headers::HttpMethodHeaderValueCollection Allow() const;
    Windows::Web::Http::Headers::HttpCacheDirectiveHeaderValueCollection CacheControl() const;
    Windows::Web::Http::Headers::HttpConnectionOptionHeaderValueCollection Connection() const;
    Windows::Foundation::IReference<Windows::Foundation::DateTime> Date() const;
    void Date(optional<Windows::Foundation::DateTime> const& value) const;
    Windows::Foundation::Uri Location() const;
    void Location(Windows::Foundation::Uri const& value) const;
    Windows::Web::Http::Headers::HttpChallengeHeaderValueCollection ProxyAuthenticate() const;
    Windows::Web::Http::Headers::HttpDateOrDeltaHeaderValue RetryAfter() const;
    void RetryAfter(Windows::Web::Http::Headers::HttpDateOrDeltaHeaderValue const& value) const;
    Windows::Web::Http::Headers::HttpTransferCodingHeaderValueCollection TransferEncoding() const;
    Windows::Web::Http::Headers::HttpChallengeHeaderValueCollection WwwAuthenticate() const;
    void Append(param::hstring const& name, param::hstring const& value) const;
    bool TryAppendWithoutValidation(param::hstring const& name, param::hstring const& value) const;
};
template <> struct consume<Windows::Web::Http::Headers::IHttpResponseHeaderCollection> { template <typename D> using type = consume_Windows_Web_Http_Headers_IHttpResponseHeaderCollection<D>; };

template <typename D>
struct consume_Windows_Web_Http_Headers_IHttpTransferCodingHeaderValue
{
    Windows::Foundation::Collections::IVector<Windows::Web::Http::Headers::HttpNameValueHeaderValue> Parameters() const;
    hstring Value() const;
};
template <> struct consume<Windows::Web::Http::Headers::IHttpTransferCodingHeaderValue> { template <typename D> using type = consume_Windows_Web_Http_Headers_IHttpTransferCodingHeaderValue<D>; };

template <typename D>
struct consume_Windows_Web_Http_Headers_IHttpTransferCodingHeaderValueCollection
{
    void ParseAdd(param::hstring const& input) const;
    bool TryParseAdd(param::hstring const& input) const;
};
template <> struct consume<Windows::Web::Http::Headers::IHttpTransferCodingHeaderValueCollection> { template <typename D> using type = consume_Windows_Web_Http_Headers_IHttpTransferCodingHeaderValueCollection<D>; };

template <typename D>
struct consume_Windows_Web_Http_Headers_IHttpTransferCodingHeaderValueFactory
{
    Windows::Web::Http::Headers::HttpTransferCodingHeaderValue Create(param::hstring const& input) const;
};
template <> struct consume<Windows::Web::Http::Headers::IHttpTransferCodingHeaderValueFactory> { template <typename D> using type = consume_Windows_Web_Http_Headers_IHttpTransferCodingHeaderValueFactory<D>; };

template <typename D>
struct consume_Windows_Web_Http_Headers_IHttpTransferCodingHeaderValueStatics
{
    Windows::Web::Http::Headers::HttpTransferCodingHeaderValue Parse(param::hstring const& input) const;
    bool TryParse(param::hstring const& input, Windows::Web::Http::Headers::HttpTransferCodingHeaderValue& transferCodingHeaderValue) const;
};
template <> struct consume<Windows::Web::Http::Headers::IHttpTransferCodingHeaderValueStatics> { template <typename D> using type = consume_Windows_Web_Http_Headers_IHttpTransferCodingHeaderValueStatics<D>; };

}
