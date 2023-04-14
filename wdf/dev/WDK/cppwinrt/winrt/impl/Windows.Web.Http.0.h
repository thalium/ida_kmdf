// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Foundation {

struct Uri;

}

WINRT_EXPORT namespace winrt::Windows::Networking::Sockets {

enum class SocketSslErrorSeverity;

}

WINRT_EXPORT namespace winrt::Windows::Security::Cryptography::Certificates {

enum class ChainValidationResult;
struct Certificate;

}

WINRT_EXPORT namespace winrt::Windows::Storage::Streams {

enum class UnicodeEncoding;
struct IBuffer;
struct IInputStream;
struct IOutputStream;

}

WINRT_EXPORT namespace winrt::Windows::Web::Http::Filters {

struct IHttpFilter;

}

WINRT_EXPORT namespace winrt::Windows::Web::Http::Headers {

struct HttpContentHeaderCollection;
struct HttpRequestHeaderCollection;
struct HttpResponseHeaderCollection;

}

WINRT_EXPORT namespace winrt::Windows::Web::Http {

enum class HttpCompletionOption : int32_t
{
    ResponseContentRead = 0,
    ResponseHeadersRead = 1,
};

enum class HttpProgressStage : int32_t
{
    None = 0,
    DetectingProxy = 10,
    ResolvingName = 20,
    ConnectingToServer = 30,
    NegotiatingSsl = 40,
    SendingHeaders = 50,
    SendingContent = 60,
    WaitingForResponse = 70,
    ReceivingHeaders = 80,
    ReceivingContent = 90,
};

enum class HttpResponseMessageSource : int32_t
{
    None = 0,
    Cache = 1,
    Network = 2,
};

enum class HttpStatusCode : int32_t
{
    None = 0,
    Continue = 100,
    SwitchingProtocols = 101,
    Processing = 102,
    Ok = 200,
    Created = 201,
    Accepted = 202,
    NonAuthoritativeInformation = 203,
    NoContent = 204,
    ResetContent = 205,
    PartialContent = 206,
    MultiStatus = 207,
    AlreadyReported = 208,
    IMUsed = 226,
    MultipleChoices = 300,
    MovedPermanently = 301,
    Found = 302,
    SeeOther = 303,
    NotModified = 304,
    UseProxy = 305,
    TemporaryRedirect = 307,
    PermanentRedirect = 308,
    BadRequest = 400,
    Unauthorized = 401,
    PaymentRequired = 402,
    Forbidden = 403,
    NotFound = 404,
    MethodNotAllowed = 405,
    NotAcceptable = 406,
    ProxyAuthenticationRequired = 407,
    RequestTimeout = 408,
    Conflict = 409,
    Gone = 410,
    LengthRequired = 411,
    PreconditionFailed = 412,
    RequestEntityTooLarge = 413,
    RequestUriTooLong = 414,
    UnsupportedMediaType = 415,
    RequestedRangeNotSatisfiable = 416,
    ExpectationFailed = 417,
    UnprocessableEntity = 422,
    Locked = 423,
    FailedDependency = 424,
    UpgradeRequired = 426,
    PreconditionRequired = 428,
    TooManyRequests = 429,
    RequestHeaderFieldsTooLarge = 431,
    InternalServerError = 500,
    NotImplemented = 501,
    BadGateway = 502,
    ServiceUnavailable = 503,
    GatewayTimeout = 504,
    HttpVersionNotSupported = 505,
    VariantAlsoNegotiates = 506,
    InsufficientStorage = 507,
    LoopDetected = 508,
    NotExtended = 510,
    NetworkAuthenticationRequired = 511,
};

enum class HttpVersion : int32_t
{
    None = 0,
    Http10 = 1,
    Http11 = 2,
    Http20 = 3,
};

struct IHttpBufferContentFactory;
struct IHttpClient;
struct IHttpClient2;
struct IHttpClientFactory;
struct IHttpContent;
struct IHttpCookie;
struct IHttpCookieFactory;
struct IHttpCookieManager;
struct IHttpFormUrlEncodedContentFactory;
struct IHttpGetBufferResult;
struct IHttpGetInputStreamResult;
struct IHttpGetStringResult;
struct IHttpMethod;
struct IHttpMethodFactory;
struct IHttpMethodStatics;
struct IHttpMultipartContent;
struct IHttpMultipartContentFactory;
struct IHttpMultipartFormDataContent;
struct IHttpMultipartFormDataContentFactory;
struct IHttpRequestMessage;
struct IHttpRequestMessageFactory;
struct IHttpRequestResult;
struct IHttpResponseMessage;
struct IHttpResponseMessageFactory;
struct IHttpStreamContentFactory;
struct IHttpStringContentFactory;
struct IHttpTransportInformation;
struct HttpBufferContent;
struct HttpClient;
struct HttpCookie;
struct HttpCookieCollection;
struct HttpCookieManager;
struct HttpFormUrlEncodedContent;
struct HttpGetBufferResult;
struct HttpGetInputStreamResult;
struct HttpGetStringResult;
struct HttpMethod;
struct HttpMultipartContent;
struct HttpMultipartFormDataContent;
struct HttpRequestMessage;
struct HttpRequestResult;
struct HttpResponseMessage;
struct HttpStreamContent;
struct HttpStringContent;
struct HttpTransportInformation;
struct HttpProgress;

}

namespace winrt::impl {

template <> struct category<Windows::Web::Http::IHttpBufferContentFactory>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::IHttpClient>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::IHttpClient2>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::IHttpClientFactory>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::IHttpContent>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::IHttpCookie>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::IHttpCookieFactory>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::IHttpCookieManager>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::IHttpFormUrlEncodedContentFactory>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::IHttpGetBufferResult>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::IHttpGetInputStreamResult>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::IHttpGetStringResult>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::IHttpMethod>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::IHttpMethodFactory>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::IHttpMethodStatics>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::IHttpMultipartContent>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::IHttpMultipartContentFactory>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::IHttpMultipartFormDataContent>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::IHttpMultipartFormDataContentFactory>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::IHttpRequestMessage>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::IHttpRequestMessageFactory>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::IHttpRequestResult>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::IHttpResponseMessage>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::IHttpResponseMessageFactory>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::IHttpStreamContentFactory>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::IHttpStringContentFactory>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::IHttpTransportInformation>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::HttpBufferContent>{ using type = class_category; };
template <> struct category<Windows::Web::Http::HttpClient>{ using type = class_category; };
template <> struct category<Windows::Web::Http::HttpCookie>{ using type = class_category; };
template <> struct category<Windows::Web::Http::HttpCookieCollection>{ using type = class_category; };
template <> struct category<Windows::Web::Http::HttpCookieManager>{ using type = class_category; };
template <> struct category<Windows::Web::Http::HttpFormUrlEncodedContent>{ using type = class_category; };
template <> struct category<Windows::Web::Http::HttpGetBufferResult>{ using type = class_category; };
template <> struct category<Windows::Web::Http::HttpGetInputStreamResult>{ using type = class_category; };
template <> struct category<Windows::Web::Http::HttpGetStringResult>{ using type = class_category; };
template <> struct category<Windows::Web::Http::HttpMethod>{ using type = class_category; };
template <> struct category<Windows::Web::Http::HttpMultipartContent>{ using type = class_category; };
template <> struct category<Windows::Web::Http::HttpMultipartFormDataContent>{ using type = class_category; };
template <> struct category<Windows::Web::Http::HttpRequestMessage>{ using type = class_category; };
template <> struct category<Windows::Web::Http::HttpRequestResult>{ using type = class_category; };
template <> struct category<Windows::Web::Http::HttpResponseMessage>{ using type = class_category; };
template <> struct category<Windows::Web::Http::HttpStreamContent>{ using type = class_category; };
template <> struct category<Windows::Web::Http::HttpStringContent>{ using type = class_category; };
template <> struct category<Windows::Web::Http::HttpTransportInformation>{ using type = class_category; };
template <> struct category<Windows::Web::Http::HttpCompletionOption>{ using type = enum_category; };
template <> struct category<Windows::Web::Http::HttpProgressStage>{ using type = enum_category; };
template <> struct category<Windows::Web::Http::HttpResponseMessageSource>{ using type = enum_category; };
template <> struct category<Windows::Web::Http::HttpStatusCode>{ using type = enum_category; };
template <> struct category<Windows::Web::Http::HttpVersion>{ using type = enum_category; };
template <> struct category<Windows::Web::Http::HttpProgress>{ using type = struct_category<Windows::Web::Http::HttpProgressStage,uint64_t,Windows::Foundation::IReference<uint64_t>,uint64_t,Windows::Foundation::IReference<uint64_t>,uint32_t>; };
template <> struct name<Windows::Web::Http::IHttpBufferContentFactory>{ static constexpr auto & value{ L"Windows.Web.Http.IHttpBufferContentFactory" }; };
template <> struct name<Windows::Web::Http::IHttpClient>{ static constexpr auto & value{ L"Windows.Web.Http.IHttpClient" }; };
template <> struct name<Windows::Web::Http::IHttpClient2>{ static constexpr auto & value{ L"Windows.Web.Http.IHttpClient2" }; };
template <> struct name<Windows::Web::Http::IHttpClientFactory>{ static constexpr auto & value{ L"Windows.Web.Http.IHttpClientFactory" }; };
template <> struct name<Windows::Web::Http::IHttpContent>{ static constexpr auto & value{ L"Windows.Web.Http.IHttpContent" }; };
template <> struct name<Windows::Web::Http::IHttpCookie>{ static constexpr auto & value{ L"Windows.Web.Http.IHttpCookie" }; };
template <> struct name<Windows::Web::Http::IHttpCookieFactory>{ static constexpr auto & value{ L"Windows.Web.Http.IHttpCookieFactory" }; };
template <> struct name<Windows::Web::Http::IHttpCookieManager>{ static constexpr auto & value{ L"Windows.Web.Http.IHttpCookieManager" }; };
template <> struct name<Windows::Web::Http::IHttpFormUrlEncodedContentFactory>{ static constexpr auto & value{ L"Windows.Web.Http.IHttpFormUrlEncodedContentFactory" }; };
template <> struct name<Windows::Web::Http::IHttpGetBufferResult>{ static constexpr auto & value{ L"Windows.Web.Http.IHttpGetBufferResult" }; };
template <> struct name<Windows::Web::Http::IHttpGetInputStreamResult>{ static constexpr auto & value{ L"Windows.Web.Http.IHttpGetInputStreamResult" }; };
template <> struct name<Windows::Web::Http::IHttpGetStringResult>{ static constexpr auto & value{ L"Windows.Web.Http.IHttpGetStringResult" }; };
template <> struct name<Windows::Web::Http::IHttpMethod>{ static constexpr auto & value{ L"Windows.Web.Http.IHttpMethod" }; };
template <> struct name<Windows::Web::Http::IHttpMethodFactory>{ static constexpr auto & value{ L"Windows.Web.Http.IHttpMethodFactory" }; };
template <> struct name<Windows::Web::Http::IHttpMethodStatics>{ static constexpr auto & value{ L"Windows.Web.Http.IHttpMethodStatics" }; };
template <> struct name<Windows::Web::Http::IHttpMultipartContent>{ static constexpr auto & value{ L"Windows.Web.Http.IHttpMultipartContent" }; };
template <> struct name<Windows::Web::Http::IHttpMultipartContentFactory>{ static constexpr auto & value{ L"Windows.Web.Http.IHttpMultipartContentFactory" }; };
template <> struct name<Windows::Web::Http::IHttpMultipartFormDataContent>{ static constexpr auto & value{ L"Windows.Web.Http.IHttpMultipartFormDataContent" }; };
template <> struct name<Windows::Web::Http::IHttpMultipartFormDataContentFactory>{ static constexpr auto & value{ L"Windows.Web.Http.IHttpMultipartFormDataContentFactory" }; };
template <> struct name<Windows::Web::Http::IHttpRequestMessage>{ static constexpr auto & value{ L"Windows.Web.Http.IHttpRequestMessage" }; };
template <> struct name<Windows::Web::Http::IHttpRequestMessageFactory>{ static constexpr auto & value{ L"Windows.Web.Http.IHttpRequestMessageFactory" }; };
template <> struct name<Windows::Web::Http::IHttpRequestResult>{ static constexpr auto & value{ L"Windows.Web.Http.IHttpRequestResult" }; };
template <> struct name<Windows::Web::Http::IHttpResponseMessage>{ static constexpr auto & value{ L"Windows.Web.Http.IHttpResponseMessage" }; };
template <> struct name<Windows::Web::Http::IHttpResponseMessageFactory>{ static constexpr auto & value{ L"Windows.Web.Http.IHttpResponseMessageFactory" }; };
template <> struct name<Windows::Web::Http::IHttpStreamContentFactory>{ static constexpr auto & value{ L"Windows.Web.Http.IHttpStreamContentFactory" }; };
template <> struct name<Windows::Web::Http::IHttpStringContentFactory>{ static constexpr auto & value{ L"Windows.Web.Http.IHttpStringContentFactory" }; };
template <> struct name<Windows::Web::Http::IHttpTransportInformation>{ static constexpr auto & value{ L"Windows.Web.Http.IHttpTransportInformation" }; };
template <> struct name<Windows::Web::Http::HttpBufferContent>{ static constexpr auto & value{ L"Windows.Web.Http.HttpBufferContent" }; };
template <> struct name<Windows::Web::Http::HttpClient>{ static constexpr auto & value{ L"Windows.Web.Http.HttpClient" }; };
template <> struct name<Windows::Web::Http::HttpCookie>{ static constexpr auto & value{ L"Windows.Web.Http.HttpCookie" }; };
template <> struct name<Windows::Web::Http::HttpCookieCollection>{ static constexpr auto & value{ L"Windows.Web.Http.HttpCookieCollection" }; };
template <> struct name<Windows::Web::Http::HttpCookieManager>{ static constexpr auto & value{ L"Windows.Web.Http.HttpCookieManager" }; };
template <> struct name<Windows::Web::Http::HttpFormUrlEncodedContent>{ static constexpr auto & value{ L"Windows.Web.Http.HttpFormUrlEncodedContent" }; };
template <> struct name<Windows::Web::Http::HttpGetBufferResult>{ static constexpr auto & value{ L"Windows.Web.Http.HttpGetBufferResult" }; };
template <> struct name<Windows::Web::Http::HttpGetInputStreamResult>{ static constexpr auto & value{ L"Windows.Web.Http.HttpGetInputStreamResult" }; };
template <> struct name<Windows::Web::Http::HttpGetStringResult>{ static constexpr auto & value{ L"Windows.Web.Http.HttpGetStringResult" }; };
template <> struct name<Windows::Web::Http::HttpMethod>{ static constexpr auto & value{ L"Windows.Web.Http.HttpMethod" }; };
template <> struct name<Windows::Web::Http::HttpMultipartContent>{ static constexpr auto & value{ L"Windows.Web.Http.HttpMultipartContent" }; };
template <> struct name<Windows::Web::Http::HttpMultipartFormDataContent>{ static constexpr auto & value{ L"Windows.Web.Http.HttpMultipartFormDataContent" }; };
template <> struct name<Windows::Web::Http::HttpRequestMessage>{ static constexpr auto & value{ L"Windows.Web.Http.HttpRequestMessage" }; };
template <> struct name<Windows::Web::Http::HttpRequestResult>{ static constexpr auto & value{ L"Windows.Web.Http.HttpRequestResult" }; };
template <> struct name<Windows::Web::Http::HttpResponseMessage>{ static constexpr auto & value{ L"Windows.Web.Http.HttpResponseMessage" }; };
template <> struct name<Windows::Web::Http::HttpStreamContent>{ static constexpr auto & value{ L"Windows.Web.Http.HttpStreamContent" }; };
template <> struct name<Windows::Web::Http::HttpStringContent>{ static constexpr auto & value{ L"Windows.Web.Http.HttpStringContent" }; };
template <> struct name<Windows::Web::Http::HttpTransportInformation>{ static constexpr auto & value{ L"Windows.Web.Http.HttpTransportInformation" }; };
template <> struct name<Windows::Web::Http::HttpCompletionOption>{ static constexpr auto & value{ L"Windows.Web.Http.HttpCompletionOption" }; };
template <> struct name<Windows::Web::Http::HttpProgressStage>{ static constexpr auto & value{ L"Windows.Web.Http.HttpProgressStage" }; };
template <> struct name<Windows::Web::Http::HttpResponseMessageSource>{ static constexpr auto & value{ L"Windows.Web.Http.HttpResponseMessageSource" }; };
template <> struct name<Windows::Web::Http::HttpStatusCode>{ static constexpr auto & value{ L"Windows.Web.Http.HttpStatusCode" }; };
template <> struct name<Windows::Web::Http::HttpVersion>{ static constexpr auto & value{ L"Windows.Web.Http.HttpVersion" }; };
template <> struct name<Windows::Web::Http::HttpProgress>{ static constexpr auto & value{ L"Windows.Web.Http.HttpProgress" }; };
template <> struct guid_storage<Windows::Web::Http::IHttpBufferContentFactory>{ static constexpr guid value{ 0xBC20C193,0xC41F,0x4FF7,{ 0x91,0x23,0x64,0x35,0x73,0x6E,0xAD,0xC2 } }; };
template <> struct guid_storage<Windows::Web::Http::IHttpClient>{ static constexpr guid value{ 0x7FDA1151,0x3574,0x4880,{ 0xA8,0xBA,0xE6,0xB1,0xE0,0x06,0x1F,0x3D } }; };
template <> struct guid_storage<Windows::Web::Http::IHttpClient2>{ static constexpr guid value{ 0xCDD83348,0xE8B7,0x4CEC,{ 0xB1,0xB0,0xDC,0x45,0x5F,0xE7,0x2C,0x92 } }; };
template <> struct guid_storage<Windows::Web::Http::IHttpClientFactory>{ static constexpr guid value{ 0xC30C4ECA,0xE3FA,0x4F99,{ 0xAF,0xB4,0x63,0xCC,0x65,0x00,0x94,0x62 } }; };
template <> struct guid_storage<Windows::Web::Http::IHttpContent>{ static constexpr guid value{ 0x6B14A441,0xFBA7,0x4BD2,{ 0xAF,0x0A,0x83,0x9D,0xE7,0xC2,0x95,0xDA } }; };
template <> struct guid_storage<Windows::Web::Http::IHttpCookie>{ static constexpr guid value{ 0x1F5488E2,0xCC2D,0x4779,{ 0x86,0xA7,0x88,0xF1,0x06,0x87,0xD2,0x49 } }; };
template <> struct guid_storage<Windows::Web::Http::IHttpCookieFactory>{ static constexpr guid value{ 0x6A0585A9,0x931C,0x4CD1,{ 0xA9,0x6D,0xC2,0x17,0x01,0x78,0x5C,0x5F } }; };
template <> struct guid_storage<Windows::Web::Http::IHttpCookieManager>{ static constexpr guid value{ 0x7A431780,0xCD4F,0x4E57,{ 0xA8,0x4A,0x5B,0x0A,0x53,0xD6,0xBB,0x96 } }; };
template <> struct guid_storage<Windows::Web::Http::IHttpFormUrlEncodedContentFactory>{ static constexpr guid value{ 0x43F0138C,0x2F73,0x4302,{ 0xB5,0xF3,0xEA,0xE9,0x23,0x8A,0x5E,0x01 } }; };
template <> struct guid_storage<Windows::Web::Http::IHttpGetBufferResult>{ static constexpr guid value{ 0x53D08E7C,0xE209,0x404E,{ 0x9A,0x49,0x74,0x2D,0x82,0x36,0xFD,0x3A } }; };
template <> struct guid_storage<Windows::Web::Http::IHttpGetInputStreamResult>{ static constexpr guid value{ 0xD5D63463,0x13AA,0x4EE0,{ 0xBE,0x95,0xA0,0xC3,0x9F,0xE9,0x12,0x03 } }; };
template <> struct guid_storage<Windows::Web::Http::IHttpGetStringResult>{ static constexpr guid value{ 0x9BAC466D,0x8509,0x4775,{ 0xB1,0x6D,0x89,0x53,0xF4,0x7A,0x7F,0x5F } }; };
template <> struct guid_storage<Windows::Web::Http::IHttpMethod>{ static constexpr guid value{ 0x728D4022,0x700D,0x4FE0,{ 0xAF,0xA5,0x40,0x29,0x9C,0x58,0xDB,0xFD } }; };
template <> struct guid_storage<Windows::Web::Http::IHttpMethodFactory>{ static constexpr guid value{ 0x3C51D10D,0x36D7,0x40F8,{ 0xA8,0x6D,0xE7,0x59,0xCA,0xF2,0xF8,0x3F } }; };
template <> struct guid_storage<Windows::Web::Http::IHttpMethodStatics>{ static constexpr guid value{ 0x64D171F0,0xD99A,0x4153,{ 0x8D,0xC6,0xD6,0x8C,0xC4,0xCC,0xE3,0x17 } }; };
template <> struct guid_storage<Windows::Web::Http::IHttpMultipartContent>{ static constexpr guid value{ 0xDF916AFF,0x9926,0x4AC9,{ 0xAA,0xF1,0xE0,0xD0,0x4E,0xF0,0x9B,0xB9 } }; };
template <> struct guid_storage<Windows::Web::Http::IHttpMultipartContentFactory>{ static constexpr guid value{ 0x7EB42E62,0x0222,0x4F20,{ 0xB3,0x72,0x47,0xD5,0xDB,0x5D,0x33,0xB4 } }; };
template <> struct guid_storage<Windows::Web::Http::IHttpMultipartFormDataContent>{ static constexpr guid value{ 0x64D337E2,0xE967,0x4624,{ 0xB6,0xD1,0xCF,0x74,0x60,0x4A,0x4A,0x42 } }; };
template <> struct guid_storage<Windows::Web::Http::IHttpMultipartFormDataContentFactory>{ static constexpr guid value{ 0xA04D7311,0x5017,0x4622,{ 0x93,0xA8,0x49,0xB2,0x4A,0x4F,0xCB,0xFC } }; };
template <> struct guid_storage<Windows::Web::Http::IHttpRequestMessage>{ static constexpr guid value{ 0xF5762B3C,0x74D4,0x4811,{ 0xB5,0xDC,0x9F,0x8B,0x4E,0x2F,0x9A,0xBF } }; };
template <> struct guid_storage<Windows::Web::Http::IHttpRequestMessageFactory>{ static constexpr guid value{ 0x5BAC994E,0x3886,0x412E,{ 0xAE,0xC3,0x52,0xEC,0x7F,0x25,0x61,0x6F } }; };
template <> struct guid_storage<Windows::Web::Http::IHttpRequestResult>{ static constexpr guid value{ 0x6ACF4DA8,0xB5EB,0x4A35,{ 0xA9,0x02,0x42,0x17,0xFB,0xE8,0x20,0xC5 } }; };
template <> struct guid_storage<Windows::Web::Http::IHttpResponseMessage>{ static constexpr guid value{ 0xFEE200FB,0x8664,0x44E0,{ 0x95,0xD9,0x42,0x69,0x61,0x99,0xBF,0xFC } }; };
template <> struct guid_storage<Windows::Web::Http::IHttpResponseMessageFactory>{ static constexpr guid value{ 0x52A8AF99,0xF095,0x43DA,{ 0xB6,0x0F,0x7C,0xFC,0x2B,0xC7,0xEA,0x2F } }; };
template <> struct guid_storage<Windows::Web::Http::IHttpStreamContentFactory>{ static constexpr guid value{ 0xF3E64D9D,0xF725,0x407E,{ 0x94,0x2F,0x0E,0xDA,0x18,0x98,0x09,0xF4 } }; };
template <> struct guid_storage<Windows::Web::Http::IHttpStringContentFactory>{ static constexpr guid value{ 0x46649D5B,0x2E93,0x48EB,{ 0x8E,0x61,0x19,0x67,0x78,0x78,0xE5,0x7F } }; };
template <> struct guid_storage<Windows::Web::Http::IHttpTransportInformation>{ static constexpr guid value{ 0x70127198,0xC6A7,0x4ED0,{ 0x83,0x3A,0x83,0xFD,0x8B,0x8F,0x17,0x8D } }; };
template <> struct default_interface<Windows::Web::Http::HttpBufferContent>{ using type = Windows::Web::Http::IHttpContent; };
template <> struct default_interface<Windows::Web::Http::HttpClient>{ using type = Windows::Web::Http::IHttpClient; };
template <> struct default_interface<Windows::Web::Http::HttpCookie>{ using type = Windows::Web::Http::IHttpCookie; };
template <> struct default_interface<Windows::Web::Http::HttpCookieCollection>{ using type = Windows::Foundation::Collections::IVectorView<Windows::Web::Http::HttpCookie>; };
template <> struct default_interface<Windows::Web::Http::HttpCookieManager>{ using type = Windows::Web::Http::IHttpCookieManager; };
template <> struct default_interface<Windows::Web::Http::HttpFormUrlEncodedContent>{ using type = Windows::Web::Http::IHttpContent; };
template <> struct default_interface<Windows::Web::Http::HttpGetBufferResult>{ using type = Windows::Web::Http::IHttpGetBufferResult; };
template <> struct default_interface<Windows::Web::Http::HttpGetInputStreamResult>{ using type = Windows::Web::Http::IHttpGetInputStreamResult; };
template <> struct default_interface<Windows::Web::Http::HttpGetStringResult>{ using type = Windows::Web::Http::IHttpGetStringResult; };
template <> struct default_interface<Windows::Web::Http::HttpMethod>{ using type = Windows::Web::Http::IHttpMethod; };
template <> struct default_interface<Windows::Web::Http::HttpMultipartContent>{ using type = Windows::Web::Http::IHttpContent; };
template <> struct default_interface<Windows::Web::Http::HttpMultipartFormDataContent>{ using type = Windows::Web::Http::IHttpContent; };
template <> struct default_interface<Windows::Web::Http::HttpRequestMessage>{ using type = Windows::Web::Http::IHttpRequestMessage; };
template <> struct default_interface<Windows::Web::Http::HttpRequestResult>{ using type = Windows::Web::Http::IHttpRequestResult; };
template <> struct default_interface<Windows::Web::Http::HttpResponseMessage>{ using type = Windows::Web::Http::IHttpResponseMessage; };
template <> struct default_interface<Windows::Web::Http::HttpStreamContent>{ using type = Windows::Web::Http::IHttpContent; };
template <> struct default_interface<Windows::Web::Http::HttpStringContent>{ using type = Windows::Web::Http::IHttpContent; };
template <> struct default_interface<Windows::Web::Http::HttpTransportInformation>{ using type = Windows::Web::Http::IHttpTransportInformation; };

template <> struct abi<Windows::Web::Http::IHttpBufferContentFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateFromBuffer(void* content, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateFromBufferWithOffset(void* content, uint32_t offset, uint32_t count, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::IHttpClient>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL DeleteAsync(void* uri, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetAsync(void* uri, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetWithOptionAsync(void* uri, Windows::Web::Http::HttpCompletionOption completionOption, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetBufferAsync(void* uri, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetInputStreamAsync(void* uri, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetStringAsync(void* uri, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL PostAsync(void* uri, void* content, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL PutAsync(void* uri, void* content, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL SendRequestAsync(void* request, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL SendRequestWithOptionAsync(void* request, Windows::Web::Http::HttpCompletionOption completionOption, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL get_DefaultRequestHeaders(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::IHttpClient2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL TryDeleteAsync(void* uri, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL TryGetAsync(void* uri, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL TryGetAsync2(void* uri, Windows::Web::Http::HttpCompletionOption completionOption, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL TryGetBufferAsync(void* uri, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL TryGetInputStreamAsync(void* uri, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL TryGetStringAsync(void* uri, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL TryPostAsync(void* uri, void* content, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL TryPutAsync(void* uri, void* content, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL TrySendRequestAsync(void* request, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL TrySendRequestAsync2(void* request, Windows::Web::Http::HttpCompletionOption completionOption, void** operation) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::IHttpClientFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Create(void* filter, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::IHttpContent>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Headers(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL BufferAllAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL ReadAsBufferAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL ReadAsInputStreamAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL ReadAsStringAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL TryComputeLength(uint64_t* length, bool* succeeded) noexcept = 0;
    virtual int32_t WINRT_CALL WriteToStreamAsync(void* outputStream, void** operation) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::IHttpCookie>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Name(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Domain(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Path(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Expires(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Expires(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HttpOnly(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_HttpOnly(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Secure(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Secure(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Value(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Value(void* value) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::IHttpCookieFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Create(void* name, void* domain, void* path, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::IHttpCookieManager>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL SetCookie(void* cookie, bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL SetCookieWithThirdParty(void* cookie, bool thirdParty, bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL DeleteCookie(void* cookie) noexcept = 0;
    virtual int32_t WINRT_CALL GetCookies(void* uri, void** result) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::IHttpFormUrlEncodedContentFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Create(void* content, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::IHttpGetBufferResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ExtendedError(winrt::hresult* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RequestMessage(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ResponseMessage(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Succeeded(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Value(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::IHttpGetInputStreamResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ExtendedError(winrt::hresult* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RequestMessage(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ResponseMessage(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Succeeded(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Value(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::IHttpGetStringResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ExtendedError(winrt::hresult* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RequestMessage(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ResponseMessage(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Succeeded(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Value(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::IHttpMethod>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Method(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::IHttpMethodFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Create(void* method, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::IHttpMethodStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Delete(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Get(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Head(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Options(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Patch(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Post(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Put(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::IHttpMultipartContent>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Add(void* content) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::IHttpMultipartContentFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateWithSubtype(void* subtype, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateWithSubtypeAndBoundary(void* subtype, void* boundary, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::IHttpMultipartFormDataContent>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Add(void* content) noexcept = 0;
    virtual int32_t WINRT_CALL AddWithName(void* content, void* name) noexcept = 0;
    virtual int32_t WINRT_CALL AddWithNameAndFileName(void* content, void* name, void* fileName) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::IHttpMultipartFormDataContentFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateWithBoundary(void* boundary, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::IHttpRequestMessage>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Content(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Content(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Headers(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Method(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Method(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Properties(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RequestUri(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_RequestUri(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TransportInformation(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::IHttpRequestMessageFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Create(void* method, void* uri, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::IHttpRequestResult>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ExtendedError(winrt::hresult* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RequestMessage(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ResponseMessage(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Succeeded(bool* value) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::IHttpResponseMessage>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Content(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Content(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Headers(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsSuccessStatusCode(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ReasonPhrase(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ReasonPhrase(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RequestMessage(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_RequestMessage(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Source(Windows::Web::Http::HttpResponseMessageSource* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Source(Windows::Web::Http::HttpResponseMessageSource value) noexcept = 0;
    virtual int32_t WINRT_CALL get_StatusCode(Windows::Web::Http::HttpStatusCode* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_StatusCode(Windows::Web::Http::HttpStatusCode value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Version(Windows::Web::Http::HttpVersion* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Version(Windows::Web::Http::HttpVersion value) noexcept = 0;
    virtual int32_t WINRT_CALL EnsureSuccessStatusCode(void** result) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::IHttpResponseMessageFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Create(Windows::Web::Http::HttpStatusCode statusCode, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::IHttpStreamContentFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateFromInputStream(void* content, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::IHttpStringContentFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateFromString(void* content, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateFromStringWithEncoding(void* content, Windows::Storage::Streams::UnicodeEncoding encoding, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateFromStringWithEncodingAndMediaType(void* content, Windows::Storage::Streams::UnicodeEncoding encoding, void* mediaType, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::IHttpTransportInformation>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ServerCertificate(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ServerCertificateErrorSeverity(Windows::Networking::Sockets::SocketSslErrorSeverity* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ServerCertificateErrors(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ServerIntermediateCertificates(void** value) noexcept = 0;
};};

template <typename D>
struct consume_Windows_Web_Http_IHttpBufferContentFactory
{
    Windows::Web::Http::HttpBufferContent CreateFromBuffer(Windows::Storage::Streams::IBuffer const& content) const;
    Windows::Web::Http::HttpBufferContent CreateFromBufferWithOffset(Windows::Storage::Streams::IBuffer const& content, uint32_t offset, uint32_t count) const;
};
template <> struct consume<Windows::Web::Http::IHttpBufferContentFactory> { template <typename D> using type = consume_Windows_Web_Http_IHttpBufferContentFactory<D>; };

template <typename D>
struct consume_Windows_Web_Http_IHttpClient
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpResponseMessage, Windows::Web::Http::HttpProgress> DeleteAsync(Windows::Foundation::Uri const& uri) const;
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpResponseMessage, Windows::Web::Http::HttpProgress> GetAsync(Windows::Foundation::Uri const& uri) const;
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpResponseMessage, Windows::Web::Http::HttpProgress> GetAsync(Windows::Foundation::Uri const& uri, Windows::Web::Http::HttpCompletionOption const& completionOption) const;
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Storage::Streams::IBuffer, Windows::Web::Http::HttpProgress> GetBufferAsync(Windows::Foundation::Uri const& uri) const;
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Storage::Streams::IInputStream, Windows::Web::Http::HttpProgress> GetInputStreamAsync(Windows::Foundation::Uri const& uri) const;
    Windows::Foundation::IAsyncOperationWithProgress<hstring, Windows::Web::Http::HttpProgress> GetStringAsync(Windows::Foundation::Uri const& uri) const;
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpResponseMessage, Windows::Web::Http::HttpProgress> PostAsync(Windows::Foundation::Uri const& uri, Windows::Web::Http::IHttpContent const& content) const;
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpResponseMessage, Windows::Web::Http::HttpProgress> PutAsync(Windows::Foundation::Uri const& uri, Windows::Web::Http::IHttpContent const& content) const;
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpResponseMessage, Windows::Web::Http::HttpProgress> SendRequestAsync(Windows::Web::Http::HttpRequestMessage const& request) const;
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpResponseMessage, Windows::Web::Http::HttpProgress> SendRequestAsync(Windows::Web::Http::HttpRequestMessage const& request, Windows::Web::Http::HttpCompletionOption const& completionOption) const;
    Windows::Web::Http::Headers::HttpRequestHeaderCollection DefaultRequestHeaders() const;
};
template <> struct consume<Windows::Web::Http::IHttpClient> { template <typename D> using type = consume_Windows_Web_Http_IHttpClient<D>; };

template <typename D>
struct consume_Windows_Web_Http_IHttpClient2
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpRequestResult, Windows::Web::Http::HttpProgress> TryDeleteAsync(Windows::Foundation::Uri const& uri) const;
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpRequestResult, Windows::Web::Http::HttpProgress> TryGetAsync(Windows::Foundation::Uri const& uri) const;
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpRequestResult, Windows::Web::Http::HttpProgress> TryGetAsync(Windows::Foundation::Uri const& uri, Windows::Web::Http::HttpCompletionOption const& completionOption) const;
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpGetBufferResult, Windows::Web::Http::HttpProgress> TryGetBufferAsync(Windows::Foundation::Uri const& uri) const;
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpGetInputStreamResult, Windows::Web::Http::HttpProgress> TryGetInputStreamAsync(Windows::Foundation::Uri const& uri) const;
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpGetStringResult, Windows::Web::Http::HttpProgress> TryGetStringAsync(Windows::Foundation::Uri const& uri) const;
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpRequestResult, Windows::Web::Http::HttpProgress> TryPostAsync(Windows::Foundation::Uri const& uri, Windows::Web::Http::IHttpContent const& content) const;
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpRequestResult, Windows::Web::Http::HttpProgress> TryPutAsync(Windows::Foundation::Uri const& uri, Windows::Web::Http::IHttpContent const& content) const;
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpRequestResult, Windows::Web::Http::HttpProgress> TrySendRequestAsync(Windows::Web::Http::HttpRequestMessage const& request) const;
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpRequestResult, Windows::Web::Http::HttpProgress> TrySendRequestAsync(Windows::Web::Http::HttpRequestMessage const& request, Windows::Web::Http::HttpCompletionOption const& completionOption) const;
};
template <> struct consume<Windows::Web::Http::IHttpClient2> { template <typename D> using type = consume_Windows_Web_Http_IHttpClient2<D>; };

template <typename D>
struct consume_Windows_Web_Http_IHttpClientFactory
{
    Windows::Web::Http::HttpClient Create(Windows::Web::Http::Filters::IHttpFilter const& filter) const;
};
template <> struct consume<Windows::Web::Http::IHttpClientFactory> { template <typename D> using type = consume_Windows_Web_Http_IHttpClientFactory<D>; };

template <typename D>
struct consume_Windows_Web_Http_IHttpContent
{
    Windows::Web::Http::Headers::HttpContentHeaderCollection Headers() const;
    Windows::Foundation::IAsyncOperationWithProgress<uint64_t, uint64_t> BufferAllAsync() const;
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Storage::Streams::IBuffer, uint64_t> ReadAsBufferAsync() const;
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Storage::Streams::IInputStream, uint64_t> ReadAsInputStreamAsync() const;
    Windows::Foundation::IAsyncOperationWithProgress<hstring, uint64_t> ReadAsStringAsync() const;
    bool TryComputeLength(uint64_t& length) const;
    Windows::Foundation::IAsyncOperationWithProgress<uint64_t, uint64_t> WriteToStreamAsync(Windows::Storage::Streams::IOutputStream const& outputStream) const;
};
template <> struct consume<Windows::Web::Http::IHttpContent> { template <typename D> using type = consume_Windows_Web_Http_IHttpContent<D>; };

template <typename D>
struct consume_Windows_Web_Http_IHttpCookie
{
    hstring Name() const;
    hstring Domain() const;
    hstring Path() const;
    Windows::Foundation::IReference<Windows::Foundation::DateTime> Expires() const;
    void Expires(optional<Windows::Foundation::DateTime> const& value) const;
    bool HttpOnly() const;
    void HttpOnly(bool value) const;
    bool Secure() const;
    void Secure(bool value) const;
    hstring Value() const;
    void Value(param::hstring const& value) const;
};
template <> struct consume<Windows::Web::Http::IHttpCookie> { template <typename D> using type = consume_Windows_Web_Http_IHttpCookie<D>; };

template <typename D>
struct consume_Windows_Web_Http_IHttpCookieFactory
{
    Windows::Web::Http::HttpCookie Create(param::hstring const& name, param::hstring const& domain, param::hstring const& path) const;
};
template <> struct consume<Windows::Web::Http::IHttpCookieFactory> { template <typename D> using type = consume_Windows_Web_Http_IHttpCookieFactory<D>; };

template <typename D>
struct consume_Windows_Web_Http_IHttpCookieManager
{
    bool SetCookie(Windows::Web::Http::HttpCookie const& cookie) const;
    bool SetCookie(Windows::Web::Http::HttpCookie const& cookie, bool thirdParty) const;
    void DeleteCookie(Windows::Web::Http::HttpCookie const& cookie) const;
    Windows::Web::Http::HttpCookieCollection GetCookies(Windows::Foundation::Uri const& uri) const;
};
template <> struct consume<Windows::Web::Http::IHttpCookieManager> { template <typename D> using type = consume_Windows_Web_Http_IHttpCookieManager<D>; };

template <typename D>
struct consume_Windows_Web_Http_IHttpFormUrlEncodedContentFactory
{
    Windows::Web::Http::HttpFormUrlEncodedContent Create(param::iterable<Windows::Foundation::Collections::IKeyValuePair<hstring, hstring>> const& content) const;
};
template <> struct consume<Windows::Web::Http::IHttpFormUrlEncodedContentFactory> { template <typename D> using type = consume_Windows_Web_Http_IHttpFormUrlEncodedContentFactory<D>; };

template <typename D>
struct consume_Windows_Web_Http_IHttpGetBufferResult
{
    winrt::hresult ExtendedError() const;
    Windows::Web::Http::HttpRequestMessage RequestMessage() const;
    Windows::Web::Http::HttpResponseMessage ResponseMessage() const;
    bool Succeeded() const;
    Windows::Storage::Streams::IBuffer Value() const;
};
template <> struct consume<Windows::Web::Http::IHttpGetBufferResult> { template <typename D> using type = consume_Windows_Web_Http_IHttpGetBufferResult<D>; };

template <typename D>
struct consume_Windows_Web_Http_IHttpGetInputStreamResult
{
    winrt::hresult ExtendedError() const;
    Windows::Web::Http::HttpRequestMessage RequestMessage() const;
    Windows::Web::Http::HttpResponseMessage ResponseMessage() const;
    bool Succeeded() const;
    Windows::Storage::Streams::IInputStream Value() const;
};
template <> struct consume<Windows::Web::Http::IHttpGetInputStreamResult> { template <typename D> using type = consume_Windows_Web_Http_IHttpGetInputStreamResult<D>; };

template <typename D>
struct consume_Windows_Web_Http_IHttpGetStringResult
{
    winrt::hresult ExtendedError() const;
    Windows::Web::Http::HttpRequestMessage RequestMessage() const;
    Windows::Web::Http::HttpResponseMessage ResponseMessage() const;
    bool Succeeded() const;
    hstring Value() const;
};
template <> struct consume<Windows::Web::Http::IHttpGetStringResult> { template <typename D> using type = consume_Windows_Web_Http_IHttpGetStringResult<D>; };

template <typename D>
struct consume_Windows_Web_Http_IHttpMethod
{
    hstring Method() const;
};
template <> struct consume<Windows::Web::Http::IHttpMethod> { template <typename D> using type = consume_Windows_Web_Http_IHttpMethod<D>; };

template <typename D>
struct consume_Windows_Web_Http_IHttpMethodFactory
{
    Windows::Web::Http::HttpMethod Create(param::hstring const& method) const;
};
template <> struct consume<Windows::Web::Http::IHttpMethodFactory> { template <typename D> using type = consume_Windows_Web_Http_IHttpMethodFactory<D>; };

template <typename D>
struct consume_Windows_Web_Http_IHttpMethodStatics
{
    Windows::Web::Http::HttpMethod Delete() const;
    Windows::Web::Http::HttpMethod Get() const;
    Windows::Web::Http::HttpMethod Head() const;
    Windows::Web::Http::HttpMethod Options() const;
    Windows::Web::Http::HttpMethod Patch() const;
    Windows::Web::Http::HttpMethod Post() const;
    Windows::Web::Http::HttpMethod Put() const;
};
template <> struct consume<Windows::Web::Http::IHttpMethodStatics> { template <typename D> using type = consume_Windows_Web_Http_IHttpMethodStatics<D>; };

template <typename D>
struct consume_Windows_Web_Http_IHttpMultipartContent
{
    void Add(Windows::Web::Http::IHttpContent const& content) const;
};
template <> struct consume<Windows::Web::Http::IHttpMultipartContent> { template <typename D> using type = consume_Windows_Web_Http_IHttpMultipartContent<D>; };

template <typename D>
struct consume_Windows_Web_Http_IHttpMultipartContentFactory
{
    Windows::Web::Http::HttpMultipartContent CreateWithSubtype(param::hstring const& subtype) const;
    Windows::Web::Http::HttpMultipartContent CreateWithSubtypeAndBoundary(param::hstring const& subtype, param::hstring const& boundary) const;
};
template <> struct consume<Windows::Web::Http::IHttpMultipartContentFactory> { template <typename D> using type = consume_Windows_Web_Http_IHttpMultipartContentFactory<D>; };

template <typename D>
struct consume_Windows_Web_Http_IHttpMultipartFormDataContent
{
    void Add(Windows::Web::Http::IHttpContent const& content) const;
    void Add(Windows::Web::Http::IHttpContent const& content, param::hstring const& name) const;
    void Add(Windows::Web::Http::IHttpContent const& content, param::hstring const& name, param::hstring const& fileName) const;
};
template <> struct consume<Windows::Web::Http::IHttpMultipartFormDataContent> { template <typename D> using type = consume_Windows_Web_Http_IHttpMultipartFormDataContent<D>; };

template <typename D>
struct consume_Windows_Web_Http_IHttpMultipartFormDataContentFactory
{
    Windows::Web::Http::HttpMultipartFormDataContent CreateWithBoundary(param::hstring const& boundary) const;
};
template <> struct consume<Windows::Web::Http::IHttpMultipartFormDataContentFactory> { template <typename D> using type = consume_Windows_Web_Http_IHttpMultipartFormDataContentFactory<D>; };

template <typename D>
struct consume_Windows_Web_Http_IHttpRequestMessage
{
    Windows::Web::Http::IHttpContent Content() const;
    void Content(Windows::Web::Http::IHttpContent const& value) const;
    Windows::Web::Http::Headers::HttpRequestHeaderCollection Headers() const;
    Windows::Web::Http::HttpMethod Method() const;
    void Method(Windows::Web::Http::HttpMethod const& value) const;
    Windows::Foundation::Collections::IMap<hstring, Windows::Foundation::IInspectable> Properties() const;
    Windows::Foundation::Uri RequestUri() const;
    void RequestUri(Windows::Foundation::Uri const& value) const;
    Windows::Web::Http::HttpTransportInformation TransportInformation() const;
};
template <> struct consume<Windows::Web::Http::IHttpRequestMessage> { template <typename D> using type = consume_Windows_Web_Http_IHttpRequestMessage<D>; };

template <typename D>
struct consume_Windows_Web_Http_IHttpRequestMessageFactory
{
    Windows::Web::Http::HttpRequestMessage Create(Windows::Web::Http::HttpMethod const& method, Windows::Foundation::Uri const& uri) const;
};
template <> struct consume<Windows::Web::Http::IHttpRequestMessageFactory> { template <typename D> using type = consume_Windows_Web_Http_IHttpRequestMessageFactory<D>; };

template <typename D>
struct consume_Windows_Web_Http_IHttpRequestResult
{
    winrt::hresult ExtendedError() const;
    Windows::Web::Http::HttpRequestMessage RequestMessage() const;
    Windows::Web::Http::HttpResponseMessage ResponseMessage() const;
    bool Succeeded() const;
};
template <> struct consume<Windows::Web::Http::IHttpRequestResult> { template <typename D> using type = consume_Windows_Web_Http_IHttpRequestResult<D>; };

template <typename D>
struct consume_Windows_Web_Http_IHttpResponseMessage
{
    Windows::Web::Http::IHttpContent Content() const;
    void Content(Windows::Web::Http::IHttpContent const& value) const;
    Windows::Web::Http::Headers::HttpResponseHeaderCollection Headers() const;
    bool IsSuccessStatusCode() const;
    hstring ReasonPhrase() const;
    void ReasonPhrase(param::hstring const& value) const;
    Windows::Web::Http::HttpRequestMessage RequestMessage() const;
    void RequestMessage(Windows::Web::Http::HttpRequestMessage const& value) const;
    Windows::Web::Http::HttpResponseMessageSource Source() const;
    void Source(Windows::Web::Http::HttpResponseMessageSource const& value) const;
    Windows::Web::Http::HttpStatusCode StatusCode() const;
    void StatusCode(Windows::Web::Http::HttpStatusCode const& value) const;
    Windows::Web::Http::HttpVersion Version() const;
    void Version(Windows::Web::Http::HttpVersion const& value) const;
    Windows::Web::Http::HttpResponseMessage EnsureSuccessStatusCode() const;
};
template <> struct consume<Windows::Web::Http::IHttpResponseMessage> { template <typename D> using type = consume_Windows_Web_Http_IHttpResponseMessage<D>; };

template <typename D>
struct consume_Windows_Web_Http_IHttpResponseMessageFactory
{
    Windows::Web::Http::HttpResponseMessage Create(Windows::Web::Http::HttpStatusCode const& statusCode) const;
};
template <> struct consume<Windows::Web::Http::IHttpResponseMessageFactory> { template <typename D> using type = consume_Windows_Web_Http_IHttpResponseMessageFactory<D>; };

template <typename D>
struct consume_Windows_Web_Http_IHttpStreamContentFactory
{
    Windows::Web::Http::HttpStreamContent CreateFromInputStream(Windows::Storage::Streams::IInputStream const& content) const;
};
template <> struct consume<Windows::Web::Http::IHttpStreamContentFactory> { template <typename D> using type = consume_Windows_Web_Http_IHttpStreamContentFactory<D>; };

template <typename D>
struct consume_Windows_Web_Http_IHttpStringContentFactory
{
    Windows::Web::Http::HttpStringContent CreateFromString(param::hstring const& content) const;
    Windows::Web::Http::HttpStringContent CreateFromStringWithEncoding(param::hstring const& content, Windows::Storage::Streams::UnicodeEncoding const& encoding) const;
    Windows::Web::Http::HttpStringContent CreateFromStringWithEncodingAndMediaType(param::hstring const& content, Windows::Storage::Streams::UnicodeEncoding const& encoding, param::hstring const& mediaType) const;
};
template <> struct consume<Windows::Web::Http::IHttpStringContentFactory> { template <typename D> using type = consume_Windows_Web_Http_IHttpStringContentFactory<D>; };

template <typename D>
struct consume_Windows_Web_Http_IHttpTransportInformation
{
    Windows::Security::Cryptography::Certificates::Certificate ServerCertificate() const;
    Windows::Networking::Sockets::SocketSslErrorSeverity ServerCertificateErrorSeverity() const;
    Windows::Foundation::Collections::IVectorView<Windows::Security::Cryptography::Certificates::ChainValidationResult> ServerCertificateErrors() const;
    Windows::Foundation::Collections::IVectorView<Windows::Security::Cryptography::Certificates::Certificate> ServerIntermediateCertificates() const;
};
template <> struct consume<Windows::Web::Http::IHttpTransportInformation> { template <typename D> using type = consume_Windows_Web_Http_IHttpTransportInformation<D>; };

struct struct_Windows_Web_Http_HttpProgress
{
    Windows::Web::Http::HttpProgressStage Stage;
    uint64_t BytesSent;
    void* TotalBytesToSend;
    uint64_t BytesReceived;
    void* TotalBytesToReceive;
    uint32_t Retries;
};
template <> struct abi<Windows::Web::Http::HttpProgress>{ using type = struct_Windows_Web_Http_HttpProgress; };


}
