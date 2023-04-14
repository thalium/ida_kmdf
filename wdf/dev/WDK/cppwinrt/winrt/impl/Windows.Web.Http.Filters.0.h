// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Foundation {

struct Deferral;

}

WINRT_EXPORT namespace winrt::Windows::Networking::Sockets {

enum class SocketSslErrorSeverity;

}

WINRT_EXPORT namespace winrt::Windows::Security::Credentials {

struct PasswordCredential;

}

WINRT_EXPORT namespace winrt::Windows::Security::Cryptography::Certificates {

enum class ChainValidationResult;
struct Certificate;

}

WINRT_EXPORT namespace winrt::Windows::System {

struct User;

}

WINRT_EXPORT namespace winrt::Windows::Web::Http {

enum class HttpVersion;
struct HttpCookieManager;
struct HttpProgress;
struct HttpRequestMessage;
struct HttpResponseMessage;

}

WINRT_EXPORT namespace winrt::Windows::Web::Http::Filters {

enum class HttpCacheReadBehavior : int32_t
{
    Default = 0,
    MostRecent = 1,
    OnlyFromCache = 2,
    NoCache = 3,
};

enum class HttpCacheWriteBehavior : int32_t
{
    Default = 0,
    NoCache = 1,
};

enum class HttpCookieUsageBehavior : int32_t
{
    Default = 0,
    NoCookies = 1,
};

struct IHttpBaseProtocolFilter;
struct IHttpBaseProtocolFilter2;
struct IHttpBaseProtocolFilter3;
struct IHttpBaseProtocolFilter4;
struct IHttpBaseProtocolFilter5;
struct IHttpBaseProtocolFilterStatics;
struct IHttpCacheControl;
struct IHttpFilter;
struct IHttpServerCustomValidationRequestedEventArgs;
struct HttpBaseProtocolFilter;
struct HttpCacheControl;
struct HttpServerCustomValidationRequestedEventArgs;

}

namespace winrt::impl {

template <> struct category<Windows::Web::Http::Filters::IHttpBaseProtocolFilter>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Filters::IHttpBaseProtocolFilter2>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Filters::IHttpBaseProtocolFilter3>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Filters::IHttpBaseProtocolFilter4>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Filters::IHttpBaseProtocolFilter5>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Filters::IHttpBaseProtocolFilterStatics>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Filters::IHttpCacheControl>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Filters::IHttpFilter>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Filters::IHttpServerCustomValidationRequestedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Web::Http::Filters::HttpBaseProtocolFilter>{ using type = class_category; };
template <> struct category<Windows::Web::Http::Filters::HttpCacheControl>{ using type = class_category; };
template <> struct category<Windows::Web::Http::Filters::HttpServerCustomValidationRequestedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Web::Http::Filters::HttpCacheReadBehavior>{ using type = enum_category; };
template <> struct category<Windows::Web::Http::Filters::HttpCacheWriteBehavior>{ using type = enum_category; };
template <> struct category<Windows::Web::Http::Filters::HttpCookieUsageBehavior>{ using type = enum_category; };
template <> struct name<Windows::Web::Http::Filters::IHttpBaseProtocolFilter>{ static constexpr auto & value{ L"Windows.Web.Http.Filters.IHttpBaseProtocolFilter" }; };
template <> struct name<Windows::Web::Http::Filters::IHttpBaseProtocolFilter2>{ static constexpr auto & value{ L"Windows.Web.Http.Filters.IHttpBaseProtocolFilter2" }; };
template <> struct name<Windows::Web::Http::Filters::IHttpBaseProtocolFilter3>{ static constexpr auto & value{ L"Windows.Web.Http.Filters.IHttpBaseProtocolFilter3" }; };
template <> struct name<Windows::Web::Http::Filters::IHttpBaseProtocolFilter4>{ static constexpr auto & value{ L"Windows.Web.Http.Filters.IHttpBaseProtocolFilter4" }; };
template <> struct name<Windows::Web::Http::Filters::IHttpBaseProtocolFilter5>{ static constexpr auto & value{ L"Windows.Web.Http.Filters.IHttpBaseProtocolFilter5" }; };
template <> struct name<Windows::Web::Http::Filters::IHttpBaseProtocolFilterStatics>{ static constexpr auto & value{ L"Windows.Web.Http.Filters.IHttpBaseProtocolFilterStatics" }; };
template <> struct name<Windows::Web::Http::Filters::IHttpCacheControl>{ static constexpr auto & value{ L"Windows.Web.Http.Filters.IHttpCacheControl" }; };
template <> struct name<Windows::Web::Http::Filters::IHttpFilter>{ static constexpr auto & value{ L"Windows.Web.Http.Filters.IHttpFilter" }; };
template <> struct name<Windows::Web::Http::Filters::IHttpServerCustomValidationRequestedEventArgs>{ static constexpr auto & value{ L"Windows.Web.Http.Filters.IHttpServerCustomValidationRequestedEventArgs" }; };
template <> struct name<Windows::Web::Http::Filters::HttpBaseProtocolFilter>{ static constexpr auto & value{ L"Windows.Web.Http.Filters.HttpBaseProtocolFilter" }; };
template <> struct name<Windows::Web::Http::Filters::HttpCacheControl>{ static constexpr auto & value{ L"Windows.Web.Http.Filters.HttpCacheControl" }; };
template <> struct name<Windows::Web::Http::Filters::HttpServerCustomValidationRequestedEventArgs>{ static constexpr auto & value{ L"Windows.Web.Http.Filters.HttpServerCustomValidationRequestedEventArgs" }; };
template <> struct name<Windows::Web::Http::Filters::HttpCacheReadBehavior>{ static constexpr auto & value{ L"Windows.Web.Http.Filters.HttpCacheReadBehavior" }; };
template <> struct name<Windows::Web::Http::Filters::HttpCacheWriteBehavior>{ static constexpr auto & value{ L"Windows.Web.Http.Filters.HttpCacheWriteBehavior" }; };
template <> struct name<Windows::Web::Http::Filters::HttpCookieUsageBehavior>{ static constexpr auto & value{ L"Windows.Web.Http.Filters.HttpCookieUsageBehavior" }; };
template <> struct guid_storage<Windows::Web::Http::Filters::IHttpBaseProtocolFilter>{ static constexpr guid value{ 0x71C89B09,0xE131,0x4B54,{ 0xA5,0x3C,0xEB,0x43,0xFF,0x37,0xE9,0xBB } }; };
template <> struct guid_storage<Windows::Web::Http::Filters::IHttpBaseProtocolFilter2>{ static constexpr guid value{ 0x2EC30013,0x9427,0x4900,{ 0xA0,0x17,0xFA,0x7D,0xA3,0xB5,0xC9,0xAE } }; };
template <> struct guid_storage<Windows::Web::Http::Filters::IHttpBaseProtocolFilter3>{ static constexpr guid value{ 0xD43F4D4C,0xBD42,0x43AE,{ 0x87,0x17,0xAD,0x2C,0x8F,0x4B,0x29,0x37 } }; };
template <> struct guid_storage<Windows::Web::Http::Filters::IHttpBaseProtocolFilter4>{ static constexpr guid value{ 0x9FE36CCF,0x2983,0x4893,{ 0x94,0x1F,0xEB,0x51,0x8C,0xA8,0xCE,0xF9 } }; };
template <> struct guid_storage<Windows::Web::Http::Filters::IHttpBaseProtocolFilter5>{ static constexpr guid value{ 0x416E4993,0x31E3,0x4816,{ 0xBF,0x09,0xE0,0x18,0xEE,0x8D,0xC1,0xF5 } }; };
template <> struct guid_storage<Windows::Web::Http::Filters::IHttpBaseProtocolFilterStatics>{ static constexpr guid value{ 0x6D4DEE0C,0xE908,0x494E,{ 0xB5,0xA3,0x12,0x63,0xC9,0xB8,0x24,0x2A } }; };
template <> struct guid_storage<Windows::Web::Http::Filters::IHttpCacheControl>{ static constexpr guid value{ 0xC77E1CB4,0x3CEA,0x4EB5,{ 0xAC,0x85,0x04,0xE1,0x86,0xE6,0x3A,0xB7 } }; };
template <> struct guid_storage<Windows::Web::Http::Filters::IHttpFilter>{ static constexpr guid value{ 0xA4CB6DD5,0x0902,0x439E,{ 0xBF,0xD7,0xE1,0x25,0x52,0xB1,0x65,0xCE } }; };
template <> struct guid_storage<Windows::Web::Http::Filters::IHttpServerCustomValidationRequestedEventArgs>{ static constexpr guid value{ 0x3165FE32,0xE7DD,0x48B7,{ 0xA3,0x61,0x93,0x9C,0x75,0x0E,0x63,0xCC } }; };
template <> struct default_interface<Windows::Web::Http::Filters::HttpBaseProtocolFilter>{ using type = Windows::Web::Http::Filters::IHttpBaseProtocolFilter; };
template <> struct default_interface<Windows::Web::Http::Filters::HttpCacheControl>{ using type = Windows::Web::Http::Filters::IHttpCacheControl; };
template <> struct default_interface<Windows::Web::Http::Filters::HttpServerCustomValidationRequestedEventArgs>{ using type = Windows::Web::Http::Filters::IHttpServerCustomValidationRequestedEventArgs; };

template <> struct abi<Windows::Web::Http::Filters::IHttpBaseProtocolFilter>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_AllowAutoRedirect(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_AllowAutoRedirect(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AllowUI(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_AllowUI(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AutomaticDecompression(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_AutomaticDecompression(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CacheControl(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CookieManager(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ClientCertificate(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ClientCertificate(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IgnorableServerCertificateErrors(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MaxConnectionsPerServer(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_MaxConnectionsPerServer(uint32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ProxyCredential(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ProxyCredential(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ServerCredential(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ServerCredential(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_UseProxy(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_UseProxy(bool value) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Filters::IHttpBaseProtocolFilter2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_MaxVersion(Windows::Web::Http::HttpVersion* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_MaxVersion(Windows::Web::Http::HttpVersion value) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Filters::IHttpBaseProtocolFilter3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_CookieUsageBehavior(Windows::Web::Http::Filters::HttpCookieUsageBehavior* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_CookieUsageBehavior(Windows::Web::Http::Filters::HttpCookieUsageBehavior value) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Filters::IHttpBaseProtocolFilter4>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL add_ServerCustomValidationRequested(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_ServerCustomValidationRequested(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL ClearAuthenticationCache() noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Filters::IHttpBaseProtocolFilter5>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_User(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Filters::IHttpBaseProtocolFilterStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateForUser(void* user, void** result) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Filters::IHttpCacheControl>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ReadBehavior(Windows::Web::Http::Filters::HttpCacheReadBehavior* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ReadBehavior(Windows::Web::Http::Filters::HttpCacheReadBehavior value) noexcept = 0;
    virtual int32_t WINRT_CALL get_WriteBehavior(Windows::Web::Http::Filters::HttpCacheWriteBehavior* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_WriteBehavior(Windows::Web::Http::Filters::HttpCacheWriteBehavior value) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Filters::IHttpFilter>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL SendRequestAsync(void* request, void** operation) noexcept = 0;
};};

template <> struct abi<Windows::Web::Http::Filters::IHttpServerCustomValidationRequestedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_RequestMessage(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ServerCertificate(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ServerCertificateErrorSeverity(Windows::Networking::Sockets::SocketSslErrorSeverity* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ServerCertificateErrors(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ServerIntermediateCertificates(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL Reject() noexcept = 0;
    virtual int32_t WINRT_CALL GetDeferral(void** result) noexcept = 0;
};};

template <typename D>
struct consume_Windows_Web_Http_Filters_IHttpBaseProtocolFilter
{
    bool AllowAutoRedirect() const;
    void AllowAutoRedirect(bool value) const;
    bool AllowUI() const;
    void AllowUI(bool value) const;
    bool AutomaticDecompression() const;
    void AutomaticDecompression(bool value) const;
    Windows::Web::Http::Filters::HttpCacheControl CacheControl() const;
    Windows::Web::Http::HttpCookieManager CookieManager() const;
    Windows::Security::Cryptography::Certificates::Certificate ClientCertificate() const;
    void ClientCertificate(Windows::Security::Cryptography::Certificates::Certificate const& value) const;
    Windows::Foundation::Collections::IVector<Windows::Security::Cryptography::Certificates::ChainValidationResult> IgnorableServerCertificateErrors() const;
    uint32_t MaxConnectionsPerServer() const;
    void MaxConnectionsPerServer(uint32_t value) const;
    Windows::Security::Credentials::PasswordCredential ProxyCredential() const;
    void ProxyCredential(Windows::Security::Credentials::PasswordCredential const& value) const;
    Windows::Security::Credentials::PasswordCredential ServerCredential() const;
    void ServerCredential(Windows::Security::Credentials::PasswordCredential const& value) const;
    bool UseProxy() const;
    void UseProxy(bool value) const;
};
template <> struct consume<Windows::Web::Http::Filters::IHttpBaseProtocolFilter> { template <typename D> using type = consume_Windows_Web_Http_Filters_IHttpBaseProtocolFilter<D>; };

template <typename D>
struct consume_Windows_Web_Http_Filters_IHttpBaseProtocolFilter2
{
    Windows::Web::Http::HttpVersion MaxVersion() const;
    void MaxVersion(Windows::Web::Http::HttpVersion const& value) const;
};
template <> struct consume<Windows::Web::Http::Filters::IHttpBaseProtocolFilter2> { template <typename D> using type = consume_Windows_Web_Http_Filters_IHttpBaseProtocolFilter2<D>; };

template <typename D>
struct consume_Windows_Web_Http_Filters_IHttpBaseProtocolFilter3
{
    Windows::Web::Http::Filters::HttpCookieUsageBehavior CookieUsageBehavior() const;
    void CookieUsageBehavior(Windows::Web::Http::Filters::HttpCookieUsageBehavior const& value) const;
};
template <> struct consume<Windows::Web::Http::Filters::IHttpBaseProtocolFilter3> { template <typename D> using type = consume_Windows_Web_Http_Filters_IHttpBaseProtocolFilter3<D>; };

template <typename D>
struct consume_Windows_Web_Http_Filters_IHttpBaseProtocolFilter4
{
    winrt::event_token ServerCustomValidationRequested(Windows::Foundation::TypedEventHandler<Windows::Web::Http::Filters::HttpBaseProtocolFilter, Windows::Web::Http::Filters::HttpServerCustomValidationRequestedEventArgs> const& handler) const;
    using ServerCustomValidationRequested_revoker = impl::event_revoker<Windows::Web::Http::Filters::IHttpBaseProtocolFilter4, &impl::abi_t<Windows::Web::Http::Filters::IHttpBaseProtocolFilter4>::remove_ServerCustomValidationRequested>;
    ServerCustomValidationRequested_revoker ServerCustomValidationRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Web::Http::Filters::HttpBaseProtocolFilter, Windows::Web::Http::Filters::HttpServerCustomValidationRequestedEventArgs> const& handler) const;
    void ServerCustomValidationRequested(winrt::event_token const& token) const noexcept;
    void ClearAuthenticationCache() const;
};
template <> struct consume<Windows::Web::Http::Filters::IHttpBaseProtocolFilter4> { template <typename D> using type = consume_Windows_Web_Http_Filters_IHttpBaseProtocolFilter4<D>; };

template <typename D>
struct consume_Windows_Web_Http_Filters_IHttpBaseProtocolFilter5
{
    Windows::System::User User() const;
};
template <> struct consume<Windows::Web::Http::Filters::IHttpBaseProtocolFilter5> { template <typename D> using type = consume_Windows_Web_Http_Filters_IHttpBaseProtocolFilter5<D>; };

template <typename D>
struct consume_Windows_Web_Http_Filters_IHttpBaseProtocolFilterStatics
{
    Windows::Web::Http::Filters::HttpBaseProtocolFilter CreateForUser(Windows::System::User const& user) const;
};
template <> struct consume<Windows::Web::Http::Filters::IHttpBaseProtocolFilterStatics> { template <typename D> using type = consume_Windows_Web_Http_Filters_IHttpBaseProtocolFilterStatics<D>; };

template <typename D>
struct consume_Windows_Web_Http_Filters_IHttpCacheControl
{
    Windows::Web::Http::Filters::HttpCacheReadBehavior ReadBehavior() const;
    void ReadBehavior(Windows::Web::Http::Filters::HttpCacheReadBehavior const& value) const;
    Windows::Web::Http::Filters::HttpCacheWriteBehavior WriteBehavior() const;
    void WriteBehavior(Windows::Web::Http::Filters::HttpCacheWriteBehavior const& value) const;
};
template <> struct consume<Windows::Web::Http::Filters::IHttpCacheControl> { template <typename D> using type = consume_Windows_Web_Http_Filters_IHttpCacheControl<D>; };

template <typename D>
struct consume_Windows_Web_Http_Filters_IHttpFilter
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Web::Http::HttpResponseMessage, Windows::Web::Http::HttpProgress> SendRequestAsync(Windows::Web::Http::HttpRequestMessage const& request) const;
};
template <> struct consume<Windows::Web::Http::Filters::IHttpFilter> { template <typename D> using type = consume_Windows_Web_Http_Filters_IHttpFilter<D>; };

template <typename D>
struct consume_Windows_Web_Http_Filters_IHttpServerCustomValidationRequestedEventArgs
{
    Windows::Web::Http::HttpRequestMessage RequestMessage() const;
    Windows::Security::Cryptography::Certificates::Certificate ServerCertificate() const;
    Windows::Networking::Sockets::SocketSslErrorSeverity ServerCertificateErrorSeverity() const;
    Windows::Foundation::Collections::IVectorView<Windows::Security::Cryptography::Certificates::ChainValidationResult> ServerCertificateErrors() const;
    Windows::Foundation::Collections::IVectorView<Windows::Security::Cryptography::Certificates::Certificate> ServerIntermediateCertificates() const;
    void Reject() const;
    Windows::Foundation::Deferral GetDeferral() const;
};
template <> struct consume<Windows::Web::Http::Filters::IHttpServerCustomValidationRequestedEventArgs> { template <typename D> using type = consume_Windows_Web_Http_Filters_IHttpServerCustomValidationRequestedEventArgs<D>; };

}
