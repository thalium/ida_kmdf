// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Foundation.0.h"
#include "winrt/impl/Windows.Networking.Sockets.0.h"
#include "winrt/impl/Windows.Security.Credentials.0.h"
#include "winrt/impl/Windows.Security.Cryptography.Certificates.0.h"
#include "winrt/impl/Windows.System.0.h"
#include "winrt/impl/Windows.Web.Http.0.h"
#include "winrt/impl/Windows.Web.Http.Filters.0.h"

WINRT_EXPORT namespace winrt::Windows::Web::Http::Filters {

struct WINRT_EBO IHttpBaseProtocolFilter :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpBaseProtocolFilter>
{
    IHttpBaseProtocolFilter(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpBaseProtocolFilter2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpBaseProtocolFilter2>
{
    IHttpBaseProtocolFilter2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpBaseProtocolFilter3 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpBaseProtocolFilter3>
{
    IHttpBaseProtocolFilter3(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpBaseProtocolFilter4 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpBaseProtocolFilter4>
{
    IHttpBaseProtocolFilter4(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpBaseProtocolFilter5 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpBaseProtocolFilter5>
{
    IHttpBaseProtocolFilter5(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpBaseProtocolFilterStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpBaseProtocolFilterStatics>
{
    IHttpBaseProtocolFilterStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpCacheControl :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpCacheControl>
{
    IHttpCacheControl(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpFilter :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpFilter>,
    impl::require<IHttpFilter, Windows::Foundation::IClosable>
{
    IHttpFilter(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHttpServerCustomValidationRequestedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHttpServerCustomValidationRequestedEventArgs>
{
    IHttpServerCustomValidationRequestedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

}
