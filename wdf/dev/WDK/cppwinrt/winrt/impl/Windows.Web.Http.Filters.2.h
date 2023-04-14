// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.Networking.Sockets.1.h"
#include "winrt/impl/Windows.Security.Credentials.1.h"
#include "winrt/impl/Windows.Security.Cryptography.Certificates.1.h"
#include "winrt/impl/Windows.System.1.h"
#include "winrt/impl/Windows.Web.Http.1.h"
#include "winrt/impl/Windows.Web.Http.Filters.1.h"

WINRT_EXPORT namespace winrt::Windows::Web::Http::Filters {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::Web::Http::Filters {

struct WINRT_EBO HttpBaseProtocolFilter :
    Windows::Web::Http::Filters::IHttpBaseProtocolFilter,
    impl::require<HttpBaseProtocolFilter, Windows::Foundation::IClosable, Windows::Web::Http::Filters::IHttpBaseProtocolFilter2, Windows::Web::Http::Filters::IHttpBaseProtocolFilter3, Windows::Web::Http::Filters::IHttpBaseProtocolFilter4, Windows::Web::Http::Filters::IHttpBaseProtocolFilter5, Windows::Web::Http::Filters::IHttpFilter>
{
    HttpBaseProtocolFilter(std::nullptr_t) noexcept {}
    HttpBaseProtocolFilter();
    static Windows::Web::Http::Filters::HttpBaseProtocolFilter CreateForUser(Windows::System::User const& user);
};

struct WINRT_EBO HttpCacheControl :
    Windows::Web::Http::Filters::IHttpCacheControl
{
    HttpCacheControl(std::nullptr_t) noexcept {}
};

struct WINRT_EBO HttpServerCustomValidationRequestedEventArgs :
    Windows::Web::Http::Filters::IHttpServerCustomValidationRequestedEventArgs
{
    HttpServerCustomValidationRequestedEventArgs(std::nullptr_t) noexcept {}
};

}
