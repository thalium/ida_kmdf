// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.ApplicationModel.DataTransfer.1.h"
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.Storage.Streams.1.h"
#include "winrt/impl/Windows.UI.1.h"
#include "winrt/impl/Windows.Web.1.h"
#include "winrt/impl/Windows.Web.Http.1.h"
#include "winrt/impl/Windows.Web.UI.1.h"

WINRT_EXPORT namespace winrt::Windows::Web::UI {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::Web::UI {

struct WINRT_EBO WebViewControlContentLoadingEventArgs :
    Windows::Web::UI::IWebViewControlContentLoadingEventArgs
{
    WebViewControlContentLoadingEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO WebViewControlDOMContentLoadedEventArgs :
    Windows::Web::UI::IWebViewControlDOMContentLoadedEventArgs
{
    WebViewControlDOMContentLoadedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO WebViewControlDeferredPermissionRequest :
    Windows::Web::UI::IWebViewControlDeferredPermissionRequest
{
    WebViewControlDeferredPermissionRequest(std::nullptr_t) noexcept {}
};

struct WINRT_EBO WebViewControlLongRunningScriptDetectedEventArgs :
    Windows::Web::UI::IWebViewControlLongRunningScriptDetectedEventArgs
{
    WebViewControlLongRunningScriptDetectedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO WebViewControlNavigationCompletedEventArgs :
    Windows::Web::UI::IWebViewControlNavigationCompletedEventArgs
{
    WebViewControlNavigationCompletedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO WebViewControlNavigationStartingEventArgs :
    Windows::Web::UI::IWebViewControlNavigationStartingEventArgs
{
    WebViewControlNavigationStartingEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO WebViewControlNewWindowRequestedEventArgs :
    Windows::Web::UI::IWebViewControlNewWindowRequestedEventArgs,
    impl::require<WebViewControlNewWindowRequestedEventArgs, Windows::Web::UI::IWebViewControlNewWindowRequestedEventArgs2>
{
    WebViewControlNewWindowRequestedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO WebViewControlPermissionRequest :
    Windows::Web::UI::IWebViewControlPermissionRequest
{
    WebViewControlPermissionRequest(std::nullptr_t) noexcept {}
};

struct WINRT_EBO WebViewControlPermissionRequestedEventArgs :
    Windows::Web::UI::IWebViewControlPermissionRequestedEventArgs
{
    WebViewControlPermissionRequestedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO WebViewControlScriptNotifyEventArgs :
    Windows::Web::UI::IWebViewControlScriptNotifyEventArgs
{
    WebViewControlScriptNotifyEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO WebViewControlSettings :
    Windows::Web::UI::IWebViewControlSettings
{
    WebViewControlSettings(std::nullptr_t) noexcept {}
};

struct WINRT_EBO WebViewControlUnsupportedUriSchemeIdentifiedEventArgs :
    Windows::Web::UI::IWebViewControlUnsupportedUriSchemeIdentifiedEventArgs
{
    WebViewControlUnsupportedUriSchemeIdentifiedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO WebViewControlUnviewableContentIdentifiedEventArgs :
    Windows::Web::UI::IWebViewControlUnviewableContentIdentifiedEventArgs
{
    WebViewControlUnviewableContentIdentifiedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO WebViewControlWebResourceRequestedEventArgs :
    Windows::Web::UI::IWebViewControlWebResourceRequestedEventArgs
{
    WebViewControlWebResourceRequestedEventArgs(std::nullptr_t) noexcept {}
};

}
