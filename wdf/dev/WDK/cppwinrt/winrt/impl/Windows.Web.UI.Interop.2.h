// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.ApplicationModel.DataTransfer.1.h"
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.Storage.Streams.1.h"
#include "winrt/impl/Windows.System.1.h"
#include "winrt/impl/Windows.UI.1.h"
#include "winrt/impl/Windows.UI.Core.1.h"
#include "winrt/impl/Windows.Web.1.h"
#include "winrt/impl/Windows.Web.Http.1.h"
#include "winrt/impl/Windows.Web.UI.1.h"
#include "winrt/impl/Windows.Web.UI.Interop.1.h"

WINRT_EXPORT namespace winrt::Windows::Web::UI::Interop {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::Web::UI::Interop {

struct WINRT_EBO WebViewControl :
    Windows::Web::UI::IWebViewControl,
    impl::require<WebViewControl, Windows::Web::UI::IWebViewControl2, Windows::Web::UI::Interop::IWebViewControlSite, Windows::Web::UI::Interop::IWebViewControlSite2>
{
    WebViewControl(std::nullptr_t) noexcept {}
};

struct WINRT_EBO WebViewControlAcceleratorKeyPressedEventArgs :
    Windows::Web::UI::Interop::IWebViewControlAcceleratorKeyPressedEventArgs
{
    WebViewControlAcceleratorKeyPressedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO WebViewControlMoveFocusRequestedEventArgs :
    Windows::Web::UI::Interop::IWebViewControlMoveFocusRequestedEventArgs
{
    WebViewControlMoveFocusRequestedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO WebViewControlProcess :
    Windows::Web::UI::Interop::IWebViewControlProcess
{
    WebViewControlProcess(std::nullptr_t) noexcept {}
    WebViewControlProcess();
    WebViewControlProcess(Windows::Web::UI::Interop::WebViewControlProcessOptions const& processOptions);
};

struct WINRT_EBO WebViewControlProcessOptions :
    Windows::Web::UI::Interop::IWebViewControlProcessOptions
{
    WebViewControlProcessOptions(std::nullptr_t) noexcept {}
    WebViewControlProcessOptions();
};

}
