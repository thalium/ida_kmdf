// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.ApplicationModel.DataTransfer.0.h"
#include "winrt/impl/Windows.Foundation.0.h"
#include "winrt/impl/Windows.Storage.Streams.0.h"
#include "winrt/impl/Windows.System.0.h"
#include "winrt/impl/Windows.UI.0.h"
#include "winrt/impl/Windows.UI.Core.0.h"
#include "winrt/impl/Windows.Web.0.h"
#include "winrt/impl/Windows.Web.Http.0.h"
#include "winrt/impl/Windows.Web.UI.0.h"
#include "winrt/impl/Windows.Web.UI.Interop.0.h"

WINRT_EXPORT namespace winrt::Windows::Web::UI::Interop {

struct WINRT_EBO IWebViewControlAcceleratorKeyPressedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IWebViewControlAcceleratorKeyPressedEventArgs>
{
    IWebViewControlAcceleratorKeyPressedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IWebViewControlMoveFocusRequestedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IWebViewControlMoveFocusRequestedEventArgs>
{
    IWebViewControlMoveFocusRequestedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IWebViewControlProcess :
    Windows::Foundation::IInspectable,
    impl::consume_t<IWebViewControlProcess>
{
    IWebViewControlProcess(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IWebViewControlProcessFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<IWebViewControlProcessFactory>
{
    IWebViewControlProcessFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IWebViewControlProcessOptions :
    Windows::Foundation::IInspectable,
    impl::consume_t<IWebViewControlProcessOptions>
{
    IWebViewControlProcessOptions(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IWebViewControlSite :
    Windows::Foundation::IInspectable,
    impl::consume_t<IWebViewControlSite>
{
    IWebViewControlSite(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IWebViewControlSite2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IWebViewControlSite2>
{
    IWebViewControlSite2(std::nullptr_t = nullptr) noexcept {}
};

}
