// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Data.Html.0.h"

WINRT_EXPORT namespace winrt::Windows::Data::Html {

struct WINRT_EBO IHtmlUtilities :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHtmlUtilities>
{
    IHtmlUtilities(std::nullptr_t = nullptr) noexcept {}
};

}
