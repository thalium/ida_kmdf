// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Data.Html.1.h"

WINRT_EXPORT namespace winrt::Windows::Data::Html {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::Data::Html {

struct HtmlUtilities
{
    HtmlUtilities() = delete;
    static hstring ConvertToText(param::hstring const& html);
};

}
