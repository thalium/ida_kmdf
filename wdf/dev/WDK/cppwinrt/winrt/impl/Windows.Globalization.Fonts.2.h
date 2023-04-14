// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.UI.Text.1.h"
#include "winrt/impl/Windows.Globalization.Fonts.1.h"

WINRT_EXPORT namespace winrt::Windows::Globalization::Fonts {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::Globalization::Fonts {

struct WINRT_EBO LanguageFont :
    Windows::Globalization::Fonts::ILanguageFont
{
    LanguageFont(std::nullptr_t) noexcept {}
};

struct WINRT_EBO LanguageFontGroup :
    Windows::Globalization::Fonts::ILanguageFontGroup
{
    LanguageFontGroup(std::nullptr_t) noexcept {}
    LanguageFontGroup(param::hstring const& languageTag);
};

}
