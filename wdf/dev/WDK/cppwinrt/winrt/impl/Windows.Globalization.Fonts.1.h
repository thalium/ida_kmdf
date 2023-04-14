// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.UI.Text.0.h"
#include "winrt/impl/Windows.Globalization.Fonts.0.h"

WINRT_EXPORT namespace winrt::Windows::Globalization::Fonts {

struct WINRT_EBO ILanguageFont :
    Windows::Foundation::IInspectable,
    impl::consume_t<ILanguageFont>
{
    ILanguageFont(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ILanguageFontGroup :
    Windows::Foundation::IInspectable,
    impl::consume_t<ILanguageFontGroup>
{
    ILanguageFontGroup(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ILanguageFontGroupFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<ILanguageFontGroupFactory>
{
    ILanguageFontGroupFactory(std::nullptr_t = nullptr) noexcept {}
};

}
