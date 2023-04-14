// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Foundation.0.h"
#include "winrt/impl/Windows.Storage.Streams.0.h"
#include "winrt/impl/Windows.UI.0.h"
#include "winrt/impl/Windows.UI.Text.0.h"

WINRT_EXPORT namespace winrt::Windows::UI::Text {

struct WINRT_EBO IContentLinkInfo :
    Windows::Foundation::IInspectable,
    impl::consume_t<IContentLinkInfo>
{
    IContentLinkInfo(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IFontWeights :
    Windows::Foundation::IInspectable,
    impl::consume_t<IFontWeights>
{
    IFontWeights(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IFontWeightsStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IFontWeightsStatics>
{
    IFontWeightsStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IRichEditTextRange :
    Windows::Foundation::IInspectable,
    impl::consume_t<IRichEditTextRange>
{
    IRichEditTextRange(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ITextCharacterFormat :
    Windows::Foundation::IInspectable,
    impl::consume_t<ITextCharacterFormat>
{
    ITextCharacterFormat(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ITextConstantsStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<ITextConstantsStatics>
{
    ITextConstantsStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ITextDocument :
    Windows::Foundation::IInspectable,
    impl::consume_t<ITextDocument>
{
    ITextDocument(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ITextDocument2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<ITextDocument2>
{
    ITextDocument2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ITextDocument3 :
    Windows::Foundation::IInspectable,
    impl::consume_t<ITextDocument3>
{
    ITextDocument3(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ITextParagraphFormat :
    Windows::Foundation::IInspectable,
    impl::consume_t<ITextParagraphFormat>
{
    ITextParagraphFormat(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ITextRange :
    Windows::Foundation::IInspectable,
    impl::consume_t<ITextRange>
{
    ITextRange(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ITextSelection :
    Windows::Foundation::IInspectable,
    impl::consume_t<ITextSelection>,
    impl::require<ITextSelection, Windows::UI::Text::ITextRange>
{
    ITextSelection(std::nullptr_t = nullptr) noexcept {}
};

}
