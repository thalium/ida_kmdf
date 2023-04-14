// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.UI.2.h"
#include "winrt/impl/Windows.UI.Text.2.h"
#include "winrt/Windows.UI.h"

namespace winrt::impl {

template <typename D> uint32_t consume_Windows_UI_Text_IContentLinkInfo<D>::Id() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::IContentLinkInfo)->get_Id(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Text_IContentLinkInfo<D>::Id(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::IContentLinkInfo)->put_Id(value));
}

template <typename D> hstring consume_Windows_UI_Text_IContentLinkInfo<D>::DisplayText() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::IContentLinkInfo)->get_DisplayText(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Text_IContentLinkInfo<D>::DisplayText(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::IContentLinkInfo)->put_DisplayText(get_abi(value)));
}

template <typename D> hstring consume_Windows_UI_Text_IContentLinkInfo<D>::SecondaryText() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::IContentLinkInfo)->get_SecondaryText(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Text_IContentLinkInfo<D>::SecondaryText(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::IContentLinkInfo)->put_SecondaryText(get_abi(value)));
}

template <typename D> Windows::Foundation::Uri consume_Windows_UI_Text_IContentLinkInfo<D>::Uri() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Text::IContentLinkInfo)->get_Uri(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Text_IContentLinkInfo<D>::Uri(Windows::Foundation::Uri const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::IContentLinkInfo)->put_Uri(get_abi(value)));
}

template <typename D> hstring consume_Windows_UI_Text_IContentLinkInfo<D>::LinkContentKind() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::IContentLinkInfo)->get_LinkContentKind(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Text_IContentLinkInfo<D>::LinkContentKind(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::IContentLinkInfo)->put_LinkContentKind(get_abi(value)));
}

template <typename D> Windows::UI::Text::FontWeight consume_Windows_UI_Text_IFontWeightsStatics<D>::Black() const
{
    Windows::UI::Text::FontWeight value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::IFontWeightsStatics)->get_Black(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Text::FontWeight consume_Windows_UI_Text_IFontWeightsStatics<D>::Bold() const
{
    Windows::UI::Text::FontWeight value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::IFontWeightsStatics)->get_Bold(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Text::FontWeight consume_Windows_UI_Text_IFontWeightsStatics<D>::ExtraBlack() const
{
    Windows::UI::Text::FontWeight value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::IFontWeightsStatics)->get_ExtraBlack(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Text::FontWeight consume_Windows_UI_Text_IFontWeightsStatics<D>::ExtraBold() const
{
    Windows::UI::Text::FontWeight value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::IFontWeightsStatics)->get_ExtraBold(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Text::FontWeight consume_Windows_UI_Text_IFontWeightsStatics<D>::ExtraLight() const
{
    Windows::UI::Text::FontWeight value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::IFontWeightsStatics)->get_ExtraLight(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Text::FontWeight consume_Windows_UI_Text_IFontWeightsStatics<D>::Light() const
{
    Windows::UI::Text::FontWeight value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::IFontWeightsStatics)->get_Light(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Text::FontWeight consume_Windows_UI_Text_IFontWeightsStatics<D>::Medium() const
{
    Windows::UI::Text::FontWeight value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::IFontWeightsStatics)->get_Medium(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Text::FontWeight consume_Windows_UI_Text_IFontWeightsStatics<D>::Normal() const
{
    Windows::UI::Text::FontWeight value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::IFontWeightsStatics)->get_Normal(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Text::FontWeight consume_Windows_UI_Text_IFontWeightsStatics<D>::SemiBold() const
{
    Windows::UI::Text::FontWeight value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::IFontWeightsStatics)->get_SemiBold(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Text::FontWeight consume_Windows_UI_Text_IFontWeightsStatics<D>::SemiLight() const
{
    Windows::UI::Text::FontWeight value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::IFontWeightsStatics)->get_SemiLight(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Text::FontWeight consume_Windows_UI_Text_IFontWeightsStatics<D>::Thin() const
{
    Windows::UI::Text::FontWeight value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::IFontWeightsStatics)->get_Thin(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Text::ContentLinkInfo consume_Windows_UI_Text_IRichEditTextRange<D>::ContentLinkInfo() const
{
    Windows::UI::Text::ContentLinkInfo value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Text::IRichEditTextRange)->get_ContentLinkInfo(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Text_IRichEditTextRange<D>::ContentLinkInfo(Windows::UI::Text::ContentLinkInfo const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::IRichEditTextRange)->put_ContentLinkInfo(get_abi(value)));
}

template <typename D> Windows::UI::Text::FormatEffect consume_Windows_UI_Text_ITextCharacterFormat<D>::AllCaps() const
{
    Windows::UI::Text::FormatEffect value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextCharacterFormat)->get_AllCaps(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Text_ITextCharacterFormat<D>::AllCaps(Windows::UI::Text::FormatEffect const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextCharacterFormat)->put_AllCaps(get_abi(value)));
}

template <typename D> Windows::UI::Color consume_Windows_UI_Text_ITextCharacterFormat<D>::BackgroundColor() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextCharacterFormat)->get_BackgroundColor(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Text_ITextCharacterFormat<D>::BackgroundColor(Windows::UI::Color const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextCharacterFormat)->put_BackgroundColor(get_abi(value)));
}

template <typename D> Windows::UI::Text::FormatEffect consume_Windows_UI_Text_ITextCharacterFormat<D>::Bold() const
{
    Windows::UI::Text::FormatEffect value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextCharacterFormat)->get_Bold(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Text_ITextCharacterFormat<D>::Bold(Windows::UI::Text::FormatEffect const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextCharacterFormat)->put_Bold(get_abi(value)));
}

template <typename D> Windows::UI::Text::FontStretch consume_Windows_UI_Text_ITextCharacterFormat<D>::FontStretch() const
{
    Windows::UI::Text::FontStretch value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextCharacterFormat)->get_FontStretch(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Text_ITextCharacterFormat<D>::FontStretch(Windows::UI::Text::FontStretch const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextCharacterFormat)->put_FontStretch(get_abi(value)));
}

template <typename D> Windows::UI::Text::FontStyle consume_Windows_UI_Text_ITextCharacterFormat<D>::FontStyle() const
{
    Windows::UI::Text::FontStyle value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextCharacterFormat)->get_FontStyle(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Text_ITextCharacterFormat<D>::FontStyle(Windows::UI::Text::FontStyle const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextCharacterFormat)->put_FontStyle(get_abi(value)));
}

template <typename D> Windows::UI::Color consume_Windows_UI_Text_ITextCharacterFormat<D>::ForegroundColor() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextCharacterFormat)->get_ForegroundColor(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Text_ITextCharacterFormat<D>::ForegroundColor(Windows::UI::Color const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextCharacterFormat)->put_ForegroundColor(get_abi(value)));
}

template <typename D> Windows::UI::Text::FormatEffect consume_Windows_UI_Text_ITextCharacterFormat<D>::Hidden() const
{
    Windows::UI::Text::FormatEffect value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextCharacterFormat)->get_Hidden(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Text_ITextCharacterFormat<D>::Hidden(Windows::UI::Text::FormatEffect const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextCharacterFormat)->put_Hidden(get_abi(value)));
}

template <typename D> Windows::UI::Text::FormatEffect consume_Windows_UI_Text_ITextCharacterFormat<D>::Italic() const
{
    Windows::UI::Text::FormatEffect value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextCharacterFormat)->get_Italic(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Text_ITextCharacterFormat<D>::Italic(Windows::UI::Text::FormatEffect const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextCharacterFormat)->put_Italic(get_abi(value)));
}

template <typename D> float consume_Windows_UI_Text_ITextCharacterFormat<D>::Kerning() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextCharacterFormat)->get_Kerning(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Text_ITextCharacterFormat<D>::Kerning(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextCharacterFormat)->put_Kerning(value));
}

template <typename D> hstring consume_Windows_UI_Text_ITextCharacterFormat<D>::LanguageTag() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextCharacterFormat)->get_LanguageTag(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Text_ITextCharacterFormat<D>::LanguageTag(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextCharacterFormat)->put_LanguageTag(get_abi(value)));
}

template <typename D> Windows::UI::Text::LinkType consume_Windows_UI_Text_ITextCharacterFormat<D>::LinkType() const
{
    Windows::UI::Text::LinkType value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextCharacterFormat)->get_LinkType(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Text_ITextCharacterFormat<D>::Name() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextCharacterFormat)->get_Name(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Text_ITextCharacterFormat<D>::Name(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextCharacterFormat)->put_Name(get_abi(value)));
}

template <typename D> Windows::UI::Text::FormatEffect consume_Windows_UI_Text_ITextCharacterFormat<D>::Outline() const
{
    Windows::UI::Text::FormatEffect value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextCharacterFormat)->get_Outline(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Text_ITextCharacterFormat<D>::Outline(Windows::UI::Text::FormatEffect const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextCharacterFormat)->put_Outline(get_abi(value)));
}

template <typename D> float consume_Windows_UI_Text_ITextCharacterFormat<D>::Position() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextCharacterFormat)->get_Position(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Text_ITextCharacterFormat<D>::Position(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextCharacterFormat)->put_Position(value));
}

template <typename D> Windows::UI::Text::FormatEffect consume_Windows_UI_Text_ITextCharacterFormat<D>::ProtectedText() const
{
    Windows::UI::Text::FormatEffect value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextCharacterFormat)->get_ProtectedText(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Text_ITextCharacterFormat<D>::ProtectedText(Windows::UI::Text::FormatEffect const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextCharacterFormat)->put_ProtectedText(get_abi(value)));
}

template <typename D> float consume_Windows_UI_Text_ITextCharacterFormat<D>::Size() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextCharacterFormat)->get_Size(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Text_ITextCharacterFormat<D>::Size(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextCharacterFormat)->put_Size(value));
}

template <typename D> Windows::UI::Text::FormatEffect consume_Windows_UI_Text_ITextCharacterFormat<D>::SmallCaps() const
{
    Windows::UI::Text::FormatEffect value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextCharacterFormat)->get_SmallCaps(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Text_ITextCharacterFormat<D>::SmallCaps(Windows::UI::Text::FormatEffect const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextCharacterFormat)->put_SmallCaps(get_abi(value)));
}

template <typename D> float consume_Windows_UI_Text_ITextCharacterFormat<D>::Spacing() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextCharacterFormat)->get_Spacing(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Text_ITextCharacterFormat<D>::Spacing(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextCharacterFormat)->put_Spacing(value));
}

template <typename D> Windows::UI::Text::FormatEffect consume_Windows_UI_Text_ITextCharacterFormat<D>::Strikethrough() const
{
    Windows::UI::Text::FormatEffect value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextCharacterFormat)->get_Strikethrough(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Text_ITextCharacterFormat<D>::Strikethrough(Windows::UI::Text::FormatEffect const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextCharacterFormat)->put_Strikethrough(get_abi(value)));
}

template <typename D> Windows::UI::Text::FormatEffect consume_Windows_UI_Text_ITextCharacterFormat<D>::Subscript() const
{
    Windows::UI::Text::FormatEffect value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextCharacterFormat)->get_Subscript(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Text_ITextCharacterFormat<D>::Subscript(Windows::UI::Text::FormatEffect const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextCharacterFormat)->put_Subscript(get_abi(value)));
}

template <typename D> Windows::UI::Text::FormatEffect consume_Windows_UI_Text_ITextCharacterFormat<D>::Superscript() const
{
    Windows::UI::Text::FormatEffect value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextCharacterFormat)->get_Superscript(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Text_ITextCharacterFormat<D>::Superscript(Windows::UI::Text::FormatEffect const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextCharacterFormat)->put_Superscript(get_abi(value)));
}

template <typename D> Windows::UI::Text::TextScript consume_Windows_UI_Text_ITextCharacterFormat<D>::TextScript() const
{
    Windows::UI::Text::TextScript value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextCharacterFormat)->get_TextScript(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Text_ITextCharacterFormat<D>::TextScript(Windows::UI::Text::TextScript const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextCharacterFormat)->put_TextScript(get_abi(value)));
}

template <typename D> Windows::UI::Text::UnderlineType consume_Windows_UI_Text_ITextCharacterFormat<D>::Underline() const
{
    Windows::UI::Text::UnderlineType value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextCharacterFormat)->get_Underline(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Text_ITextCharacterFormat<D>::Underline(Windows::UI::Text::UnderlineType const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextCharacterFormat)->put_Underline(get_abi(value)));
}

template <typename D> int32_t consume_Windows_UI_Text_ITextCharacterFormat<D>::Weight() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextCharacterFormat)->get_Weight(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Text_ITextCharacterFormat<D>::Weight(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextCharacterFormat)->put_Weight(value));
}

template <typename D> void consume_Windows_UI_Text_ITextCharacterFormat<D>::SetClone(Windows::UI::Text::ITextCharacterFormat const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextCharacterFormat)->SetClone(get_abi(value)));
}

template <typename D> Windows::UI::Text::ITextCharacterFormat consume_Windows_UI_Text_ITextCharacterFormat<D>::GetClone() const
{
    Windows::UI::Text::ITextCharacterFormat result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextCharacterFormat)->GetClone(put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_UI_Text_ITextCharacterFormat<D>::IsEqual(Windows::UI::Text::ITextCharacterFormat const& format) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextCharacterFormat)->IsEqual(get_abi(format), &result));
    return result;
}

template <typename D> Windows::UI::Color consume_Windows_UI_Text_ITextConstantsStatics<D>::AutoColor() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextConstantsStatics)->get_AutoColor(put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_UI_Text_ITextConstantsStatics<D>::MinUnitCount() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextConstantsStatics)->get_MinUnitCount(&value));
    return value;
}

template <typename D> int32_t consume_Windows_UI_Text_ITextConstantsStatics<D>::MaxUnitCount() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextConstantsStatics)->get_MaxUnitCount(&value));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_Text_ITextConstantsStatics<D>::UndefinedColor() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextConstantsStatics)->get_UndefinedColor(put_abi(value)));
    return value;
}

template <typename D> float consume_Windows_UI_Text_ITextConstantsStatics<D>::UndefinedFloatValue() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextConstantsStatics)->get_UndefinedFloatValue(&value));
    return value;
}

template <typename D> int32_t consume_Windows_UI_Text_ITextConstantsStatics<D>::UndefinedInt32Value() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextConstantsStatics)->get_UndefinedInt32Value(&value));
    return value;
}

template <typename D> Windows::UI::Text::FontStretch consume_Windows_UI_Text_ITextConstantsStatics<D>::UndefinedFontStretch() const
{
    Windows::UI::Text::FontStretch value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextConstantsStatics)->get_UndefinedFontStretch(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Text::FontStyle consume_Windows_UI_Text_ITextConstantsStatics<D>::UndefinedFontStyle() const
{
    Windows::UI::Text::FontStyle value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextConstantsStatics)->get_UndefinedFontStyle(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Text::CaretType consume_Windows_UI_Text_ITextDocument<D>::CaretType() const
{
    Windows::UI::Text::CaretType value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextDocument)->get_CaretType(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Text_ITextDocument<D>::CaretType(Windows::UI::Text::CaretType const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextDocument)->put_CaretType(get_abi(value)));
}

template <typename D> float consume_Windows_UI_Text_ITextDocument<D>::DefaultTabStop() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextDocument)->get_DefaultTabStop(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Text_ITextDocument<D>::DefaultTabStop(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextDocument)->put_DefaultTabStop(value));
}

template <typename D> Windows::UI::Text::ITextSelection consume_Windows_UI_Text_ITextDocument<D>::Selection() const
{
    Windows::UI::Text::ITextSelection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextDocument)->get_Selection(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_UI_Text_ITextDocument<D>::UndoLimit() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextDocument)->get_UndoLimit(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Text_ITextDocument<D>::UndoLimit(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextDocument)->put_UndoLimit(value));
}

template <typename D> bool consume_Windows_UI_Text_ITextDocument<D>::CanCopy() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextDocument)->CanCopy(&result));
    return result;
}

template <typename D> bool consume_Windows_UI_Text_ITextDocument<D>::CanPaste() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextDocument)->CanPaste(&result));
    return result;
}

template <typename D> bool consume_Windows_UI_Text_ITextDocument<D>::CanRedo() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextDocument)->CanRedo(&result));
    return result;
}

template <typename D> bool consume_Windows_UI_Text_ITextDocument<D>::CanUndo() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextDocument)->CanUndo(&result));
    return result;
}

template <typename D> int32_t consume_Windows_UI_Text_ITextDocument<D>::ApplyDisplayUpdates() const
{
    int32_t result{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextDocument)->ApplyDisplayUpdates(&result));
    return result;
}

template <typename D> int32_t consume_Windows_UI_Text_ITextDocument<D>::BatchDisplayUpdates() const
{
    int32_t result{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextDocument)->BatchDisplayUpdates(&result));
    return result;
}

template <typename D> void consume_Windows_UI_Text_ITextDocument<D>::BeginUndoGroup() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextDocument)->BeginUndoGroup());
}

template <typename D> void consume_Windows_UI_Text_ITextDocument<D>::EndUndoGroup() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextDocument)->EndUndoGroup());
}

template <typename D> Windows::UI::Text::ITextCharacterFormat consume_Windows_UI_Text_ITextDocument<D>::GetDefaultCharacterFormat() const
{
    Windows::UI::Text::ITextCharacterFormat result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextDocument)->GetDefaultCharacterFormat(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Text::ITextParagraphFormat consume_Windows_UI_Text_ITextDocument<D>::GetDefaultParagraphFormat() const
{
    Windows::UI::Text::ITextParagraphFormat result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextDocument)->GetDefaultParagraphFormat(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Text::ITextRange consume_Windows_UI_Text_ITextDocument<D>::GetRange(int32_t startPosition, int32_t endPosition) const
{
    Windows::UI::Text::ITextRange result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextDocument)->GetRange(startPosition, endPosition, put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Text::ITextRange consume_Windows_UI_Text_ITextDocument<D>::GetRangeFromPoint(Windows::Foundation::Point const& point, Windows::UI::Text::PointOptions const& options) const
{
    Windows::UI::Text::ITextRange result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextDocument)->GetRangeFromPoint(get_abi(point), get_abi(options), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Text_ITextDocument<D>::GetText(Windows::UI::Text::TextGetOptions const& options, hstring& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextDocument)->GetText(get_abi(options), put_abi(value)));
}

template <typename D> void consume_Windows_UI_Text_ITextDocument<D>::LoadFromStream(Windows::UI::Text::TextSetOptions const& options, Windows::Storage::Streams::IRandomAccessStream const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextDocument)->LoadFromStream(get_abi(options), get_abi(value)));
}

template <typename D> void consume_Windows_UI_Text_ITextDocument<D>::Redo() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextDocument)->Redo());
}

template <typename D> void consume_Windows_UI_Text_ITextDocument<D>::SaveToStream(Windows::UI::Text::TextGetOptions const& options, Windows::Storage::Streams::IRandomAccessStream const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextDocument)->SaveToStream(get_abi(options), get_abi(value)));
}

template <typename D> void consume_Windows_UI_Text_ITextDocument<D>::SetDefaultCharacterFormat(Windows::UI::Text::ITextCharacterFormat const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextDocument)->SetDefaultCharacterFormat(get_abi(value)));
}

template <typename D> void consume_Windows_UI_Text_ITextDocument<D>::SetDefaultParagraphFormat(Windows::UI::Text::ITextParagraphFormat const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextDocument)->SetDefaultParagraphFormat(get_abi(value)));
}

template <typename D> void consume_Windows_UI_Text_ITextDocument<D>::SetText(Windows::UI::Text::TextSetOptions const& options, param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextDocument)->SetText(get_abi(options), get_abi(value)));
}

template <typename D> void consume_Windows_UI_Text_ITextDocument<D>::Undo() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextDocument)->Undo());
}

template <typename D> bool consume_Windows_UI_Text_ITextDocument2<D>::AlignmentIncludesTrailingWhitespace() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextDocument2)->get_AlignmentIncludesTrailingWhitespace(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Text_ITextDocument2<D>::AlignmentIncludesTrailingWhitespace(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextDocument2)->put_AlignmentIncludesTrailingWhitespace(value));
}

template <typename D> bool consume_Windows_UI_Text_ITextDocument2<D>::IgnoreTrailingCharacterSpacing() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextDocument2)->get_IgnoreTrailingCharacterSpacing(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Text_ITextDocument2<D>::IgnoreTrailingCharacterSpacing(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextDocument2)->put_IgnoreTrailingCharacterSpacing(value));
}

template <typename D> void consume_Windows_UI_Text_ITextDocument3<D>::ClearUndoRedoHistory() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextDocument3)->ClearUndoRedoHistory());
}

template <typename D> Windows::UI::Text::ParagraphAlignment consume_Windows_UI_Text_ITextParagraphFormat<D>::Alignment() const
{
    Windows::UI::Text::ParagraphAlignment value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextParagraphFormat)->get_Alignment(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Text_ITextParagraphFormat<D>::Alignment(Windows::UI::Text::ParagraphAlignment const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextParagraphFormat)->put_Alignment(get_abi(value)));
}

template <typename D> float consume_Windows_UI_Text_ITextParagraphFormat<D>::FirstLineIndent() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextParagraphFormat)->get_FirstLineIndent(&value));
    return value;
}

template <typename D> Windows::UI::Text::FormatEffect consume_Windows_UI_Text_ITextParagraphFormat<D>::KeepTogether() const
{
    Windows::UI::Text::FormatEffect value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextParagraphFormat)->get_KeepTogether(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Text_ITextParagraphFormat<D>::KeepTogether(Windows::UI::Text::FormatEffect const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextParagraphFormat)->put_KeepTogether(get_abi(value)));
}

template <typename D> Windows::UI::Text::FormatEffect consume_Windows_UI_Text_ITextParagraphFormat<D>::KeepWithNext() const
{
    Windows::UI::Text::FormatEffect value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextParagraphFormat)->get_KeepWithNext(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Text_ITextParagraphFormat<D>::KeepWithNext(Windows::UI::Text::FormatEffect const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextParagraphFormat)->put_KeepWithNext(get_abi(value)));
}

template <typename D> float consume_Windows_UI_Text_ITextParagraphFormat<D>::LeftIndent() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextParagraphFormat)->get_LeftIndent(&value));
    return value;
}

template <typename D> float consume_Windows_UI_Text_ITextParagraphFormat<D>::LineSpacing() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextParagraphFormat)->get_LineSpacing(&value));
    return value;
}

template <typename D> Windows::UI::Text::LineSpacingRule consume_Windows_UI_Text_ITextParagraphFormat<D>::LineSpacingRule() const
{
    Windows::UI::Text::LineSpacingRule value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextParagraphFormat)->get_LineSpacingRule(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Text::MarkerAlignment consume_Windows_UI_Text_ITextParagraphFormat<D>::ListAlignment() const
{
    Windows::UI::Text::MarkerAlignment value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextParagraphFormat)->get_ListAlignment(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Text_ITextParagraphFormat<D>::ListAlignment(Windows::UI::Text::MarkerAlignment const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextParagraphFormat)->put_ListAlignment(get_abi(value)));
}

template <typename D> int32_t consume_Windows_UI_Text_ITextParagraphFormat<D>::ListLevelIndex() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextParagraphFormat)->get_ListLevelIndex(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Text_ITextParagraphFormat<D>::ListLevelIndex(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextParagraphFormat)->put_ListLevelIndex(value));
}

template <typename D> int32_t consume_Windows_UI_Text_ITextParagraphFormat<D>::ListStart() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextParagraphFormat)->get_ListStart(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Text_ITextParagraphFormat<D>::ListStart(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextParagraphFormat)->put_ListStart(value));
}

template <typename D> Windows::UI::Text::MarkerStyle consume_Windows_UI_Text_ITextParagraphFormat<D>::ListStyle() const
{
    Windows::UI::Text::MarkerStyle value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextParagraphFormat)->get_ListStyle(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Text_ITextParagraphFormat<D>::ListStyle(Windows::UI::Text::MarkerStyle const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextParagraphFormat)->put_ListStyle(get_abi(value)));
}

template <typename D> float consume_Windows_UI_Text_ITextParagraphFormat<D>::ListTab() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextParagraphFormat)->get_ListTab(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Text_ITextParagraphFormat<D>::ListTab(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextParagraphFormat)->put_ListTab(value));
}

template <typename D> Windows::UI::Text::MarkerType consume_Windows_UI_Text_ITextParagraphFormat<D>::ListType() const
{
    Windows::UI::Text::MarkerType value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextParagraphFormat)->get_ListType(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Text_ITextParagraphFormat<D>::ListType(Windows::UI::Text::MarkerType const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextParagraphFormat)->put_ListType(get_abi(value)));
}

template <typename D> Windows::UI::Text::FormatEffect consume_Windows_UI_Text_ITextParagraphFormat<D>::NoLineNumber() const
{
    Windows::UI::Text::FormatEffect value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextParagraphFormat)->get_NoLineNumber(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Text_ITextParagraphFormat<D>::NoLineNumber(Windows::UI::Text::FormatEffect const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextParagraphFormat)->put_NoLineNumber(get_abi(value)));
}

template <typename D> Windows::UI::Text::FormatEffect consume_Windows_UI_Text_ITextParagraphFormat<D>::PageBreakBefore() const
{
    Windows::UI::Text::FormatEffect value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextParagraphFormat)->get_PageBreakBefore(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Text_ITextParagraphFormat<D>::PageBreakBefore(Windows::UI::Text::FormatEffect const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextParagraphFormat)->put_PageBreakBefore(get_abi(value)));
}

template <typename D> float consume_Windows_UI_Text_ITextParagraphFormat<D>::RightIndent() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextParagraphFormat)->get_RightIndent(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Text_ITextParagraphFormat<D>::RightIndent(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextParagraphFormat)->put_RightIndent(value));
}

template <typename D> Windows::UI::Text::FormatEffect consume_Windows_UI_Text_ITextParagraphFormat<D>::RightToLeft() const
{
    Windows::UI::Text::FormatEffect value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextParagraphFormat)->get_RightToLeft(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Text_ITextParagraphFormat<D>::RightToLeft(Windows::UI::Text::FormatEffect const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextParagraphFormat)->put_RightToLeft(get_abi(value)));
}

template <typename D> Windows::UI::Text::ParagraphStyle consume_Windows_UI_Text_ITextParagraphFormat<D>::Style() const
{
    Windows::UI::Text::ParagraphStyle value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextParagraphFormat)->get_Style(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Text_ITextParagraphFormat<D>::Style(Windows::UI::Text::ParagraphStyle const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextParagraphFormat)->put_Style(get_abi(value)));
}

template <typename D> float consume_Windows_UI_Text_ITextParagraphFormat<D>::SpaceAfter() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextParagraphFormat)->get_SpaceAfter(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Text_ITextParagraphFormat<D>::SpaceAfter(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextParagraphFormat)->put_SpaceAfter(value));
}

template <typename D> float consume_Windows_UI_Text_ITextParagraphFormat<D>::SpaceBefore() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextParagraphFormat)->get_SpaceBefore(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Text_ITextParagraphFormat<D>::SpaceBefore(float value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextParagraphFormat)->put_SpaceBefore(value));
}

template <typename D> Windows::UI::Text::FormatEffect consume_Windows_UI_Text_ITextParagraphFormat<D>::WidowControl() const
{
    Windows::UI::Text::FormatEffect value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextParagraphFormat)->get_WidowControl(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Text_ITextParagraphFormat<D>::WidowControl(Windows::UI::Text::FormatEffect const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextParagraphFormat)->put_WidowControl(get_abi(value)));
}

template <typename D> int32_t consume_Windows_UI_Text_ITextParagraphFormat<D>::TabCount() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextParagraphFormat)->get_TabCount(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Text_ITextParagraphFormat<D>::AddTab(float position, Windows::UI::Text::TabAlignment const& align, Windows::UI::Text::TabLeader const& leader) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextParagraphFormat)->AddTab(position, get_abi(align), get_abi(leader)));
}

template <typename D> void consume_Windows_UI_Text_ITextParagraphFormat<D>::ClearAllTabs() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextParagraphFormat)->ClearAllTabs());
}

template <typename D> void consume_Windows_UI_Text_ITextParagraphFormat<D>::DeleteTab(float position) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextParagraphFormat)->DeleteTab(position));
}

template <typename D> Windows::UI::Text::ITextParagraphFormat consume_Windows_UI_Text_ITextParagraphFormat<D>::GetClone() const
{
    Windows::UI::Text::ITextParagraphFormat result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextParagraphFormat)->GetClone(put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Text_ITextParagraphFormat<D>::GetTab(int32_t index, float& position, Windows::UI::Text::TabAlignment& align, Windows::UI::Text::TabLeader& leader) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextParagraphFormat)->GetTab(index, &position, put_abi(align), put_abi(leader)));
}

template <typename D> bool consume_Windows_UI_Text_ITextParagraphFormat<D>::IsEqual(Windows::UI::Text::ITextParagraphFormat const& format) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextParagraphFormat)->IsEqual(get_abi(format), &result));
    return result;
}

template <typename D> void consume_Windows_UI_Text_ITextParagraphFormat<D>::SetClone(Windows::UI::Text::ITextParagraphFormat const& format) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextParagraphFormat)->SetClone(get_abi(format)));
}

template <typename D> void consume_Windows_UI_Text_ITextParagraphFormat<D>::SetIndents(float start, float left, float right) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextParagraphFormat)->SetIndents(start, left, right));
}

template <typename D> void consume_Windows_UI_Text_ITextParagraphFormat<D>::SetLineSpacing(Windows::UI::Text::LineSpacingRule const& rule, float spacing) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextParagraphFormat)->SetLineSpacing(get_abi(rule), spacing));
}

template <typename D> char16_t consume_Windows_UI_Text_ITextRange<D>::Character() const
{
    char16_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextRange)->get_Character(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Text_ITextRange<D>::Character(char16_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextRange)->put_Character(value));
}

template <typename D> Windows::UI::Text::ITextCharacterFormat consume_Windows_UI_Text_ITextRange<D>::CharacterFormat() const
{
    Windows::UI::Text::ITextCharacterFormat value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextRange)->get_CharacterFormat(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Text_ITextRange<D>::CharacterFormat(Windows::UI::Text::ITextCharacterFormat const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextRange)->put_CharacterFormat(get_abi(value)));
}

template <typename D> Windows::UI::Text::ITextRange consume_Windows_UI_Text_ITextRange<D>::FormattedText() const
{
    Windows::UI::Text::ITextRange value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextRange)->get_FormattedText(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Text_ITextRange<D>::FormattedText(Windows::UI::Text::ITextRange const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextRange)->put_FormattedText(get_abi(value)));
}

template <typename D> int32_t consume_Windows_UI_Text_ITextRange<D>::EndPosition() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextRange)->get_EndPosition(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Text_ITextRange<D>::EndPosition(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextRange)->put_EndPosition(value));
}

template <typename D> Windows::UI::Text::RangeGravity consume_Windows_UI_Text_ITextRange<D>::Gravity() const
{
    Windows::UI::Text::RangeGravity value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextRange)->get_Gravity(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Text_ITextRange<D>::Gravity(Windows::UI::Text::RangeGravity const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextRange)->put_Gravity(get_abi(value)));
}

template <typename D> int32_t consume_Windows_UI_Text_ITextRange<D>::Length() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextRange)->get_Length(&value));
    return value;
}

template <typename D> hstring consume_Windows_UI_Text_ITextRange<D>::Link() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextRange)->get_Link(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Text_ITextRange<D>::Link(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextRange)->put_Link(get_abi(value)));
}

template <typename D> Windows::UI::Text::ITextParagraphFormat consume_Windows_UI_Text_ITextRange<D>::ParagraphFormat() const
{
    Windows::UI::Text::ITextParagraphFormat value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextRange)->get_ParagraphFormat(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Text_ITextRange<D>::ParagraphFormat(Windows::UI::Text::ITextParagraphFormat const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextRange)->put_ParagraphFormat(get_abi(value)));
}

template <typename D> int32_t consume_Windows_UI_Text_ITextRange<D>::StartPosition() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextRange)->get_StartPosition(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Text_ITextRange<D>::StartPosition(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextRange)->put_StartPosition(value));
}

template <typename D> int32_t consume_Windows_UI_Text_ITextRange<D>::StoryLength() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextRange)->get_StoryLength(&value));
    return value;
}

template <typename D> hstring consume_Windows_UI_Text_ITextRange<D>::Text() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextRange)->get_Text(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Text_ITextRange<D>::Text(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextRange)->put_Text(get_abi(value)));
}

template <typename D> bool consume_Windows_UI_Text_ITextRange<D>::CanPaste(int32_t format) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextRange)->CanPaste(format, &result));
    return result;
}

template <typename D> void consume_Windows_UI_Text_ITextRange<D>::ChangeCase(Windows::UI::Text::LetterCase const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextRange)->ChangeCase(get_abi(value)));
}

template <typename D> void consume_Windows_UI_Text_ITextRange<D>::Collapse(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextRange)->Collapse(value));
}

template <typename D> void consume_Windows_UI_Text_ITextRange<D>::Copy() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextRange)->Copy());
}

template <typename D> void consume_Windows_UI_Text_ITextRange<D>::Cut() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextRange)->Cut());
}

template <typename D> int32_t consume_Windows_UI_Text_ITextRange<D>::Delete(Windows::UI::Text::TextRangeUnit const& unit, int32_t count) const
{
    int32_t result{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextRange)->Delete(get_abi(unit), count, &result));
    return result;
}

template <typename D> int32_t consume_Windows_UI_Text_ITextRange<D>::EndOf(Windows::UI::Text::TextRangeUnit const& unit, bool extend) const
{
    int32_t result{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextRange)->EndOf(get_abi(unit), extend, &result));
    return result;
}

template <typename D> int32_t consume_Windows_UI_Text_ITextRange<D>::Expand(Windows::UI::Text::TextRangeUnit const& unit) const
{
    int32_t result{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextRange)->Expand(get_abi(unit), &result));
    return result;
}

template <typename D> int32_t consume_Windows_UI_Text_ITextRange<D>::FindText(param::hstring const& value, int32_t scanLength, Windows::UI::Text::FindOptions const& options) const
{
    int32_t result{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextRange)->FindText(get_abi(value), scanLength, get_abi(options), &result));
    return result;
}

template <typename D> void consume_Windows_UI_Text_ITextRange<D>::GetCharacterUtf32(uint32_t& value, int32_t offset) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextRange)->GetCharacterUtf32(&value, offset));
}

template <typename D> Windows::UI::Text::ITextRange consume_Windows_UI_Text_ITextRange<D>::GetClone() const
{
    Windows::UI::Text::ITextRange result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextRange)->GetClone(put_abi(result)));
    return result;
}

template <typename D> int32_t consume_Windows_UI_Text_ITextRange<D>::GetIndex(Windows::UI::Text::TextRangeUnit const& unit) const
{
    int32_t result{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextRange)->GetIndex(get_abi(unit), &result));
    return result;
}

template <typename D> void consume_Windows_UI_Text_ITextRange<D>::GetPoint(Windows::UI::Text::HorizontalCharacterAlignment const& horizontalAlign, Windows::UI::Text::VerticalCharacterAlignment const& verticalAlign, Windows::UI::Text::PointOptions const& options, Windows::Foundation::Point& point) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextRange)->GetPoint(get_abi(horizontalAlign), get_abi(verticalAlign), get_abi(options), put_abi(point)));
}

template <typename D> void consume_Windows_UI_Text_ITextRange<D>::GetRect(Windows::UI::Text::PointOptions const& options, Windows::Foundation::Rect& rect, int32_t& hit) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextRange)->GetRect(get_abi(options), put_abi(rect), &hit));
}

template <typename D> void consume_Windows_UI_Text_ITextRange<D>::GetText(Windows::UI::Text::TextGetOptions const& options, hstring& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextRange)->GetText(get_abi(options), put_abi(value)));
}

template <typename D> void consume_Windows_UI_Text_ITextRange<D>::GetTextViaStream(Windows::UI::Text::TextGetOptions const& options, Windows::Storage::Streams::IRandomAccessStream const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextRange)->GetTextViaStream(get_abi(options), get_abi(value)));
}

template <typename D> bool consume_Windows_UI_Text_ITextRange<D>::InRange(Windows::UI::Text::ITextRange const& range) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextRange)->InRange(get_abi(range), &result));
    return result;
}

template <typename D> void consume_Windows_UI_Text_ITextRange<D>::InsertImage(int32_t width, int32_t height, int32_t ascent, Windows::UI::Text::VerticalCharacterAlignment const& verticalAlign, param::hstring const& alternateText, Windows::Storage::Streams::IRandomAccessStream const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextRange)->InsertImage(width, height, ascent, get_abi(verticalAlign), get_abi(alternateText), get_abi(value)));
}

template <typename D> bool consume_Windows_UI_Text_ITextRange<D>::InStory(Windows::UI::Text::ITextRange const& range) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextRange)->InStory(get_abi(range), &result));
    return result;
}

template <typename D> bool consume_Windows_UI_Text_ITextRange<D>::IsEqual(Windows::UI::Text::ITextRange const& range) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextRange)->IsEqual(get_abi(range), &result));
    return result;
}

template <typename D> int32_t consume_Windows_UI_Text_ITextRange<D>::Move(Windows::UI::Text::TextRangeUnit const& unit, int32_t count) const
{
    int32_t result{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextRange)->Move(get_abi(unit), count, &result));
    return result;
}

template <typename D> int32_t consume_Windows_UI_Text_ITextRange<D>::MoveEnd(Windows::UI::Text::TextRangeUnit const& unit, int32_t count) const
{
    int32_t result{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextRange)->MoveEnd(get_abi(unit), count, &result));
    return result;
}

template <typename D> int32_t consume_Windows_UI_Text_ITextRange<D>::MoveStart(Windows::UI::Text::TextRangeUnit const& unit, int32_t count) const
{
    int32_t result{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextRange)->MoveStart(get_abi(unit), count, &result));
    return result;
}

template <typename D> void consume_Windows_UI_Text_ITextRange<D>::Paste(int32_t format) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextRange)->Paste(format));
}

template <typename D> void consume_Windows_UI_Text_ITextRange<D>::ScrollIntoView(Windows::UI::Text::PointOptions const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextRange)->ScrollIntoView(get_abi(value)));
}

template <typename D> void consume_Windows_UI_Text_ITextRange<D>::MatchSelection() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextRange)->MatchSelection());
}

template <typename D> void consume_Windows_UI_Text_ITextRange<D>::SetIndex(Windows::UI::Text::TextRangeUnit const& unit, int32_t index, bool extend) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextRange)->SetIndex(get_abi(unit), index, extend));
}

template <typename D> void consume_Windows_UI_Text_ITextRange<D>::SetPoint(Windows::Foundation::Point const& point, Windows::UI::Text::PointOptions const& options, bool extend) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextRange)->SetPoint(get_abi(point), get_abi(options), extend));
}

template <typename D> void consume_Windows_UI_Text_ITextRange<D>::SetRange(int32_t startPosition, int32_t endPosition) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextRange)->SetRange(startPosition, endPosition));
}

template <typename D> void consume_Windows_UI_Text_ITextRange<D>::SetText(Windows::UI::Text::TextSetOptions const& options, param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextRange)->SetText(get_abi(options), get_abi(value)));
}

template <typename D> void consume_Windows_UI_Text_ITextRange<D>::SetTextViaStream(Windows::UI::Text::TextSetOptions const& options, Windows::Storage::Streams::IRandomAccessStream const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextRange)->SetTextViaStream(get_abi(options), get_abi(value)));
}

template <typename D> int32_t consume_Windows_UI_Text_ITextRange<D>::StartOf(Windows::UI::Text::TextRangeUnit const& unit, bool extend) const
{
    int32_t result{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextRange)->StartOf(get_abi(unit), extend, &result));
    return result;
}

template <typename D> Windows::UI::Text::SelectionOptions consume_Windows_UI_Text_ITextSelection<D>::Options() const
{
    Windows::UI::Text::SelectionOptions value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextSelection)->get_Options(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Text_ITextSelection<D>::Options(Windows::UI::Text::SelectionOptions const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextSelection)->put_Options(get_abi(value)));
}

template <typename D> Windows::UI::Text::SelectionType consume_Windows_UI_Text_ITextSelection<D>::Type() const
{
    Windows::UI::Text::SelectionType value{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextSelection)->get_Type(put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_UI_Text_ITextSelection<D>::EndKey(Windows::UI::Text::TextRangeUnit const& unit, bool extend) const
{
    int32_t result{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextSelection)->EndKey(get_abi(unit), extend, &result));
    return result;
}

template <typename D> int32_t consume_Windows_UI_Text_ITextSelection<D>::HomeKey(Windows::UI::Text::TextRangeUnit const& unit, bool extend) const
{
    int32_t result{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextSelection)->HomeKey(get_abi(unit), extend, &result));
    return result;
}

template <typename D> int32_t consume_Windows_UI_Text_ITextSelection<D>::MoveDown(Windows::UI::Text::TextRangeUnit const& unit, int32_t count, bool extend) const
{
    int32_t result{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextSelection)->MoveDown(get_abi(unit), count, extend, &result));
    return result;
}

template <typename D> int32_t consume_Windows_UI_Text_ITextSelection<D>::MoveLeft(Windows::UI::Text::TextRangeUnit const& unit, int32_t count, bool extend) const
{
    int32_t result{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextSelection)->MoveLeft(get_abi(unit), count, extend, &result));
    return result;
}

template <typename D> int32_t consume_Windows_UI_Text_ITextSelection<D>::MoveRight(Windows::UI::Text::TextRangeUnit const& unit, int32_t count, bool extend) const
{
    int32_t result{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextSelection)->MoveRight(get_abi(unit), count, extend, &result));
    return result;
}

template <typename D> int32_t consume_Windows_UI_Text_ITextSelection<D>::MoveUp(Windows::UI::Text::TextRangeUnit const& unit, int32_t count, bool extend) const
{
    int32_t result{};
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextSelection)->MoveUp(get_abi(unit), count, extend, &result));
    return result;
}

template <typename D> void consume_Windows_UI_Text_ITextSelection<D>::TypeText(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Text::ITextSelection)->TypeText(get_abi(value)));
}

template <typename D>
struct produce<D, Windows::UI::Text::IContentLinkInfo> : produce_base<D, Windows::UI::Text::IContentLinkInfo>
{
    int32_t WINRT_CALL get_Id(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Id, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Id(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Id, WINRT_WRAP(void), uint32_t);
            this->shim().Id(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DisplayText(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayText, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DisplayText());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DisplayText(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayText, WINRT_WRAP(void), hstring const&);
            this->shim().DisplayText(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SecondaryText(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SecondaryText, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SecondaryText());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SecondaryText(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SecondaryText, WINRT_WRAP(void), hstring const&);
            this->shim().SecondaryText(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Uri(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Uri, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().Uri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Uri(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Uri, WINRT_WRAP(void), Windows::Foundation::Uri const&);
            this->shim().Uri(*reinterpret_cast<Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LinkContentKind(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LinkContentKind, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().LinkContentKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_LinkContentKind(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LinkContentKind, WINRT_WRAP(void), hstring const&);
            this->shim().LinkContentKind(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Text::IFontWeights> : produce_base<D, Windows::UI::Text::IFontWeights>
{};

template <typename D>
struct produce<D, Windows::UI::Text::IFontWeightsStatics> : produce_base<D, Windows::UI::Text::IFontWeightsStatics>
{
    int32_t WINRT_CALL get_Black(struct struct_Windows_UI_Text_FontWeight* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Black, WINRT_WRAP(Windows::UI::Text::FontWeight));
            *value = detach_from<Windows::UI::Text::FontWeight>(this->shim().Black());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Bold(struct struct_Windows_UI_Text_FontWeight* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Bold, WINRT_WRAP(Windows::UI::Text::FontWeight));
            *value = detach_from<Windows::UI::Text::FontWeight>(this->shim().Bold());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExtraBlack(struct struct_Windows_UI_Text_FontWeight* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExtraBlack, WINRT_WRAP(Windows::UI::Text::FontWeight));
            *value = detach_from<Windows::UI::Text::FontWeight>(this->shim().ExtraBlack());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExtraBold(struct struct_Windows_UI_Text_FontWeight* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExtraBold, WINRT_WRAP(Windows::UI::Text::FontWeight));
            *value = detach_from<Windows::UI::Text::FontWeight>(this->shim().ExtraBold());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExtraLight(struct struct_Windows_UI_Text_FontWeight* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExtraLight, WINRT_WRAP(Windows::UI::Text::FontWeight));
            *value = detach_from<Windows::UI::Text::FontWeight>(this->shim().ExtraLight());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Light(struct struct_Windows_UI_Text_FontWeight* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Light, WINRT_WRAP(Windows::UI::Text::FontWeight));
            *value = detach_from<Windows::UI::Text::FontWeight>(this->shim().Light());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Medium(struct struct_Windows_UI_Text_FontWeight* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Medium, WINRT_WRAP(Windows::UI::Text::FontWeight));
            *value = detach_from<Windows::UI::Text::FontWeight>(this->shim().Medium());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Normal(struct struct_Windows_UI_Text_FontWeight* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Normal, WINRT_WRAP(Windows::UI::Text::FontWeight));
            *value = detach_from<Windows::UI::Text::FontWeight>(this->shim().Normal());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SemiBold(struct struct_Windows_UI_Text_FontWeight* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SemiBold, WINRT_WRAP(Windows::UI::Text::FontWeight));
            *value = detach_from<Windows::UI::Text::FontWeight>(this->shim().SemiBold());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SemiLight(struct struct_Windows_UI_Text_FontWeight* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SemiLight, WINRT_WRAP(Windows::UI::Text::FontWeight));
            *value = detach_from<Windows::UI::Text::FontWeight>(this->shim().SemiLight());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Thin(struct struct_Windows_UI_Text_FontWeight* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Thin, WINRT_WRAP(Windows::UI::Text::FontWeight));
            *value = detach_from<Windows::UI::Text::FontWeight>(this->shim().Thin());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Text::IRichEditTextRange> : produce_base<D, Windows::UI::Text::IRichEditTextRange>
{
    int32_t WINRT_CALL get_ContentLinkInfo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentLinkInfo, WINRT_WRAP(Windows::UI::Text::ContentLinkInfo));
            *value = detach_from<Windows::UI::Text::ContentLinkInfo>(this->shim().ContentLinkInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ContentLinkInfo(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentLinkInfo, WINRT_WRAP(void), Windows::UI::Text::ContentLinkInfo const&);
            this->shim().ContentLinkInfo(*reinterpret_cast<Windows::UI::Text::ContentLinkInfo const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Text::ITextCharacterFormat> : produce_base<D, Windows::UI::Text::ITextCharacterFormat>
{
    int32_t WINRT_CALL get_AllCaps(Windows::UI::Text::FormatEffect* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllCaps, WINRT_WRAP(Windows::UI::Text::FormatEffect));
            *value = detach_from<Windows::UI::Text::FormatEffect>(this->shim().AllCaps());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AllCaps(Windows::UI::Text::FormatEffect value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllCaps, WINRT_WRAP(void), Windows::UI::Text::FormatEffect const&);
            this->shim().AllCaps(*reinterpret_cast<Windows::UI::Text::FormatEffect const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BackgroundColor(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BackgroundColor, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().BackgroundColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_BackgroundColor(struct struct_Windows_UI_Color value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BackgroundColor, WINRT_WRAP(void), Windows::UI::Color const&);
            this->shim().BackgroundColor(*reinterpret_cast<Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Bold(Windows::UI::Text::FormatEffect* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Bold, WINRT_WRAP(Windows::UI::Text::FormatEffect));
            *value = detach_from<Windows::UI::Text::FormatEffect>(this->shim().Bold());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Bold(Windows::UI::Text::FormatEffect value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Bold, WINRT_WRAP(void), Windows::UI::Text::FormatEffect const&);
            this->shim().Bold(*reinterpret_cast<Windows::UI::Text::FormatEffect const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FontStretch(Windows::UI::Text::FontStretch* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FontStretch, WINRT_WRAP(Windows::UI::Text::FontStretch));
            *value = detach_from<Windows::UI::Text::FontStretch>(this->shim().FontStretch());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FontStretch(Windows::UI::Text::FontStretch value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FontStretch, WINRT_WRAP(void), Windows::UI::Text::FontStretch const&);
            this->shim().FontStretch(*reinterpret_cast<Windows::UI::Text::FontStretch const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FontStyle(Windows::UI::Text::FontStyle* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FontStyle, WINRT_WRAP(Windows::UI::Text::FontStyle));
            *value = detach_from<Windows::UI::Text::FontStyle>(this->shim().FontStyle());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FontStyle(Windows::UI::Text::FontStyle value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FontStyle, WINRT_WRAP(void), Windows::UI::Text::FontStyle const&);
            this->shim().FontStyle(*reinterpret_cast<Windows::UI::Text::FontStyle const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ForegroundColor(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ForegroundColor, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().ForegroundColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ForegroundColor(struct struct_Windows_UI_Color value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ForegroundColor, WINRT_WRAP(void), Windows::UI::Color const&);
            this->shim().ForegroundColor(*reinterpret_cast<Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Hidden(Windows::UI::Text::FormatEffect* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Hidden, WINRT_WRAP(Windows::UI::Text::FormatEffect));
            *value = detach_from<Windows::UI::Text::FormatEffect>(this->shim().Hidden());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Hidden(Windows::UI::Text::FormatEffect value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Hidden, WINRT_WRAP(void), Windows::UI::Text::FormatEffect const&);
            this->shim().Hidden(*reinterpret_cast<Windows::UI::Text::FormatEffect const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Italic(Windows::UI::Text::FormatEffect* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Italic, WINRT_WRAP(Windows::UI::Text::FormatEffect));
            *value = detach_from<Windows::UI::Text::FormatEffect>(this->shim().Italic());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Italic(Windows::UI::Text::FormatEffect value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Italic, WINRT_WRAP(void), Windows::UI::Text::FormatEffect const&);
            this->shim().Italic(*reinterpret_cast<Windows::UI::Text::FormatEffect const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Kerning(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Kerning, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().Kerning());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Kerning(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Kerning, WINRT_WRAP(void), float);
            this->shim().Kerning(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LanguageTag(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LanguageTag, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().LanguageTag());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_LanguageTag(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LanguageTag, WINRT_WRAP(void), hstring const&);
            this->shim().LanguageTag(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LinkType(Windows::UI::Text::LinkType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LinkType, WINRT_WRAP(Windows::UI::Text::LinkType));
            *value = detach_from<Windows::UI::Text::LinkType>(this->shim().LinkType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Name(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Name, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Name(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Name, WINRT_WRAP(void), hstring const&);
            this->shim().Name(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Outline(Windows::UI::Text::FormatEffect* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Outline, WINRT_WRAP(Windows::UI::Text::FormatEffect));
            *value = detach_from<Windows::UI::Text::FormatEffect>(this->shim().Outline());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Outline(Windows::UI::Text::FormatEffect value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Outline, WINRT_WRAP(void), Windows::UI::Text::FormatEffect const&);
            this->shim().Outline(*reinterpret_cast<Windows::UI::Text::FormatEffect const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Position(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Position, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Position(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Position, WINRT_WRAP(void), float);
            this->shim().Position(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProtectedText(Windows::UI::Text::FormatEffect* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProtectedText, WINRT_WRAP(Windows::UI::Text::FormatEffect));
            *value = detach_from<Windows::UI::Text::FormatEffect>(this->shim().ProtectedText());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ProtectedText(Windows::UI::Text::FormatEffect value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProtectedText, WINRT_WRAP(void), Windows::UI::Text::FormatEffect const&);
            this->shim().ProtectedText(*reinterpret_cast<Windows::UI::Text::FormatEffect const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Size(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Size, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().Size());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Size(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Size, WINRT_WRAP(void), float);
            this->shim().Size(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SmallCaps(Windows::UI::Text::FormatEffect* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SmallCaps, WINRT_WRAP(Windows::UI::Text::FormatEffect));
            *value = detach_from<Windows::UI::Text::FormatEffect>(this->shim().SmallCaps());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SmallCaps(Windows::UI::Text::FormatEffect value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SmallCaps, WINRT_WRAP(void), Windows::UI::Text::FormatEffect const&);
            this->shim().SmallCaps(*reinterpret_cast<Windows::UI::Text::FormatEffect const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Spacing(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Spacing, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().Spacing());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Spacing(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Spacing, WINRT_WRAP(void), float);
            this->shim().Spacing(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Strikethrough(Windows::UI::Text::FormatEffect* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Strikethrough, WINRT_WRAP(Windows::UI::Text::FormatEffect));
            *value = detach_from<Windows::UI::Text::FormatEffect>(this->shim().Strikethrough());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Strikethrough(Windows::UI::Text::FormatEffect value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Strikethrough, WINRT_WRAP(void), Windows::UI::Text::FormatEffect const&);
            this->shim().Strikethrough(*reinterpret_cast<Windows::UI::Text::FormatEffect const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Subscript(Windows::UI::Text::FormatEffect* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Subscript, WINRT_WRAP(Windows::UI::Text::FormatEffect));
            *value = detach_from<Windows::UI::Text::FormatEffect>(this->shim().Subscript());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Subscript(Windows::UI::Text::FormatEffect value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Subscript, WINRT_WRAP(void), Windows::UI::Text::FormatEffect const&);
            this->shim().Subscript(*reinterpret_cast<Windows::UI::Text::FormatEffect const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Superscript(Windows::UI::Text::FormatEffect* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Superscript, WINRT_WRAP(Windows::UI::Text::FormatEffect));
            *value = detach_from<Windows::UI::Text::FormatEffect>(this->shim().Superscript());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Superscript(Windows::UI::Text::FormatEffect value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Superscript, WINRT_WRAP(void), Windows::UI::Text::FormatEffect const&);
            this->shim().Superscript(*reinterpret_cast<Windows::UI::Text::FormatEffect const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TextScript(Windows::UI::Text::TextScript* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TextScript, WINRT_WRAP(Windows::UI::Text::TextScript));
            *value = detach_from<Windows::UI::Text::TextScript>(this->shim().TextScript());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TextScript(Windows::UI::Text::TextScript value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TextScript, WINRT_WRAP(void), Windows::UI::Text::TextScript const&);
            this->shim().TextScript(*reinterpret_cast<Windows::UI::Text::TextScript const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Underline(Windows::UI::Text::UnderlineType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Underline, WINRT_WRAP(Windows::UI::Text::UnderlineType));
            *value = detach_from<Windows::UI::Text::UnderlineType>(this->shim().Underline());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Underline(Windows::UI::Text::UnderlineType value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Underline, WINRT_WRAP(void), Windows::UI::Text::UnderlineType const&);
            this->shim().Underline(*reinterpret_cast<Windows::UI::Text::UnderlineType const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Weight(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Weight, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().Weight());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Weight(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Weight, WINRT_WRAP(void), int32_t);
            this->shim().Weight(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetClone(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetClone, WINRT_WRAP(void), Windows::UI::Text::ITextCharacterFormat const&);
            this->shim().SetClone(*reinterpret_cast<Windows::UI::Text::ITextCharacterFormat const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetClone(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetClone, WINRT_WRAP(Windows::UI::Text::ITextCharacterFormat));
            *result = detach_from<Windows::UI::Text::ITextCharacterFormat>(this->shim().GetClone());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsEqual(void* format, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsEqual, WINRT_WRAP(bool), Windows::UI::Text::ITextCharacterFormat const&);
            *result = detach_from<bool>(this->shim().IsEqual(*reinterpret_cast<Windows::UI::Text::ITextCharacterFormat const*>(&format)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Text::ITextConstantsStatics> : produce_base<D, Windows::UI::Text::ITextConstantsStatics>
{
    int32_t WINRT_CALL get_AutoColor(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AutoColor, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().AutoColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MinUnitCount(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinUnitCount, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().MinUnitCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxUnitCount(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxUnitCount, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().MaxUnitCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UndefinedColor(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UndefinedColor, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().UndefinedColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UndefinedFloatValue(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UndefinedFloatValue, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().UndefinedFloatValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UndefinedInt32Value(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UndefinedInt32Value, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().UndefinedInt32Value());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UndefinedFontStretch(Windows::UI::Text::FontStretch* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UndefinedFontStretch, WINRT_WRAP(Windows::UI::Text::FontStretch));
            *value = detach_from<Windows::UI::Text::FontStretch>(this->shim().UndefinedFontStretch());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UndefinedFontStyle(Windows::UI::Text::FontStyle* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UndefinedFontStyle, WINRT_WRAP(Windows::UI::Text::FontStyle));
            *value = detach_from<Windows::UI::Text::FontStyle>(this->shim().UndefinedFontStyle());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Text::ITextDocument> : produce_base<D, Windows::UI::Text::ITextDocument>
{
    int32_t WINRT_CALL get_CaretType(Windows::UI::Text::CaretType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CaretType, WINRT_WRAP(Windows::UI::Text::CaretType));
            *value = detach_from<Windows::UI::Text::CaretType>(this->shim().CaretType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CaretType(Windows::UI::Text::CaretType value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CaretType, WINRT_WRAP(void), Windows::UI::Text::CaretType const&);
            this->shim().CaretType(*reinterpret_cast<Windows::UI::Text::CaretType const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DefaultTabStop(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DefaultTabStop, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().DefaultTabStop());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DefaultTabStop(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DefaultTabStop, WINRT_WRAP(void), float);
            this->shim().DefaultTabStop(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Selection(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Selection, WINRT_WRAP(Windows::UI::Text::ITextSelection));
            *value = detach_from<Windows::UI::Text::ITextSelection>(this->shim().Selection());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UndoLimit(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UndoLimit, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().UndoLimit());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_UndoLimit(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UndoLimit, WINRT_WRAP(void), uint32_t);
            this->shim().UndoLimit(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CanCopy(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanCopy, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().CanCopy());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CanPaste(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanPaste, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().CanPaste());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CanRedo(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanRedo, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().CanRedo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CanUndo(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanUndo, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().CanUndo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ApplyDisplayUpdates(int32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ApplyDisplayUpdates, WINRT_WRAP(int32_t));
            *result = detach_from<int32_t>(this->shim().ApplyDisplayUpdates());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL BatchDisplayUpdates(int32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BatchDisplayUpdates, WINRT_WRAP(int32_t));
            *result = detach_from<int32_t>(this->shim().BatchDisplayUpdates());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL BeginUndoGroup() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BeginUndoGroup, WINRT_WRAP(void));
            this->shim().BeginUndoGroup();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL EndUndoGroup() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EndUndoGroup, WINRT_WRAP(void));
            this->shim().EndUndoGroup();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDefaultCharacterFormat(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefaultCharacterFormat, WINRT_WRAP(Windows::UI::Text::ITextCharacterFormat));
            *result = detach_from<Windows::UI::Text::ITextCharacterFormat>(this->shim().GetDefaultCharacterFormat());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDefaultParagraphFormat(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefaultParagraphFormat, WINRT_WRAP(Windows::UI::Text::ITextParagraphFormat));
            *result = detach_from<Windows::UI::Text::ITextParagraphFormat>(this->shim().GetDefaultParagraphFormat());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetRange(int32_t startPosition, int32_t endPosition, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetRange, WINRT_WRAP(Windows::UI::Text::ITextRange), int32_t, int32_t);
            *result = detach_from<Windows::UI::Text::ITextRange>(this->shim().GetRange(startPosition, endPosition));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetRangeFromPoint(Windows::Foundation::Point point, Windows::UI::Text::PointOptions options, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetRangeFromPoint, WINRT_WRAP(Windows::UI::Text::ITextRange), Windows::Foundation::Point const&, Windows::UI::Text::PointOptions const&);
            *result = detach_from<Windows::UI::Text::ITextRange>(this->shim().GetRangeFromPoint(*reinterpret_cast<Windows::Foundation::Point const*>(&point), *reinterpret_cast<Windows::UI::Text::PointOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetText(Windows::UI::Text::TextGetOptions options, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetText, WINRT_WRAP(void), Windows::UI::Text::TextGetOptions const&, hstring&);
            this->shim().GetText(*reinterpret_cast<Windows::UI::Text::TextGetOptions const*>(&options), *reinterpret_cast<hstring*>(value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL LoadFromStream(Windows::UI::Text::TextSetOptions options, void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LoadFromStream, WINRT_WRAP(void), Windows::UI::Text::TextSetOptions const&, Windows::Storage::Streams::IRandomAccessStream const&);
            this->shim().LoadFromStream(*reinterpret_cast<Windows::UI::Text::TextSetOptions const*>(&options), *reinterpret_cast<Windows::Storage::Streams::IRandomAccessStream const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Redo() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Redo, WINRT_WRAP(void));
            this->shim().Redo();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SaveToStream(Windows::UI::Text::TextGetOptions options, void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SaveToStream, WINRT_WRAP(void), Windows::UI::Text::TextGetOptions const&, Windows::Storage::Streams::IRandomAccessStream const&);
            this->shim().SaveToStream(*reinterpret_cast<Windows::UI::Text::TextGetOptions const*>(&options), *reinterpret_cast<Windows::Storage::Streams::IRandomAccessStream const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetDefaultCharacterFormat(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetDefaultCharacterFormat, WINRT_WRAP(void), Windows::UI::Text::ITextCharacterFormat const&);
            this->shim().SetDefaultCharacterFormat(*reinterpret_cast<Windows::UI::Text::ITextCharacterFormat const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetDefaultParagraphFormat(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetDefaultParagraphFormat, WINRT_WRAP(void), Windows::UI::Text::ITextParagraphFormat const&);
            this->shim().SetDefaultParagraphFormat(*reinterpret_cast<Windows::UI::Text::ITextParagraphFormat const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetText(Windows::UI::Text::TextSetOptions options, void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetText, WINRT_WRAP(void), Windows::UI::Text::TextSetOptions const&, hstring const&);
            this->shim().SetText(*reinterpret_cast<Windows::UI::Text::TextSetOptions const*>(&options), *reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Undo() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Undo, WINRT_WRAP(void));
            this->shim().Undo();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Text::ITextDocument2> : produce_base<D, Windows::UI::Text::ITextDocument2>
{
    int32_t WINRT_CALL get_AlignmentIncludesTrailingWhitespace(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AlignmentIncludesTrailingWhitespace, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AlignmentIncludesTrailingWhitespace());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AlignmentIncludesTrailingWhitespace(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AlignmentIncludesTrailingWhitespace, WINRT_WRAP(void), bool);
            this->shim().AlignmentIncludesTrailingWhitespace(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IgnoreTrailingCharacterSpacing(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IgnoreTrailingCharacterSpacing, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IgnoreTrailingCharacterSpacing());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IgnoreTrailingCharacterSpacing(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IgnoreTrailingCharacterSpacing, WINRT_WRAP(void), bool);
            this->shim().IgnoreTrailingCharacterSpacing(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Text::ITextDocument3> : produce_base<D, Windows::UI::Text::ITextDocument3>
{
    int32_t WINRT_CALL ClearUndoRedoHistory() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClearUndoRedoHistory, WINRT_WRAP(void));
            this->shim().ClearUndoRedoHistory();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Text::ITextParagraphFormat> : produce_base<D, Windows::UI::Text::ITextParagraphFormat>
{
    int32_t WINRT_CALL get_Alignment(Windows::UI::Text::ParagraphAlignment* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Alignment, WINRT_WRAP(Windows::UI::Text::ParagraphAlignment));
            *value = detach_from<Windows::UI::Text::ParagraphAlignment>(this->shim().Alignment());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Alignment(Windows::UI::Text::ParagraphAlignment value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Alignment, WINRT_WRAP(void), Windows::UI::Text::ParagraphAlignment const&);
            this->shim().Alignment(*reinterpret_cast<Windows::UI::Text::ParagraphAlignment const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FirstLineIndent(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FirstLineIndent, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().FirstLineIndent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_KeepTogether(Windows::UI::Text::FormatEffect* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeepTogether, WINRT_WRAP(Windows::UI::Text::FormatEffect));
            *value = detach_from<Windows::UI::Text::FormatEffect>(this->shim().KeepTogether());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_KeepTogether(Windows::UI::Text::FormatEffect value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeepTogether, WINRT_WRAP(void), Windows::UI::Text::FormatEffect const&);
            this->shim().KeepTogether(*reinterpret_cast<Windows::UI::Text::FormatEffect const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_KeepWithNext(Windows::UI::Text::FormatEffect* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeepWithNext, WINRT_WRAP(Windows::UI::Text::FormatEffect));
            *value = detach_from<Windows::UI::Text::FormatEffect>(this->shim().KeepWithNext());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_KeepWithNext(Windows::UI::Text::FormatEffect value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeepWithNext, WINRT_WRAP(void), Windows::UI::Text::FormatEffect const&);
            this->shim().KeepWithNext(*reinterpret_cast<Windows::UI::Text::FormatEffect const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LeftIndent(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LeftIndent, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().LeftIndent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LineSpacing(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LineSpacing, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().LineSpacing());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LineSpacingRule(Windows::UI::Text::LineSpacingRule* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LineSpacingRule, WINRT_WRAP(Windows::UI::Text::LineSpacingRule));
            *value = detach_from<Windows::UI::Text::LineSpacingRule>(this->shim().LineSpacingRule());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ListAlignment(Windows::UI::Text::MarkerAlignment* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ListAlignment, WINRT_WRAP(Windows::UI::Text::MarkerAlignment));
            *value = detach_from<Windows::UI::Text::MarkerAlignment>(this->shim().ListAlignment());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ListAlignment(Windows::UI::Text::MarkerAlignment value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ListAlignment, WINRT_WRAP(void), Windows::UI::Text::MarkerAlignment const&);
            this->shim().ListAlignment(*reinterpret_cast<Windows::UI::Text::MarkerAlignment const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ListLevelIndex(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ListLevelIndex, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().ListLevelIndex());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ListLevelIndex(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ListLevelIndex, WINRT_WRAP(void), int32_t);
            this->shim().ListLevelIndex(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ListStart(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ListStart, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().ListStart());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ListStart(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ListStart, WINRT_WRAP(void), int32_t);
            this->shim().ListStart(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ListStyle(Windows::UI::Text::MarkerStyle* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ListStyle, WINRT_WRAP(Windows::UI::Text::MarkerStyle));
            *value = detach_from<Windows::UI::Text::MarkerStyle>(this->shim().ListStyle());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ListStyle(Windows::UI::Text::MarkerStyle value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ListStyle, WINRT_WRAP(void), Windows::UI::Text::MarkerStyle const&);
            this->shim().ListStyle(*reinterpret_cast<Windows::UI::Text::MarkerStyle const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ListTab(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ListTab, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().ListTab());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ListTab(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ListTab, WINRT_WRAP(void), float);
            this->shim().ListTab(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ListType(Windows::UI::Text::MarkerType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ListType, WINRT_WRAP(Windows::UI::Text::MarkerType));
            *value = detach_from<Windows::UI::Text::MarkerType>(this->shim().ListType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ListType(Windows::UI::Text::MarkerType value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ListType, WINRT_WRAP(void), Windows::UI::Text::MarkerType const&);
            this->shim().ListType(*reinterpret_cast<Windows::UI::Text::MarkerType const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NoLineNumber(Windows::UI::Text::FormatEffect* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NoLineNumber, WINRT_WRAP(Windows::UI::Text::FormatEffect));
            *value = detach_from<Windows::UI::Text::FormatEffect>(this->shim().NoLineNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_NoLineNumber(Windows::UI::Text::FormatEffect value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NoLineNumber, WINRT_WRAP(void), Windows::UI::Text::FormatEffect const&);
            this->shim().NoLineNumber(*reinterpret_cast<Windows::UI::Text::FormatEffect const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PageBreakBefore(Windows::UI::Text::FormatEffect* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PageBreakBefore, WINRT_WRAP(Windows::UI::Text::FormatEffect));
            *value = detach_from<Windows::UI::Text::FormatEffect>(this->shim().PageBreakBefore());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PageBreakBefore(Windows::UI::Text::FormatEffect value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PageBreakBefore, WINRT_WRAP(void), Windows::UI::Text::FormatEffect const&);
            this->shim().PageBreakBefore(*reinterpret_cast<Windows::UI::Text::FormatEffect const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RightIndent(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RightIndent, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().RightIndent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RightIndent(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RightIndent, WINRT_WRAP(void), float);
            this->shim().RightIndent(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RightToLeft(Windows::UI::Text::FormatEffect* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RightToLeft, WINRT_WRAP(Windows::UI::Text::FormatEffect));
            *value = detach_from<Windows::UI::Text::FormatEffect>(this->shim().RightToLeft());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RightToLeft(Windows::UI::Text::FormatEffect value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RightToLeft, WINRT_WRAP(void), Windows::UI::Text::FormatEffect const&);
            this->shim().RightToLeft(*reinterpret_cast<Windows::UI::Text::FormatEffect const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Style(Windows::UI::Text::ParagraphStyle* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Style, WINRT_WRAP(Windows::UI::Text::ParagraphStyle));
            *value = detach_from<Windows::UI::Text::ParagraphStyle>(this->shim().Style());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Style(Windows::UI::Text::ParagraphStyle value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Style, WINRT_WRAP(void), Windows::UI::Text::ParagraphStyle const&);
            this->shim().Style(*reinterpret_cast<Windows::UI::Text::ParagraphStyle const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SpaceAfter(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SpaceAfter, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().SpaceAfter());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SpaceAfter(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SpaceAfter, WINRT_WRAP(void), float);
            this->shim().SpaceAfter(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SpaceBefore(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SpaceBefore, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().SpaceBefore());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SpaceBefore(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SpaceBefore, WINRT_WRAP(void), float);
            this->shim().SpaceBefore(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WidowControl(Windows::UI::Text::FormatEffect* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WidowControl, WINRT_WRAP(Windows::UI::Text::FormatEffect));
            *value = detach_from<Windows::UI::Text::FormatEffect>(this->shim().WidowControl());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_WidowControl(Windows::UI::Text::FormatEffect value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WidowControl, WINRT_WRAP(void), Windows::UI::Text::FormatEffect const&);
            this->shim().WidowControl(*reinterpret_cast<Windows::UI::Text::FormatEffect const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TabCount(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TabCount, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().TabCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AddTab(float position, Windows::UI::Text::TabAlignment align, Windows::UI::Text::TabLeader leader) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddTab, WINRT_WRAP(void), float, Windows::UI::Text::TabAlignment const&, Windows::UI::Text::TabLeader const&);
            this->shim().AddTab(position, *reinterpret_cast<Windows::UI::Text::TabAlignment const*>(&align), *reinterpret_cast<Windows::UI::Text::TabLeader const*>(&leader));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ClearAllTabs() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClearAllTabs, WINRT_WRAP(void));
            this->shim().ClearAllTabs();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DeleteTab(float position) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeleteTab, WINRT_WRAP(void), float);
            this->shim().DeleteTab(position);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetClone(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetClone, WINRT_WRAP(Windows::UI::Text::ITextParagraphFormat));
            *result = detach_from<Windows::UI::Text::ITextParagraphFormat>(this->shim().GetClone());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetTab(int32_t index, float* position, Windows::UI::Text::TabAlignment* align, Windows::UI::Text::TabLeader* leader) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetTab, WINRT_WRAP(void), int32_t, float&, Windows::UI::Text::TabAlignment&, Windows::UI::Text::TabLeader&);
            this->shim().GetTab(index, *position, *reinterpret_cast<Windows::UI::Text::TabAlignment*>(align), *reinterpret_cast<Windows::UI::Text::TabLeader*>(leader));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsEqual(void* format, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsEqual, WINRT_WRAP(bool), Windows::UI::Text::ITextParagraphFormat const&);
            *result = detach_from<bool>(this->shim().IsEqual(*reinterpret_cast<Windows::UI::Text::ITextParagraphFormat const*>(&format)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetClone(void* format) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetClone, WINRT_WRAP(void), Windows::UI::Text::ITextParagraphFormat const&);
            this->shim().SetClone(*reinterpret_cast<Windows::UI::Text::ITextParagraphFormat const*>(&format));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetIndents(float start, float left, float right) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetIndents, WINRT_WRAP(void), float, float, float);
            this->shim().SetIndents(start, left, right);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetLineSpacing(Windows::UI::Text::LineSpacingRule rule, float spacing) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetLineSpacing, WINRT_WRAP(void), Windows::UI::Text::LineSpacingRule const&, float);
            this->shim().SetLineSpacing(*reinterpret_cast<Windows::UI::Text::LineSpacingRule const*>(&rule), spacing);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Text::ITextRange> : produce_base<D, Windows::UI::Text::ITextRange>
{
    int32_t WINRT_CALL get_Character(char16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Character, WINRT_WRAP(char16_t));
            *value = detach_from<char16_t>(this->shim().Character());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Character(char16_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Character, WINRT_WRAP(void), char16_t);
            this->shim().Character(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CharacterFormat(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CharacterFormat, WINRT_WRAP(Windows::UI::Text::ITextCharacterFormat));
            *value = detach_from<Windows::UI::Text::ITextCharacterFormat>(this->shim().CharacterFormat());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CharacterFormat(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CharacterFormat, WINRT_WRAP(void), Windows::UI::Text::ITextCharacterFormat const&);
            this->shim().CharacterFormat(*reinterpret_cast<Windows::UI::Text::ITextCharacterFormat const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FormattedText(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FormattedText, WINRT_WRAP(Windows::UI::Text::ITextRange));
            *value = detach_from<Windows::UI::Text::ITextRange>(this->shim().FormattedText());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FormattedText(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FormattedText, WINRT_WRAP(void), Windows::UI::Text::ITextRange const&);
            this->shim().FormattedText(*reinterpret_cast<Windows::UI::Text::ITextRange const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EndPosition(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EndPosition, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().EndPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_EndPosition(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EndPosition, WINRT_WRAP(void), int32_t);
            this->shim().EndPosition(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Gravity(Windows::UI::Text::RangeGravity* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Gravity, WINRT_WRAP(Windows::UI::Text::RangeGravity));
            *value = detach_from<Windows::UI::Text::RangeGravity>(this->shim().Gravity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Gravity(Windows::UI::Text::RangeGravity value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Gravity, WINRT_WRAP(void), Windows::UI::Text::RangeGravity const&);
            this->shim().Gravity(*reinterpret_cast<Windows::UI::Text::RangeGravity const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Length(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Length, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().Length());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Link(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Link, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Link());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Link(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Link, WINRT_WRAP(void), hstring const&);
            this->shim().Link(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ParagraphFormat(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ParagraphFormat, WINRT_WRAP(Windows::UI::Text::ITextParagraphFormat));
            *value = detach_from<Windows::UI::Text::ITextParagraphFormat>(this->shim().ParagraphFormat());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ParagraphFormat(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ParagraphFormat, WINRT_WRAP(void), Windows::UI::Text::ITextParagraphFormat const&);
            this->shim().ParagraphFormat(*reinterpret_cast<Windows::UI::Text::ITextParagraphFormat const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StartPosition(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartPosition, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().StartPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_StartPosition(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartPosition, WINRT_WRAP(void), int32_t);
            this->shim().StartPosition(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StoryLength(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StoryLength, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().StoryLength());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Text(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Text, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Text());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Text(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Text, WINRT_WRAP(void), hstring const&);
            this->shim().Text(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CanPaste(int32_t format, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanPaste, WINRT_WRAP(bool), int32_t);
            *result = detach_from<bool>(this->shim().CanPaste(format));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ChangeCase(Windows::UI::Text::LetterCase value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChangeCase, WINRT_WRAP(void), Windows::UI::Text::LetterCase const&);
            this->shim().ChangeCase(*reinterpret_cast<Windows::UI::Text::LetterCase const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Collapse(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Collapse, WINRT_WRAP(void), bool);
            this->shim().Collapse(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Copy() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Copy, WINRT_WRAP(void));
            this->shim().Copy();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Cut() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Cut, WINRT_WRAP(void));
            this->shim().Cut();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Delete(Windows::UI::Text::TextRangeUnit unit, int32_t count, int32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Delete, WINRT_WRAP(int32_t), Windows::UI::Text::TextRangeUnit const&, int32_t);
            *result = detach_from<int32_t>(this->shim().Delete(*reinterpret_cast<Windows::UI::Text::TextRangeUnit const*>(&unit), count));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL EndOf(Windows::UI::Text::TextRangeUnit unit, bool extend, int32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EndOf, WINRT_WRAP(int32_t), Windows::UI::Text::TextRangeUnit const&, bool);
            *result = detach_from<int32_t>(this->shim().EndOf(*reinterpret_cast<Windows::UI::Text::TextRangeUnit const*>(&unit), extend));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Expand(Windows::UI::Text::TextRangeUnit unit, int32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Expand, WINRT_WRAP(int32_t), Windows::UI::Text::TextRangeUnit const&);
            *result = detach_from<int32_t>(this->shim().Expand(*reinterpret_cast<Windows::UI::Text::TextRangeUnit const*>(&unit)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindText(void* value, int32_t scanLength, Windows::UI::Text::FindOptions options, int32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindText, WINRT_WRAP(int32_t), hstring const&, int32_t, Windows::UI::Text::FindOptions const&);
            *result = detach_from<int32_t>(this->shim().FindText(*reinterpret_cast<hstring const*>(&value), scanLength, *reinterpret_cast<Windows::UI::Text::FindOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetCharacterUtf32(uint32_t* value, int32_t offset) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCharacterUtf32, WINRT_WRAP(void), uint32_t&, int32_t);
            this->shim().GetCharacterUtf32(*value, offset);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetClone(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetClone, WINRT_WRAP(Windows::UI::Text::ITextRange));
            *result = detach_from<Windows::UI::Text::ITextRange>(this->shim().GetClone());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetIndex(Windows::UI::Text::TextRangeUnit unit, int32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetIndex, WINRT_WRAP(int32_t), Windows::UI::Text::TextRangeUnit const&);
            *result = detach_from<int32_t>(this->shim().GetIndex(*reinterpret_cast<Windows::UI::Text::TextRangeUnit const*>(&unit)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetPoint(Windows::UI::Text::HorizontalCharacterAlignment horizontalAlign, Windows::UI::Text::VerticalCharacterAlignment verticalAlign, Windows::UI::Text::PointOptions options, Windows::Foundation::Point* point) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetPoint, WINRT_WRAP(void), Windows::UI::Text::HorizontalCharacterAlignment const&, Windows::UI::Text::VerticalCharacterAlignment const&, Windows::UI::Text::PointOptions const&, Windows::Foundation::Point&);
            this->shim().GetPoint(*reinterpret_cast<Windows::UI::Text::HorizontalCharacterAlignment const*>(&horizontalAlign), *reinterpret_cast<Windows::UI::Text::VerticalCharacterAlignment const*>(&verticalAlign), *reinterpret_cast<Windows::UI::Text::PointOptions const*>(&options), *reinterpret_cast<Windows::Foundation::Point*>(point));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetRect(Windows::UI::Text::PointOptions options, Windows::Foundation::Rect* rect, int32_t* hit) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetRect, WINRT_WRAP(void), Windows::UI::Text::PointOptions const&, Windows::Foundation::Rect&, int32_t&);
            this->shim().GetRect(*reinterpret_cast<Windows::UI::Text::PointOptions const*>(&options), *reinterpret_cast<Windows::Foundation::Rect*>(rect), *hit);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetText(Windows::UI::Text::TextGetOptions options, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetText, WINRT_WRAP(void), Windows::UI::Text::TextGetOptions const&, hstring&);
            this->shim().GetText(*reinterpret_cast<Windows::UI::Text::TextGetOptions const*>(&options), *reinterpret_cast<hstring*>(value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetTextViaStream(Windows::UI::Text::TextGetOptions options, void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetTextViaStream, WINRT_WRAP(void), Windows::UI::Text::TextGetOptions const&, Windows::Storage::Streams::IRandomAccessStream const&);
            this->shim().GetTextViaStream(*reinterpret_cast<Windows::UI::Text::TextGetOptions const*>(&options), *reinterpret_cast<Windows::Storage::Streams::IRandomAccessStream const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL InRange(void* range, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InRange, WINRT_WRAP(bool), Windows::UI::Text::ITextRange const&);
            *result = detach_from<bool>(this->shim().InRange(*reinterpret_cast<Windows::UI::Text::ITextRange const*>(&range)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL InsertImage(int32_t width, int32_t height, int32_t ascent, Windows::UI::Text::VerticalCharacterAlignment verticalAlign, void* alternateText, void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InsertImage, WINRT_WRAP(void), int32_t, int32_t, int32_t, Windows::UI::Text::VerticalCharacterAlignment const&, hstring const&, Windows::Storage::Streams::IRandomAccessStream const&);
            this->shim().InsertImage(width, height, ascent, *reinterpret_cast<Windows::UI::Text::VerticalCharacterAlignment const*>(&verticalAlign), *reinterpret_cast<hstring const*>(&alternateText), *reinterpret_cast<Windows::Storage::Streams::IRandomAccessStream const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL InStory(void* range, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InStory, WINRT_WRAP(bool), Windows::UI::Text::ITextRange const&);
            *result = detach_from<bool>(this->shim().InStory(*reinterpret_cast<Windows::UI::Text::ITextRange const*>(&range)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsEqual(void* range, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsEqual, WINRT_WRAP(bool), Windows::UI::Text::ITextRange const&);
            *result = detach_from<bool>(this->shim().IsEqual(*reinterpret_cast<Windows::UI::Text::ITextRange const*>(&range)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Move(Windows::UI::Text::TextRangeUnit unit, int32_t count, int32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Move, WINRT_WRAP(int32_t), Windows::UI::Text::TextRangeUnit const&, int32_t);
            *result = detach_from<int32_t>(this->shim().Move(*reinterpret_cast<Windows::UI::Text::TextRangeUnit const*>(&unit), count));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL MoveEnd(Windows::UI::Text::TextRangeUnit unit, int32_t count, int32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MoveEnd, WINRT_WRAP(int32_t), Windows::UI::Text::TextRangeUnit const&, int32_t);
            *result = detach_from<int32_t>(this->shim().MoveEnd(*reinterpret_cast<Windows::UI::Text::TextRangeUnit const*>(&unit), count));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL MoveStart(Windows::UI::Text::TextRangeUnit unit, int32_t count, int32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MoveStart, WINRT_WRAP(int32_t), Windows::UI::Text::TextRangeUnit const&, int32_t);
            *result = detach_from<int32_t>(this->shim().MoveStart(*reinterpret_cast<Windows::UI::Text::TextRangeUnit const*>(&unit), count));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Paste(int32_t format) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Paste, WINRT_WRAP(void), int32_t);
            this->shim().Paste(format);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ScrollIntoView(Windows::UI::Text::PointOptions value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScrollIntoView, WINRT_WRAP(void), Windows::UI::Text::PointOptions const&);
            this->shim().ScrollIntoView(*reinterpret_cast<Windows::UI::Text::PointOptions const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL MatchSelection() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MatchSelection, WINRT_WRAP(void));
            this->shim().MatchSelection();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetIndex(Windows::UI::Text::TextRangeUnit unit, int32_t index, bool extend) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetIndex, WINRT_WRAP(void), Windows::UI::Text::TextRangeUnit const&, int32_t, bool);
            this->shim().SetIndex(*reinterpret_cast<Windows::UI::Text::TextRangeUnit const*>(&unit), index, extend);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetPoint(Windows::Foundation::Point point, Windows::UI::Text::PointOptions options, bool extend) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetPoint, WINRT_WRAP(void), Windows::Foundation::Point const&, Windows::UI::Text::PointOptions const&, bool);
            this->shim().SetPoint(*reinterpret_cast<Windows::Foundation::Point const*>(&point), *reinterpret_cast<Windows::UI::Text::PointOptions const*>(&options), extend);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetRange(int32_t startPosition, int32_t endPosition) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetRange, WINRT_WRAP(void), int32_t, int32_t);
            this->shim().SetRange(startPosition, endPosition);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetText(Windows::UI::Text::TextSetOptions options, void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetText, WINRT_WRAP(void), Windows::UI::Text::TextSetOptions const&, hstring const&);
            this->shim().SetText(*reinterpret_cast<Windows::UI::Text::TextSetOptions const*>(&options), *reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetTextViaStream(Windows::UI::Text::TextSetOptions options, void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetTextViaStream, WINRT_WRAP(void), Windows::UI::Text::TextSetOptions const&, Windows::Storage::Streams::IRandomAccessStream const&);
            this->shim().SetTextViaStream(*reinterpret_cast<Windows::UI::Text::TextSetOptions const*>(&options), *reinterpret_cast<Windows::Storage::Streams::IRandomAccessStream const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StartOf(Windows::UI::Text::TextRangeUnit unit, bool extend, int32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartOf, WINRT_WRAP(int32_t), Windows::UI::Text::TextRangeUnit const&, bool);
            *result = detach_from<int32_t>(this->shim().StartOf(*reinterpret_cast<Windows::UI::Text::TextRangeUnit const*>(&unit), extend));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Text::ITextSelection> : produce_base<D, Windows::UI::Text::ITextSelection>
{
    int32_t WINRT_CALL get_Options(Windows::UI::Text::SelectionOptions* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Options, WINRT_WRAP(Windows::UI::Text::SelectionOptions));
            *value = detach_from<Windows::UI::Text::SelectionOptions>(this->shim().Options());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Options(Windows::UI::Text::SelectionOptions value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Options, WINRT_WRAP(void), Windows::UI::Text::SelectionOptions const&);
            this->shim().Options(*reinterpret_cast<Windows::UI::Text::SelectionOptions const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Type(Windows::UI::Text::SelectionType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Type, WINRT_WRAP(Windows::UI::Text::SelectionType));
            *value = detach_from<Windows::UI::Text::SelectionType>(this->shim().Type());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL EndKey(Windows::UI::Text::TextRangeUnit unit, bool extend, int32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EndKey, WINRT_WRAP(int32_t), Windows::UI::Text::TextRangeUnit const&, bool);
            *result = detach_from<int32_t>(this->shim().EndKey(*reinterpret_cast<Windows::UI::Text::TextRangeUnit const*>(&unit), extend));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL HomeKey(Windows::UI::Text::TextRangeUnit unit, bool extend, int32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HomeKey, WINRT_WRAP(int32_t), Windows::UI::Text::TextRangeUnit const&, bool);
            *result = detach_from<int32_t>(this->shim().HomeKey(*reinterpret_cast<Windows::UI::Text::TextRangeUnit const*>(&unit), extend));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL MoveDown(Windows::UI::Text::TextRangeUnit unit, int32_t count, bool extend, int32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MoveDown, WINRT_WRAP(int32_t), Windows::UI::Text::TextRangeUnit const&, int32_t, bool);
            *result = detach_from<int32_t>(this->shim().MoveDown(*reinterpret_cast<Windows::UI::Text::TextRangeUnit const*>(&unit), count, extend));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL MoveLeft(Windows::UI::Text::TextRangeUnit unit, int32_t count, bool extend, int32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MoveLeft, WINRT_WRAP(int32_t), Windows::UI::Text::TextRangeUnit const&, int32_t, bool);
            *result = detach_from<int32_t>(this->shim().MoveLeft(*reinterpret_cast<Windows::UI::Text::TextRangeUnit const*>(&unit), count, extend));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL MoveRight(Windows::UI::Text::TextRangeUnit unit, int32_t count, bool extend, int32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MoveRight, WINRT_WRAP(int32_t), Windows::UI::Text::TextRangeUnit const&, int32_t, bool);
            *result = detach_from<int32_t>(this->shim().MoveRight(*reinterpret_cast<Windows::UI::Text::TextRangeUnit const*>(&unit), count, extend));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL MoveUp(Windows::UI::Text::TextRangeUnit unit, int32_t count, bool extend, int32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MoveUp, WINRT_WRAP(int32_t), Windows::UI::Text::TextRangeUnit const&, int32_t, bool);
            *result = detach_from<int32_t>(this->shim().MoveUp(*reinterpret_cast<Windows::UI::Text::TextRangeUnit const*>(&unit), count, extend));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TypeText(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TypeText, WINRT_WRAP(void), hstring const&);
            this->shim().TypeText(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::UI::Text {

inline ContentLinkInfo::ContentLinkInfo() :
    ContentLinkInfo(impl::call_factory<ContentLinkInfo>([](auto&& f) { return f.template ActivateInstance<ContentLinkInfo>(); }))
{}

inline Windows::UI::Text::FontWeight FontWeights::Black()
{
    return impl::call_factory<FontWeights, Windows::UI::Text::IFontWeightsStatics>([&](auto&& f) { return f.Black(); });
}

inline Windows::UI::Text::FontWeight FontWeights::Bold()
{
    return impl::call_factory<FontWeights, Windows::UI::Text::IFontWeightsStatics>([&](auto&& f) { return f.Bold(); });
}

inline Windows::UI::Text::FontWeight FontWeights::ExtraBlack()
{
    return impl::call_factory<FontWeights, Windows::UI::Text::IFontWeightsStatics>([&](auto&& f) { return f.ExtraBlack(); });
}

inline Windows::UI::Text::FontWeight FontWeights::ExtraBold()
{
    return impl::call_factory<FontWeights, Windows::UI::Text::IFontWeightsStatics>([&](auto&& f) { return f.ExtraBold(); });
}

inline Windows::UI::Text::FontWeight FontWeights::ExtraLight()
{
    return impl::call_factory<FontWeights, Windows::UI::Text::IFontWeightsStatics>([&](auto&& f) { return f.ExtraLight(); });
}

inline Windows::UI::Text::FontWeight FontWeights::Light()
{
    return impl::call_factory<FontWeights, Windows::UI::Text::IFontWeightsStatics>([&](auto&& f) { return f.Light(); });
}

inline Windows::UI::Text::FontWeight FontWeights::Medium()
{
    return impl::call_factory<FontWeights, Windows::UI::Text::IFontWeightsStatics>([&](auto&& f) { return f.Medium(); });
}

inline Windows::UI::Text::FontWeight FontWeights::Normal()
{
    return impl::call_factory<FontWeights, Windows::UI::Text::IFontWeightsStatics>([&](auto&& f) { return f.Normal(); });
}

inline Windows::UI::Text::FontWeight FontWeights::SemiBold()
{
    return impl::call_factory<FontWeights, Windows::UI::Text::IFontWeightsStatics>([&](auto&& f) { return f.SemiBold(); });
}

inline Windows::UI::Text::FontWeight FontWeights::SemiLight()
{
    return impl::call_factory<FontWeights, Windows::UI::Text::IFontWeightsStatics>([&](auto&& f) { return f.SemiLight(); });
}

inline Windows::UI::Text::FontWeight FontWeights::Thin()
{
    return impl::call_factory<FontWeights, Windows::UI::Text::IFontWeightsStatics>([&](auto&& f) { return f.Thin(); });
}

inline Windows::UI::Color TextConstants::AutoColor()
{
    return impl::call_factory<TextConstants, Windows::UI::Text::ITextConstantsStatics>([&](auto&& f) { return f.AutoColor(); });
}

inline int32_t TextConstants::MinUnitCount()
{
    return impl::call_factory<TextConstants, Windows::UI::Text::ITextConstantsStatics>([&](auto&& f) { return f.MinUnitCount(); });
}

inline int32_t TextConstants::MaxUnitCount()
{
    return impl::call_factory<TextConstants, Windows::UI::Text::ITextConstantsStatics>([&](auto&& f) { return f.MaxUnitCount(); });
}

inline Windows::UI::Color TextConstants::UndefinedColor()
{
    return impl::call_factory<TextConstants, Windows::UI::Text::ITextConstantsStatics>([&](auto&& f) { return f.UndefinedColor(); });
}

inline float TextConstants::UndefinedFloatValue()
{
    return impl::call_factory<TextConstants, Windows::UI::Text::ITextConstantsStatics>([&](auto&& f) { return f.UndefinedFloatValue(); });
}

inline int32_t TextConstants::UndefinedInt32Value()
{
    return impl::call_factory<TextConstants, Windows::UI::Text::ITextConstantsStatics>([&](auto&& f) { return f.UndefinedInt32Value(); });
}

inline Windows::UI::Text::FontStretch TextConstants::UndefinedFontStretch()
{
    return impl::call_factory<TextConstants, Windows::UI::Text::ITextConstantsStatics>([&](auto&& f) { return f.UndefinedFontStretch(); });
}

inline Windows::UI::Text::FontStyle TextConstants::UndefinedFontStyle()
{
    return impl::call_factory<TextConstants, Windows::UI::Text::ITextConstantsStatics>([&](auto&& f) { return f.UndefinedFontStyle(); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::UI::Text::IContentLinkInfo> : winrt::impl::hash_base<winrt::Windows::UI::Text::IContentLinkInfo> {};
template<> struct hash<winrt::Windows::UI::Text::IFontWeights> : winrt::impl::hash_base<winrt::Windows::UI::Text::IFontWeights> {};
template<> struct hash<winrt::Windows::UI::Text::IFontWeightsStatics> : winrt::impl::hash_base<winrt::Windows::UI::Text::IFontWeightsStatics> {};
template<> struct hash<winrt::Windows::UI::Text::IRichEditTextRange> : winrt::impl::hash_base<winrt::Windows::UI::Text::IRichEditTextRange> {};
template<> struct hash<winrt::Windows::UI::Text::ITextCharacterFormat> : winrt::impl::hash_base<winrt::Windows::UI::Text::ITextCharacterFormat> {};
template<> struct hash<winrt::Windows::UI::Text::ITextConstantsStatics> : winrt::impl::hash_base<winrt::Windows::UI::Text::ITextConstantsStatics> {};
template<> struct hash<winrt::Windows::UI::Text::ITextDocument> : winrt::impl::hash_base<winrt::Windows::UI::Text::ITextDocument> {};
template<> struct hash<winrt::Windows::UI::Text::ITextDocument2> : winrt::impl::hash_base<winrt::Windows::UI::Text::ITextDocument2> {};
template<> struct hash<winrt::Windows::UI::Text::ITextDocument3> : winrt::impl::hash_base<winrt::Windows::UI::Text::ITextDocument3> {};
template<> struct hash<winrt::Windows::UI::Text::ITextParagraphFormat> : winrt::impl::hash_base<winrt::Windows::UI::Text::ITextParagraphFormat> {};
template<> struct hash<winrt::Windows::UI::Text::ITextRange> : winrt::impl::hash_base<winrt::Windows::UI::Text::ITextRange> {};
template<> struct hash<winrt::Windows::UI::Text::ITextSelection> : winrt::impl::hash_base<winrt::Windows::UI::Text::ITextSelection> {};
template<> struct hash<winrt::Windows::UI::Text::ContentLinkInfo> : winrt::impl::hash_base<winrt::Windows::UI::Text::ContentLinkInfo> {};
template<> struct hash<winrt::Windows::UI::Text::FontWeights> : winrt::impl::hash_base<winrt::Windows::UI::Text::FontWeights> {};
template<> struct hash<winrt::Windows::UI::Text::RichEditTextDocument> : winrt::impl::hash_base<winrt::Windows::UI::Text::RichEditTextDocument> {};
template<> struct hash<winrt::Windows::UI::Text::RichEditTextRange> : winrt::impl::hash_base<winrt::Windows::UI::Text::RichEditTextRange> {};
template<> struct hash<winrt::Windows::UI::Text::TextConstants> : winrt::impl::hash_base<winrt::Windows::UI::Text::TextConstants> {};

}
