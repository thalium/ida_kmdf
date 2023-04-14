// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.UI.Text.2.h"
#include "winrt/impl/Windows.Globalization.Fonts.2.h"
#include "winrt/Windows.Globalization.h"

namespace winrt::impl {

template <typename D> hstring consume_Windows_Globalization_Fonts_ILanguageFont<D>::FontFamily() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Globalization::Fonts::ILanguageFont)->get_FontFamily(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Text::FontWeight consume_Windows_Globalization_Fonts_ILanguageFont<D>::FontWeight() const
{
    Windows::UI::Text::FontWeight weight{};
    check_hresult(WINRT_SHIM(Windows::Globalization::Fonts::ILanguageFont)->get_FontWeight(put_abi(weight)));
    return weight;
}

template <typename D> Windows::UI::Text::FontStretch consume_Windows_Globalization_Fonts_ILanguageFont<D>::FontStretch() const
{
    Windows::UI::Text::FontStretch stretch{};
    check_hresult(WINRT_SHIM(Windows::Globalization::Fonts::ILanguageFont)->get_FontStretch(put_abi(stretch)));
    return stretch;
}

template <typename D> Windows::UI::Text::FontStyle consume_Windows_Globalization_Fonts_ILanguageFont<D>::FontStyle() const
{
    Windows::UI::Text::FontStyle style{};
    check_hresult(WINRT_SHIM(Windows::Globalization::Fonts::ILanguageFont)->get_FontStyle(put_abi(style)));
    return style;
}

template <typename D> double consume_Windows_Globalization_Fonts_ILanguageFont<D>::ScaleFactor() const
{
    double scale{};
    check_hresult(WINRT_SHIM(Windows::Globalization::Fonts::ILanguageFont)->get_ScaleFactor(&scale));
    return scale;
}

template <typename D> Windows::Globalization::Fonts::LanguageFont consume_Windows_Globalization_Fonts_ILanguageFontGroup<D>::UITextFont() const
{
    Windows::Globalization::Fonts::LanguageFont value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Globalization::Fonts::ILanguageFontGroup)->get_UITextFont(put_abi(value)));
    return value;
}

template <typename D> Windows::Globalization::Fonts::LanguageFont consume_Windows_Globalization_Fonts_ILanguageFontGroup<D>::UIHeadingFont() const
{
    Windows::Globalization::Fonts::LanguageFont value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Globalization::Fonts::ILanguageFontGroup)->get_UIHeadingFont(put_abi(value)));
    return value;
}

template <typename D> Windows::Globalization::Fonts::LanguageFont consume_Windows_Globalization_Fonts_ILanguageFontGroup<D>::UITitleFont() const
{
    Windows::Globalization::Fonts::LanguageFont value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Globalization::Fonts::ILanguageFontGroup)->get_UITitleFont(put_abi(value)));
    return value;
}

template <typename D> Windows::Globalization::Fonts::LanguageFont consume_Windows_Globalization_Fonts_ILanguageFontGroup<D>::UICaptionFont() const
{
    Windows::Globalization::Fonts::LanguageFont value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Globalization::Fonts::ILanguageFontGroup)->get_UICaptionFont(put_abi(value)));
    return value;
}

template <typename D> Windows::Globalization::Fonts::LanguageFont consume_Windows_Globalization_Fonts_ILanguageFontGroup<D>::UINotificationHeadingFont() const
{
    Windows::Globalization::Fonts::LanguageFont value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Globalization::Fonts::ILanguageFontGroup)->get_UINotificationHeadingFont(put_abi(value)));
    return value;
}

template <typename D> Windows::Globalization::Fonts::LanguageFont consume_Windows_Globalization_Fonts_ILanguageFontGroup<D>::TraditionalDocumentFont() const
{
    Windows::Globalization::Fonts::LanguageFont value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Globalization::Fonts::ILanguageFontGroup)->get_TraditionalDocumentFont(put_abi(value)));
    return value;
}

template <typename D> Windows::Globalization::Fonts::LanguageFont consume_Windows_Globalization_Fonts_ILanguageFontGroup<D>::ModernDocumentFont() const
{
    Windows::Globalization::Fonts::LanguageFont value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Globalization::Fonts::ILanguageFontGroup)->get_ModernDocumentFont(put_abi(value)));
    return value;
}

template <typename D> Windows::Globalization::Fonts::LanguageFont consume_Windows_Globalization_Fonts_ILanguageFontGroup<D>::DocumentHeadingFont() const
{
    Windows::Globalization::Fonts::LanguageFont value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Globalization::Fonts::ILanguageFontGroup)->get_DocumentHeadingFont(put_abi(value)));
    return value;
}

template <typename D> Windows::Globalization::Fonts::LanguageFont consume_Windows_Globalization_Fonts_ILanguageFontGroup<D>::FixedWidthTextFont() const
{
    Windows::Globalization::Fonts::LanguageFont value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Globalization::Fonts::ILanguageFontGroup)->get_FixedWidthTextFont(put_abi(value)));
    return value;
}

template <typename D> Windows::Globalization::Fonts::LanguageFont consume_Windows_Globalization_Fonts_ILanguageFontGroup<D>::DocumentAlternate1Font() const
{
    Windows::Globalization::Fonts::LanguageFont value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Globalization::Fonts::ILanguageFontGroup)->get_DocumentAlternate1Font(put_abi(value)));
    return value;
}

template <typename D> Windows::Globalization::Fonts::LanguageFont consume_Windows_Globalization_Fonts_ILanguageFontGroup<D>::DocumentAlternate2Font() const
{
    Windows::Globalization::Fonts::LanguageFont value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Globalization::Fonts::ILanguageFontGroup)->get_DocumentAlternate2Font(put_abi(value)));
    return value;
}

template <typename D> Windows::Globalization::Fonts::LanguageFontGroup consume_Windows_Globalization_Fonts_ILanguageFontGroupFactory<D>::CreateLanguageFontGroup(param::hstring const& languageTag) const
{
    Windows::Globalization::Fonts::LanguageFontGroup recommendedFonts{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Globalization::Fonts::ILanguageFontGroupFactory)->CreateLanguageFontGroup(get_abi(languageTag), put_abi(recommendedFonts)));
    return recommendedFonts;
}

template <typename D>
struct produce<D, Windows::Globalization::Fonts::ILanguageFont> : produce_base<D, Windows::Globalization::Fonts::ILanguageFont>
{
    int32_t WINRT_CALL get_FontFamily(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FontFamily, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().FontFamily());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FontWeight(struct struct_Windows_UI_Text_FontWeight* weight) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FontWeight, WINRT_WRAP(Windows::UI::Text::FontWeight));
            *weight = detach_from<Windows::UI::Text::FontWeight>(this->shim().FontWeight());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FontStretch(Windows::UI::Text::FontStretch* stretch) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FontStretch, WINRT_WRAP(Windows::UI::Text::FontStretch));
            *stretch = detach_from<Windows::UI::Text::FontStretch>(this->shim().FontStretch());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FontStyle(Windows::UI::Text::FontStyle* style) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FontStyle, WINRT_WRAP(Windows::UI::Text::FontStyle));
            *style = detach_from<Windows::UI::Text::FontStyle>(this->shim().FontStyle());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ScaleFactor(double* scale) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScaleFactor, WINRT_WRAP(double));
            *scale = detach_from<double>(this->shim().ScaleFactor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Globalization::Fonts::ILanguageFontGroup> : produce_base<D, Windows::Globalization::Fonts::ILanguageFontGroup>
{
    int32_t WINRT_CALL get_UITextFont(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UITextFont, WINRT_WRAP(Windows::Globalization::Fonts::LanguageFont));
            *value = detach_from<Windows::Globalization::Fonts::LanguageFont>(this->shim().UITextFont());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UIHeadingFont(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UIHeadingFont, WINRT_WRAP(Windows::Globalization::Fonts::LanguageFont));
            *value = detach_from<Windows::Globalization::Fonts::LanguageFont>(this->shim().UIHeadingFont());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UITitleFont(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UITitleFont, WINRT_WRAP(Windows::Globalization::Fonts::LanguageFont));
            *value = detach_from<Windows::Globalization::Fonts::LanguageFont>(this->shim().UITitleFont());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UICaptionFont(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UICaptionFont, WINRT_WRAP(Windows::Globalization::Fonts::LanguageFont));
            *value = detach_from<Windows::Globalization::Fonts::LanguageFont>(this->shim().UICaptionFont());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UINotificationHeadingFont(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UINotificationHeadingFont, WINRT_WRAP(Windows::Globalization::Fonts::LanguageFont));
            *value = detach_from<Windows::Globalization::Fonts::LanguageFont>(this->shim().UINotificationHeadingFont());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TraditionalDocumentFont(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TraditionalDocumentFont, WINRT_WRAP(Windows::Globalization::Fonts::LanguageFont));
            *value = detach_from<Windows::Globalization::Fonts::LanguageFont>(this->shim().TraditionalDocumentFont());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ModernDocumentFont(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ModernDocumentFont, WINRT_WRAP(Windows::Globalization::Fonts::LanguageFont));
            *value = detach_from<Windows::Globalization::Fonts::LanguageFont>(this->shim().ModernDocumentFont());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DocumentHeadingFont(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DocumentHeadingFont, WINRT_WRAP(Windows::Globalization::Fonts::LanguageFont));
            *value = detach_from<Windows::Globalization::Fonts::LanguageFont>(this->shim().DocumentHeadingFont());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FixedWidthTextFont(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FixedWidthTextFont, WINRT_WRAP(Windows::Globalization::Fonts::LanguageFont));
            *value = detach_from<Windows::Globalization::Fonts::LanguageFont>(this->shim().FixedWidthTextFont());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DocumentAlternate1Font(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DocumentAlternate1Font, WINRT_WRAP(Windows::Globalization::Fonts::LanguageFont));
            *value = detach_from<Windows::Globalization::Fonts::LanguageFont>(this->shim().DocumentAlternate1Font());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DocumentAlternate2Font(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DocumentAlternate2Font, WINRT_WRAP(Windows::Globalization::Fonts::LanguageFont));
            *value = detach_from<Windows::Globalization::Fonts::LanguageFont>(this->shim().DocumentAlternate2Font());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Globalization::Fonts::ILanguageFontGroupFactory> : produce_base<D, Windows::Globalization::Fonts::ILanguageFontGroupFactory>
{
    int32_t WINRT_CALL CreateLanguageFontGroup(void* languageTag, void** recommendedFonts) noexcept final
    {
        try
        {
            *recommendedFonts = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateLanguageFontGroup, WINRT_WRAP(Windows::Globalization::Fonts::LanguageFontGroup), hstring const&);
            *recommendedFonts = detach_from<Windows::Globalization::Fonts::LanguageFontGroup>(this->shim().CreateLanguageFontGroup(*reinterpret_cast<hstring const*>(&languageTag)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Globalization::Fonts {

inline LanguageFontGroup::LanguageFontGroup(param::hstring const& languageTag) :
    LanguageFontGroup(impl::call_factory<LanguageFontGroup, Windows::Globalization::Fonts::ILanguageFontGroupFactory>([&](auto&& f) { return f.CreateLanguageFontGroup(languageTag); }))
{}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Globalization::Fonts::ILanguageFont> : winrt::impl::hash_base<winrt::Windows::Globalization::Fonts::ILanguageFont> {};
template<> struct hash<winrt::Windows::Globalization::Fonts::ILanguageFontGroup> : winrt::impl::hash_base<winrt::Windows::Globalization::Fonts::ILanguageFontGroup> {};
template<> struct hash<winrt::Windows::Globalization::Fonts::ILanguageFontGroupFactory> : winrt::impl::hash_base<winrt::Windows::Globalization::Fonts::ILanguageFontGroupFactory> {};
template<> struct hash<winrt::Windows::Globalization::Fonts::LanguageFont> : winrt::impl::hash_base<winrt::Windows::Globalization::Fonts::LanguageFont> {};
template<> struct hash<winrt::Windows::Globalization::Fonts::LanguageFontGroup> : winrt::impl::hash_base<winrt::Windows::Globalization::Fonts::LanguageFontGroup> {};

}
