// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.UI.2.h"
#include "winrt/impl/Windows.Media.ClosedCaptioning.2.h"
#include "winrt/Windows.Media.h"

namespace winrt::impl {

template <typename D> Windows::Media::ClosedCaptioning::ClosedCaptionColor consume_Windows_Media_ClosedCaptioning_IClosedCaptionPropertiesStatics<D>::FontColor() const
{
    Windows::Media::ClosedCaptioning::ClosedCaptionColor value{};
    check_hresult(WINRT_SHIM(Windows::Media::ClosedCaptioning::IClosedCaptionPropertiesStatics)->get_FontColor(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_Media_ClosedCaptioning_IClosedCaptionPropertiesStatics<D>::ComputedFontColor() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::Media::ClosedCaptioning::IClosedCaptionPropertiesStatics)->get_ComputedFontColor(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::ClosedCaptioning::ClosedCaptionOpacity consume_Windows_Media_ClosedCaptioning_IClosedCaptionPropertiesStatics<D>::FontOpacity() const
{
    Windows::Media::ClosedCaptioning::ClosedCaptionOpacity value{};
    check_hresult(WINRT_SHIM(Windows::Media::ClosedCaptioning::IClosedCaptionPropertiesStatics)->get_FontOpacity(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::ClosedCaptioning::ClosedCaptionSize consume_Windows_Media_ClosedCaptioning_IClosedCaptionPropertiesStatics<D>::FontSize() const
{
    Windows::Media::ClosedCaptioning::ClosedCaptionSize value{};
    check_hresult(WINRT_SHIM(Windows::Media::ClosedCaptioning::IClosedCaptionPropertiesStatics)->get_FontSize(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::ClosedCaptioning::ClosedCaptionStyle consume_Windows_Media_ClosedCaptioning_IClosedCaptionPropertiesStatics<D>::FontStyle() const
{
    Windows::Media::ClosedCaptioning::ClosedCaptionStyle value{};
    check_hresult(WINRT_SHIM(Windows::Media::ClosedCaptioning::IClosedCaptionPropertiesStatics)->get_FontStyle(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::ClosedCaptioning::ClosedCaptionEdgeEffect consume_Windows_Media_ClosedCaptioning_IClosedCaptionPropertiesStatics<D>::FontEffect() const
{
    Windows::Media::ClosedCaptioning::ClosedCaptionEdgeEffect value{};
    check_hresult(WINRT_SHIM(Windows::Media::ClosedCaptioning::IClosedCaptionPropertiesStatics)->get_FontEffect(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::ClosedCaptioning::ClosedCaptionColor consume_Windows_Media_ClosedCaptioning_IClosedCaptionPropertiesStatics<D>::BackgroundColor() const
{
    Windows::Media::ClosedCaptioning::ClosedCaptionColor value{};
    check_hresult(WINRT_SHIM(Windows::Media::ClosedCaptioning::IClosedCaptionPropertiesStatics)->get_BackgroundColor(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_Media_ClosedCaptioning_IClosedCaptionPropertiesStatics<D>::ComputedBackgroundColor() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::Media::ClosedCaptioning::IClosedCaptionPropertiesStatics)->get_ComputedBackgroundColor(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::ClosedCaptioning::ClosedCaptionOpacity consume_Windows_Media_ClosedCaptioning_IClosedCaptionPropertiesStatics<D>::BackgroundOpacity() const
{
    Windows::Media::ClosedCaptioning::ClosedCaptionOpacity value{};
    check_hresult(WINRT_SHIM(Windows::Media::ClosedCaptioning::IClosedCaptionPropertiesStatics)->get_BackgroundOpacity(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::ClosedCaptioning::ClosedCaptionColor consume_Windows_Media_ClosedCaptioning_IClosedCaptionPropertiesStatics<D>::RegionColor() const
{
    Windows::Media::ClosedCaptioning::ClosedCaptionColor value{};
    check_hresult(WINRT_SHIM(Windows::Media::ClosedCaptioning::IClosedCaptionPropertiesStatics)->get_RegionColor(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_Media_ClosedCaptioning_IClosedCaptionPropertiesStatics<D>::ComputedRegionColor() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::Media::ClosedCaptioning::IClosedCaptionPropertiesStatics)->get_ComputedRegionColor(put_abi(value)));
    return value;
}

template <typename D> Windows::Media::ClosedCaptioning::ClosedCaptionOpacity consume_Windows_Media_ClosedCaptioning_IClosedCaptionPropertiesStatics<D>::RegionOpacity() const
{
    Windows::Media::ClosedCaptioning::ClosedCaptionOpacity value{};
    check_hresult(WINRT_SHIM(Windows::Media::ClosedCaptioning::IClosedCaptionPropertiesStatics)->get_RegionOpacity(put_abi(value)));
    return value;
}

template <typename D>
struct produce<D, Windows::Media::ClosedCaptioning::IClosedCaptionPropertiesStatics> : produce_base<D, Windows::Media::ClosedCaptioning::IClosedCaptionPropertiesStatics>
{
    int32_t WINRT_CALL get_FontColor(Windows::Media::ClosedCaptioning::ClosedCaptionColor* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FontColor, WINRT_WRAP(Windows::Media::ClosedCaptioning::ClosedCaptionColor));
            *value = detach_from<Windows::Media::ClosedCaptioning::ClosedCaptionColor>(this->shim().FontColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ComputedFontColor(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ComputedFontColor, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().ComputedFontColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FontOpacity(Windows::Media::ClosedCaptioning::ClosedCaptionOpacity* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FontOpacity, WINRT_WRAP(Windows::Media::ClosedCaptioning::ClosedCaptionOpacity));
            *value = detach_from<Windows::Media::ClosedCaptioning::ClosedCaptionOpacity>(this->shim().FontOpacity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FontSize(Windows::Media::ClosedCaptioning::ClosedCaptionSize* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FontSize, WINRT_WRAP(Windows::Media::ClosedCaptioning::ClosedCaptionSize));
            *value = detach_from<Windows::Media::ClosedCaptioning::ClosedCaptionSize>(this->shim().FontSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FontStyle(Windows::Media::ClosedCaptioning::ClosedCaptionStyle* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FontStyle, WINRT_WRAP(Windows::Media::ClosedCaptioning::ClosedCaptionStyle));
            *value = detach_from<Windows::Media::ClosedCaptioning::ClosedCaptionStyle>(this->shim().FontStyle());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FontEffect(Windows::Media::ClosedCaptioning::ClosedCaptionEdgeEffect* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FontEffect, WINRT_WRAP(Windows::Media::ClosedCaptioning::ClosedCaptionEdgeEffect));
            *value = detach_from<Windows::Media::ClosedCaptioning::ClosedCaptionEdgeEffect>(this->shim().FontEffect());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BackgroundColor(Windows::Media::ClosedCaptioning::ClosedCaptionColor* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BackgroundColor, WINRT_WRAP(Windows::Media::ClosedCaptioning::ClosedCaptionColor));
            *value = detach_from<Windows::Media::ClosedCaptioning::ClosedCaptionColor>(this->shim().BackgroundColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ComputedBackgroundColor(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ComputedBackgroundColor, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().ComputedBackgroundColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BackgroundOpacity(Windows::Media::ClosedCaptioning::ClosedCaptionOpacity* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BackgroundOpacity, WINRT_WRAP(Windows::Media::ClosedCaptioning::ClosedCaptionOpacity));
            *value = detach_from<Windows::Media::ClosedCaptioning::ClosedCaptionOpacity>(this->shim().BackgroundOpacity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RegionColor(Windows::Media::ClosedCaptioning::ClosedCaptionColor* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RegionColor, WINRT_WRAP(Windows::Media::ClosedCaptioning::ClosedCaptionColor));
            *value = detach_from<Windows::Media::ClosedCaptioning::ClosedCaptionColor>(this->shim().RegionColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ComputedRegionColor(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ComputedRegionColor, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().ComputedRegionColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RegionOpacity(Windows::Media::ClosedCaptioning::ClosedCaptionOpacity* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RegionOpacity, WINRT_WRAP(Windows::Media::ClosedCaptioning::ClosedCaptionOpacity));
            *value = detach_from<Windows::Media::ClosedCaptioning::ClosedCaptionOpacity>(this->shim().RegionOpacity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Media::ClosedCaptioning {

inline Windows::Media::ClosedCaptioning::ClosedCaptionColor ClosedCaptionProperties::FontColor()
{
    return impl::call_factory<ClosedCaptionProperties, Windows::Media::ClosedCaptioning::IClosedCaptionPropertiesStatics>([&](auto&& f) { return f.FontColor(); });
}

inline Windows::UI::Color ClosedCaptionProperties::ComputedFontColor()
{
    return impl::call_factory<ClosedCaptionProperties, Windows::Media::ClosedCaptioning::IClosedCaptionPropertiesStatics>([&](auto&& f) { return f.ComputedFontColor(); });
}

inline Windows::Media::ClosedCaptioning::ClosedCaptionOpacity ClosedCaptionProperties::FontOpacity()
{
    return impl::call_factory<ClosedCaptionProperties, Windows::Media::ClosedCaptioning::IClosedCaptionPropertiesStatics>([&](auto&& f) { return f.FontOpacity(); });
}

inline Windows::Media::ClosedCaptioning::ClosedCaptionSize ClosedCaptionProperties::FontSize()
{
    return impl::call_factory<ClosedCaptionProperties, Windows::Media::ClosedCaptioning::IClosedCaptionPropertiesStatics>([&](auto&& f) { return f.FontSize(); });
}

inline Windows::Media::ClosedCaptioning::ClosedCaptionStyle ClosedCaptionProperties::FontStyle()
{
    return impl::call_factory<ClosedCaptionProperties, Windows::Media::ClosedCaptioning::IClosedCaptionPropertiesStatics>([&](auto&& f) { return f.FontStyle(); });
}

inline Windows::Media::ClosedCaptioning::ClosedCaptionEdgeEffect ClosedCaptionProperties::FontEffect()
{
    return impl::call_factory<ClosedCaptionProperties, Windows::Media::ClosedCaptioning::IClosedCaptionPropertiesStatics>([&](auto&& f) { return f.FontEffect(); });
}

inline Windows::Media::ClosedCaptioning::ClosedCaptionColor ClosedCaptionProperties::BackgroundColor()
{
    return impl::call_factory<ClosedCaptionProperties, Windows::Media::ClosedCaptioning::IClosedCaptionPropertiesStatics>([&](auto&& f) { return f.BackgroundColor(); });
}

inline Windows::UI::Color ClosedCaptionProperties::ComputedBackgroundColor()
{
    return impl::call_factory<ClosedCaptionProperties, Windows::Media::ClosedCaptioning::IClosedCaptionPropertiesStatics>([&](auto&& f) { return f.ComputedBackgroundColor(); });
}

inline Windows::Media::ClosedCaptioning::ClosedCaptionOpacity ClosedCaptionProperties::BackgroundOpacity()
{
    return impl::call_factory<ClosedCaptionProperties, Windows::Media::ClosedCaptioning::IClosedCaptionPropertiesStatics>([&](auto&& f) { return f.BackgroundOpacity(); });
}

inline Windows::Media::ClosedCaptioning::ClosedCaptionColor ClosedCaptionProperties::RegionColor()
{
    return impl::call_factory<ClosedCaptionProperties, Windows::Media::ClosedCaptioning::IClosedCaptionPropertiesStatics>([&](auto&& f) { return f.RegionColor(); });
}

inline Windows::UI::Color ClosedCaptionProperties::ComputedRegionColor()
{
    return impl::call_factory<ClosedCaptionProperties, Windows::Media::ClosedCaptioning::IClosedCaptionPropertiesStatics>([&](auto&& f) { return f.ComputedRegionColor(); });
}

inline Windows::Media::ClosedCaptioning::ClosedCaptionOpacity ClosedCaptionProperties::RegionOpacity()
{
    return impl::call_factory<ClosedCaptionProperties, Windows::Media::ClosedCaptioning::IClosedCaptionPropertiesStatics>([&](auto&& f) { return f.RegionOpacity(); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Media::ClosedCaptioning::IClosedCaptionPropertiesStatics> : winrt::impl::hash_base<winrt::Windows::Media::ClosedCaptioning::IClosedCaptionPropertiesStatics> {};
template<> struct hash<winrt::Windows::Media::ClosedCaptioning::ClosedCaptionProperties> : winrt::impl::hash_base<winrt::Windows::Media::ClosedCaptioning::ClosedCaptionProperties> {};

}
