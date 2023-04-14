// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.UI.2.h"

namespace winrt::impl {

template <typename D> Windows::UI::Color consume_Windows_UI_IColorHelperStatics<D>::FromArgb(uint8_t a, uint8_t r, uint8_t g, uint8_t b) const
{
    Windows::UI::Color returnValue{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorHelperStatics)->FromArgb(a, r, g, b, put_abi(returnValue)));
    return returnValue;
}

template <typename D> hstring consume_Windows_UI_IColorHelperStatics2<D>::ToDisplayName(Windows::UI::Color const& color) const
{
    hstring returnValue{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorHelperStatics2)->ToDisplayName(get_abi(color), put_abi(returnValue)));
    return returnValue;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::AliceBlue() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_AliceBlue(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::AntiqueWhite() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_AntiqueWhite(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::Aqua() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_Aqua(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::Aquamarine() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_Aquamarine(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::Azure() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_Azure(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::Beige() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_Beige(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::Bisque() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_Bisque(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::Black() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_Black(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::BlanchedAlmond() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_BlanchedAlmond(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::Blue() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_Blue(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::BlueViolet() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_BlueViolet(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::Brown() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_Brown(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::BurlyWood() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_BurlyWood(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::CadetBlue() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_CadetBlue(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::Chartreuse() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_Chartreuse(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::Chocolate() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_Chocolate(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::Coral() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_Coral(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::CornflowerBlue() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_CornflowerBlue(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::Cornsilk() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_Cornsilk(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::Crimson() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_Crimson(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::Cyan() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_Cyan(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::DarkBlue() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_DarkBlue(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::DarkCyan() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_DarkCyan(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::DarkGoldenrod() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_DarkGoldenrod(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::DarkGray() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_DarkGray(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::DarkGreen() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_DarkGreen(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::DarkKhaki() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_DarkKhaki(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::DarkMagenta() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_DarkMagenta(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::DarkOliveGreen() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_DarkOliveGreen(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::DarkOrange() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_DarkOrange(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::DarkOrchid() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_DarkOrchid(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::DarkRed() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_DarkRed(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::DarkSalmon() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_DarkSalmon(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::DarkSeaGreen() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_DarkSeaGreen(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::DarkSlateBlue() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_DarkSlateBlue(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::DarkSlateGray() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_DarkSlateGray(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::DarkTurquoise() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_DarkTurquoise(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::DarkViolet() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_DarkViolet(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::DeepPink() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_DeepPink(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::DeepSkyBlue() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_DeepSkyBlue(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::DimGray() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_DimGray(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::DodgerBlue() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_DodgerBlue(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::Firebrick() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_Firebrick(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::FloralWhite() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_FloralWhite(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::ForestGreen() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_ForestGreen(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::Fuchsia() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_Fuchsia(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::Gainsboro() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_Gainsboro(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::GhostWhite() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_GhostWhite(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::Gold() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_Gold(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::Goldenrod() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_Goldenrod(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::Gray() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_Gray(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::Green() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_Green(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::GreenYellow() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_GreenYellow(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::Honeydew() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_Honeydew(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::HotPink() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_HotPink(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::IndianRed() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_IndianRed(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::Indigo() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_Indigo(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::Ivory() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_Ivory(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::Khaki() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_Khaki(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::Lavender() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_Lavender(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::LavenderBlush() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_LavenderBlush(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::LawnGreen() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_LawnGreen(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::LemonChiffon() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_LemonChiffon(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::LightBlue() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_LightBlue(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::LightCoral() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_LightCoral(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::LightCyan() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_LightCyan(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::LightGoldenrodYellow() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_LightGoldenrodYellow(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::LightGreen() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_LightGreen(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::LightGray() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_LightGray(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::LightPink() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_LightPink(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::LightSalmon() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_LightSalmon(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::LightSeaGreen() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_LightSeaGreen(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::LightSkyBlue() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_LightSkyBlue(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::LightSlateGray() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_LightSlateGray(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::LightSteelBlue() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_LightSteelBlue(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::LightYellow() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_LightYellow(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::Lime() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_Lime(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::LimeGreen() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_LimeGreen(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::Linen() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_Linen(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::Magenta() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_Magenta(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::Maroon() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_Maroon(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::MediumAquamarine() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_MediumAquamarine(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::MediumBlue() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_MediumBlue(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::MediumOrchid() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_MediumOrchid(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::MediumPurple() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_MediumPurple(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::MediumSeaGreen() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_MediumSeaGreen(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::MediumSlateBlue() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_MediumSlateBlue(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::MediumSpringGreen() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_MediumSpringGreen(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::MediumTurquoise() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_MediumTurquoise(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::MediumVioletRed() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_MediumVioletRed(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::MidnightBlue() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_MidnightBlue(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::MintCream() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_MintCream(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::MistyRose() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_MistyRose(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::Moccasin() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_Moccasin(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::NavajoWhite() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_NavajoWhite(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::Navy() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_Navy(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::OldLace() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_OldLace(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::Olive() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_Olive(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::OliveDrab() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_OliveDrab(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::Orange() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_Orange(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::OrangeRed() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_OrangeRed(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::Orchid() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_Orchid(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::PaleGoldenrod() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_PaleGoldenrod(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::PaleGreen() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_PaleGreen(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::PaleTurquoise() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_PaleTurquoise(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::PaleVioletRed() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_PaleVioletRed(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::PapayaWhip() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_PapayaWhip(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::PeachPuff() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_PeachPuff(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::Peru() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_Peru(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::Pink() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_Pink(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::Plum() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_Plum(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::PowderBlue() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_PowderBlue(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::Purple() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_Purple(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::Red() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_Red(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::RosyBrown() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_RosyBrown(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::RoyalBlue() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_RoyalBlue(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::SaddleBrown() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_SaddleBrown(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::Salmon() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_Salmon(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::SandyBrown() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_SandyBrown(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::SeaGreen() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_SeaGreen(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::SeaShell() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_SeaShell(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::Sienna() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_Sienna(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::Silver() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_Silver(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::SkyBlue() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_SkyBlue(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::SlateBlue() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_SlateBlue(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::SlateGray() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_SlateGray(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::Snow() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_Snow(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::SpringGreen() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_SpringGreen(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::SteelBlue() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_SteelBlue(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::Tan() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_Tan(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::Teal() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_Teal(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::Thistle() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_Thistle(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::Tomato() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_Tomato(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::Transparent() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_Transparent(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::Turquoise() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_Turquoise(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::Violet() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_Violet(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::Wheat() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_Wheat(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::White() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_White(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::WhiteSmoke() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_WhiteSmoke(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::Yellow() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_Yellow(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_IColorsStatics<D>::YellowGreen() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::IColorsStatics)->get_YellowGreen(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::UIContext consume_Windows_UI_IUIContentRoot<D>::UIContext() const
{
    Windows::UI::UIContext value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::IUIContentRoot)->get_UIContext(put_abi(value)));
    return value;
}

template <typename D>
struct produce<D, Windows::UI::IColorHelper> : produce_base<D, Windows::UI::IColorHelper>
{};

template <typename D>
struct produce<D, Windows::UI::IColorHelperStatics> : produce_base<D, Windows::UI::IColorHelperStatics>
{
    int32_t WINRT_CALL FromArgb(uint8_t a, uint8_t r, uint8_t g, uint8_t b, struct struct_Windows_UI_Color* returnValue) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromArgb, WINRT_WRAP(Windows::UI::Color), uint8_t, uint8_t, uint8_t, uint8_t);
            *returnValue = detach_from<Windows::UI::Color>(this->shim().FromArgb(a, r, g, b));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::IColorHelperStatics2> : produce_base<D, Windows::UI::IColorHelperStatics2>
{
    int32_t WINRT_CALL ToDisplayName(struct struct_Windows_UI_Color color, void** returnValue) noexcept final
    {
        try
        {
            *returnValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ToDisplayName, WINRT_WRAP(hstring), Windows::UI::Color const&);
            *returnValue = detach_from<hstring>(this->shim().ToDisplayName(*reinterpret_cast<Windows::UI::Color const*>(&color)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::IColors> : produce_base<D, Windows::UI::IColors>
{};

template <typename D>
struct produce<D, Windows::UI::IColorsStatics> : produce_base<D, Windows::UI::IColorsStatics>
{
    int32_t WINRT_CALL get_AliceBlue(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AliceBlue, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().AliceBlue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AntiqueWhite(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AntiqueWhite, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().AntiqueWhite());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Aqua(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Aqua, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Aqua());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Aquamarine(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Aquamarine, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Aquamarine());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Azure(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Azure, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Azure());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Beige(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Beige, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Beige());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Bisque(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Bisque, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Bisque());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Black(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Black, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Black());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BlanchedAlmond(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BlanchedAlmond, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().BlanchedAlmond());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Blue(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Blue, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Blue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BlueViolet(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BlueViolet, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().BlueViolet());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Brown(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Brown, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Brown());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BurlyWood(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BurlyWood, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().BurlyWood());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CadetBlue(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CadetBlue, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().CadetBlue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Chartreuse(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Chartreuse, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Chartreuse());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Chocolate(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Chocolate, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Chocolate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Coral(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Coral, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Coral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CornflowerBlue(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CornflowerBlue, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().CornflowerBlue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Cornsilk(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Cornsilk, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Cornsilk());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Crimson(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Crimson, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Crimson());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Cyan(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Cyan, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Cyan());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DarkBlue(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DarkBlue, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().DarkBlue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DarkCyan(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DarkCyan, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().DarkCyan());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DarkGoldenrod(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DarkGoldenrod, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().DarkGoldenrod());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DarkGray(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DarkGray, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().DarkGray());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DarkGreen(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DarkGreen, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().DarkGreen());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DarkKhaki(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DarkKhaki, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().DarkKhaki());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DarkMagenta(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DarkMagenta, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().DarkMagenta());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DarkOliveGreen(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DarkOliveGreen, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().DarkOliveGreen());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DarkOrange(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DarkOrange, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().DarkOrange());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DarkOrchid(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DarkOrchid, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().DarkOrchid());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DarkRed(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DarkRed, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().DarkRed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DarkSalmon(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DarkSalmon, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().DarkSalmon());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DarkSeaGreen(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DarkSeaGreen, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().DarkSeaGreen());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DarkSlateBlue(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DarkSlateBlue, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().DarkSlateBlue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DarkSlateGray(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DarkSlateGray, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().DarkSlateGray());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DarkTurquoise(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DarkTurquoise, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().DarkTurquoise());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DarkViolet(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DarkViolet, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().DarkViolet());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DeepPink(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeepPink, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().DeepPink());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DeepSkyBlue(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeepSkyBlue, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().DeepSkyBlue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DimGray(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DimGray, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().DimGray());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DodgerBlue(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DodgerBlue, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().DodgerBlue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Firebrick(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Firebrick, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Firebrick());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FloralWhite(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FloralWhite, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().FloralWhite());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ForestGreen(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ForestGreen, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().ForestGreen());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Fuchsia(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Fuchsia, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Fuchsia());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Gainsboro(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Gainsboro, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Gainsboro());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_GhostWhite(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GhostWhite, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().GhostWhite());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Gold(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Gold, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Gold());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Goldenrod(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Goldenrod, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Goldenrod());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Gray(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Gray, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Gray());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Green(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Green, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Green());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_GreenYellow(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GreenYellow, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().GreenYellow());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Honeydew(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Honeydew, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Honeydew());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HotPink(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HotPink, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().HotPink());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IndianRed(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IndianRed, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().IndianRed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Indigo(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Indigo, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Indigo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Ivory(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Ivory, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Ivory());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Khaki(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Khaki, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Khaki());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Lavender(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Lavender, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Lavender());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LavenderBlush(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LavenderBlush, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().LavenderBlush());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LawnGreen(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LawnGreen, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().LawnGreen());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LemonChiffon(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LemonChiffon, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().LemonChiffon());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LightBlue(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LightBlue, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().LightBlue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LightCoral(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LightCoral, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().LightCoral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LightCyan(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LightCyan, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().LightCyan());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LightGoldenrodYellow(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LightGoldenrodYellow, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().LightGoldenrodYellow());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LightGreen(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LightGreen, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().LightGreen());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LightGray(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LightGray, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().LightGray());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LightPink(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LightPink, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().LightPink());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LightSalmon(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LightSalmon, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().LightSalmon());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LightSeaGreen(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LightSeaGreen, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().LightSeaGreen());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LightSkyBlue(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LightSkyBlue, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().LightSkyBlue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LightSlateGray(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LightSlateGray, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().LightSlateGray());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LightSteelBlue(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LightSteelBlue, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().LightSteelBlue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LightYellow(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LightYellow, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().LightYellow());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Lime(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Lime, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Lime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LimeGreen(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LimeGreen, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().LimeGreen());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Linen(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Linen, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Linen());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Magenta(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Magenta, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Magenta());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Maroon(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Maroon, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Maroon());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MediumAquamarine(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MediumAquamarine, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().MediumAquamarine());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MediumBlue(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MediumBlue, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().MediumBlue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MediumOrchid(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MediumOrchid, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().MediumOrchid());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MediumPurple(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MediumPurple, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().MediumPurple());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MediumSeaGreen(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MediumSeaGreen, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().MediumSeaGreen());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MediumSlateBlue(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MediumSlateBlue, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().MediumSlateBlue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MediumSpringGreen(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MediumSpringGreen, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().MediumSpringGreen());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MediumTurquoise(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MediumTurquoise, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().MediumTurquoise());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MediumVioletRed(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MediumVioletRed, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().MediumVioletRed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MidnightBlue(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MidnightBlue, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().MidnightBlue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MintCream(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MintCream, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().MintCream());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MistyRose(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MistyRose, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().MistyRose());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Moccasin(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Moccasin, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Moccasin());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NavajoWhite(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NavajoWhite, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().NavajoWhite());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Navy(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Navy, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Navy());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OldLace(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OldLace, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().OldLace());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Olive(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Olive, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Olive());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OliveDrab(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OliveDrab, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().OliveDrab());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Orange(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Orange, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Orange());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OrangeRed(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OrangeRed, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().OrangeRed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Orchid(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Orchid, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Orchid());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PaleGoldenrod(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PaleGoldenrod, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().PaleGoldenrod());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PaleGreen(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PaleGreen, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().PaleGreen());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PaleTurquoise(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PaleTurquoise, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().PaleTurquoise());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PaleVioletRed(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PaleVioletRed, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().PaleVioletRed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PapayaWhip(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PapayaWhip, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().PapayaWhip());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PeachPuff(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PeachPuff, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().PeachPuff());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Peru(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Peru, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Peru());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Pink(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Pink, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Pink());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Plum(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Plum, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Plum());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PowderBlue(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PowderBlue, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().PowderBlue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Purple(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Purple, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Purple());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Red(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Red, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Red());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RosyBrown(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RosyBrown, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().RosyBrown());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RoyalBlue(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RoyalBlue, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().RoyalBlue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SaddleBrown(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SaddleBrown, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().SaddleBrown());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Salmon(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Salmon, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Salmon());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SandyBrown(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SandyBrown, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().SandyBrown());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SeaGreen(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SeaGreen, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().SeaGreen());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SeaShell(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SeaShell, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().SeaShell());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Sienna(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Sienna, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Sienna());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Silver(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Silver, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Silver());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SkyBlue(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SkyBlue, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().SkyBlue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SlateBlue(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SlateBlue, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().SlateBlue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SlateGray(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SlateGray, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().SlateGray());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Snow(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Snow, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Snow());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SpringGreen(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SpringGreen, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().SpringGreen());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SteelBlue(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SteelBlue, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().SteelBlue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Tan(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Tan, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Tan());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Teal(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Teal, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Teal());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Thistle(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Thistle, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Thistle());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Tomato(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Tomato, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Tomato());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Transparent(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Transparent, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Transparent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Turquoise(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Turquoise, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Turquoise());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Violet(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Violet, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Violet());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Wheat(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Wheat, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Wheat());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_White(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(White, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().White());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WhiteSmoke(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WhiteSmoke, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().WhiteSmoke());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Yellow(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Yellow, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Yellow());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_YellowGreen(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(YellowGreen, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().YellowGreen());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::IUIContentRoot> : produce_base<D, Windows::UI::IUIContentRoot>
{
    int32_t WINRT_CALL get_UIContext(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UIContext, WINRT_WRAP(Windows::UI::UIContext));
            *value = detach_from<Windows::UI::UIContext>(this->shim().UIContext());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::IUIContext> : produce_base<D, Windows::UI::IUIContext>
{};

}

WINRT_EXPORT namespace winrt::Windows::UI {

inline Windows::UI::Color ColorHelper::FromArgb(uint8_t a, uint8_t r, uint8_t g, uint8_t b)
{
    return impl::call_factory<ColorHelper, Windows::UI::IColorHelperStatics>([&](auto&& f) { return f.FromArgb(a, r, g, b); });
}

inline hstring ColorHelper::ToDisplayName(Windows::UI::Color const& color)
{
    return impl::call_factory<ColorHelper, Windows::UI::IColorHelperStatics2>([&](auto&& f) { return f.ToDisplayName(color); });
}

inline Windows::UI::Color Colors::AliceBlue()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.AliceBlue(); });
}

inline Windows::UI::Color Colors::AntiqueWhite()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.AntiqueWhite(); });
}

inline Windows::UI::Color Colors::Aqua()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.Aqua(); });
}

inline Windows::UI::Color Colors::Aquamarine()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.Aquamarine(); });
}

inline Windows::UI::Color Colors::Azure()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.Azure(); });
}

inline Windows::UI::Color Colors::Beige()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.Beige(); });
}

inline Windows::UI::Color Colors::Bisque()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.Bisque(); });
}

inline Windows::UI::Color Colors::Black()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.Black(); });
}

inline Windows::UI::Color Colors::BlanchedAlmond()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.BlanchedAlmond(); });
}

inline Windows::UI::Color Colors::Blue()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.Blue(); });
}

inline Windows::UI::Color Colors::BlueViolet()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.BlueViolet(); });
}

inline Windows::UI::Color Colors::Brown()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.Brown(); });
}

inline Windows::UI::Color Colors::BurlyWood()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.BurlyWood(); });
}

inline Windows::UI::Color Colors::CadetBlue()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.CadetBlue(); });
}

inline Windows::UI::Color Colors::Chartreuse()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.Chartreuse(); });
}

inline Windows::UI::Color Colors::Chocolate()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.Chocolate(); });
}

inline Windows::UI::Color Colors::Coral()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.Coral(); });
}

inline Windows::UI::Color Colors::CornflowerBlue()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.CornflowerBlue(); });
}

inline Windows::UI::Color Colors::Cornsilk()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.Cornsilk(); });
}

inline Windows::UI::Color Colors::Crimson()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.Crimson(); });
}

inline Windows::UI::Color Colors::Cyan()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.Cyan(); });
}

inline Windows::UI::Color Colors::DarkBlue()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.DarkBlue(); });
}

inline Windows::UI::Color Colors::DarkCyan()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.DarkCyan(); });
}

inline Windows::UI::Color Colors::DarkGoldenrod()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.DarkGoldenrod(); });
}

inline Windows::UI::Color Colors::DarkGray()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.DarkGray(); });
}

inline Windows::UI::Color Colors::DarkGreen()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.DarkGreen(); });
}

inline Windows::UI::Color Colors::DarkKhaki()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.DarkKhaki(); });
}

inline Windows::UI::Color Colors::DarkMagenta()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.DarkMagenta(); });
}

inline Windows::UI::Color Colors::DarkOliveGreen()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.DarkOliveGreen(); });
}

inline Windows::UI::Color Colors::DarkOrange()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.DarkOrange(); });
}

inline Windows::UI::Color Colors::DarkOrchid()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.DarkOrchid(); });
}

inline Windows::UI::Color Colors::DarkRed()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.DarkRed(); });
}

inline Windows::UI::Color Colors::DarkSalmon()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.DarkSalmon(); });
}

inline Windows::UI::Color Colors::DarkSeaGreen()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.DarkSeaGreen(); });
}

inline Windows::UI::Color Colors::DarkSlateBlue()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.DarkSlateBlue(); });
}

inline Windows::UI::Color Colors::DarkSlateGray()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.DarkSlateGray(); });
}

inline Windows::UI::Color Colors::DarkTurquoise()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.DarkTurquoise(); });
}

inline Windows::UI::Color Colors::DarkViolet()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.DarkViolet(); });
}

inline Windows::UI::Color Colors::DeepPink()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.DeepPink(); });
}

inline Windows::UI::Color Colors::DeepSkyBlue()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.DeepSkyBlue(); });
}

inline Windows::UI::Color Colors::DimGray()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.DimGray(); });
}

inline Windows::UI::Color Colors::DodgerBlue()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.DodgerBlue(); });
}

inline Windows::UI::Color Colors::Firebrick()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.Firebrick(); });
}

inline Windows::UI::Color Colors::FloralWhite()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.FloralWhite(); });
}

inline Windows::UI::Color Colors::ForestGreen()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.ForestGreen(); });
}

inline Windows::UI::Color Colors::Fuchsia()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.Fuchsia(); });
}

inline Windows::UI::Color Colors::Gainsboro()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.Gainsboro(); });
}

inline Windows::UI::Color Colors::GhostWhite()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.GhostWhite(); });
}

inline Windows::UI::Color Colors::Gold()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.Gold(); });
}

inline Windows::UI::Color Colors::Goldenrod()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.Goldenrod(); });
}

inline Windows::UI::Color Colors::Gray()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.Gray(); });
}

inline Windows::UI::Color Colors::Green()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.Green(); });
}

inline Windows::UI::Color Colors::GreenYellow()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.GreenYellow(); });
}

inline Windows::UI::Color Colors::Honeydew()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.Honeydew(); });
}

inline Windows::UI::Color Colors::HotPink()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.HotPink(); });
}

inline Windows::UI::Color Colors::IndianRed()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.IndianRed(); });
}

inline Windows::UI::Color Colors::Indigo()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.Indigo(); });
}

inline Windows::UI::Color Colors::Ivory()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.Ivory(); });
}

inline Windows::UI::Color Colors::Khaki()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.Khaki(); });
}

inline Windows::UI::Color Colors::Lavender()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.Lavender(); });
}

inline Windows::UI::Color Colors::LavenderBlush()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.LavenderBlush(); });
}

inline Windows::UI::Color Colors::LawnGreen()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.LawnGreen(); });
}

inline Windows::UI::Color Colors::LemonChiffon()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.LemonChiffon(); });
}

inline Windows::UI::Color Colors::LightBlue()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.LightBlue(); });
}

inline Windows::UI::Color Colors::LightCoral()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.LightCoral(); });
}

inline Windows::UI::Color Colors::LightCyan()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.LightCyan(); });
}

inline Windows::UI::Color Colors::LightGoldenrodYellow()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.LightGoldenrodYellow(); });
}

inline Windows::UI::Color Colors::LightGreen()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.LightGreen(); });
}

inline Windows::UI::Color Colors::LightGray()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.LightGray(); });
}

inline Windows::UI::Color Colors::LightPink()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.LightPink(); });
}

inline Windows::UI::Color Colors::LightSalmon()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.LightSalmon(); });
}

inline Windows::UI::Color Colors::LightSeaGreen()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.LightSeaGreen(); });
}

inline Windows::UI::Color Colors::LightSkyBlue()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.LightSkyBlue(); });
}

inline Windows::UI::Color Colors::LightSlateGray()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.LightSlateGray(); });
}

inline Windows::UI::Color Colors::LightSteelBlue()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.LightSteelBlue(); });
}

inline Windows::UI::Color Colors::LightYellow()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.LightYellow(); });
}

inline Windows::UI::Color Colors::Lime()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.Lime(); });
}

inline Windows::UI::Color Colors::LimeGreen()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.LimeGreen(); });
}

inline Windows::UI::Color Colors::Linen()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.Linen(); });
}

inline Windows::UI::Color Colors::Magenta()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.Magenta(); });
}

inline Windows::UI::Color Colors::Maroon()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.Maroon(); });
}

inline Windows::UI::Color Colors::MediumAquamarine()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.MediumAquamarine(); });
}

inline Windows::UI::Color Colors::MediumBlue()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.MediumBlue(); });
}

inline Windows::UI::Color Colors::MediumOrchid()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.MediumOrchid(); });
}

inline Windows::UI::Color Colors::MediumPurple()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.MediumPurple(); });
}

inline Windows::UI::Color Colors::MediumSeaGreen()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.MediumSeaGreen(); });
}

inline Windows::UI::Color Colors::MediumSlateBlue()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.MediumSlateBlue(); });
}

inline Windows::UI::Color Colors::MediumSpringGreen()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.MediumSpringGreen(); });
}

inline Windows::UI::Color Colors::MediumTurquoise()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.MediumTurquoise(); });
}

inline Windows::UI::Color Colors::MediumVioletRed()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.MediumVioletRed(); });
}

inline Windows::UI::Color Colors::MidnightBlue()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.MidnightBlue(); });
}

inline Windows::UI::Color Colors::MintCream()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.MintCream(); });
}

inline Windows::UI::Color Colors::MistyRose()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.MistyRose(); });
}

inline Windows::UI::Color Colors::Moccasin()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.Moccasin(); });
}

inline Windows::UI::Color Colors::NavajoWhite()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.NavajoWhite(); });
}

inline Windows::UI::Color Colors::Navy()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.Navy(); });
}

inline Windows::UI::Color Colors::OldLace()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.OldLace(); });
}

inline Windows::UI::Color Colors::Olive()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.Olive(); });
}

inline Windows::UI::Color Colors::OliveDrab()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.OliveDrab(); });
}

inline Windows::UI::Color Colors::Orange()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.Orange(); });
}

inline Windows::UI::Color Colors::OrangeRed()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.OrangeRed(); });
}

inline Windows::UI::Color Colors::Orchid()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.Orchid(); });
}

inline Windows::UI::Color Colors::PaleGoldenrod()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.PaleGoldenrod(); });
}

inline Windows::UI::Color Colors::PaleGreen()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.PaleGreen(); });
}

inline Windows::UI::Color Colors::PaleTurquoise()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.PaleTurquoise(); });
}

inline Windows::UI::Color Colors::PaleVioletRed()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.PaleVioletRed(); });
}

inline Windows::UI::Color Colors::PapayaWhip()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.PapayaWhip(); });
}

inline Windows::UI::Color Colors::PeachPuff()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.PeachPuff(); });
}

inline Windows::UI::Color Colors::Peru()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.Peru(); });
}

inline Windows::UI::Color Colors::Pink()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.Pink(); });
}

inline Windows::UI::Color Colors::Plum()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.Plum(); });
}

inline Windows::UI::Color Colors::PowderBlue()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.PowderBlue(); });
}

inline Windows::UI::Color Colors::Purple()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.Purple(); });
}

inline Windows::UI::Color Colors::Red()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.Red(); });
}

inline Windows::UI::Color Colors::RosyBrown()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.RosyBrown(); });
}

inline Windows::UI::Color Colors::RoyalBlue()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.RoyalBlue(); });
}

inline Windows::UI::Color Colors::SaddleBrown()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.SaddleBrown(); });
}

inline Windows::UI::Color Colors::Salmon()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.Salmon(); });
}

inline Windows::UI::Color Colors::SandyBrown()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.SandyBrown(); });
}

inline Windows::UI::Color Colors::SeaGreen()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.SeaGreen(); });
}

inline Windows::UI::Color Colors::SeaShell()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.SeaShell(); });
}

inline Windows::UI::Color Colors::Sienna()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.Sienna(); });
}

inline Windows::UI::Color Colors::Silver()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.Silver(); });
}

inline Windows::UI::Color Colors::SkyBlue()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.SkyBlue(); });
}

inline Windows::UI::Color Colors::SlateBlue()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.SlateBlue(); });
}

inline Windows::UI::Color Colors::SlateGray()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.SlateGray(); });
}

inline Windows::UI::Color Colors::Snow()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.Snow(); });
}

inline Windows::UI::Color Colors::SpringGreen()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.SpringGreen(); });
}

inline Windows::UI::Color Colors::SteelBlue()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.SteelBlue(); });
}

inline Windows::UI::Color Colors::Tan()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.Tan(); });
}

inline Windows::UI::Color Colors::Teal()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.Teal(); });
}

inline Windows::UI::Color Colors::Thistle()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.Thistle(); });
}

inline Windows::UI::Color Colors::Tomato()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.Tomato(); });
}

inline Windows::UI::Color Colors::Transparent()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.Transparent(); });
}

inline Windows::UI::Color Colors::Turquoise()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.Turquoise(); });
}

inline Windows::UI::Color Colors::Violet()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.Violet(); });
}

inline Windows::UI::Color Colors::Wheat()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.Wheat(); });
}

inline Windows::UI::Color Colors::White()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.White(); });
}

inline Windows::UI::Color Colors::WhiteSmoke()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.WhiteSmoke(); });
}

inline Windows::UI::Color Colors::Yellow()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.Yellow(); });
}

inline Windows::UI::Color Colors::YellowGreen()
{
    return impl::call_factory<Colors, Windows::UI::IColorsStatics>([&](auto&& f) { return f.YellowGreen(); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::UI::IColorHelper> : winrt::impl::hash_base<winrt::Windows::UI::IColorHelper> {};
template<> struct hash<winrt::Windows::UI::IColorHelperStatics> : winrt::impl::hash_base<winrt::Windows::UI::IColorHelperStatics> {};
template<> struct hash<winrt::Windows::UI::IColorHelperStatics2> : winrt::impl::hash_base<winrt::Windows::UI::IColorHelperStatics2> {};
template<> struct hash<winrt::Windows::UI::IColors> : winrt::impl::hash_base<winrt::Windows::UI::IColors> {};
template<> struct hash<winrt::Windows::UI::IColorsStatics> : winrt::impl::hash_base<winrt::Windows::UI::IColorsStatics> {};
template<> struct hash<winrt::Windows::UI::IUIContentRoot> : winrt::impl::hash_base<winrt::Windows::UI::IUIContentRoot> {};
template<> struct hash<winrt::Windows::UI::IUIContext> : winrt::impl::hash_base<winrt::Windows::UI::IUIContext> {};
template<> struct hash<winrt::Windows::UI::ColorHelper> : winrt::impl::hash_base<winrt::Windows::UI::ColorHelper> {};
template<> struct hash<winrt::Windows::UI::Colors> : winrt::impl::hash_base<winrt::Windows::UI::Colors> {};
template<> struct hash<winrt::Windows::UI::UIContentRoot> : winrt::impl::hash_base<winrt::Windows::UI::UIContentRoot> {};
template<> struct hash<winrt::Windows::UI::UIContext> : winrt::impl::hash_base<winrt::Windows::UI::UIContext> {};

}
