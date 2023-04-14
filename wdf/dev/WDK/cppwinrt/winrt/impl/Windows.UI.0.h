// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::UI {

struct IColorHelper;
struct IColorHelperStatics;
struct IColorHelperStatics2;
struct IColors;
struct IColorsStatics;
struct IUIContentRoot;
struct IUIContext;
struct ColorHelper;
struct Colors;
struct UIContentRoot;
struct UIContext;
struct Color;

}

namespace winrt::impl {

template <> struct category<Windows::UI::IColorHelper>{ using type = interface_category; };
template <> struct category<Windows::UI::IColorHelperStatics>{ using type = interface_category; };
template <> struct category<Windows::UI::IColorHelperStatics2>{ using type = interface_category; };
template <> struct category<Windows::UI::IColors>{ using type = interface_category; };
template <> struct category<Windows::UI::IColorsStatics>{ using type = interface_category; };
template <> struct category<Windows::UI::IUIContentRoot>{ using type = interface_category; };
template <> struct category<Windows::UI::IUIContext>{ using type = interface_category; };
template <> struct category<Windows::UI::ColorHelper>{ using type = class_category; };
template <> struct category<Windows::UI::Colors>{ using type = class_category; };
template <> struct category<Windows::UI::UIContentRoot>{ using type = class_category; };
template <> struct category<Windows::UI::UIContext>{ using type = class_category; };
template <> struct category<Windows::UI::Color>{ using type = struct_category<uint8_t,uint8_t,uint8_t,uint8_t>; };
template <> struct name<Windows::UI::IColorHelper>{ static constexpr auto & value{ L"Windows.UI.IColorHelper" }; };
template <> struct name<Windows::UI::IColorHelperStatics>{ static constexpr auto & value{ L"Windows.UI.IColorHelperStatics" }; };
template <> struct name<Windows::UI::IColorHelperStatics2>{ static constexpr auto & value{ L"Windows.UI.IColorHelperStatics2" }; };
template <> struct name<Windows::UI::IColors>{ static constexpr auto & value{ L"Windows.UI.IColors" }; };
template <> struct name<Windows::UI::IColorsStatics>{ static constexpr auto & value{ L"Windows.UI.IColorsStatics" }; };
template <> struct name<Windows::UI::IUIContentRoot>{ static constexpr auto & value{ L"Windows.UI.IUIContentRoot" }; };
template <> struct name<Windows::UI::IUIContext>{ static constexpr auto & value{ L"Windows.UI.IUIContext" }; };
template <> struct name<Windows::UI::ColorHelper>{ static constexpr auto & value{ L"Windows.UI.ColorHelper" }; };
template <> struct name<Windows::UI::Colors>{ static constexpr auto & value{ L"Windows.UI.Colors" }; };
template <> struct name<Windows::UI::UIContentRoot>{ static constexpr auto & value{ L"Windows.UI.UIContentRoot" }; };
template <> struct name<Windows::UI::UIContext>{ static constexpr auto & value{ L"Windows.UI.UIContext" }; };
template <> struct name<Windows::UI::Color>{ static constexpr auto & value{ L"Windows.UI.Color" }; };
template <> struct guid_storage<Windows::UI::IColorHelper>{ static constexpr guid value{ 0x193CFBE7,0x65C7,0x4540,{ 0xAD,0x08,0x62,0x83,0xBA,0x76,0x87,0x9A } }; };
template <> struct guid_storage<Windows::UI::IColorHelperStatics>{ static constexpr guid value{ 0x8504DBEA,0xFB6A,0x4144,{ 0xA6,0xC2,0x33,0x49,0x9C,0x92,0x84,0xF5 } }; };
template <> struct guid_storage<Windows::UI::IColorHelperStatics2>{ static constexpr guid value{ 0x24D9AF02,0x6EB0,0x4B94,{ 0x85,0x5C,0xFC,0xF0,0x81,0x8D,0x9A,0x16 } }; };
template <> struct guid_storage<Windows::UI::IColors>{ static constexpr guid value{ 0x9B8C9326,0x4CA6,0x4CE5,{ 0x89,0x94,0x9E,0xFF,0x65,0xCA,0xBD,0xCC } }; };
template <> struct guid_storage<Windows::UI::IColorsStatics>{ static constexpr guid value{ 0xCFF52E04,0xCCA6,0x4614,{ 0xA1,0x7E,0x75,0x49,0x10,0xC8,0x4A,0x99 } }; };
template <> struct guid_storage<Windows::UI::IUIContentRoot>{ static constexpr guid value{ 0x1DFCBAC6,0xB36B,0x5CB9,{ 0x9B,0xC5,0x2B,0x7A,0x0E,0xDD,0xC3,0x78 } }; };
template <> struct guid_storage<Windows::UI::IUIContext>{ static constexpr guid value{ 0xBB5CFACD,0x5BD8,0x59D0,{ 0xA5,0x9E,0x1C,0x17,0xA4,0xD6,0xD2,0x43 } }; };
template <> struct default_interface<Windows::UI::ColorHelper>{ using type = Windows::UI::IColorHelper; };
template <> struct default_interface<Windows::UI::Colors>{ using type = Windows::UI::IColors; };
template <> struct default_interface<Windows::UI::UIContentRoot>{ using type = Windows::UI::IUIContentRoot; };
template <> struct default_interface<Windows::UI::UIContext>{ using type = Windows::UI::IUIContext; };

template <> struct abi<Windows::UI::IColorHelper>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::UI::IColorHelperStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL FromArgb(uint8_t a, uint8_t r, uint8_t g, uint8_t b, struct struct_Windows_UI_Color* returnValue) noexcept = 0;
};};

template <> struct abi<Windows::UI::IColorHelperStatics2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL ToDisplayName(struct struct_Windows_UI_Color color, void** returnValue) noexcept = 0;
};};

template <> struct abi<Windows::UI::IColors>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::UI::IColorsStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_AliceBlue(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AntiqueWhite(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Aqua(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Aquamarine(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Azure(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Beige(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Bisque(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Black(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BlanchedAlmond(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Blue(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BlueViolet(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Brown(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BurlyWood(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CadetBlue(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Chartreuse(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Chocolate(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Coral(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CornflowerBlue(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Cornsilk(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Crimson(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Cyan(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DarkBlue(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DarkCyan(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DarkGoldenrod(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DarkGray(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DarkGreen(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DarkKhaki(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DarkMagenta(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DarkOliveGreen(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DarkOrange(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DarkOrchid(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DarkRed(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DarkSalmon(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DarkSeaGreen(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DarkSlateBlue(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DarkSlateGray(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DarkTurquoise(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DarkViolet(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DeepPink(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DeepSkyBlue(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DimGray(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DodgerBlue(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Firebrick(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_FloralWhite(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ForestGreen(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Fuchsia(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Gainsboro(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_GhostWhite(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Gold(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Goldenrod(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Gray(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Green(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_GreenYellow(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Honeydew(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HotPink(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IndianRed(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Indigo(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Ivory(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Khaki(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Lavender(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LavenderBlush(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LawnGreen(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LemonChiffon(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LightBlue(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LightCoral(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LightCyan(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LightGoldenrodYellow(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LightGreen(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LightGray(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LightPink(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LightSalmon(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LightSeaGreen(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LightSkyBlue(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LightSlateGray(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LightSteelBlue(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LightYellow(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Lime(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LimeGreen(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Linen(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Magenta(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Maroon(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MediumAquamarine(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MediumBlue(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MediumOrchid(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MediumPurple(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MediumSeaGreen(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MediumSlateBlue(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MediumSpringGreen(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MediumTurquoise(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MediumVioletRed(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MidnightBlue(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MintCream(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MistyRose(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Moccasin(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_NavajoWhite(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Navy(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_OldLace(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Olive(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_OliveDrab(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Orange(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_OrangeRed(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Orchid(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PaleGoldenrod(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PaleGreen(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PaleTurquoise(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PaleVioletRed(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PapayaWhip(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PeachPuff(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Peru(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Pink(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Plum(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PowderBlue(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Purple(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Red(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RosyBrown(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RoyalBlue(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SaddleBrown(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Salmon(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SandyBrown(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SeaGreen(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SeaShell(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Sienna(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Silver(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SkyBlue(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SlateBlue(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SlateGray(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Snow(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SpringGreen(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SteelBlue(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Tan(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Teal(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Thistle(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Tomato(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Transparent(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Turquoise(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Violet(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Wheat(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_White(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_WhiteSmoke(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Yellow(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_YellowGreen(struct struct_Windows_UI_Color* value) noexcept = 0;
};};

template <> struct abi<Windows::UI::IUIContentRoot>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_UIContext(void** value) noexcept = 0;
};};

template <> struct abi<Windows::UI::IUIContext>{ struct type : IInspectable
{
};};

template <typename D>
struct consume_Windows_UI_IColorHelper
{
};
template <> struct consume<Windows::UI::IColorHelper> { template <typename D> using type = consume_Windows_UI_IColorHelper<D>; };

template <typename D>
struct consume_Windows_UI_IColorHelperStatics
{
    Windows::UI::Color FromArgb(uint8_t a, uint8_t r, uint8_t g, uint8_t b) const;
};
template <> struct consume<Windows::UI::IColorHelperStatics> { template <typename D> using type = consume_Windows_UI_IColorHelperStatics<D>; };

template <typename D>
struct consume_Windows_UI_IColorHelperStatics2
{
    hstring ToDisplayName(Windows::UI::Color const& color) const;
};
template <> struct consume<Windows::UI::IColorHelperStatics2> { template <typename D> using type = consume_Windows_UI_IColorHelperStatics2<D>; };

template <typename D>
struct consume_Windows_UI_IColors
{
};
template <> struct consume<Windows::UI::IColors> { template <typename D> using type = consume_Windows_UI_IColors<D>; };

template <typename D>
struct consume_Windows_UI_IColorsStatics
{
    Windows::UI::Color AliceBlue() const;
    Windows::UI::Color AntiqueWhite() const;
    Windows::UI::Color Aqua() const;
    Windows::UI::Color Aquamarine() const;
    Windows::UI::Color Azure() const;
    Windows::UI::Color Beige() const;
    Windows::UI::Color Bisque() const;
    Windows::UI::Color Black() const;
    Windows::UI::Color BlanchedAlmond() const;
    Windows::UI::Color Blue() const;
    Windows::UI::Color BlueViolet() const;
    Windows::UI::Color Brown() const;
    Windows::UI::Color BurlyWood() const;
    Windows::UI::Color CadetBlue() const;
    Windows::UI::Color Chartreuse() const;
    Windows::UI::Color Chocolate() const;
    Windows::UI::Color Coral() const;
    Windows::UI::Color CornflowerBlue() const;
    Windows::UI::Color Cornsilk() const;
    Windows::UI::Color Crimson() const;
    Windows::UI::Color Cyan() const;
    Windows::UI::Color DarkBlue() const;
    Windows::UI::Color DarkCyan() const;
    Windows::UI::Color DarkGoldenrod() const;
    Windows::UI::Color DarkGray() const;
    Windows::UI::Color DarkGreen() const;
    Windows::UI::Color DarkKhaki() const;
    Windows::UI::Color DarkMagenta() const;
    Windows::UI::Color DarkOliveGreen() const;
    Windows::UI::Color DarkOrange() const;
    Windows::UI::Color DarkOrchid() const;
    Windows::UI::Color DarkRed() const;
    Windows::UI::Color DarkSalmon() const;
    Windows::UI::Color DarkSeaGreen() const;
    Windows::UI::Color DarkSlateBlue() const;
    Windows::UI::Color DarkSlateGray() const;
    Windows::UI::Color DarkTurquoise() const;
    Windows::UI::Color DarkViolet() const;
    Windows::UI::Color DeepPink() const;
    Windows::UI::Color DeepSkyBlue() const;
    Windows::UI::Color DimGray() const;
    Windows::UI::Color DodgerBlue() const;
    Windows::UI::Color Firebrick() const;
    Windows::UI::Color FloralWhite() const;
    Windows::UI::Color ForestGreen() const;
    Windows::UI::Color Fuchsia() const;
    Windows::UI::Color Gainsboro() const;
    Windows::UI::Color GhostWhite() const;
    Windows::UI::Color Gold() const;
    Windows::UI::Color Goldenrod() const;
    Windows::UI::Color Gray() const;
    Windows::UI::Color Green() const;
    Windows::UI::Color GreenYellow() const;
    Windows::UI::Color Honeydew() const;
    Windows::UI::Color HotPink() const;
    Windows::UI::Color IndianRed() const;
    Windows::UI::Color Indigo() const;
    Windows::UI::Color Ivory() const;
    Windows::UI::Color Khaki() const;
    Windows::UI::Color Lavender() const;
    Windows::UI::Color LavenderBlush() const;
    Windows::UI::Color LawnGreen() const;
    Windows::UI::Color LemonChiffon() const;
    Windows::UI::Color LightBlue() const;
    Windows::UI::Color LightCoral() const;
    Windows::UI::Color LightCyan() const;
    Windows::UI::Color LightGoldenrodYellow() const;
    Windows::UI::Color LightGreen() const;
    Windows::UI::Color LightGray() const;
    Windows::UI::Color LightPink() const;
    Windows::UI::Color LightSalmon() const;
    Windows::UI::Color LightSeaGreen() const;
    Windows::UI::Color LightSkyBlue() const;
    Windows::UI::Color LightSlateGray() const;
    Windows::UI::Color LightSteelBlue() const;
    Windows::UI::Color LightYellow() const;
    Windows::UI::Color Lime() const;
    Windows::UI::Color LimeGreen() const;
    Windows::UI::Color Linen() const;
    Windows::UI::Color Magenta() const;
    Windows::UI::Color Maroon() const;
    Windows::UI::Color MediumAquamarine() const;
    Windows::UI::Color MediumBlue() const;
    Windows::UI::Color MediumOrchid() const;
    Windows::UI::Color MediumPurple() const;
    Windows::UI::Color MediumSeaGreen() const;
    Windows::UI::Color MediumSlateBlue() const;
    Windows::UI::Color MediumSpringGreen() const;
    Windows::UI::Color MediumTurquoise() const;
    Windows::UI::Color MediumVioletRed() const;
    Windows::UI::Color MidnightBlue() const;
    Windows::UI::Color MintCream() const;
    Windows::UI::Color MistyRose() const;
    Windows::UI::Color Moccasin() const;
    Windows::UI::Color NavajoWhite() const;
    Windows::UI::Color Navy() const;
    Windows::UI::Color OldLace() const;
    Windows::UI::Color Olive() const;
    Windows::UI::Color OliveDrab() const;
    Windows::UI::Color Orange() const;
    Windows::UI::Color OrangeRed() const;
    Windows::UI::Color Orchid() const;
    Windows::UI::Color PaleGoldenrod() const;
    Windows::UI::Color PaleGreen() const;
    Windows::UI::Color PaleTurquoise() const;
    Windows::UI::Color PaleVioletRed() const;
    Windows::UI::Color PapayaWhip() const;
    Windows::UI::Color PeachPuff() const;
    Windows::UI::Color Peru() const;
    Windows::UI::Color Pink() const;
    Windows::UI::Color Plum() const;
    Windows::UI::Color PowderBlue() const;
    Windows::UI::Color Purple() const;
    Windows::UI::Color Red() const;
    Windows::UI::Color RosyBrown() const;
    Windows::UI::Color RoyalBlue() const;
    Windows::UI::Color SaddleBrown() const;
    Windows::UI::Color Salmon() const;
    Windows::UI::Color SandyBrown() const;
    Windows::UI::Color SeaGreen() const;
    Windows::UI::Color SeaShell() const;
    Windows::UI::Color Sienna() const;
    Windows::UI::Color Silver() const;
    Windows::UI::Color SkyBlue() const;
    Windows::UI::Color SlateBlue() const;
    Windows::UI::Color SlateGray() const;
    Windows::UI::Color Snow() const;
    Windows::UI::Color SpringGreen() const;
    Windows::UI::Color SteelBlue() const;
    Windows::UI::Color Tan() const;
    Windows::UI::Color Teal() const;
    Windows::UI::Color Thistle() const;
    Windows::UI::Color Tomato() const;
    Windows::UI::Color Transparent() const;
    Windows::UI::Color Turquoise() const;
    Windows::UI::Color Violet() const;
    Windows::UI::Color Wheat() const;
    Windows::UI::Color White() const;
    Windows::UI::Color WhiteSmoke() const;
    Windows::UI::Color Yellow() const;
    Windows::UI::Color YellowGreen() const;
};
template <> struct consume<Windows::UI::IColorsStatics> { template <typename D> using type = consume_Windows_UI_IColorsStatics<D>; };

template <typename D>
struct consume_Windows_UI_IUIContentRoot
{
    Windows::UI::UIContext UIContext() const;
};
template <> struct consume<Windows::UI::IUIContentRoot> { template <typename D> using type = consume_Windows_UI_IUIContentRoot<D>; };

template <typename D>
struct consume_Windows_UI_IUIContext
{
};
template <> struct consume<Windows::UI::IUIContext> { template <typename D> using type = consume_Windows_UI_IUIContext<D>; };

struct struct_Windows_UI_Color
{
    uint8_t A;
    uint8_t R;
    uint8_t G;
    uint8_t B;
};
template <> struct abi<Windows::UI::Color>{ using type = struct_Windows_UI_Color; };


}
