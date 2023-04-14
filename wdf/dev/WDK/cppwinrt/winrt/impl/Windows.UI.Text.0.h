// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Foundation {

struct Uri;

}

WINRT_EXPORT namespace winrt::Windows::Storage::Streams {

struct IRandomAccessStream;

}

WINRT_EXPORT namespace winrt::Windows::UI {

struct Color;

}

WINRT_EXPORT namespace winrt::Windows::UI::Text {

enum class CaretType : int32_t
{
    Normal = 0,
    Null = 1,
};

enum class FindOptions : uint32_t
{
    None = 0x0,
    Word = 0x2,
    Case = 0x4,
};

enum class FontStretch : int32_t
{
    Undefined = 0,
    UltraCondensed = 1,
    ExtraCondensed = 2,
    Condensed = 3,
    SemiCondensed = 4,
    Normal = 5,
    SemiExpanded = 6,
    Expanded = 7,
    ExtraExpanded = 8,
    UltraExpanded = 9,
};

enum class FontStyle : int32_t
{
    Normal = 0,
    Oblique = 1,
    Italic = 2,
};

enum class FormatEffect : int32_t
{
    Off = 0,
    On = 1,
    Toggle = 2,
    Undefined = 3,
};

enum class HorizontalCharacterAlignment : int32_t
{
    Left = 0,
    Right = 1,
    Center = 2,
};

enum class LetterCase : int32_t
{
    Lower = 0,
    Upper = 1,
};

enum class LineSpacingRule : int32_t
{
    Undefined = 0,
    Single = 1,
    OneAndHalf = 2,
    Double = 3,
    AtLeast = 4,
    Exactly = 5,
    Multiple = 6,
    Percent = 7,
};

enum class LinkType : int32_t
{
    Undefined = 0,
    NotALink = 1,
    ClientLink = 2,
    FriendlyLinkName = 3,
    FriendlyLinkAddress = 4,
    AutoLink = 5,
    AutoLinkEmail = 6,
    AutoLinkPhone = 7,
    AutoLinkPath = 8,
};

enum class MarkerAlignment : int32_t
{
    Undefined = 0,
    Left = 1,
    Center = 2,
    Right = 3,
};

enum class MarkerStyle : int32_t
{
    Undefined = 0,
    Parenthesis = 1,
    Parentheses = 2,
    Period = 3,
    Plain = 4,
    Minus = 5,
    NoNumber = 6,
};

enum class MarkerType : int32_t
{
    Undefined = 0,
    None = 1,
    Bullet = 2,
    Arabic = 3,
    LowercaseEnglishLetter = 4,
    UppercaseEnglishLetter = 5,
    LowercaseRoman = 6,
    UppercaseRoman = 7,
    UnicodeSequence = 8,
    CircledNumber = 9,
    BlackCircleWingding = 10,
    WhiteCircleWingding = 11,
    ArabicWide = 12,
    SimplifiedChinese = 13,
    TraditionalChinese = 14,
    JapanSimplifiedChinese = 15,
    JapanKorea = 16,
    ArabicDictionary = 17,
    ArabicAbjad = 18,
    Hebrew = 19,
    ThaiAlphabetic = 20,
    ThaiNumeric = 21,
    DevanagariVowel = 22,
    DevanagariConsonant = 23,
    DevanagariNumeric = 24,
};

enum class ParagraphAlignment : int32_t
{
    Undefined = 0,
    Left = 1,
    Center = 2,
    Right = 3,
    Justify = 4,
};

enum class ParagraphStyle : int32_t
{
    Undefined = 0,
    None = 1,
    Normal = 2,
    Heading1 = 3,
    Heading2 = 4,
    Heading3 = 5,
    Heading4 = 6,
    Heading5 = 7,
    Heading6 = 8,
    Heading7 = 9,
    Heading8 = 10,
    Heading9 = 11,
};

enum class PointOptions : uint32_t
{
    None = 0x0,
    IncludeInset = 0x1,
    Start = 0x20,
    ClientCoordinates = 0x100,
    AllowOffClient = 0x200,
    Transform = 0x400,
    NoHorizontalScroll = 0x10000,
    NoVerticalScroll = 0x40000,
};

enum class RangeGravity : int32_t
{
    UIBehavior = 0,
    Backward = 1,
    Forward = 2,
    Inward = 3,
    Outward = 4,
};

enum class SelectionOptions : uint32_t
{
    StartActive = 0x1,
    AtEndOfLine = 0x2,
    Overtype = 0x4,
    Active = 0x8,
    Replace = 0x10,
};

enum class SelectionType : int32_t
{
    None = 0,
    InsertionPoint = 1,
    Normal = 2,
    InlineShape = 7,
    Shape = 8,
};

enum class TabAlignment : int32_t
{
    Left = 0,
    Center = 1,
    Right = 2,
    Decimal = 3,
    Bar = 4,
};

enum class TabLeader : int32_t
{
    Spaces = 0,
    Dots = 1,
    Dashes = 2,
    Lines = 3,
    ThickLines = 4,
    Equals = 5,
};

enum class TextDecorations : uint32_t
{
    None = 0x0,
    Underline = 0x1,
    Strikethrough = 0x2,
};

enum class TextGetOptions : uint32_t
{
    None = 0x0,
    AdjustCrlf = 0x1,
    UseCrlf = 0x2,
    UseObjectText = 0x4,
    AllowFinalEop = 0x8,
    NoHidden = 0x20,
    IncludeNumbering = 0x40,
    FormatRtf = 0x2000,
    UseLf = 0x1000000,
};

enum class TextRangeUnit : int32_t
{
    Character = 0,
    Word = 1,
    Sentence = 2,
    Paragraph = 3,
    Line = 4,
    Story = 5,
    Screen = 6,
    Section = 7,
    Window = 8,
    CharacterFormat = 9,
    ParagraphFormat = 10,
    Object = 11,
    HardParagraph = 12,
    Cluster = 13,
    Bold = 14,
    Italic = 15,
    Underline = 16,
    Strikethrough = 17,
    ProtectedText = 18,
    Link = 19,
    SmallCaps = 20,
    AllCaps = 21,
    Hidden = 22,
    Outline = 23,
    Shadow = 24,
    Imprint = 25,
    Disabled = 26,
    Revised = 27,
    Subscript = 28,
    Superscript = 29,
    FontBound = 30,
    LinkProtected = 31,
    ContentLink = 32,
};

enum class TextScript : int32_t
{
    Undefined = 0,
    Ansi = 1,
    EastEurope = 2,
    Cyrillic = 3,
    Greek = 4,
    Turkish = 5,
    Hebrew = 6,
    Arabic = 7,
    Baltic = 8,
    Vietnamese = 9,
    Default = 10,
    Symbol = 11,
    Thai = 12,
    ShiftJis = 13,
    GB2312 = 14,
    Hangul = 15,
    Big5 = 16,
    PC437 = 17,
    Oem = 18,
    Mac = 19,
    Armenian = 20,
    Syriac = 21,
    Thaana = 22,
    Devanagari = 23,
    Bengali = 24,
    Gurmukhi = 25,
    Gujarati = 26,
    Oriya = 27,
    Tamil = 28,
    Telugu = 29,
    Kannada = 30,
    Malayalam = 31,
    Sinhala = 32,
    Lao = 33,
    Tibetan = 34,
    Myanmar = 35,
    Georgian = 36,
    Jamo = 37,
    Ethiopic = 38,
    Cherokee = 39,
    Aboriginal = 40,
    Ogham = 41,
    Runic = 42,
    Khmer = 43,
    Mongolian = 44,
    Braille = 45,
    Yi = 46,
    Limbu = 47,
    TaiLe = 48,
    NewTaiLue = 49,
    SylotiNagri = 50,
    Kharoshthi = 51,
    Kayahli = 52,
    UnicodeSymbol = 53,
    Emoji = 54,
    Glagolitic = 55,
    Lisu = 56,
    Vai = 57,
    NKo = 58,
    Osmanya = 59,
    PhagsPa = 60,
    Gothic = 61,
    Deseret = 62,
    Tifinagh = 63,
};

enum class TextSetOptions : uint32_t
{
    None = 0x0,
    UnicodeBidi = 0x1,
    Unlink = 0x8,
    Unhide = 0x10,
    CheckTextLimit = 0x20,
    FormatRtf = 0x2000,
    ApplyRtfDocumentDefaults = 0x4000,
};

enum class UnderlineType : int32_t
{
    Undefined = 0,
    None = 1,
    Single = 2,
    Words = 3,
    Double = 4,
    Dotted = 5,
    Dash = 6,
    DashDot = 7,
    DashDotDot = 8,
    Wave = 9,
    Thick = 10,
    Thin = 11,
    DoubleWave = 12,
    HeavyWave = 13,
    LongDash = 14,
    ThickDash = 15,
    ThickDashDot = 16,
    ThickDashDotDot = 17,
    ThickDotted = 18,
    ThickLongDash = 19,
};

enum class VerticalCharacterAlignment : int32_t
{
    Top = 0,
    Baseline = 1,
    Bottom = 2,
};

struct IContentLinkInfo;
struct IFontWeights;
struct IFontWeightsStatics;
struct IRichEditTextRange;
struct ITextCharacterFormat;
struct ITextConstantsStatics;
struct ITextDocument;
struct ITextDocument2;
struct ITextDocument3;
struct ITextParagraphFormat;
struct ITextRange;
struct ITextSelection;
struct ContentLinkInfo;
struct FontWeights;
struct RichEditTextDocument;
struct RichEditTextRange;
struct TextConstants;
struct FontWeight;

}

namespace winrt::impl {

template<> struct is_enum_flag<Windows::UI::Text::FindOptions> : std::true_type {};
template<> struct is_enum_flag<Windows::UI::Text::PointOptions> : std::true_type {};
template<> struct is_enum_flag<Windows::UI::Text::SelectionOptions> : std::true_type {};
template<> struct is_enum_flag<Windows::UI::Text::TextDecorations> : std::true_type {};
template<> struct is_enum_flag<Windows::UI::Text::TextGetOptions> : std::true_type {};
template<> struct is_enum_flag<Windows::UI::Text::TextSetOptions> : std::true_type {};
template <> struct category<Windows::UI::Text::IContentLinkInfo>{ using type = interface_category; };
template <> struct category<Windows::UI::Text::IFontWeights>{ using type = interface_category; };
template <> struct category<Windows::UI::Text::IFontWeightsStatics>{ using type = interface_category; };
template <> struct category<Windows::UI::Text::IRichEditTextRange>{ using type = interface_category; };
template <> struct category<Windows::UI::Text::ITextCharacterFormat>{ using type = interface_category; };
template <> struct category<Windows::UI::Text::ITextConstantsStatics>{ using type = interface_category; };
template <> struct category<Windows::UI::Text::ITextDocument>{ using type = interface_category; };
template <> struct category<Windows::UI::Text::ITextDocument2>{ using type = interface_category; };
template <> struct category<Windows::UI::Text::ITextDocument3>{ using type = interface_category; };
template <> struct category<Windows::UI::Text::ITextParagraphFormat>{ using type = interface_category; };
template <> struct category<Windows::UI::Text::ITextRange>{ using type = interface_category; };
template <> struct category<Windows::UI::Text::ITextSelection>{ using type = interface_category; };
template <> struct category<Windows::UI::Text::ContentLinkInfo>{ using type = class_category; };
template <> struct category<Windows::UI::Text::FontWeights>{ using type = class_category; };
template <> struct category<Windows::UI::Text::RichEditTextDocument>{ using type = class_category; };
template <> struct category<Windows::UI::Text::RichEditTextRange>{ using type = class_category; };
template <> struct category<Windows::UI::Text::TextConstants>{ using type = class_category; };
template <> struct category<Windows::UI::Text::CaretType>{ using type = enum_category; };
template <> struct category<Windows::UI::Text::FindOptions>{ using type = enum_category; };
template <> struct category<Windows::UI::Text::FontStretch>{ using type = enum_category; };
template <> struct category<Windows::UI::Text::FontStyle>{ using type = enum_category; };
template <> struct category<Windows::UI::Text::FormatEffect>{ using type = enum_category; };
template <> struct category<Windows::UI::Text::HorizontalCharacterAlignment>{ using type = enum_category; };
template <> struct category<Windows::UI::Text::LetterCase>{ using type = enum_category; };
template <> struct category<Windows::UI::Text::LineSpacingRule>{ using type = enum_category; };
template <> struct category<Windows::UI::Text::LinkType>{ using type = enum_category; };
template <> struct category<Windows::UI::Text::MarkerAlignment>{ using type = enum_category; };
template <> struct category<Windows::UI::Text::MarkerStyle>{ using type = enum_category; };
template <> struct category<Windows::UI::Text::MarkerType>{ using type = enum_category; };
template <> struct category<Windows::UI::Text::ParagraphAlignment>{ using type = enum_category; };
template <> struct category<Windows::UI::Text::ParagraphStyle>{ using type = enum_category; };
template <> struct category<Windows::UI::Text::PointOptions>{ using type = enum_category; };
template <> struct category<Windows::UI::Text::RangeGravity>{ using type = enum_category; };
template <> struct category<Windows::UI::Text::SelectionOptions>{ using type = enum_category; };
template <> struct category<Windows::UI::Text::SelectionType>{ using type = enum_category; };
template <> struct category<Windows::UI::Text::TabAlignment>{ using type = enum_category; };
template <> struct category<Windows::UI::Text::TabLeader>{ using type = enum_category; };
template <> struct category<Windows::UI::Text::TextDecorations>{ using type = enum_category; };
template <> struct category<Windows::UI::Text::TextGetOptions>{ using type = enum_category; };
template <> struct category<Windows::UI::Text::TextRangeUnit>{ using type = enum_category; };
template <> struct category<Windows::UI::Text::TextScript>{ using type = enum_category; };
template <> struct category<Windows::UI::Text::TextSetOptions>{ using type = enum_category; };
template <> struct category<Windows::UI::Text::UnderlineType>{ using type = enum_category; };
template <> struct category<Windows::UI::Text::VerticalCharacterAlignment>{ using type = enum_category; };
template <> struct category<Windows::UI::Text::FontWeight>{ using type = struct_category<uint16_t>; };
template <> struct name<Windows::UI::Text::IContentLinkInfo>{ static constexpr auto & value{ L"Windows.UI.Text.IContentLinkInfo" }; };
template <> struct name<Windows::UI::Text::IFontWeights>{ static constexpr auto & value{ L"Windows.UI.Text.IFontWeights" }; };
template <> struct name<Windows::UI::Text::IFontWeightsStatics>{ static constexpr auto & value{ L"Windows.UI.Text.IFontWeightsStatics" }; };
template <> struct name<Windows::UI::Text::IRichEditTextRange>{ static constexpr auto & value{ L"Windows.UI.Text.IRichEditTextRange" }; };
template <> struct name<Windows::UI::Text::ITextCharacterFormat>{ static constexpr auto & value{ L"Windows.UI.Text.ITextCharacterFormat" }; };
template <> struct name<Windows::UI::Text::ITextConstantsStatics>{ static constexpr auto & value{ L"Windows.UI.Text.ITextConstantsStatics" }; };
template <> struct name<Windows::UI::Text::ITextDocument>{ static constexpr auto & value{ L"Windows.UI.Text.ITextDocument" }; };
template <> struct name<Windows::UI::Text::ITextDocument2>{ static constexpr auto & value{ L"Windows.UI.Text.ITextDocument2" }; };
template <> struct name<Windows::UI::Text::ITextDocument3>{ static constexpr auto & value{ L"Windows.UI.Text.ITextDocument3" }; };
template <> struct name<Windows::UI::Text::ITextParagraphFormat>{ static constexpr auto & value{ L"Windows.UI.Text.ITextParagraphFormat" }; };
template <> struct name<Windows::UI::Text::ITextRange>{ static constexpr auto & value{ L"Windows.UI.Text.ITextRange" }; };
template <> struct name<Windows::UI::Text::ITextSelection>{ static constexpr auto & value{ L"Windows.UI.Text.ITextSelection" }; };
template <> struct name<Windows::UI::Text::ContentLinkInfo>{ static constexpr auto & value{ L"Windows.UI.Text.ContentLinkInfo" }; };
template <> struct name<Windows::UI::Text::FontWeights>{ static constexpr auto & value{ L"Windows.UI.Text.FontWeights" }; };
template <> struct name<Windows::UI::Text::RichEditTextDocument>{ static constexpr auto & value{ L"Windows.UI.Text.RichEditTextDocument" }; };
template <> struct name<Windows::UI::Text::RichEditTextRange>{ static constexpr auto & value{ L"Windows.UI.Text.RichEditTextRange" }; };
template <> struct name<Windows::UI::Text::TextConstants>{ static constexpr auto & value{ L"Windows.UI.Text.TextConstants" }; };
template <> struct name<Windows::UI::Text::CaretType>{ static constexpr auto & value{ L"Windows.UI.Text.CaretType" }; };
template <> struct name<Windows::UI::Text::FindOptions>{ static constexpr auto & value{ L"Windows.UI.Text.FindOptions" }; };
template <> struct name<Windows::UI::Text::FontStretch>{ static constexpr auto & value{ L"Windows.UI.Text.FontStretch" }; };
template <> struct name<Windows::UI::Text::FontStyle>{ static constexpr auto & value{ L"Windows.UI.Text.FontStyle" }; };
template <> struct name<Windows::UI::Text::FormatEffect>{ static constexpr auto & value{ L"Windows.UI.Text.FormatEffect" }; };
template <> struct name<Windows::UI::Text::HorizontalCharacterAlignment>{ static constexpr auto & value{ L"Windows.UI.Text.HorizontalCharacterAlignment" }; };
template <> struct name<Windows::UI::Text::LetterCase>{ static constexpr auto & value{ L"Windows.UI.Text.LetterCase" }; };
template <> struct name<Windows::UI::Text::LineSpacingRule>{ static constexpr auto & value{ L"Windows.UI.Text.LineSpacingRule" }; };
template <> struct name<Windows::UI::Text::LinkType>{ static constexpr auto & value{ L"Windows.UI.Text.LinkType" }; };
template <> struct name<Windows::UI::Text::MarkerAlignment>{ static constexpr auto & value{ L"Windows.UI.Text.MarkerAlignment" }; };
template <> struct name<Windows::UI::Text::MarkerStyle>{ static constexpr auto & value{ L"Windows.UI.Text.MarkerStyle" }; };
template <> struct name<Windows::UI::Text::MarkerType>{ static constexpr auto & value{ L"Windows.UI.Text.MarkerType" }; };
template <> struct name<Windows::UI::Text::ParagraphAlignment>{ static constexpr auto & value{ L"Windows.UI.Text.ParagraphAlignment" }; };
template <> struct name<Windows::UI::Text::ParagraphStyle>{ static constexpr auto & value{ L"Windows.UI.Text.ParagraphStyle" }; };
template <> struct name<Windows::UI::Text::PointOptions>{ static constexpr auto & value{ L"Windows.UI.Text.PointOptions" }; };
template <> struct name<Windows::UI::Text::RangeGravity>{ static constexpr auto & value{ L"Windows.UI.Text.RangeGravity" }; };
template <> struct name<Windows::UI::Text::SelectionOptions>{ static constexpr auto & value{ L"Windows.UI.Text.SelectionOptions" }; };
template <> struct name<Windows::UI::Text::SelectionType>{ static constexpr auto & value{ L"Windows.UI.Text.SelectionType" }; };
template <> struct name<Windows::UI::Text::TabAlignment>{ static constexpr auto & value{ L"Windows.UI.Text.TabAlignment" }; };
template <> struct name<Windows::UI::Text::TabLeader>{ static constexpr auto & value{ L"Windows.UI.Text.TabLeader" }; };
template <> struct name<Windows::UI::Text::TextDecorations>{ static constexpr auto & value{ L"Windows.UI.Text.TextDecorations" }; };
template <> struct name<Windows::UI::Text::TextGetOptions>{ static constexpr auto & value{ L"Windows.UI.Text.TextGetOptions" }; };
template <> struct name<Windows::UI::Text::TextRangeUnit>{ static constexpr auto & value{ L"Windows.UI.Text.TextRangeUnit" }; };
template <> struct name<Windows::UI::Text::TextScript>{ static constexpr auto & value{ L"Windows.UI.Text.TextScript" }; };
template <> struct name<Windows::UI::Text::TextSetOptions>{ static constexpr auto & value{ L"Windows.UI.Text.TextSetOptions" }; };
template <> struct name<Windows::UI::Text::UnderlineType>{ static constexpr auto & value{ L"Windows.UI.Text.UnderlineType" }; };
template <> struct name<Windows::UI::Text::VerticalCharacterAlignment>{ static constexpr auto & value{ L"Windows.UI.Text.VerticalCharacterAlignment" }; };
template <> struct name<Windows::UI::Text::FontWeight>{ static constexpr auto & value{ L"Windows.UI.Text.FontWeight" }; };
template <> struct guid_storage<Windows::UI::Text::IContentLinkInfo>{ static constexpr guid value{ 0x1ED52525,0x1C5F,0x48CB,{ 0xB3,0x35,0x78,0xB5,0x0A,0x2E,0xE6,0x42 } }; };
template <> struct guid_storage<Windows::UI::Text::IFontWeights>{ static constexpr guid value{ 0x7880A444,0x01AB,0x4997,{ 0x85,0x17,0xDF,0x82,0x2A,0x0C,0x45,0xF1 } }; };
template <> struct guid_storage<Windows::UI::Text::IFontWeightsStatics>{ static constexpr guid value{ 0xB3B579D5,0x1BA9,0x48EB,{ 0x9D,0xAD,0xC0,0x95,0xE8,0xC2,0x3B,0xA3 } }; };
template <> struct guid_storage<Windows::UI::Text::IRichEditTextRange>{ static constexpr guid value{ 0x374E3515,0xBA8A,0x4A6E,{ 0x8C,0x59,0x0D,0xDE,0x3D,0x0C,0xF5,0xCD } }; };
template <> struct guid_storage<Windows::UI::Text::ITextCharacterFormat>{ static constexpr guid value{ 0x5ADEF3DB,0x05FB,0x442D,{ 0x80,0x65,0x64,0x2A,0xFE,0xA0,0x2C,0xED } }; };
template <> struct guid_storage<Windows::UI::Text::ITextConstantsStatics>{ static constexpr guid value{ 0x779E7C33,0x189D,0x4BFA,{ 0x97,0xC8,0x10,0xDB,0x13,0x5D,0x97,0x6E } }; };
template <> struct guid_storage<Windows::UI::Text::ITextDocument>{ static constexpr guid value{ 0xBEEE4DDB,0x90B2,0x408C,{ 0xA2,0xF6,0x0A,0x0A,0xC3,0x1E,0x33,0xE4 } }; };
template <> struct guid_storage<Windows::UI::Text::ITextDocument2>{ static constexpr guid value{ 0xF2311112,0x8C89,0x49C9,{ 0x91,0x18,0xF0,0x57,0xCB,0xB8,0x14,0xEE } }; };
template <> struct guid_storage<Windows::UI::Text::ITextDocument3>{ static constexpr guid value{ 0x75AB03A1,0xA6F8,0x441D,{ 0xAA,0x18,0x0A,0x85,0x1D,0x6E,0x5E,0x3C } }; };
template <> struct guid_storage<Windows::UI::Text::ITextParagraphFormat>{ static constexpr guid value{ 0x2CF8CFA6,0x4676,0x498A,{ 0x93,0xF5,0xBB,0xDB,0xFC,0x0B,0xD8,0x83 } }; };
template <> struct guid_storage<Windows::UI::Text::ITextRange>{ static constexpr guid value{ 0x5B9E4E57,0xC072,0x42A0,{ 0x89,0x45,0xAF,0x50,0x3E,0xE5,0x47,0x68 } }; };
template <> struct guid_storage<Windows::UI::Text::ITextSelection>{ static constexpr guid value{ 0xA6D36724,0xF28F,0x430A,{ 0xB2,0xCF,0xC3,0x43,0x67,0x1E,0xC0,0xE9 } }; };
template <> struct default_interface<Windows::UI::Text::ContentLinkInfo>{ using type = Windows::UI::Text::IContentLinkInfo; };
template <> struct default_interface<Windows::UI::Text::FontWeights>{ using type = Windows::UI::Text::IFontWeights; };
template <> struct default_interface<Windows::UI::Text::RichEditTextDocument>{ using type = Windows::UI::Text::ITextDocument; };
template <> struct default_interface<Windows::UI::Text::RichEditTextRange>{ using type = Windows::UI::Text::ITextRange; };

template <> struct abi<Windows::UI::Text::IContentLinkInfo>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Id(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Id(uint32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DisplayText(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_DisplayText(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SecondaryText(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_SecondaryText(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Uri(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Uri(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LinkContentKind(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_LinkContentKind(void* value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Text::IFontWeights>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::UI::Text::IFontWeightsStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Black(struct struct_Windows_UI_Text_FontWeight* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Bold(struct struct_Windows_UI_Text_FontWeight* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ExtraBlack(struct struct_Windows_UI_Text_FontWeight* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ExtraBold(struct struct_Windows_UI_Text_FontWeight* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ExtraLight(struct struct_Windows_UI_Text_FontWeight* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Light(struct struct_Windows_UI_Text_FontWeight* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Medium(struct struct_Windows_UI_Text_FontWeight* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Normal(struct struct_Windows_UI_Text_FontWeight* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SemiBold(struct struct_Windows_UI_Text_FontWeight* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SemiLight(struct struct_Windows_UI_Text_FontWeight* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Thin(struct struct_Windows_UI_Text_FontWeight* value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Text::IRichEditTextRange>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ContentLinkInfo(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ContentLinkInfo(void* value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Text::ITextCharacterFormat>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_AllCaps(Windows::UI::Text::FormatEffect* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_AllCaps(Windows::UI::Text::FormatEffect value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BackgroundColor(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_BackgroundColor(struct struct_Windows_UI_Color value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Bold(Windows::UI::Text::FormatEffect* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Bold(Windows::UI::Text::FormatEffect value) noexcept = 0;
    virtual int32_t WINRT_CALL get_FontStretch(Windows::UI::Text::FontStretch* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_FontStretch(Windows::UI::Text::FontStretch value) noexcept = 0;
    virtual int32_t WINRT_CALL get_FontStyle(Windows::UI::Text::FontStyle* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_FontStyle(Windows::UI::Text::FontStyle value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ForegroundColor(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ForegroundColor(struct struct_Windows_UI_Color value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Hidden(Windows::UI::Text::FormatEffect* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Hidden(Windows::UI::Text::FormatEffect value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Italic(Windows::UI::Text::FormatEffect* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Italic(Windows::UI::Text::FormatEffect value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Kerning(float* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Kerning(float value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LanguageTag(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_LanguageTag(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LinkType(Windows::UI::Text::LinkType* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Name(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Name(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Outline(Windows::UI::Text::FormatEffect* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Outline(Windows::UI::Text::FormatEffect value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Position(float* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Position(float value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ProtectedText(Windows::UI::Text::FormatEffect* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ProtectedText(Windows::UI::Text::FormatEffect value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Size(float* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Size(float value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SmallCaps(Windows::UI::Text::FormatEffect* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_SmallCaps(Windows::UI::Text::FormatEffect value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Spacing(float* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Spacing(float value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Strikethrough(Windows::UI::Text::FormatEffect* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Strikethrough(Windows::UI::Text::FormatEffect value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Subscript(Windows::UI::Text::FormatEffect* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Subscript(Windows::UI::Text::FormatEffect value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Superscript(Windows::UI::Text::FormatEffect* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Superscript(Windows::UI::Text::FormatEffect value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TextScript(Windows::UI::Text::TextScript* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_TextScript(Windows::UI::Text::TextScript value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Underline(Windows::UI::Text::UnderlineType* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Underline(Windows::UI::Text::UnderlineType value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Weight(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Weight(int32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL SetClone(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL GetClone(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL IsEqual(void* format, bool* result) noexcept = 0;
};};

template <> struct abi<Windows::UI::Text::ITextConstantsStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_AutoColor(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MinUnitCount(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MaxUnitCount(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_UndefinedColor(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_UndefinedFloatValue(float* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_UndefinedInt32Value(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_UndefinedFontStretch(Windows::UI::Text::FontStretch* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_UndefinedFontStyle(Windows::UI::Text::FontStyle* value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Text::ITextDocument>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_CaretType(Windows::UI::Text::CaretType* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_CaretType(Windows::UI::Text::CaretType value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DefaultTabStop(float* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_DefaultTabStop(float value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Selection(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_UndoLimit(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_UndoLimit(uint32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL CanCopy(bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL CanPaste(bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL CanRedo(bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL CanUndo(bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL ApplyDisplayUpdates(int32_t* result) noexcept = 0;
    virtual int32_t WINRT_CALL BatchDisplayUpdates(int32_t* result) noexcept = 0;
    virtual int32_t WINRT_CALL BeginUndoGroup() noexcept = 0;
    virtual int32_t WINRT_CALL EndUndoGroup() noexcept = 0;
    virtual int32_t WINRT_CALL GetDefaultCharacterFormat(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL GetDefaultParagraphFormat(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL GetRange(int32_t startPosition, int32_t endPosition, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL GetRangeFromPoint(Windows::Foundation::Point point, Windows::UI::Text::PointOptions options, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL GetText(Windows::UI::Text::TextGetOptions options, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL LoadFromStream(Windows::UI::Text::TextSetOptions options, void* value) noexcept = 0;
    virtual int32_t WINRT_CALL Redo() noexcept = 0;
    virtual int32_t WINRT_CALL SaveToStream(Windows::UI::Text::TextGetOptions options, void* value) noexcept = 0;
    virtual int32_t WINRT_CALL SetDefaultCharacterFormat(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL SetDefaultParagraphFormat(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL SetText(Windows::UI::Text::TextSetOptions options, void* value) noexcept = 0;
    virtual int32_t WINRT_CALL Undo() noexcept = 0;
};};

template <> struct abi<Windows::UI::Text::ITextDocument2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_AlignmentIncludesTrailingWhitespace(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_AlignmentIncludesTrailingWhitespace(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IgnoreTrailingCharacterSpacing(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IgnoreTrailingCharacterSpacing(bool value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Text::ITextDocument3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL ClearUndoRedoHistory() noexcept = 0;
};};

template <> struct abi<Windows::UI::Text::ITextParagraphFormat>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Alignment(Windows::UI::Text::ParagraphAlignment* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Alignment(Windows::UI::Text::ParagraphAlignment value) noexcept = 0;
    virtual int32_t WINRT_CALL get_FirstLineIndent(float* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_KeepTogether(Windows::UI::Text::FormatEffect* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_KeepTogether(Windows::UI::Text::FormatEffect value) noexcept = 0;
    virtual int32_t WINRT_CALL get_KeepWithNext(Windows::UI::Text::FormatEffect* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_KeepWithNext(Windows::UI::Text::FormatEffect value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LeftIndent(float* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LineSpacing(float* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LineSpacingRule(Windows::UI::Text::LineSpacingRule* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ListAlignment(Windows::UI::Text::MarkerAlignment* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ListAlignment(Windows::UI::Text::MarkerAlignment value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ListLevelIndex(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ListLevelIndex(int32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ListStart(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ListStart(int32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ListStyle(Windows::UI::Text::MarkerStyle* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ListStyle(Windows::UI::Text::MarkerStyle value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ListTab(float* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ListTab(float value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ListType(Windows::UI::Text::MarkerType* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ListType(Windows::UI::Text::MarkerType value) noexcept = 0;
    virtual int32_t WINRT_CALL get_NoLineNumber(Windows::UI::Text::FormatEffect* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_NoLineNumber(Windows::UI::Text::FormatEffect value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PageBreakBefore(Windows::UI::Text::FormatEffect* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_PageBreakBefore(Windows::UI::Text::FormatEffect value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RightIndent(float* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_RightIndent(float value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RightToLeft(Windows::UI::Text::FormatEffect* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_RightToLeft(Windows::UI::Text::FormatEffect value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Style(Windows::UI::Text::ParagraphStyle* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Style(Windows::UI::Text::ParagraphStyle value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SpaceAfter(float* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_SpaceAfter(float value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SpaceBefore(float* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_SpaceBefore(float value) noexcept = 0;
    virtual int32_t WINRT_CALL get_WidowControl(Windows::UI::Text::FormatEffect* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_WidowControl(Windows::UI::Text::FormatEffect value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TabCount(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL AddTab(float position, Windows::UI::Text::TabAlignment align, Windows::UI::Text::TabLeader leader) noexcept = 0;
    virtual int32_t WINRT_CALL ClearAllTabs() noexcept = 0;
    virtual int32_t WINRT_CALL DeleteTab(float position) noexcept = 0;
    virtual int32_t WINRT_CALL GetClone(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL GetTab(int32_t index, float* position, Windows::UI::Text::TabAlignment* align, Windows::UI::Text::TabLeader* leader) noexcept = 0;
    virtual int32_t WINRT_CALL IsEqual(void* format, bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL SetClone(void* format) noexcept = 0;
    virtual int32_t WINRT_CALL SetIndents(float start, float left, float right) noexcept = 0;
    virtual int32_t WINRT_CALL SetLineSpacing(Windows::UI::Text::LineSpacingRule rule, float spacing) noexcept = 0;
};};

template <> struct abi<Windows::UI::Text::ITextRange>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Character(char16_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Character(char16_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CharacterFormat(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_CharacterFormat(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_FormattedText(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_FormattedText(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_EndPosition(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_EndPosition(int32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Gravity(Windows::UI::Text::RangeGravity* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Gravity(Windows::UI::Text::RangeGravity value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Length(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Link(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Link(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ParagraphFormat(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ParagraphFormat(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_StartPosition(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_StartPosition(int32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_StoryLength(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Text(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Text(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL CanPaste(int32_t format, bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL ChangeCase(Windows::UI::Text::LetterCase value) noexcept = 0;
    virtual int32_t WINRT_CALL Collapse(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL Copy() noexcept = 0;
    virtual int32_t WINRT_CALL Cut() noexcept = 0;
    virtual int32_t WINRT_CALL Delete(Windows::UI::Text::TextRangeUnit unit, int32_t count, int32_t* result) noexcept = 0;
    virtual int32_t WINRT_CALL EndOf(Windows::UI::Text::TextRangeUnit unit, bool extend, int32_t* result) noexcept = 0;
    virtual int32_t WINRT_CALL Expand(Windows::UI::Text::TextRangeUnit unit, int32_t* result) noexcept = 0;
    virtual int32_t WINRT_CALL FindText(void* value, int32_t scanLength, Windows::UI::Text::FindOptions options, int32_t* result) noexcept = 0;
    virtual int32_t WINRT_CALL GetCharacterUtf32(uint32_t* value, int32_t offset) noexcept = 0;
    virtual int32_t WINRT_CALL GetClone(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL GetIndex(Windows::UI::Text::TextRangeUnit unit, int32_t* result) noexcept = 0;
    virtual int32_t WINRT_CALL GetPoint(Windows::UI::Text::HorizontalCharacterAlignment horizontalAlign, Windows::UI::Text::VerticalCharacterAlignment verticalAlign, Windows::UI::Text::PointOptions options, Windows::Foundation::Point* point) noexcept = 0;
    virtual int32_t WINRT_CALL GetRect(Windows::UI::Text::PointOptions options, Windows::Foundation::Rect* rect, int32_t* hit) noexcept = 0;
    virtual int32_t WINRT_CALL GetText(Windows::UI::Text::TextGetOptions options, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetTextViaStream(Windows::UI::Text::TextGetOptions options, void* value) noexcept = 0;
    virtual int32_t WINRT_CALL InRange(void* range, bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL InsertImage(int32_t width, int32_t height, int32_t ascent, Windows::UI::Text::VerticalCharacterAlignment verticalAlign, void* alternateText, void* value) noexcept = 0;
    virtual int32_t WINRT_CALL InStory(void* range, bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL IsEqual(void* range, bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL Move(Windows::UI::Text::TextRangeUnit unit, int32_t count, int32_t* result) noexcept = 0;
    virtual int32_t WINRT_CALL MoveEnd(Windows::UI::Text::TextRangeUnit unit, int32_t count, int32_t* result) noexcept = 0;
    virtual int32_t WINRT_CALL MoveStart(Windows::UI::Text::TextRangeUnit unit, int32_t count, int32_t* result) noexcept = 0;
    virtual int32_t WINRT_CALL Paste(int32_t format) noexcept = 0;
    virtual int32_t WINRT_CALL ScrollIntoView(Windows::UI::Text::PointOptions value) noexcept = 0;
    virtual int32_t WINRT_CALL MatchSelection() noexcept = 0;
    virtual int32_t WINRT_CALL SetIndex(Windows::UI::Text::TextRangeUnit unit, int32_t index, bool extend) noexcept = 0;
    virtual int32_t WINRT_CALL SetPoint(Windows::Foundation::Point point, Windows::UI::Text::PointOptions options, bool extend) noexcept = 0;
    virtual int32_t WINRT_CALL SetRange(int32_t startPosition, int32_t endPosition) noexcept = 0;
    virtual int32_t WINRT_CALL SetText(Windows::UI::Text::TextSetOptions options, void* value) noexcept = 0;
    virtual int32_t WINRT_CALL SetTextViaStream(Windows::UI::Text::TextSetOptions options, void* value) noexcept = 0;
    virtual int32_t WINRT_CALL StartOf(Windows::UI::Text::TextRangeUnit unit, bool extend, int32_t* result) noexcept = 0;
};};

template <> struct abi<Windows::UI::Text::ITextSelection>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Options(Windows::UI::Text::SelectionOptions* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Options(Windows::UI::Text::SelectionOptions value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Type(Windows::UI::Text::SelectionType* value) noexcept = 0;
    virtual int32_t WINRT_CALL EndKey(Windows::UI::Text::TextRangeUnit unit, bool extend, int32_t* result) noexcept = 0;
    virtual int32_t WINRT_CALL HomeKey(Windows::UI::Text::TextRangeUnit unit, bool extend, int32_t* result) noexcept = 0;
    virtual int32_t WINRT_CALL MoveDown(Windows::UI::Text::TextRangeUnit unit, int32_t count, bool extend, int32_t* result) noexcept = 0;
    virtual int32_t WINRT_CALL MoveLeft(Windows::UI::Text::TextRangeUnit unit, int32_t count, bool extend, int32_t* result) noexcept = 0;
    virtual int32_t WINRT_CALL MoveRight(Windows::UI::Text::TextRangeUnit unit, int32_t count, bool extend, int32_t* result) noexcept = 0;
    virtual int32_t WINRT_CALL MoveUp(Windows::UI::Text::TextRangeUnit unit, int32_t count, bool extend, int32_t* result) noexcept = 0;
    virtual int32_t WINRT_CALL TypeText(void* value) noexcept = 0;
};};

template <typename D>
struct consume_Windows_UI_Text_IContentLinkInfo
{
    uint32_t Id() const;
    void Id(uint32_t value) const;
    hstring DisplayText() const;
    void DisplayText(param::hstring const& value) const;
    hstring SecondaryText() const;
    void SecondaryText(param::hstring const& value) const;
    Windows::Foundation::Uri Uri() const;
    void Uri(Windows::Foundation::Uri const& value) const;
    hstring LinkContentKind() const;
    void LinkContentKind(param::hstring const& value) const;
};
template <> struct consume<Windows::UI::Text::IContentLinkInfo> { template <typename D> using type = consume_Windows_UI_Text_IContentLinkInfo<D>; };

template <typename D>
struct consume_Windows_UI_Text_IFontWeights
{
};
template <> struct consume<Windows::UI::Text::IFontWeights> { template <typename D> using type = consume_Windows_UI_Text_IFontWeights<D>; };

template <typename D>
struct consume_Windows_UI_Text_IFontWeightsStatics
{
    Windows::UI::Text::FontWeight Black() const;
    Windows::UI::Text::FontWeight Bold() const;
    Windows::UI::Text::FontWeight ExtraBlack() const;
    Windows::UI::Text::FontWeight ExtraBold() const;
    Windows::UI::Text::FontWeight ExtraLight() const;
    Windows::UI::Text::FontWeight Light() const;
    Windows::UI::Text::FontWeight Medium() const;
    Windows::UI::Text::FontWeight Normal() const;
    Windows::UI::Text::FontWeight SemiBold() const;
    Windows::UI::Text::FontWeight SemiLight() const;
    Windows::UI::Text::FontWeight Thin() const;
};
template <> struct consume<Windows::UI::Text::IFontWeightsStatics> { template <typename D> using type = consume_Windows_UI_Text_IFontWeightsStatics<D>; };

template <typename D>
struct consume_Windows_UI_Text_IRichEditTextRange
{
    Windows::UI::Text::ContentLinkInfo ContentLinkInfo() const;
    void ContentLinkInfo(Windows::UI::Text::ContentLinkInfo const& value) const;
};
template <> struct consume<Windows::UI::Text::IRichEditTextRange> { template <typename D> using type = consume_Windows_UI_Text_IRichEditTextRange<D>; };

template <typename D>
struct consume_Windows_UI_Text_ITextCharacterFormat
{
    Windows::UI::Text::FormatEffect AllCaps() const;
    void AllCaps(Windows::UI::Text::FormatEffect const& value) const;
    Windows::UI::Color BackgroundColor() const;
    void BackgroundColor(Windows::UI::Color const& value) const;
    Windows::UI::Text::FormatEffect Bold() const;
    void Bold(Windows::UI::Text::FormatEffect const& value) const;
    Windows::UI::Text::FontStretch FontStretch() const;
    void FontStretch(Windows::UI::Text::FontStretch const& value) const;
    Windows::UI::Text::FontStyle FontStyle() const;
    void FontStyle(Windows::UI::Text::FontStyle const& value) const;
    Windows::UI::Color ForegroundColor() const;
    void ForegroundColor(Windows::UI::Color const& value) const;
    Windows::UI::Text::FormatEffect Hidden() const;
    void Hidden(Windows::UI::Text::FormatEffect const& value) const;
    Windows::UI::Text::FormatEffect Italic() const;
    void Italic(Windows::UI::Text::FormatEffect const& value) const;
    float Kerning() const;
    void Kerning(float value) const;
    hstring LanguageTag() const;
    void LanguageTag(param::hstring const& value) const;
    Windows::UI::Text::LinkType LinkType() const;
    hstring Name() const;
    void Name(param::hstring const& value) const;
    Windows::UI::Text::FormatEffect Outline() const;
    void Outline(Windows::UI::Text::FormatEffect const& value) const;
    float Position() const;
    void Position(float value) const;
    Windows::UI::Text::FormatEffect ProtectedText() const;
    void ProtectedText(Windows::UI::Text::FormatEffect const& value) const;
    float Size() const;
    void Size(float value) const;
    Windows::UI::Text::FormatEffect SmallCaps() const;
    void SmallCaps(Windows::UI::Text::FormatEffect const& value) const;
    float Spacing() const;
    void Spacing(float value) const;
    Windows::UI::Text::FormatEffect Strikethrough() const;
    void Strikethrough(Windows::UI::Text::FormatEffect const& value) const;
    Windows::UI::Text::FormatEffect Subscript() const;
    void Subscript(Windows::UI::Text::FormatEffect const& value) const;
    Windows::UI::Text::FormatEffect Superscript() const;
    void Superscript(Windows::UI::Text::FormatEffect const& value) const;
    Windows::UI::Text::TextScript TextScript() const;
    void TextScript(Windows::UI::Text::TextScript const& value) const;
    Windows::UI::Text::UnderlineType Underline() const;
    void Underline(Windows::UI::Text::UnderlineType const& value) const;
    int32_t Weight() const;
    void Weight(int32_t value) const;
    void SetClone(Windows::UI::Text::ITextCharacterFormat const& value) const;
    Windows::UI::Text::ITextCharacterFormat GetClone() const;
    bool IsEqual(Windows::UI::Text::ITextCharacterFormat const& format) const;
};
template <> struct consume<Windows::UI::Text::ITextCharacterFormat> { template <typename D> using type = consume_Windows_UI_Text_ITextCharacterFormat<D>; };

template <typename D>
struct consume_Windows_UI_Text_ITextConstantsStatics
{
    Windows::UI::Color AutoColor() const;
    int32_t MinUnitCount() const;
    int32_t MaxUnitCount() const;
    Windows::UI::Color UndefinedColor() const;
    float UndefinedFloatValue() const;
    int32_t UndefinedInt32Value() const;
    Windows::UI::Text::FontStretch UndefinedFontStretch() const;
    Windows::UI::Text::FontStyle UndefinedFontStyle() const;
};
template <> struct consume<Windows::UI::Text::ITextConstantsStatics> { template <typename D> using type = consume_Windows_UI_Text_ITextConstantsStatics<D>; };

template <typename D>
struct consume_Windows_UI_Text_ITextDocument
{
    Windows::UI::Text::CaretType CaretType() const;
    void CaretType(Windows::UI::Text::CaretType const& value) const;
    float DefaultTabStop() const;
    void DefaultTabStop(float value) const;
    Windows::UI::Text::ITextSelection Selection() const;
    uint32_t UndoLimit() const;
    void UndoLimit(uint32_t value) const;
    bool CanCopy() const;
    bool CanPaste() const;
    bool CanRedo() const;
    bool CanUndo() const;
    int32_t ApplyDisplayUpdates() const;
    int32_t BatchDisplayUpdates() const;
    void BeginUndoGroup() const;
    void EndUndoGroup() const;
    Windows::UI::Text::ITextCharacterFormat GetDefaultCharacterFormat() const;
    Windows::UI::Text::ITextParagraphFormat GetDefaultParagraphFormat() const;
    Windows::UI::Text::ITextRange GetRange(int32_t startPosition, int32_t endPosition) const;
    Windows::UI::Text::ITextRange GetRangeFromPoint(Windows::Foundation::Point const& point, Windows::UI::Text::PointOptions const& options) const;
    void GetText(Windows::UI::Text::TextGetOptions const& options, hstring& value) const;
    void LoadFromStream(Windows::UI::Text::TextSetOptions const& options, Windows::Storage::Streams::IRandomAccessStream const& value) const;
    void Redo() const;
    void SaveToStream(Windows::UI::Text::TextGetOptions const& options, Windows::Storage::Streams::IRandomAccessStream const& value) const;
    void SetDefaultCharacterFormat(Windows::UI::Text::ITextCharacterFormat const& value) const;
    void SetDefaultParagraphFormat(Windows::UI::Text::ITextParagraphFormat const& value) const;
    void SetText(Windows::UI::Text::TextSetOptions const& options, param::hstring const& value) const;
    void Undo() const;
};
template <> struct consume<Windows::UI::Text::ITextDocument> { template <typename D> using type = consume_Windows_UI_Text_ITextDocument<D>; };

template <typename D>
struct consume_Windows_UI_Text_ITextDocument2
{
    bool AlignmentIncludesTrailingWhitespace() const;
    void AlignmentIncludesTrailingWhitespace(bool value) const;
    bool IgnoreTrailingCharacterSpacing() const;
    void IgnoreTrailingCharacterSpacing(bool value) const;
};
template <> struct consume<Windows::UI::Text::ITextDocument2> { template <typename D> using type = consume_Windows_UI_Text_ITextDocument2<D>; };

template <typename D>
struct consume_Windows_UI_Text_ITextDocument3
{
    void ClearUndoRedoHistory() const;
};
template <> struct consume<Windows::UI::Text::ITextDocument3> { template <typename D> using type = consume_Windows_UI_Text_ITextDocument3<D>; };

template <typename D>
struct consume_Windows_UI_Text_ITextParagraphFormat
{
    Windows::UI::Text::ParagraphAlignment Alignment() const;
    void Alignment(Windows::UI::Text::ParagraphAlignment const& value) const;
    float FirstLineIndent() const;
    Windows::UI::Text::FormatEffect KeepTogether() const;
    void KeepTogether(Windows::UI::Text::FormatEffect const& value) const;
    Windows::UI::Text::FormatEffect KeepWithNext() const;
    void KeepWithNext(Windows::UI::Text::FormatEffect const& value) const;
    float LeftIndent() const;
    float LineSpacing() const;
    Windows::UI::Text::LineSpacingRule LineSpacingRule() const;
    Windows::UI::Text::MarkerAlignment ListAlignment() const;
    void ListAlignment(Windows::UI::Text::MarkerAlignment const& value) const;
    int32_t ListLevelIndex() const;
    void ListLevelIndex(int32_t value) const;
    int32_t ListStart() const;
    void ListStart(int32_t value) const;
    Windows::UI::Text::MarkerStyle ListStyle() const;
    void ListStyle(Windows::UI::Text::MarkerStyle const& value) const;
    float ListTab() const;
    void ListTab(float value) const;
    Windows::UI::Text::MarkerType ListType() const;
    void ListType(Windows::UI::Text::MarkerType const& value) const;
    Windows::UI::Text::FormatEffect NoLineNumber() const;
    void NoLineNumber(Windows::UI::Text::FormatEffect const& value) const;
    Windows::UI::Text::FormatEffect PageBreakBefore() const;
    void PageBreakBefore(Windows::UI::Text::FormatEffect const& value) const;
    float RightIndent() const;
    void RightIndent(float value) const;
    Windows::UI::Text::FormatEffect RightToLeft() const;
    void RightToLeft(Windows::UI::Text::FormatEffect const& value) const;
    Windows::UI::Text::ParagraphStyle Style() const;
    void Style(Windows::UI::Text::ParagraphStyle const& value) const;
    float SpaceAfter() const;
    void SpaceAfter(float value) const;
    float SpaceBefore() const;
    void SpaceBefore(float value) const;
    Windows::UI::Text::FormatEffect WidowControl() const;
    void WidowControl(Windows::UI::Text::FormatEffect const& value) const;
    int32_t TabCount() const;
    void AddTab(float position, Windows::UI::Text::TabAlignment const& align, Windows::UI::Text::TabLeader const& leader) const;
    void ClearAllTabs() const;
    void DeleteTab(float position) const;
    Windows::UI::Text::ITextParagraphFormat GetClone() const;
    void GetTab(int32_t index, float& position, Windows::UI::Text::TabAlignment& align, Windows::UI::Text::TabLeader& leader) const;
    bool IsEqual(Windows::UI::Text::ITextParagraphFormat const& format) const;
    void SetClone(Windows::UI::Text::ITextParagraphFormat const& format) const;
    void SetIndents(float start, float left, float right) const;
    void SetLineSpacing(Windows::UI::Text::LineSpacingRule const& rule, float spacing) const;
};
template <> struct consume<Windows::UI::Text::ITextParagraphFormat> { template <typename D> using type = consume_Windows_UI_Text_ITextParagraphFormat<D>; };

template <typename D>
struct consume_Windows_UI_Text_ITextRange
{
    char16_t Character() const;
    void Character(char16_t value) const;
    Windows::UI::Text::ITextCharacterFormat CharacterFormat() const;
    void CharacterFormat(Windows::UI::Text::ITextCharacterFormat const& value) const;
    Windows::UI::Text::ITextRange FormattedText() const;
    void FormattedText(Windows::UI::Text::ITextRange const& value) const;
    int32_t EndPosition() const;
    void EndPosition(int32_t value) const;
    Windows::UI::Text::RangeGravity Gravity() const;
    void Gravity(Windows::UI::Text::RangeGravity const& value) const;
    int32_t Length() const;
    hstring Link() const;
    void Link(param::hstring const& value) const;
    Windows::UI::Text::ITextParagraphFormat ParagraphFormat() const;
    void ParagraphFormat(Windows::UI::Text::ITextParagraphFormat const& value) const;
    int32_t StartPosition() const;
    void StartPosition(int32_t value) const;
    int32_t StoryLength() const;
    hstring Text() const;
    void Text(param::hstring const& value) const;
    bool CanPaste(int32_t format) const;
    void ChangeCase(Windows::UI::Text::LetterCase const& value) const;
    void Collapse(bool value) const;
    void Copy() const;
    void Cut() const;
    int32_t Delete(Windows::UI::Text::TextRangeUnit const& unit, int32_t count) const;
    int32_t EndOf(Windows::UI::Text::TextRangeUnit const& unit, bool extend) const;
    int32_t Expand(Windows::UI::Text::TextRangeUnit const& unit) const;
    int32_t FindText(param::hstring const& value, int32_t scanLength, Windows::UI::Text::FindOptions const& options) const;
    void GetCharacterUtf32(uint32_t& value, int32_t offset) const;
    Windows::UI::Text::ITextRange GetClone() const;
    int32_t GetIndex(Windows::UI::Text::TextRangeUnit const& unit) const;
    void GetPoint(Windows::UI::Text::HorizontalCharacterAlignment const& horizontalAlign, Windows::UI::Text::VerticalCharacterAlignment const& verticalAlign, Windows::UI::Text::PointOptions const& options, Windows::Foundation::Point& point) const;
    void GetRect(Windows::UI::Text::PointOptions const& options, Windows::Foundation::Rect& rect, int32_t& hit) const;
    void GetText(Windows::UI::Text::TextGetOptions const& options, hstring& value) const;
    void GetTextViaStream(Windows::UI::Text::TextGetOptions const& options, Windows::Storage::Streams::IRandomAccessStream const& value) const;
    bool InRange(Windows::UI::Text::ITextRange const& range) const;
    void InsertImage(int32_t width, int32_t height, int32_t ascent, Windows::UI::Text::VerticalCharacterAlignment const& verticalAlign, param::hstring const& alternateText, Windows::Storage::Streams::IRandomAccessStream const& value) const;
    bool InStory(Windows::UI::Text::ITextRange const& range) const;
    bool IsEqual(Windows::UI::Text::ITextRange const& range) const;
    int32_t Move(Windows::UI::Text::TextRangeUnit const& unit, int32_t count) const;
    int32_t MoveEnd(Windows::UI::Text::TextRangeUnit const& unit, int32_t count) const;
    int32_t MoveStart(Windows::UI::Text::TextRangeUnit const& unit, int32_t count) const;
    void Paste(int32_t format) const;
    void ScrollIntoView(Windows::UI::Text::PointOptions const& value) const;
    void MatchSelection() const;
    void SetIndex(Windows::UI::Text::TextRangeUnit const& unit, int32_t index, bool extend) const;
    void SetPoint(Windows::Foundation::Point const& point, Windows::UI::Text::PointOptions const& options, bool extend) const;
    void SetRange(int32_t startPosition, int32_t endPosition) const;
    void SetText(Windows::UI::Text::TextSetOptions const& options, param::hstring const& value) const;
    void SetTextViaStream(Windows::UI::Text::TextSetOptions const& options, Windows::Storage::Streams::IRandomAccessStream const& value) const;
    int32_t StartOf(Windows::UI::Text::TextRangeUnit const& unit, bool extend) const;
};
template <> struct consume<Windows::UI::Text::ITextRange> { template <typename D> using type = consume_Windows_UI_Text_ITextRange<D>; };

template <typename D>
struct consume_Windows_UI_Text_ITextSelection
{
    Windows::UI::Text::SelectionOptions Options() const;
    void Options(Windows::UI::Text::SelectionOptions const& value) const;
    Windows::UI::Text::SelectionType Type() const;
    int32_t EndKey(Windows::UI::Text::TextRangeUnit const& unit, bool extend) const;
    int32_t HomeKey(Windows::UI::Text::TextRangeUnit const& unit, bool extend) const;
    int32_t MoveDown(Windows::UI::Text::TextRangeUnit const& unit, int32_t count, bool extend) const;
    int32_t MoveLeft(Windows::UI::Text::TextRangeUnit const& unit, int32_t count, bool extend) const;
    int32_t MoveRight(Windows::UI::Text::TextRangeUnit const& unit, int32_t count, bool extend) const;
    int32_t MoveUp(Windows::UI::Text::TextRangeUnit const& unit, int32_t count, bool extend) const;
    void TypeText(param::hstring const& value) const;
};
template <> struct consume<Windows::UI::Text::ITextSelection> { template <typename D> using type = consume_Windows_UI_Text_ITextSelection<D>; };

struct struct_Windows_UI_Text_FontWeight
{
    uint16_t Weight;
};
template <> struct abi<Windows::UI::Text::FontWeight>{ using type = struct_Windows_UI_Text_FontWeight; };


}
