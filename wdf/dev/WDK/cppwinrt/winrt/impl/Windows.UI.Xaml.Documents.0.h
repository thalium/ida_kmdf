// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Foundation {

struct Uri;

}

WINRT_EXPORT namespace winrt::Windows::UI::Core {

enum class CoreCursorType;

}

WINRT_EXPORT namespace winrt::Windows::UI::Text {

enum class FontStretch;
enum class FontStyle;
enum class TextDecorations : unsigned;
struct ContentLinkInfo;
struct FontWeight;

}

WINRT_EXPORT namespace winrt::Windows::UI::Xaml {

enum class ElementSoundMode;
enum class FlowDirection;
enum class FocusState;
enum class FontCapitals;
enum class FontEastAsianLanguage;
enum class FontEastAsianWidths;
enum class FontFraction;
enum class FontNumeralAlignment;
enum class FontNumeralStyle;
enum class FontVariants;
enum class LineStackingStrategy;
enum class TextAlignment;
struct DependencyObject;
struct DependencyProperty;
struct FrameworkElement;
struct RoutedEventHandler;
struct Thickness;
struct UIElement;
struct XamlRoot;

}

WINRT_EXPORT namespace winrt::Windows::UI::Xaml::Input {

enum class KeyTipPlacementMode;
enum class XYFocusNavigationStrategy;
struct AccessKeyDisplayDismissedEventArgs;
struct AccessKeyDisplayRequestedEventArgs;
struct AccessKeyInvokedEventArgs;

}

WINRT_EXPORT namespace winrt::Windows::UI::Xaml::Media {

enum class StyleSimulations;
struct Brush;
struct FontFamily;

}

WINRT_EXPORT namespace winrt::Windows::UI::Xaml::Documents {

enum class LogicalDirection : int32_t
{
    Backward = 0,
    Forward = 1,
};

enum class UnderlineStyle : int32_t
{
    None = 0,
    Single = 1,
};

struct IBlock;
struct IBlock2;
struct IBlockFactory;
struct IBlockStatics;
struct IBlockStatics2;
struct IBold;
struct IContactContentLinkProvider;
struct IContentLink;
struct IContentLinkInvokedEventArgs;
struct IContentLinkProvider;
struct IContentLinkProviderCollection;
struct IContentLinkProviderFactory;
struct IContentLinkStatics;
struct IGlyphs;
struct IGlyphs2;
struct IGlyphsStatics;
struct IGlyphsStatics2;
struct IHyperlink;
struct IHyperlink2;
struct IHyperlink3;
struct IHyperlink4;
struct IHyperlink5;
struct IHyperlinkClickEventArgs;
struct IHyperlinkStatics;
struct IHyperlinkStatics2;
struct IHyperlinkStatics3;
struct IHyperlinkStatics4;
struct IHyperlinkStatics5;
struct IInline;
struct IInlineFactory;
struct IInlineUIContainer;
struct IItalic;
struct ILineBreak;
struct IParagraph;
struct IParagraphStatics;
struct IPlaceContentLinkProvider;
struct IRun;
struct IRunStatics;
struct ISpan;
struct ISpanFactory;
struct ITextElement;
struct ITextElement2;
struct ITextElement3;
struct ITextElement4;
struct ITextElement5;
struct ITextElementFactory;
struct ITextElementOverrides;
struct ITextElementStatics;
struct ITextElementStatics2;
struct ITextElementStatics3;
struct ITextElementStatics4;
struct ITextHighlighter;
struct ITextHighlighterBase;
struct ITextHighlighterBaseFactory;
struct ITextHighlighterFactory;
struct ITextHighlighterStatics;
struct ITextPointer;
struct ITypography;
struct ITypographyStatics;
struct IUnderline;
struct Block;
struct BlockCollection;
struct Bold;
struct ContactContentLinkProvider;
struct ContentLink;
struct ContentLinkInvokedEventArgs;
struct ContentLinkProvider;
struct ContentLinkProviderCollection;
struct Glyphs;
struct Hyperlink;
struct HyperlinkClickEventArgs;
struct Inline;
struct InlineCollection;
struct InlineUIContainer;
struct Italic;
struct LineBreak;
struct Paragraph;
struct PlaceContentLinkProvider;
struct Run;
struct Span;
struct TextElement;
struct TextHighlighter;
struct TextHighlighterBase;
struct TextPointer;
struct Typography;
struct Underline;
struct TextRange;

}

namespace winrt::impl {

template <> struct category<Windows::UI::Xaml::Documents::IBlock>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Documents::IBlock2>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Documents::IBlockFactory>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Documents::IBlockStatics>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Documents::IBlockStatics2>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Documents::IBold>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Documents::IContactContentLinkProvider>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Documents::IContentLink>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Documents::IContentLinkInvokedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Documents::IContentLinkProvider>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Documents::IContentLinkProviderCollection>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Documents::IContentLinkProviderFactory>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Documents::IContentLinkStatics>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Documents::IGlyphs>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Documents::IGlyphs2>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Documents::IGlyphsStatics>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Documents::IGlyphsStatics2>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Documents::IHyperlink>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Documents::IHyperlink2>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Documents::IHyperlink3>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Documents::IHyperlink4>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Documents::IHyperlink5>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Documents::IHyperlinkClickEventArgs>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Documents::IHyperlinkStatics>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Documents::IHyperlinkStatics2>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Documents::IHyperlinkStatics3>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Documents::IHyperlinkStatics4>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Documents::IHyperlinkStatics5>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Documents::IInline>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Documents::IInlineFactory>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Documents::IInlineUIContainer>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Documents::IItalic>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Documents::ILineBreak>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Documents::IParagraph>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Documents::IParagraphStatics>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Documents::IPlaceContentLinkProvider>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Documents::IRun>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Documents::IRunStatics>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Documents::ISpan>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Documents::ISpanFactory>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Documents::ITextElement>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Documents::ITextElement2>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Documents::ITextElement3>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Documents::ITextElement4>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Documents::ITextElement5>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Documents::ITextElementFactory>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Documents::ITextElementOverrides>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Documents::ITextElementStatics>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Documents::ITextElementStatics2>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Documents::ITextElementStatics3>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Documents::ITextElementStatics4>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Documents::ITextHighlighter>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Documents::ITextHighlighterBase>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Documents::ITextHighlighterBaseFactory>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Documents::ITextHighlighterFactory>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Documents::ITextHighlighterStatics>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Documents::ITextPointer>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Documents::ITypography>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Documents::ITypographyStatics>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Documents::IUnderline>{ using type = interface_category; };
template <> struct category<Windows::UI::Xaml::Documents::Block>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Documents::BlockCollection>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Documents::Bold>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Documents::ContactContentLinkProvider>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Documents::ContentLink>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Documents::ContentLinkInvokedEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Documents::ContentLinkProvider>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Documents::ContentLinkProviderCollection>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Documents::Glyphs>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Documents::Hyperlink>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Documents::HyperlinkClickEventArgs>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Documents::Inline>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Documents::InlineCollection>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Documents::InlineUIContainer>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Documents::Italic>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Documents::LineBreak>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Documents::Paragraph>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Documents::PlaceContentLinkProvider>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Documents::Run>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Documents::Span>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Documents::TextElement>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Documents::TextHighlighter>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Documents::TextHighlighterBase>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Documents::TextPointer>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Documents::Typography>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Documents::Underline>{ using type = class_category; };
template <> struct category<Windows::UI::Xaml::Documents::LogicalDirection>{ using type = enum_category; };
template <> struct category<Windows::UI::Xaml::Documents::UnderlineStyle>{ using type = enum_category; };
template <> struct category<Windows::UI::Xaml::Documents::TextRange>{ using type = struct_category<int32_t,int32_t>; };
template <> struct name<Windows::UI::Xaml::Documents::IBlock>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.IBlock" }; };
template <> struct name<Windows::UI::Xaml::Documents::IBlock2>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.IBlock2" }; };
template <> struct name<Windows::UI::Xaml::Documents::IBlockFactory>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.IBlockFactory" }; };
template <> struct name<Windows::UI::Xaml::Documents::IBlockStatics>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.IBlockStatics" }; };
template <> struct name<Windows::UI::Xaml::Documents::IBlockStatics2>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.IBlockStatics2" }; };
template <> struct name<Windows::UI::Xaml::Documents::IBold>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.IBold" }; };
template <> struct name<Windows::UI::Xaml::Documents::IContactContentLinkProvider>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.IContactContentLinkProvider" }; };
template <> struct name<Windows::UI::Xaml::Documents::IContentLink>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.IContentLink" }; };
template <> struct name<Windows::UI::Xaml::Documents::IContentLinkInvokedEventArgs>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.IContentLinkInvokedEventArgs" }; };
template <> struct name<Windows::UI::Xaml::Documents::IContentLinkProvider>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.IContentLinkProvider" }; };
template <> struct name<Windows::UI::Xaml::Documents::IContentLinkProviderCollection>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.IContentLinkProviderCollection" }; };
template <> struct name<Windows::UI::Xaml::Documents::IContentLinkProviderFactory>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.IContentLinkProviderFactory" }; };
template <> struct name<Windows::UI::Xaml::Documents::IContentLinkStatics>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.IContentLinkStatics" }; };
template <> struct name<Windows::UI::Xaml::Documents::IGlyphs>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.IGlyphs" }; };
template <> struct name<Windows::UI::Xaml::Documents::IGlyphs2>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.IGlyphs2" }; };
template <> struct name<Windows::UI::Xaml::Documents::IGlyphsStatics>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.IGlyphsStatics" }; };
template <> struct name<Windows::UI::Xaml::Documents::IGlyphsStatics2>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.IGlyphsStatics2" }; };
template <> struct name<Windows::UI::Xaml::Documents::IHyperlink>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.IHyperlink" }; };
template <> struct name<Windows::UI::Xaml::Documents::IHyperlink2>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.IHyperlink2" }; };
template <> struct name<Windows::UI::Xaml::Documents::IHyperlink3>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.IHyperlink3" }; };
template <> struct name<Windows::UI::Xaml::Documents::IHyperlink4>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.IHyperlink4" }; };
template <> struct name<Windows::UI::Xaml::Documents::IHyperlink5>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.IHyperlink5" }; };
template <> struct name<Windows::UI::Xaml::Documents::IHyperlinkClickEventArgs>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.IHyperlinkClickEventArgs" }; };
template <> struct name<Windows::UI::Xaml::Documents::IHyperlinkStatics>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.IHyperlinkStatics" }; };
template <> struct name<Windows::UI::Xaml::Documents::IHyperlinkStatics2>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.IHyperlinkStatics2" }; };
template <> struct name<Windows::UI::Xaml::Documents::IHyperlinkStatics3>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.IHyperlinkStatics3" }; };
template <> struct name<Windows::UI::Xaml::Documents::IHyperlinkStatics4>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.IHyperlinkStatics4" }; };
template <> struct name<Windows::UI::Xaml::Documents::IHyperlinkStatics5>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.IHyperlinkStatics5" }; };
template <> struct name<Windows::UI::Xaml::Documents::IInline>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.IInline" }; };
template <> struct name<Windows::UI::Xaml::Documents::IInlineFactory>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.IInlineFactory" }; };
template <> struct name<Windows::UI::Xaml::Documents::IInlineUIContainer>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.IInlineUIContainer" }; };
template <> struct name<Windows::UI::Xaml::Documents::IItalic>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.IItalic" }; };
template <> struct name<Windows::UI::Xaml::Documents::ILineBreak>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.ILineBreak" }; };
template <> struct name<Windows::UI::Xaml::Documents::IParagraph>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.IParagraph" }; };
template <> struct name<Windows::UI::Xaml::Documents::IParagraphStatics>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.IParagraphStatics" }; };
template <> struct name<Windows::UI::Xaml::Documents::IPlaceContentLinkProvider>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.IPlaceContentLinkProvider" }; };
template <> struct name<Windows::UI::Xaml::Documents::IRun>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.IRun" }; };
template <> struct name<Windows::UI::Xaml::Documents::IRunStatics>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.IRunStatics" }; };
template <> struct name<Windows::UI::Xaml::Documents::ISpan>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.ISpan" }; };
template <> struct name<Windows::UI::Xaml::Documents::ISpanFactory>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.ISpanFactory" }; };
template <> struct name<Windows::UI::Xaml::Documents::ITextElement>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.ITextElement" }; };
template <> struct name<Windows::UI::Xaml::Documents::ITextElement2>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.ITextElement2" }; };
template <> struct name<Windows::UI::Xaml::Documents::ITextElement3>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.ITextElement3" }; };
template <> struct name<Windows::UI::Xaml::Documents::ITextElement4>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.ITextElement4" }; };
template <> struct name<Windows::UI::Xaml::Documents::ITextElement5>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.ITextElement5" }; };
template <> struct name<Windows::UI::Xaml::Documents::ITextElementFactory>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.ITextElementFactory" }; };
template <> struct name<Windows::UI::Xaml::Documents::ITextElementOverrides>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.ITextElementOverrides" }; };
template <> struct name<Windows::UI::Xaml::Documents::ITextElementStatics>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.ITextElementStatics" }; };
template <> struct name<Windows::UI::Xaml::Documents::ITextElementStatics2>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.ITextElementStatics2" }; };
template <> struct name<Windows::UI::Xaml::Documents::ITextElementStatics3>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.ITextElementStatics3" }; };
template <> struct name<Windows::UI::Xaml::Documents::ITextElementStatics4>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.ITextElementStatics4" }; };
template <> struct name<Windows::UI::Xaml::Documents::ITextHighlighter>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.ITextHighlighter" }; };
template <> struct name<Windows::UI::Xaml::Documents::ITextHighlighterBase>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.ITextHighlighterBase" }; };
template <> struct name<Windows::UI::Xaml::Documents::ITextHighlighterBaseFactory>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.ITextHighlighterBaseFactory" }; };
template <> struct name<Windows::UI::Xaml::Documents::ITextHighlighterFactory>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.ITextHighlighterFactory" }; };
template <> struct name<Windows::UI::Xaml::Documents::ITextHighlighterStatics>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.ITextHighlighterStatics" }; };
template <> struct name<Windows::UI::Xaml::Documents::ITextPointer>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.ITextPointer" }; };
template <> struct name<Windows::UI::Xaml::Documents::ITypography>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.ITypography" }; };
template <> struct name<Windows::UI::Xaml::Documents::ITypographyStatics>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.ITypographyStatics" }; };
template <> struct name<Windows::UI::Xaml::Documents::IUnderline>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.IUnderline" }; };
template <> struct name<Windows::UI::Xaml::Documents::Block>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.Block" }; };
template <> struct name<Windows::UI::Xaml::Documents::BlockCollection>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.BlockCollection" }; };
template <> struct name<Windows::UI::Xaml::Documents::Bold>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.Bold" }; };
template <> struct name<Windows::UI::Xaml::Documents::ContactContentLinkProvider>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.ContactContentLinkProvider" }; };
template <> struct name<Windows::UI::Xaml::Documents::ContentLink>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.ContentLink" }; };
template <> struct name<Windows::UI::Xaml::Documents::ContentLinkInvokedEventArgs>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.ContentLinkInvokedEventArgs" }; };
template <> struct name<Windows::UI::Xaml::Documents::ContentLinkProvider>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.ContentLinkProvider" }; };
template <> struct name<Windows::UI::Xaml::Documents::ContentLinkProviderCollection>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.ContentLinkProviderCollection" }; };
template <> struct name<Windows::UI::Xaml::Documents::Glyphs>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.Glyphs" }; };
template <> struct name<Windows::UI::Xaml::Documents::Hyperlink>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.Hyperlink" }; };
template <> struct name<Windows::UI::Xaml::Documents::HyperlinkClickEventArgs>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.HyperlinkClickEventArgs" }; };
template <> struct name<Windows::UI::Xaml::Documents::Inline>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.Inline" }; };
template <> struct name<Windows::UI::Xaml::Documents::InlineCollection>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.InlineCollection" }; };
template <> struct name<Windows::UI::Xaml::Documents::InlineUIContainer>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.InlineUIContainer" }; };
template <> struct name<Windows::UI::Xaml::Documents::Italic>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.Italic" }; };
template <> struct name<Windows::UI::Xaml::Documents::LineBreak>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.LineBreak" }; };
template <> struct name<Windows::UI::Xaml::Documents::Paragraph>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.Paragraph" }; };
template <> struct name<Windows::UI::Xaml::Documents::PlaceContentLinkProvider>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.PlaceContentLinkProvider" }; };
template <> struct name<Windows::UI::Xaml::Documents::Run>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.Run" }; };
template <> struct name<Windows::UI::Xaml::Documents::Span>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.Span" }; };
template <> struct name<Windows::UI::Xaml::Documents::TextElement>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.TextElement" }; };
template <> struct name<Windows::UI::Xaml::Documents::TextHighlighter>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.TextHighlighter" }; };
template <> struct name<Windows::UI::Xaml::Documents::TextHighlighterBase>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.TextHighlighterBase" }; };
template <> struct name<Windows::UI::Xaml::Documents::TextPointer>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.TextPointer" }; };
template <> struct name<Windows::UI::Xaml::Documents::Typography>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.Typography" }; };
template <> struct name<Windows::UI::Xaml::Documents::Underline>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.Underline" }; };
template <> struct name<Windows::UI::Xaml::Documents::LogicalDirection>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.LogicalDirection" }; };
template <> struct name<Windows::UI::Xaml::Documents::UnderlineStyle>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.UnderlineStyle" }; };
template <> struct name<Windows::UI::Xaml::Documents::TextRange>{ static constexpr auto & value{ L"Windows.UI.Xaml.Documents.TextRange" }; };
template <> struct guid_storage<Windows::UI::Xaml::Documents::IBlock>{ static constexpr guid value{ 0x4BCE0016,0xDD47,0x4350,{ 0x8C,0xB0,0xE1,0x71,0x60,0x0A,0xC8,0x96 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Documents::IBlock2>{ static constexpr guid value{ 0x5EC7BDF3,0x1333,0x4A92,{ 0x83,0x18,0x6C,0xAE,0xDC,0x12,0xEF,0x89 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Documents::IBlockFactory>{ static constexpr guid value{ 0x07110532,0x4F59,0x4F3B,{ 0x9C,0xE5,0x25,0x78,0x4C,0x43,0x05,0x07 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Documents::IBlockStatics>{ static constexpr guid value{ 0xF86A8C34,0x8D18,0x4C53,{ 0xAE,0xBD,0x91,0xE6,0x10,0xA5,0xE0,0x10 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Documents::IBlockStatics2>{ static constexpr guid value{ 0xAF01A4D6,0x03E3,0x4CEE,{ 0x9B,0x02,0x2B,0xFC,0x30,0x8B,0x27,0xA9 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Documents::IBold>{ static constexpr guid value{ 0xADE73784,0x1B59,0x4DA4,{ 0xBB,0x23,0x0F,0x20,0xE8,0x85,0xB4,0xBF } }; };
template <> struct guid_storage<Windows::UI::Xaml::Documents::IContactContentLinkProvider>{ static constexpr guid value{ 0xF92FD29B,0x589B,0x4ABD,{ 0x9D,0x37,0x35,0xA1,0x46,0x8F,0x02,0x1E } }; };
template <> struct guid_storage<Windows::UI::Xaml::Documents::IContentLink>{ static constexpr guid value{ 0x6C60C3E1,0x528C,0x42F8,{ 0x92,0xBE,0x34,0xB8,0xC6,0x8B,0xE3,0x04 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Documents::IContentLinkInvokedEventArgs>{ static constexpr guid value{ 0x546717C1,0xE8DF,0x4593,{ 0x96,0x39,0x97,0x59,0x5F,0xDF,0x83,0x10 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Documents::IContentLinkProvider>{ static constexpr guid value{ 0x730587FD,0xBFDC,0x4CB3,{ 0x90,0x4D,0xB6,0x5A,0xB3,0x39,0xBB,0xF5 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Documents::IContentLinkProviderCollection>{ static constexpr guid value{ 0xF5B84D0C,0xA9F4,0x4D1A,{ 0xA1,0x3C,0x10,0xDE,0xF1,0x84,0x37,0x34 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Documents::IContentLinkProviderFactory>{ static constexpr guid value{ 0x57D60D3B,0xEF1A,0x4E8E,{ 0x83,0x9B,0xD3,0x6E,0xF3,0xA5,0x03,0xE0 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Documents::IContentLinkStatics>{ static constexpr guid value{ 0xA34E3063,0xEB16,0x484E,{ 0xA3,0xDF,0x52,0x2B,0x9A,0x83,0x2E,0x6E } }; };
template <> struct guid_storage<Windows::UI::Xaml::Documents::IGlyphs>{ static constexpr guid value{ 0xD079498B,0xF2B1,0x4281,{ 0x99,0xA2,0xE4,0xD0,0x59,0x32,0xB2,0xB5 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Documents::IGlyphs2>{ static constexpr guid value{ 0xAA8BFE5C,0x3754,0x4BEE,{ 0xBB,0xE1,0x44,0x03,0xEE,0x9B,0x86,0xF0 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Documents::IGlyphsStatics>{ static constexpr guid value{ 0x225CF4C5,0xFDF1,0x43ED,{ 0x95,0x8F,0x41,0x4E,0x86,0xF1,0x03,0xF2 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Documents::IGlyphsStatics2>{ static constexpr guid value{ 0x10489AA7,0x1615,0x4A33,{ 0xAA,0x02,0xD7,0xEF,0x2A,0xEF,0xC7,0x39 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Documents::IHyperlink>{ static constexpr guid value{ 0x0FE2363B,0x14E9,0x4152,{ 0x9E,0x58,0x5A,0xEA,0x5B,0x21,0xF0,0x8D } }; };
template <> struct guid_storage<Windows::UI::Xaml::Documents::IHyperlink2>{ static constexpr guid value{ 0x4CE9DA5F,0x7CFF,0x4291,{ 0xB7,0x8F,0xDF,0xEC,0x72,0x49,0x05,0x76 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Documents::IHyperlink3>{ static constexpr guid value{ 0xC3F157D9,0xE5D3,0x4FB7,{ 0x87,0x02,0x4F,0x6D,0x85,0xDD,0x9E,0x0A } }; };
template <> struct guid_storage<Windows::UI::Xaml::Documents::IHyperlink4>{ static constexpr guid value{ 0xF7D02959,0x82FB,0x400A,{ 0xA4,0x07,0x5A,0x4E,0xE6,0x77,0x98,0x8A } }; };
template <> struct guid_storage<Windows::UI::Xaml::Documents::IHyperlink5>{ static constexpr guid value{ 0x607DD7D2,0x0945,0x4328,{ 0x91,0xEE,0x94,0xCC,0xEC,0x2E,0xA6,0xC3 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Documents::IHyperlinkClickEventArgs>{ static constexpr guid value{ 0xC755916B,0x7BDC,0x4BE7,{ 0xB3,0x73,0x92,0x40,0xA5,0x03,0xD8,0x70 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Documents::IHyperlinkStatics>{ static constexpr guid value{ 0x3A44D3D4,0xFD41,0x41DB,{ 0x8C,0x72,0x3B,0x79,0x0A,0xCD,0x9F,0xD3 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Documents::IHyperlinkStatics2>{ static constexpr guid value{ 0x5028D8B7,0x7ADF,0x43EE,{ 0xA4,0xAE,0x9C,0x92,0x5F,0x75,0x57,0x16 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Documents::IHyperlinkStatics3>{ static constexpr guid value{ 0x3E15DEA0,0x205E,0x4947,{ 0x99,0xA5,0x74,0xE7,0x57,0xE8,0xE1,0xB4 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Documents::IHyperlinkStatics4>{ static constexpr guid value{ 0x0476B378,0x8FAA,0x4E24,{ 0xB3,0xB6,0xE9,0xDE,0x4D,0x3C,0x70,0x8C } }; };
template <> struct guid_storage<Windows::UI::Xaml::Documents::IHyperlinkStatics5>{ static constexpr guid value{ 0x59308CEA,0x1E49,0x4921,{ 0xBD,0x88,0xA2,0x87,0x8D,0x07,0xE3,0x0E } }; };
template <> struct guid_storage<Windows::UI::Xaml::Documents::IInline>{ static constexpr guid value{ 0x0C92712D,0x1BC9,0x4931,{ 0x8C,0xB1,0x1A,0xEA,0xDF,0x1C,0xC6,0x85 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Documents::IInlineFactory>{ static constexpr guid value{ 0x4058ACD1,0x2F90,0x4B8F,{ 0x99,0xDD,0x42,0x18,0xEF,0x5F,0x03,0xDE } }; };
template <> struct guid_storage<Windows::UI::Xaml::Documents::IInlineUIContainer>{ static constexpr guid value{ 0x1416CE81,0x28EE,0x452E,{ 0xB1,0x21,0x5F,0xC4,0xF6,0x0B,0x86,0xA6 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Documents::IItalic>{ static constexpr guid value{ 0x91F4619C,0xFCBB,0x4157,{ 0x80,0x2C,0x76,0xF6,0x3B,0x5F,0xB6,0x57 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Documents::ILineBreak>{ static constexpr guid value{ 0x645589C4,0xF769,0x41ED,{ 0x89,0x5B,0x8A,0x1B,0x2F,0xB3,0x15,0x62 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Documents::IParagraph>{ static constexpr guid value{ 0xF83EF59A,0xFA61,0x4BEF,{ 0xAE,0x33,0x0B,0x0A,0xD7,0x56,0xA8,0x4D } }; };
template <> struct guid_storage<Windows::UI::Xaml::Documents::IParagraphStatics>{ static constexpr guid value{ 0xEF08889A,0x535B,0x4E4C,{ 0x8D,0x84,0x28,0x3B,0x33,0xE9,0x8A,0x37 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Documents::IPlaceContentLinkProvider>{ static constexpr guid value{ 0x10348A4C,0x2366,0x41BE,{ 0x90,0xC8,0x32,0x58,0xB5,0x3B,0x54,0x83 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Documents::IRun>{ static constexpr guid value{ 0x59553C83,0x0E14,0x49BD,{ 0xB8,0x4B,0xC5,0x26,0xF3,0x03,0x43,0x49 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Documents::IRunStatics>{ static constexpr guid value{ 0xE9303CEF,0x65A0,0x4B8D,{ 0xA7,0xF7,0x8F,0xDB,0x28,0x7B,0x46,0xF3 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Documents::ISpan>{ static constexpr guid value{ 0x9839D4A9,0x02AF,0x4811,{ 0xAA,0x15,0x6B,0xEF,0x3A,0xCA,0xC9,0x7A } }; };
template <> struct guid_storage<Windows::UI::Xaml::Documents::ISpanFactory>{ static constexpr guid value{ 0x5B916F5C,0xCD2D,0x40C0,{ 0x95,0x6A,0x38,0x64,0x48,0x32,0x2F,0x79 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Documents::ITextElement>{ static constexpr guid value{ 0xE83B0062,0xD776,0x4F92,{ 0xBA,0xEA,0x40,0xE7,0x7D,0x47,0x91,0xD5 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Documents::ITextElement2>{ static constexpr guid value{ 0xA8076AA8,0xF892,0x49F6,{ 0x8C,0xD2,0x89,0xAD,0xDA,0xF0,0x6D,0x2D } }; };
template <> struct guid_storage<Windows::UI::Xaml::Documents::ITextElement3>{ static constexpr guid value{ 0xD1DB340F,0x1BC4,0x4CA8,{ 0xBC,0xF7,0x77,0x0B,0xFF,0x9B,0x27,0xAB } }; };
template <> struct guid_storage<Windows::UI::Xaml::Documents::ITextElement4>{ static constexpr guid value{ 0xB196E222,0xCA0E,0x48A9,{ 0x83,0xBC,0x36,0xCE,0x50,0x56,0x6A,0xC7 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Documents::ITextElement5>{ static constexpr guid value{ 0xBD9552F3,0x540D,0x58BF,{ 0xB6,0xA8,0x07,0x55,0x6A,0xED,0xA2,0xEA } }; };
template <> struct guid_storage<Windows::UI::Xaml::Documents::ITextElementFactory>{ static constexpr guid value{ 0x35007285,0xCF47,0x4BFE,{ 0xB1,0xBC,0x39,0xC9,0x3A,0xF4,0xAE,0x80 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Documents::ITextElementOverrides>{ static constexpr guid value{ 0x0CE21EE7,0x4F76,0x4DD9,{ 0xBF,0x91,0x16,0x3B,0xEC,0xCF,0x84,0xBC } }; };
template <> struct guid_storage<Windows::UI::Xaml::Documents::ITextElementStatics>{ static constexpr guid value{ 0x0A2F9B98,0x6C03,0x4470,{ 0xA7,0x9B,0x32,0x98,0xA1,0x04,0x82,0xCE } }; };
template <> struct guid_storage<Windows::UI::Xaml::Documents::ITextElementStatics2>{ static constexpr guid value{ 0x164297B2,0x982B,0x49E1,{ 0x8C,0x03,0xCA,0x43,0xBC,0x4D,0x5B,0x6D } }; };
template <> struct guid_storage<Windows::UI::Xaml::Documents::ITextElementStatics3>{ static constexpr guid value{ 0xCFEFCFAF,0x0FA1,0x45EC,{ 0x9A,0x4E,0x9B,0x33,0x66,0x4D,0xC8,0xB1 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Documents::ITextElementStatics4>{ static constexpr guid value{ 0xFD8F641E,0x6B12,0x40D5,{ 0xB6,0xEF,0xD1,0xBD,0x12,0xAC,0x90,0x66 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Documents::ITextHighlighter>{ static constexpr guid value{ 0xBA6CB54B,0x7D75,0x4535,{ 0xB3,0x0D,0xA8,0x1A,0x00,0xB6,0x37,0xA4 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Documents::ITextHighlighterBase>{ static constexpr guid value{ 0xD957601A,0x5F0D,0x4CDF,{ 0x97,0x58,0x97,0xE0,0xEB,0x95,0xC8,0xFA } }; };
template <> struct guid_storage<Windows::UI::Xaml::Documents::ITextHighlighterBaseFactory>{ static constexpr guid value{ 0x9592B2D0,0xEADC,0x4C74,{ 0x92,0xC8,0x6E,0x89,0x6E,0x22,0x50,0x6D } }; };
template <> struct guid_storage<Windows::UI::Xaml::Documents::ITextHighlighterFactory>{ static constexpr guid value{ 0x70125461,0x9A8F,0x4FA0,{ 0xB2,0x35,0x8F,0xFA,0xA5,0x07,0xBE,0xF2 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Documents::ITextHighlighterStatics>{ static constexpr guid value{ 0xB3B009C4,0x3A7E,0x49CC,{ 0xAB,0x84,0x29,0xC4,0x05,0x48,0x87,0x65 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Documents::ITextPointer>{ static constexpr guid value{ 0xAC687AA1,0x6A41,0x43FF,{ 0x85,0x1E,0x45,0x34,0x8A,0xA2,0xCF,0x7B } }; };
template <> struct guid_storage<Windows::UI::Xaml::Documents::ITypography>{ static constexpr guid value{ 0x866F65D5,0xEA97,0x42AB,{ 0x92,0x88,0x9C,0x01,0xAE,0xBC,0x7A,0x97 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Documents::ITypographyStatics>{ static constexpr guid value{ 0x67B9EC88,0x6C57,0x4CE0,{ 0x95,0xF1,0xD4,0xB9,0xED,0x63,0x2F,0xB4 } }; };
template <> struct guid_storage<Windows::UI::Xaml::Documents::IUnderline>{ static constexpr guid value{ 0xA5FA8202,0x61C0,0x47D7,{ 0x93,0xEF,0xBC,0x0B,0x57,0x7C,0x5F,0x26 } }; };
template <> struct default_interface<Windows::UI::Xaml::Documents::Block>{ using type = Windows::UI::Xaml::Documents::IBlock; };
template <> struct default_interface<Windows::UI::Xaml::Documents::BlockCollection>{ using type = Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Documents::Block>; };
template <> struct default_interface<Windows::UI::Xaml::Documents::Bold>{ using type = Windows::UI::Xaml::Documents::IBold; };
template <> struct default_interface<Windows::UI::Xaml::Documents::ContactContentLinkProvider>{ using type = Windows::UI::Xaml::Documents::IContactContentLinkProvider; };
template <> struct default_interface<Windows::UI::Xaml::Documents::ContentLink>{ using type = Windows::UI::Xaml::Documents::IContentLink; };
template <> struct default_interface<Windows::UI::Xaml::Documents::ContentLinkInvokedEventArgs>{ using type = Windows::UI::Xaml::Documents::IContentLinkInvokedEventArgs; };
template <> struct default_interface<Windows::UI::Xaml::Documents::ContentLinkProvider>{ using type = Windows::UI::Xaml::Documents::IContentLinkProvider; };
template <> struct default_interface<Windows::UI::Xaml::Documents::ContentLinkProviderCollection>{ using type = Windows::UI::Xaml::Documents::IContentLinkProviderCollection; };
template <> struct default_interface<Windows::UI::Xaml::Documents::Glyphs>{ using type = Windows::UI::Xaml::Documents::IGlyphs; };
template <> struct default_interface<Windows::UI::Xaml::Documents::Hyperlink>{ using type = Windows::UI::Xaml::Documents::IHyperlink; };
template <> struct default_interface<Windows::UI::Xaml::Documents::HyperlinkClickEventArgs>{ using type = Windows::UI::Xaml::Documents::IHyperlinkClickEventArgs; };
template <> struct default_interface<Windows::UI::Xaml::Documents::Inline>{ using type = Windows::UI::Xaml::Documents::IInline; };
template <> struct default_interface<Windows::UI::Xaml::Documents::InlineCollection>{ using type = Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Documents::Inline>; };
template <> struct default_interface<Windows::UI::Xaml::Documents::InlineUIContainer>{ using type = Windows::UI::Xaml::Documents::IInlineUIContainer; };
template <> struct default_interface<Windows::UI::Xaml::Documents::Italic>{ using type = Windows::UI::Xaml::Documents::IItalic; };
template <> struct default_interface<Windows::UI::Xaml::Documents::LineBreak>{ using type = Windows::UI::Xaml::Documents::ILineBreak; };
template <> struct default_interface<Windows::UI::Xaml::Documents::Paragraph>{ using type = Windows::UI::Xaml::Documents::IParagraph; };
template <> struct default_interface<Windows::UI::Xaml::Documents::PlaceContentLinkProvider>{ using type = Windows::UI::Xaml::Documents::IPlaceContentLinkProvider; };
template <> struct default_interface<Windows::UI::Xaml::Documents::Run>{ using type = Windows::UI::Xaml::Documents::IRun; };
template <> struct default_interface<Windows::UI::Xaml::Documents::Span>{ using type = Windows::UI::Xaml::Documents::ISpan; };
template <> struct default_interface<Windows::UI::Xaml::Documents::TextElement>{ using type = Windows::UI::Xaml::Documents::ITextElement; };
template <> struct default_interface<Windows::UI::Xaml::Documents::TextHighlighter>{ using type = Windows::UI::Xaml::Documents::ITextHighlighter; };
template <> struct default_interface<Windows::UI::Xaml::Documents::TextHighlighterBase>{ using type = Windows::UI::Xaml::Documents::ITextHighlighterBase; };
template <> struct default_interface<Windows::UI::Xaml::Documents::TextPointer>{ using type = Windows::UI::Xaml::Documents::ITextPointer; };
template <> struct default_interface<Windows::UI::Xaml::Documents::Typography>{ using type = Windows::UI::Xaml::Documents::ITypography; };
template <> struct default_interface<Windows::UI::Xaml::Documents::Underline>{ using type = Windows::UI::Xaml::Documents::IUnderline; };

template <> struct abi<Windows::UI::Xaml::Documents::IBlock>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_TextAlignment(Windows::UI::Xaml::TextAlignment* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_TextAlignment(Windows::UI::Xaml::TextAlignment value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LineHeight(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_LineHeight(double value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LineStackingStrategy(Windows::UI::Xaml::LineStackingStrategy* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_LineStackingStrategy(Windows::UI::Xaml::LineStackingStrategy value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Margin(struct struct_Windows_UI_Xaml_Thickness* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Margin(struct struct_Windows_UI_Xaml_Thickness value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Documents::IBlock2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_HorizontalTextAlignment(Windows::UI::Xaml::TextAlignment* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_HorizontalTextAlignment(Windows::UI::Xaml::TextAlignment value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Documents::IBlockFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Documents::IBlockStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_TextAlignmentProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LineHeightProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LineStackingStrategyProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MarginProperty(void** value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Documents::IBlockStatics2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_HorizontalTextAlignmentProperty(void** value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Documents::IBold>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::UI::Xaml::Documents::IContactContentLinkProvider>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::UI::Xaml::Documents::IContentLink>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Info(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Info(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Background(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Background(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Cursor(Windows::UI::Core::CoreCursorType* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Cursor(Windows::UI::Core::CoreCursorType value) noexcept = 0;
    virtual int32_t WINRT_CALL get_XYFocusLeft(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_XYFocusLeft(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_XYFocusRight(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_XYFocusRight(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_XYFocusUp(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_XYFocusUp(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_XYFocusDown(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_XYFocusDown(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ElementSoundMode(Windows::UI::Xaml::ElementSoundMode* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ElementSoundMode(Windows::UI::Xaml::ElementSoundMode value) noexcept = 0;
    virtual int32_t WINRT_CALL get_FocusState(Windows::UI::Xaml::FocusState* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_XYFocusUpNavigationStrategy(Windows::UI::Xaml::Input::XYFocusNavigationStrategy* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_XYFocusUpNavigationStrategy(Windows::UI::Xaml::Input::XYFocusNavigationStrategy value) noexcept = 0;
    virtual int32_t WINRT_CALL get_XYFocusDownNavigationStrategy(Windows::UI::Xaml::Input::XYFocusNavigationStrategy* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_XYFocusDownNavigationStrategy(Windows::UI::Xaml::Input::XYFocusNavigationStrategy value) noexcept = 0;
    virtual int32_t WINRT_CALL get_XYFocusLeftNavigationStrategy(Windows::UI::Xaml::Input::XYFocusNavigationStrategy* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_XYFocusLeftNavigationStrategy(Windows::UI::Xaml::Input::XYFocusNavigationStrategy value) noexcept = 0;
    virtual int32_t WINRT_CALL get_XYFocusRightNavigationStrategy(Windows::UI::Xaml::Input::XYFocusNavigationStrategy* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_XYFocusRightNavigationStrategy(Windows::UI::Xaml::Input::XYFocusNavigationStrategy value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsTabStop(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IsTabStop(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TabIndex(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_TabIndex(int32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL add_Invoked(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_Invoked(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_GotFocus(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_GotFocus(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_LostFocus(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_LostFocus(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL Focus(Windows::UI::Xaml::FocusState value, bool* result) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Documents::IContentLinkInvokedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ContentLinkInfo(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Handled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Handled(bool value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Documents::IContentLinkProvider>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::UI::Xaml::Documents::IContentLinkProviderCollection>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::UI::Xaml::Documents::IContentLinkProviderFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Documents::IContentLinkStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_BackgroundProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CursorProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_XYFocusLeftProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_XYFocusRightProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_XYFocusUpProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_XYFocusDownProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ElementSoundModeProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_FocusStateProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_XYFocusUpNavigationStrategyProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_XYFocusDownNavigationStrategyProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_XYFocusLeftNavigationStrategyProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_XYFocusRightNavigationStrategyProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsTabStopProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TabIndexProperty(void** value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Documents::IGlyphs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_UnicodeString(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_UnicodeString(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Indices(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Indices(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_FontUri(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_FontUri(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_StyleSimulations(Windows::UI::Xaml::Media::StyleSimulations* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_StyleSimulations(Windows::UI::Xaml::Media::StyleSimulations value) noexcept = 0;
    virtual int32_t WINRT_CALL get_FontRenderingEmSize(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_FontRenderingEmSize(double value) noexcept = 0;
    virtual int32_t WINRT_CALL get_OriginX(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_OriginX(double value) noexcept = 0;
    virtual int32_t WINRT_CALL get_OriginY(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_OriginY(double value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Fill(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Fill(void* value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Documents::IGlyphs2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsColorFontEnabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IsColorFontEnabled(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ColorFontPaletteIndex(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ColorFontPaletteIndex(int32_t value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Documents::IGlyphsStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_UnicodeStringProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IndicesProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_FontUriProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_StyleSimulationsProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_FontRenderingEmSizeProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_OriginXProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_OriginYProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_FillProperty(void** value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Documents::IGlyphsStatics2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsColorFontEnabledProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ColorFontPaletteIndexProperty(void** value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Documents::IHyperlink>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_NavigateUri(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_NavigateUri(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL add_Click(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_Click(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Documents::IHyperlink2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_UnderlineStyle(Windows::UI::Xaml::Documents::UnderlineStyle* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_UnderlineStyle(Windows::UI::Xaml::Documents::UnderlineStyle value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Documents::IHyperlink3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_XYFocusLeft(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_XYFocusLeft(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_XYFocusRight(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_XYFocusRight(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_XYFocusUp(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_XYFocusUp(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_XYFocusDown(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_XYFocusDown(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ElementSoundMode(Windows::UI::Xaml::ElementSoundMode* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ElementSoundMode(Windows::UI::Xaml::ElementSoundMode value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Documents::IHyperlink4>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_FocusState(Windows::UI::Xaml::FocusState* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_XYFocusUpNavigationStrategy(Windows::UI::Xaml::Input::XYFocusNavigationStrategy* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_XYFocusUpNavigationStrategy(Windows::UI::Xaml::Input::XYFocusNavigationStrategy value) noexcept = 0;
    virtual int32_t WINRT_CALL get_XYFocusDownNavigationStrategy(Windows::UI::Xaml::Input::XYFocusNavigationStrategy* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_XYFocusDownNavigationStrategy(Windows::UI::Xaml::Input::XYFocusNavigationStrategy value) noexcept = 0;
    virtual int32_t WINRT_CALL get_XYFocusLeftNavigationStrategy(Windows::UI::Xaml::Input::XYFocusNavigationStrategy* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_XYFocusLeftNavigationStrategy(Windows::UI::Xaml::Input::XYFocusNavigationStrategy value) noexcept = 0;
    virtual int32_t WINRT_CALL get_XYFocusRightNavigationStrategy(Windows::UI::Xaml::Input::XYFocusNavigationStrategy* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_XYFocusRightNavigationStrategy(Windows::UI::Xaml::Input::XYFocusNavigationStrategy value) noexcept = 0;
    virtual int32_t WINRT_CALL add_GotFocus(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_GotFocus(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_LostFocus(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_LostFocus(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL Focus(Windows::UI::Xaml::FocusState value, bool* result) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Documents::IHyperlink5>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsTabStop(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IsTabStop(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TabIndex(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_TabIndex(int32_t value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Documents::IHyperlinkClickEventArgs>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::UI::Xaml::Documents::IHyperlinkStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_NavigateUriProperty(void** value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Documents::IHyperlinkStatics2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_UnderlineStyleProperty(void** value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Documents::IHyperlinkStatics3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_XYFocusLeftProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_XYFocusRightProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_XYFocusUpProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_XYFocusDownProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ElementSoundModeProperty(void** value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Documents::IHyperlinkStatics4>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_FocusStateProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_XYFocusUpNavigationStrategyProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_XYFocusDownNavigationStrategyProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_XYFocusLeftNavigationStrategyProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_XYFocusRightNavigationStrategyProperty(void** value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Documents::IHyperlinkStatics5>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsTabStopProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TabIndexProperty(void** value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Documents::IInline>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::UI::Xaml::Documents::IInlineFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Documents::IInlineUIContainer>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Child(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Child(void* value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Documents::IItalic>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::UI::Xaml::Documents::ILineBreak>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::UI::Xaml::Documents::IParagraph>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Inlines(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TextIndent(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_TextIndent(double value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Documents::IParagraphStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_TextIndentProperty(void** value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Documents::IPlaceContentLinkProvider>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::UI::Xaml::Documents::IRun>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Text(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Text(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_FlowDirection(Windows::UI::Xaml::FlowDirection* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_FlowDirection(Windows::UI::Xaml::FlowDirection value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Documents::IRunStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_FlowDirectionProperty(void** value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Documents::ISpan>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Inlines(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Inlines(void* value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Documents::ISpanFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Documents::ITextElement>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Name(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_FontSize(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_FontSize(double value) noexcept = 0;
    virtual int32_t WINRT_CALL get_FontFamily(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_FontFamily(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_FontWeight(struct struct_Windows_UI_Text_FontWeight* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_FontWeight(struct struct_Windows_UI_Text_FontWeight value) noexcept = 0;
    virtual int32_t WINRT_CALL get_FontStyle(Windows::UI::Text::FontStyle* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_FontStyle(Windows::UI::Text::FontStyle value) noexcept = 0;
    virtual int32_t WINRT_CALL get_FontStretch(Windows::UI::Text::FontStretch* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_FontStretch(Windows::UI::Text::FontStretch value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CharacterSpacing(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_CharacterSpacing(int32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Foreground(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Foreground(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Language(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Language(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ContentStart(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ContentEnd(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ElementStart(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ElementEnd(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL FindName(void* name, void** result) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Documents::ITextElement2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsTextScaleFactorEnabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IsTextScaleFactorEnabled(bool value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Documents::ITextElement3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_AllowFocusOnInteraction(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_AllowFocusOnInteraction(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AccessKey(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_AccessKey(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ExitDisplayModeOnAccessKeyInvoked(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ExitDisplayModeOnAccessKeyInvoked(bool value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Documents::ITextElement4>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_TextDecorations(Windows::UI::Text::TextDecorations* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_TextDecorations(Windows::UI::Text::TextDecorations value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsAccessKeyScope(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IsAccessKeyScope(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AccessKeyScopeOwner(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_AccessKeyScopeOwner(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_KeyTipPlacementMode(Windows::UI::Xaml::Input::KeyTipPlacementMode* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_KeyTipPlacementMode(Windows::UI::Xaml::Input::KeyTipPlacementMode value) noexcept = 0;
    virtual int32_t WINRT_CALL get_KeyTipHorizontalOffset(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_KeyTipHorizontalOffset(double value) noexcept = 0;
    virtual int32_t WINRT_CALL get_KeyTipVerticalOffset(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_KeyTipVerticalOffset(double value) noexcept = 0;
    virtual int32_t WINRT_CALL add_AccessKeyDisplayRequested(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_AccessKeyDisplayRequested(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_AccessKeyDisplayDismissed(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_AccessKeyDisplayDismissed(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_AccessKeyInvoked(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_AccessKeyInvoked(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Documents::ITextElement5>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_XamlRoot(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_XamlRoot(void* value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Documents::ITextElementFactory>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::UI::Xaml::Documents::ITextElementOverrides>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL OnDisconnectVisualChildren() noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Documents::ITextElementStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_FontSizeProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_FontFamilyProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_FontWeightProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_FontStyleProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_FontStretchProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CharacterSpacingProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ForegroundProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LanguageProperty(void** value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Documents::ITextElementStatics2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsTextScaleFactorEnabledProperty(void** value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Documents::ITextElementStatics3>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_AllowFocusOnInteractionProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AccessKeyProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ExitDisplayModeOnAccessKeyInvokedProperty(void** value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Documents::ITextElementStatics4>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_TextDecorationsProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsAccessKeyScopeProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AccessKeyScopeOwnerProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_KeyTipPlacementModeProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_KeyTipHorizontalOffsetProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_KeyTipVerticalOffsetProperty(void** value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Documents::ITextHighlighter>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Ranges(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Foreground(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Foreground(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Background(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Background(void* value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Documents::ITextHighlighterBase>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::UI::Xaml::Documents::ITextHighlighterBaseFactory>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::UI::Xaml::Documents::ITextHighlighterFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Documents::ITextHighlighterStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ForegroundProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BackgroundProperty(void** value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Documents::ITextPointer>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Parent(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_VisualParent(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LogicalDirection(Windows::UI::Xaml::Documents::LogicalDirection* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Offset(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL GetCharacterRect(Windows::UI::Xaml::Documents::LogicalDirection direction, Windows::Foundation::Rect* result) noexcept = 0;
    virtual int32_t WINRT_CALL GetPositionAtOffset(int32_t offset, Windows::UI::Xaml::Documents::LogicalDirection direction, void** result) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Documents::ITypography>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::UI::Xaml::Documents::ITypographyStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_AnnotationAlternatesProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetAnnotationAlternates(void* element, int32_t* result) noexcept = 0;
    virtual int32_t WINRT_CALL SetAnnotationAlternates(void* element, int32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_EastAsianExpertFormsProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetEastAsianExpertForms(void* element, bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL SetEastAsianExpertForms(void* element, bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_EastAsianLanguageProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetEastAsianLanguage(void* element, Windows::UI::Xaml::FontEastAsianLanguage* result) noexcept = 0;
    virtual int32_t WINRT_CALL SetEastAsianLanguage(void* element, Windows::UI::Xaml::FontEastAsianLanguage value) noexcept = 0;
    virtual int32_t WINRT_CALL get_EastAsianWidthsProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetEastAsianWidths(void* element, Windows::UI::Xaml::FontEastAsianWidths* result) noexcept = 0;
    virtual int32_t WINRT_CALL SetEastAsianWidths(void* element, Windows::UI::Xaml::FontEastAsianWidths value) noexcept = 0;
    virtual int32_t WINRT_CALL get_StandardLigaturesProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetStandardLigatures(void* element, bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL SetStandardLigatures(void* element, bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ContextualLigaturesProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetContextualLigatures(void* element, bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL SetContextualLigatures(void* element, bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DiscretionaryLigaturesProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetDiscretionaryLigatures(void* element, bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL SetDiscretionaryLigatures(void* element, bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HistoricalLigaturesProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetHistoricalLigatures(void* element, bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL SetHistoricalLigatures(void* element, bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_StandardSwashesProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetStandardSwashes(void* element, int32_t* result) noexcept = 0;
    virtual int32_t WINRT_CALL SetStandardSwashes(void* element, int32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ContextualSwashesProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetContextualSwashes(void* element, int32_t* result) noexcept = 0;
    virtual int32_t WINRT_CALL SetContextualSwashes(void* element, int32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ContextualAlternatesProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetContextualAlternates(void* element, bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL SetContextualAlternates(void* element, bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_StylisticAlternatesProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetStylisticAlternates(void* element, int32_t* result) noexcept = 0;
    virtual int32_t WINRT_CALL SetStylisticAlternates(void* element, int32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_StylisticSet1Property(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetStylisticSet1(void* element, bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL SetStylisticSet1(void* element, bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_StylisticSet2Property(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetStylisticSet2(void* element, bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL SetStylisticSet2(void* element, bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_StylisticSet3Property(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetStylisticSet3(void* element, bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL SetStylisticSet3(void* element, bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_StylisticSet4Property(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetStylisticSet4(void* element, bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL SetStylisticSet4(void* element, bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_StylisticSet5Property(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetStylisticSet5(void* element, bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL SetStylisticSet5(void* element, bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_StylisticSet6Property(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetStylisticSet6(void* element, bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL SetStylisticSet6(void* element, bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_StylisticSet7Property(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetStylisticSet7(void* element, bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL SetStylisticSet7(void* element, bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_StylisticSet8Property(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetStylisticSet8(void* element, bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL SetStylisticSet8(void* element, bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_StylisticSet9Property(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetStylisticSet9(void* element, bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL SetStylisticSet9(void* element, bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_StylisticSet10Property(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetStylisticSet10(void* element, bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL SetStylisticSet10(void* element, bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_StylisticSet11Property(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetStylisticSet11(void* element, bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL SetStylisticSet11(void* element, bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_StylisticSet12Property(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetStylisticSet12(void* element, bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL SetStylisticSet12(void* element, bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_StylisticSet13Property(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetStylisticSet13(void* element, bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL SetStylisticSet13(void* element, bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_StylisticSet14Property(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetStylisticSet14(void* element, bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL SetStylisticSet14(void* element, bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_StylisticSet15Property(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetStylisticSet15(void* element, bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL SetStylisticSet15(void* element, bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_StylisticSet16Property(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetStylisticSet16(void* element, bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL SetStylisticSet16(void* element, bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_StylisticSet17Property(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetStylisticSet17(void* element, bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL SetStylisticSet17(void* element, bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_StylisticSet18Property(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetStylisticSet18(void* element, bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL SetStylisticSet18(void* element, bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_StylisticSet19Property(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetStylisticSet19(void* element, bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL SetStylisticSet19(void* element, bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_StylisticSet20Property(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetStylisticSet20(void* element, bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL SetStylisticSet20(void* element, bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CapitalsProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetCapitals(void* element, Windows::UI::Xaml::FontCapitals* result) noexcept = 0;
    virtual int32_t WINRT_CALL SetCapitals(void* element, Windows::UI::Xaml::FontCapitals value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CapitalSpacingProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetCapitalSpacing(void* element, bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL SetCapitalSpacing(void* element, bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_KerningProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetKerning(void* element, bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL SetKerning(void* element, bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CaseSensitiveFormsProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetCaseSensitiveForms(void* element, bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL SetCaseSensitiveForms(void* element, bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HistoricalFormsProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetHistoricalForms(void* element, bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL SetHistoricalForms(void* element, bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_FractionProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetFraction(void* element, Windows::UI::Xaml::FontFraction* result) noexcept = 0;
    virtual int32_t WINRT_CALL SetFraction(void* element, Windows::UI::Xaml::FontFraction value) noexcept = 0;
    virtual int32_t WINRT_CALL get_NumeralStyleProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetNumeralStyle(void* element, Windows::UI::Xaml::FontNumeralStyle* result) noexcept = 0;
    virtual int32_t WINRT_CALL SetNumeralStyle(void* element, Windows::UI::Xaml::FontNumeralStyle value) noexcept = 0;
    virtual int32_t WINRT_CALL get_NumeralAlignmentProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetNumeralAlignment(void* element, Windows::UI::Xaml::FontNumeralAlignment* result) noexcept = 0;
    virtual int32_t WINRT_CALL SetNumeralAlignment(void* element, Windows::UI::Xaml::FontNumeralAlignment value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SlashedZeroProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetSlashedZero(void* element, bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL SetSlashedZero(void* element, bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MathematicalGreekProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetMathematicalGreek(void* element, bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL SetMathematicalGreek(void* element, bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_VariantsProperty(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetVariants(void* element, Windows::UI::Xaml::FontVariants* result) noexcept = 0;
    virtual int32_t WINRT_CALL SetVariants(void* element, Windows::UI::Xaml::FontVariants value) noexcept = 0;
};};

template <> struct abi<Windows::UI::Xaml::Documents::IUnderline>{ struct type : IInspectable
{
};};

template <typename D>
struct consume_Windows_UI_Xaml_Documents_IBlock
{
    Windows::UI::Xaml::TextAlignment TextAlignment() const;
    void TextAlignment(Windows::UI::Xaml::TextAlignment const& value) const;
    double LineHeight() const;
    void LineHeight(double value) const;
    Windows::UI::Xaml::LineStackingStrategy LineStackingStrategy() const;
    void LineStackingStrategy(Windows::UI::Xaml::LineStackingStrategy const& value) const;
    Windows::UI::Xaml::Thickness Margin() const;
    void Margin(Windows::UI::Xaml::Thickness const& value) const;
};
template <> struct consume<Windows::UI::Xaml::Documents::IBlock> { template <typename D> using type = consume_Windows_UI_Xaml_Documents_IBlock<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Documents_IBlock2
{
    Windows::UI::Xaml::TextAlignment HorizontalTextAlignment() const;
    void HorizontalTextAlignment(Windows::UI::Xaml::TextAlignment const& value) const;
};
template <> struct consume<Windows::UI::Xaml::Documents::IBlock2> { template <typename D> using type = consume_Windows_UI_Xaml_Documents_IBlock2<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Documents_IBlockFactory
{
    Windows::UI::Xaml::Documents::Block CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const;
};
template <> struct consume<Windows::UI::Xaml::Documents::IBlockFactory> { template <typename D> using type = consume_Windows_UI_Xaml_Documents_IBlockFactory<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Documents_IBlockStatics
{
    Windows::UI::Xaml::DependencyProperty TextAlignmentProperty() const;
    Windows::UI::Xaml::DependencyProperty LineHeightProperty() const;
    Windows::UI::Xaml::DependencyProperty LineStackingStrategyProperty() const;
    Windows::UI::Xaml::DependencyProperty MarginProperty() const;
};
template <> struct consume<Windows::UI::Xaml::Documents::IBlockStatics> { template <typename D> using type = consume_Windows_UI_Xaml_Documents_IBlockStatics<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Documents_IBlockStatics2
{
    Windows::UI::Xaml::DependencyProperty HorizontalTextAlignmentProperty() const;
};
template <> struct consume<Windows::UI::Xaml::Documents::IBlockStatics2> { template <typename D> using type = consume_Windows_UI_Xaml_Documents_IBlockStatics2<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Documents_IBold
{
};
template <> struct consume<Windows::UI::Xaml::Documents::IBold> { template <typename D> using type = consume_Windows_UI_Xaml_Documents_IBold<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Documents_IContactContentLinkProvider
{
};
template <> struct consume<Windows::UI::Xaml::Documents::IContactContentLinkProvider> { template <typename D> using type = consume_Windows_UI_Xaml_Documents_IContactContentLinkProvider<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Documents_IContentLink
{
    Windows::UI::Text::ContentLinkInfo Info() const;
    void Info(Windows::UI::Text::ContentLinkInfo const& value) const;
    Windows::UI::Xaml::Media::Brush Background() const;
    void Background(Windows::UI::Xaml::Media::Brush const& value) const;
    Windows::UI::Core::CoreCursorType Cursor() const;
    void Cursor(Windows::UI::Core::CoreCursorType const& value) const;
    Windows::UI::Xaml::DependencyObject XYFocusLeft() const;
    void XYFocusLeft(Windows::UI::Xaml::DependencyObject const& value) const;
    Windows::UI::Xaml::DependencyObject XYFocusRight() const;
    void XYFocusRight(Windows::UI::Xaml::DependencyObject const& value) const;
    Windows::UI::Xaml::DependencyObject XYFocusUp() const;
    void XYFocusUp(Windows::UI::Xaml::DependencyObject const& value) const;
    Windows::UI::Xaml::DependencyObject XYFocusDown() const;
    void XYFocusDown(Windows::UI::Xaml::DependencyObject const& value) const;
    Windows::UI::Xaml::ElementSoundMode ElementSoundMode() const;
    void ElementSoundMode(Windows::UI::Xaml::ElementSoundMode const& value) const;
    Windows::UI::Xaml::FocusState FocusState() const;
    Windows::UI::Xaml::Input::XYFocusNavigationStrategy XYFocusUpNavigationStrategy() const;
    void XYFocusUpNavigationStrategy(Windows::UI::Xaml::Input::XYFocusNavigationStrategy const& value) const;
    Windows::UI::Xaml::Input::XYFocusNavigationStrategy XYFocusDownNavigationStrategy() const;
    void XYFocusDownNavigationStrategy(Windows::UI::Xaml::Input::XYFocusNavigationStrategy const& value) const;
    Windows::UI::Xaml::Input::XYFocusNavigationStrategy XYFocusLeftNavigationStrategy() const;
    void XYFocusLeftNavigationStrategy(Windows::UI::Xaml::Input::XYFocusNavigationStrategy const& value) const;
    Windows::UI::Xaml::Input::XYFocusNavigationStrategy XYFocusRightNavigationStrategy() const;
    void XYFocusRightNavigationStrategy(Windows::UI::Xaml::Input::XYFocusNavigationStrategy const& value) const;
    bool IsTabStop() const;
    void IsTabStop(bool value) const;
    int32_t TabIndex() const;
    void TabIndex(int32_t value) const;
    winrt::event_token Invoked(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Documents::ContentLink, Windows::UI::Xaml::Documents::ContentLinkInvokedEventArgs> const& handler) const;
    using Invoked_revoker = impl::event_revoker<Windows::UI::Xaml::Documents::IContentLink, &impl::abi_t<Windows::UI::Xaml::Documents::IContentLink>::remove_Invoked>;
    Invoked_revoker Invoked(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Documents::ContentLink, Windows::UI::Xaml::Documents::ContentLinkInvokedEventArgs> const& handler) const;
    void Invoked(winrt::event_token const& token) const noexcept;
    winrt::event_token GotFocus(Windows::UI::Xaml::RoutedEventHandler const& handler) const;
    using GotFocus_revoker = impl::event_revoker<Windows::UI::Xaml::Documents::IContentLink, &impl::abi_t<Windows::UI::Xaml::Documents::IContentLink>::remove_GotFocus>;
    GotFocus_revoker GotFocus(auto_revoke_t, Windows::UI::Xaml::RoutedEventHandler const& handler) const;
    void GotFocus(winrt::event_token const& token) const noexcept;
    winrt::event_token LostFocus(Windows::UI::Xaml::RoutedEventHandler const& handler) const;
    using LostFocus_revoker = impl::event_revoker<Windows::UI::Xaml::Documents::IContentLink, &impl::abi_t<Windows::UI::Xaml::Documents::IContentLink>::remove_LostFocus>;
    LostFocus_revoker LostFocus(auto_revoke_t, Windows::UI::Xaml::RoutedEventHandler const& handler) const;
    void LostFocus(winrt::event_token const& token) const noexcept;
    bool Focus(Windows::UI::Xaml::FocusState const& value) const;
};
template <> struct consume<Windows::UI::Xaml::Documents::IContentLink> { template <typename D> using type = consume_Windows_UI_Xaml_Documents_IContentLink<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Documents_IContentLinkInvokedEventArgs
{
    Windows::UI::Text::ContentLinkInfo ContentLinkInfo() const;
    bool Handled() const;
    void Handled(bool value) const;
};
template <> struct consume<Windows::UI::Xaml::Documents::IContentLinkInvokedEventArgs> { template <typename D> using type = consume_Windows_UI_Xaml_Documents_IContentLinkInvokedEventArgs<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Documents_IContentLinkProvider
{
};
template <> struct consume<Windows::UI::Xaml::Documents::IContentLinkProvider> { template <typename D> using type = consume_Windows_UI_Xaml_Documents_IContentLinkProvider<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Documents_IContentLinkProviderCollection
{
};
template <> struct consume<Windows::UI::Xaml::Documents::IContentLinkProviderCollection> { template <typename D> using type = consume_Windows_UI_Xaml_Documents_IContentLinkProviderCollection<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Documents_IContentLinkProviderFactory
{
    Windows::UI::Xaml::Documents::ContentLinkProvider CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const;
};
template <> struct consume<Windows::UI::Xaml::Documents::IContentLinkProviderFactory> { template <typename D> using type = consume_Windows_UI_Xaml_Documents_IContentLinkProviderFactory<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Documents_IContentLinkStatics
{
    Windows::UI::Xaml::DependencyProperty BackgroundProperty() const;
    Windows::UI::Xaml::DependencyProperty CursorProperty() const;
    Windows::UI::Xaml::DependencyProperty XYFocusLeftProperty() const;
    Windows::UI::Xaml::DependencyProperty XYFocusRightProperty() const;
    Windows::UI::Xaml::DependencyProperty XYFocusUpProperty() const;
    Windows::UI::Xaml::DependencyProperty XYFocusDownProperty() const;
    Windows::UI::Xaml::DependencyProperty ElementSoundModeProperty() const;
    Windows::UI::Xaml::DependencyProperty FocusStateProperty() const;
    Windows::UI::Xaml::DependencyProperty XYFocusUpNavigationStrategyProperty() const;
    Windows::UI::Xaml::DependencyProperty XYFocusDownNavigationStrategyProperty() const;
    Windows::UI::Xaml::DependencyProperty XYFocusLeftNavigationStrategyProperty() const;
    Windows::UI::Xaml::DependencyProperty XYFocusRightNavigationStrategyProperty() const;
    Windows::UI::Xaml::DependencyProperty IsTabStopProperty() const;
    Windows::UI::Xaml::DependencyProperty TabIndexProperty() const;
};
template <> struct consume<Windows::UI::Xaml::Documents::IContentLinkStatics> { template <typename D> using type = consume_Windows_UI_Xaml_Documents_IContentLinkStatics<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Documents_IGlyphs
{
    hstring UnicodeString() const;
    void UnicodeString(param::hstring const& value) const;
    hstring Indices() const;
    void Indices(param::hstring const& value) const;
    Windows::Foundation::Uri FontUri() const;
    void FontUri(Windows::Foundation::Uri const& value) const;
    Windows::UI::Xaml::Media::StyleSimulations StyleSimulations() const;
    void StyleSimulations(Windows::UI::Xaml::Media::StyleSimulations const& value) const;
    double FontRenderingEmSize() const;
    void FontRenderingEmSize(double value) const;
    double OriginX() const;
    void OriginX(double value) const;
    double OriginY() const;
    void OriginY(double value) const;
    Windows::UI::Xaml::Media::Brush Fill() const;
    void Fill(Windows::UI::Xaml::Media::Brush const& value) const;
};
template <> struct consume<Windows::UI::Xaml::Documents::IGlyphs> { template <typename D> using type = consume_Windows_UI_Xaml_Documents_IGlyphs<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Documents_IGlyphs2
{
    bool IsColorFontEnabled() const;
    void IsColorFontEnabled(bool value) const;
    int32_t ColorFontPaletteIndex() const;
    void ColorFontPaletteIndex(int32_t value) const;
};
template <> struct consume<Windows::UI::Xaml::Documents::IGlyphs2> { template <typename D> using type = consume_Windows_UI_Xaml_Documents_IGlyphs2<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Documents_IGlyphsStatics
{
    Windows::UI::Xaml::DependencyProperty UnicodeStringProperty() const;
    Windows::UI::Xaml::DependencyProperty IndicesProperty() const;
    Windows::UI::Xaml::DependencyProperty FontUriProperty() const;
    Windows::UI::Xaml::DependencyProperty StyleSimulationsProperty() const;
    Windows::UI::Xaml::DependencyProperty FontRenderingEmSizeProperty() const;
    Windows::UI::Xaml::DependencyProperty OriginXProperty() const;
    Windows::UI::Xaml::DependencyProperty OriginYProperty() const;
    Windows::UI::Xaml::DependencyProperty FillProperty() const;
};
template <> struct consume<Windows::UI::Xaml::Documents::IGlyphsStatics> { template <typename D> using type = consume_Windows_UI_Xaml_Documents_IGlyphsStatics<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Documents_IGlyphsStatics2
{
    Windows::UI::Xaml::DependencyProperty IsColorFontEnabledProperty() const;
    Windows::UI::Xaml::DependencyProperty ColorFontPaletteIndexProperty() const;
};
template <> struct consume<Windows::UI::Xaml::Documents::IGlyphsStatics2> { template <typename D> using type = consume_Windows_UI_Xaml_Documents_IGlyphsStatics2<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Documents_IHyperlink
{
    Windows::Foundation::Uri NavigateUri() const;
    void NavigateUri(Windows::Foundation::Uri const& value) const;
    winrt::event_token Click(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Documents::Hyperlink, Windows::UI::Xaml::Documents::HyperlinkClickEventArgs> const& handler) const;
    using Click_revoker = impl::event_revoker<Windows::UI::Xaml::Documents::IHyperlink, &impl::abi_t<Windows::UI::Xaml::Documents::IHyperlink>::remove_Click>;
    Click_revoker Click(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Documents::Hyperlink, Windows::UI::Xaml::Documents::HyperlinkClickEventArgs> const& handler) const;
    void Click(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::UI::Xaml::Documents::IHyperlink> { template <typename D> using type = consume_Windows_UI_Xaml_Documents_IHyperlink<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Documents_IHyperlink2
{
    Windows::UI::Xaml::Documents::UnderlineStyle UnderlineStyle() const;
    void UnderlineStyle(Windows::UI::Xaml::Documents::UnderlineStyle const& value) const;
};
template <> struct consume<Windows::UI::Xaml::Documents::IHyperlink2> { template <typename D> using type = consume_Windows_UI_Xaml_Documents_IHyperlink2<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Documents_IHyperlink3
{
    Windows::UI::Xaml::DependencyObject XYFocusLeft() const;
    void XYFocusLeft(Windows::UI::Xaml::DependencyObject const& value) const;
    Windows::UI::Xaml::DependencyObject XYFocusRight() const;
    void XYFocusRight(Windows::UI::Xaml::DependencyObject const& value) const;
    Windows::UI::Xaml::DependencyObject XYFocusUp() const;
    void XYFocusUp(Windows::UI::Xaml::DependencyObject const& value) const;
    Windows::UI::Xaml::DependencyObject XYFocusDown() const;
    void XYFocusDown(Windows::UI::Xaml::DependencyObject const& value) const;
    Windows::UI::Xaml::ElementSoundMode ElementSoundMode() const;
    void ElementSoundMode(Windows::UI::Xaml::ElementSoundMode const& value) const;
};
template <> struct consume<Windows::UI::Xaml::Documents::IHyperlink3> { template <typename D> using type = consume_Windows_UI_Xaml_Documents_IHyperlink3<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Documents_IHyperlink4
{
    Windows::UI::Xaml::FocusState FocusState() const;
    Windows::UI::Xaml::Input::XYFocusNavigationStrategy XYFocusUpNavigationStrategy() const;
    void XYFocusUpNavigationStrategy(Windows::UI::Xaml::Input::XYFocusNavigationStrategy const& value) const;
    Windows::UI::Xaml::Input::XYFocusNavigationStrategy XYFocusDownNavigationStrategy() const;
    void XYFocusDownNavigationStrategy(Windows::UI::Xaml::Input::XYFocusNavigationStrategy const& value) const;
    Windows::UI::Xaml::Input::XYFocusNavigationStrategy XYFocusLeftNavigationStrategy() const;
    void XYFocusLeftNavigationStrategy(Windows::UI::Xaml::Input::XYFocusNavigationStrategy const& value) const;
    Windows::UI::Xaml::Input::XYFocusNavigationStrategy XYFocusRightNavigationStrategy() const;
    void XYFocusRightNavigationStrategy(Windows::UI::Xaml::Input::XYFocusNavigationStrategy const& value) const;
    winrt::event_token GotFocus(Windows::UI::Xaml::RoutedEventHandler const& handler) const;
    using GotFocus_revoker = impl::event_revoker<Windows::UI::Xaml::Documents::IHyperlink4, &impl::abi_t<Windows::UI::Xaml::Documents::IHyperlink4>::remove_GotFocus>;
    GotFocus_revoker GotFocus(auto_revoke_t, Windows::UI::Xaml::RoutedEventHandler const& handler) const;
    void GotFocus(winrt::event_token const& token) const noexcept;
    winrt::event_token LostFocus(Windows::UI::Xaml::RoutedEventHandler const& handler) const;
    using LostFocus_revoker = impl::event_revoker<Windows::UI::Xaml::Documents::IHyperlink4, &impl::abi_t<Windows::UI::Xaml::Documents::IHyperlink4>::remove_LostFocus>;
    LostFocus_revoker LostFocus(auto_revoke_t, Windows::UI::Xaml::RoutedEventHandler const& handler) const;
    void LostFocus(winrt::event_token const& token) const noexcept;
    bool Focus(Windows::UI::Xaml::FocusState const& value) const;
};
template <> struct consume<Windows::UI::Xaml::Documents::IHyperlink4> { template <typename D> using type = consume_Windows_UI_Xaml_Documents_IHyperlink4<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Documents_IHyperlink5
{
    bool IsTabStop() const;
    void IsTabStop(bool value) const;
    int32_t TabIndex() const;
    void TabIndex(int32_t value) const;
};
template <> struct consume<Windows::UI::Xaml::Documents::IHyperlink5> { template <typename D> using type = consume_Windows_UI_Xaml_Documents_IHyperlink5<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Documents_IHyperlinkClickEventArgs
{
};
template <> struct consume<Windows::UI::Xaml::Documents::IHyperlinkClickEventArgs> { template <typename D> using type = consume_Windows_UI_Xaml_Documents_IHyperlinkClickEventArgs<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Documents_IHyperlinkStatics
{
    Windows::UI::Xaml::DependencyProperty NavigateUriProperty() const;
};
template <> struct consume<Windows::UI::Xaml::Documents::IHyperlinkStatics> { template <typename D> using type = consume_Windows_UI_Xaml_Documents_IHyperlinkStatics<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Documents_IHyperlinkStatics2
{
    Windows::UI::Xaml::DependencyProperty UnderlineStyleProperty() const;
};
template <> struct consume<Windows::UI::Xaml::Documents::IHyperlinkStatics2> { template <typename D> using type = consume_Windows_UI_Xaml_Documents_IHyperlinkStatics2<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Documents_IHyperlinkStatics3
{
    Windows::UI::Xaml::DependencyProperty XYFocusLeftProperty() const;
    Windows::UI::Xaml::DependencyProperty XYFocusRightProperty() const;
    Windows::UI::Xaml::DependencyProperty XYFocusUpProperty() const;
    Windows::UI::Xaml::DependencyProperty XYFocusDownProperty() const;
    Windows::UI::Xaml::DependencyProperty ElementSoundModeProperty() const;
};
template <> struct consume<Windows::UI::Xaml::Documents::IHyperlinkStatics3> { template <typename D> using type = consume_Windows_UI_Xaml_Documents_IHyperlinkStatics3<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Documents_IHyperlinkStatics4
{
    Windows::UI::Xaml::DependencyProperty FocusStateProperty() const;
    Windows::UI::Xaml::DependencyProperty XYFocusUpNavigationStrategyProperty() const;
    Windows::UI::Xaml::DependencyProperty XYFocusDownNavigationStrategyProperty() const;
    Windows::UI::Xaml::DependencyProperty XYFocusLeftNavigationStrategyProperty() const;
    Windows::UI::Xaml::DependencyProperty XYFocusRightNavigationStrategyProperty() const;
};
template <> struct consume<Windows::UI::Xaml::Documents::IHyperlinkStatics4> { template <typename D> using type = consume_Windows_UI_Xaml_Documents_IHyperlinkStatics4<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Documents_IHyperlinkStatics5
{
    Windows::UI::Xaml::DependencyProperty IsTabStopProperty() const;
    Windows::UI::Xaml::DependencyProperty TabIndexProperty() const;
};
template <> struct consume<Windows::UI::Xaml::Documents::IHyperlinkStatics5> { template <typename D> using type = consume_Windows_UI_Xaml_Documents_IHyperlinkStatics5<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Documents_IInline
{
};
template <> struct consume<Windows::UI::Xaml::Documents::IInline> { template <typename D> using type = consume_Windows_UI_Xaml_Documents_IInline<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Documents_IInlineFactory
{
    Windows::UI::Xaml::Documents::Inline CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const;
};
template <> struct consume<Windows::UI::Xaml::Documents::IInlineFactory> { template <typename D> using type = consume_Windows_UI_Xaml_Documents_IInlineFactory<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Documents_IInlineUIContainer
{
    Windows::UI::Xaml::UIElement Child() const;
    void Child(Windows::UI::Xaml::UIElement const& value) const;
};
template <> struct consume<Windows::UI::Xaml::Documents::IInlineUIContainer> { template <typename D> using type = consume_Windows_UI_Xaml_Documents_IInlineUIContainer<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Documents_IItalic
{
};
template <> struct consume<Windows::UI::Xaml::Documents::IItalic> { template <typename D> using type = consume_Windows_UI_Xaml_Documents_IItalic<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Documents_ILineBreak
{
};
template <> struct consume<Windows::UI::Xaml::Documents::ILineBreak> { template <typename D> using type = consume_Windows_UI_Xaml_Documents_ILineBreak<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Documents_IParagraph
{
    Windows::UI::Xaml::Documents::InlineCollection Inlines() const;
    double TextIndent() const;
    void TextIndent(double value) const;
};
template <> struct consume<Windows::UI::Xaml::Documents::IParagraph> { template <typename D> using type = consume_Windows_UI_Xaml_Documents_IParagraph<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Documents_IParagraphStatics
{
    Windows::UI::Xaml::DependencyProperty TextIndentProperty() const;
};
template <> struct consume<Windows::UI::Xaml::Documents::IParagraphStatics> { template <typename D> using type = consume_Windows_UI_Xaml_Documents_IParagraphStatics<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Documents_IPlaceContentLinkProvider
{
};
template <> struct consume<Windows::UI::Xaml::Documents::IPlaceContentLinkProvider> { template <typename D> using type = consume_Windows_UI_Xaml_Documents_IPlaceContentLinkProvider<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Documents_IRun
{
    hstring Text() const;
    void Text(param::hstring const& value) const;
    Windows::UI::Xaml::FlowDirection FlowDirection() const;
    void FlowDirection(Windows::UI::Xaml::FlowDirection const& value) const;
};
template <> struct consume<Windows::UI::Xaml::Documents::IRun> { template <typename D> using type = consume_Windows_UI_Xaml_Documents_IRun<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Documents_IRunStatics
{
    Windows::UI::Xaml::DependencyProperty FlowDirectionProperty() const;
};
template <> struct consume<Windows::UI::Xaml::Documents::IRunStatics> { template <typename D> using type = consume_Windows_UI_Xaml_Documents_IRunStatics<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Documents_ISpan
{
    Windows::UI::Xaml::Documents::InlineCollection Inlines() const;
    void Inlines(Windows::UI::Xaml::Documents::InlineCollection const& value) const;
};
template <> struct consume<Windows::UI::Xaml::Documents::ISpan> { template <typename D> using type = consume_Windows_UI_Xaml_Documents_ISpan<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Documents_ISpanFactory
{
    Windows::UI::Xaml::Documents::Span CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const;
};
template <> struct consume<Windows::UI::Xaml::Documents::ISpanFactory> { template <typename D> using type = consume_Windows_UI_Xaml_Documents_ISpanFactory<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Documents_ITextElement
{
    hstring Name() const;
    double FontSize() const;
    void FontSize(double value) const;
    Windows::UI::Xaml::Media::FontFamily FontFamily() const;
    void FontFamily(Windows::UI::Xaml::Media::FontFamily const& value) const;
    Windows::UI::Text::FontWeight FontWeight() const;
    void FontWeight(Windows::UI::Text::FontWeight const& value) const;
    Windows::UI::Text::FontStyle FontStyle() const;
    void FontStyle(Windows::UI::Text::FontStyle const& value) const;
    Windows::UI::Text::FontStretch FontStretch() const;
    void FontStretch(Windows::UI::Text::FontStretch const& value) const;
    int32_t CharacterSpacing() const;
    void CharacterSpacing(int32_t value) const;
    Windows::UI::Xaml::Media::Brush Foreground() const;
    void Foreground(Windows::UI::Xaml::Media::Brush const& value) const;
    hstring Language() const;
    void Language(param::hstring const& value) const;
    Windows::UI::Xaml::Documents::TextPointer ContentStart() const;
    Windows::UI::Xaml::Documents::TextPointer ContentEnd() const;
    Windows::UI::Xaml::Documents::TextPointer ElementStart() const;
    Windows::UI::Xaml::Documents::TextPointer ElementEnd() const;
    Windows::Foundation::IInspectable FindName(param::hstring const& name) const;
};
template <> struct consume<Windows::UI::Xaml::Documents::ITextElement> { template <typename D> using type = consume_Windows_UI_Xaml_Documents_ITextElement<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Documents_ITextElement2
{
    bool IsTextScaleFactorEnabled() const;
    void IsTextScaleFactorEnabled(bool value) const;
};
template <> struct consume<Windows::UI::Xaml::Documents::ITextElement2> { template <typename D> using type = consume_Windows_UI_Xaml_Documents_ITextElement2<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Documents_ITextElement3
{
    bool AllowFocusOnInteraction() const;
    void AllowFocusOnInteraction(bool value) const;
    hstring AccessKey() const;
    void AccessKey(param::hstring const& value) const;
    bool ExitDisplayModeOnAccessKeyInvoked() const;
    void ExitDisplayModeOnAccessKeyInvoked(bool value) const;
};
template <> struct consume<Windows::UI::Xaml::Documents::ITextElement3> { template <typename D> using type = consume_Windows_UI_Xaml_Documents_ITextElement3<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Documents_ITextElement4
{
    Windows::UI::Text::TextDecorations TextDecorations() const;
    void TextDecorations(Windows::UI::Text::TextDecorations const& value) const;
    bool IsAccessKeyScope() const;
    void IsAccessKeyScope(bool value) const;
    Windows::UI::Xaml::DependencyObject AccessKeyScopeOwner() const;
    void AccessKeyScopeOwner(Windows::UI::Xaml::DependencyObject const& value) const;
    Windows::UI::Xaml::Input::KeyTipPlacementMode KeyTipPlacementMode() const;
    void KeyTipPlacementMode(Windows::UI::Xaml::Input::KeyTipPlacementMode const& value) const;
    double KeyTipHorizontalOffset() const;
    void KeyTipHorizontalOffset(double value) const;
    double KeyTipVerticalOffset() const;
    void KeyTipVerticalOffset(double value) const;
    winrt::event_token AccessKeyDisplayRequested(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Documents::TextElement, Windows::UI::Xaml::Input::AccessKeyDisplayRequestedEventArgs> const& handler) const;
    using AccessKeyDisplayRequested_revoker = impl::event_revoker<Windows::UI::Xaml::Documents::ITextElement4, &impl::abi_t<Windows::UI::Xaml::Documents::ITextElement4>::remove_AccessKeyDisplayRequested>;
    AccessKeyDisplayRequested_revoker AccessKeyDisplayRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Documents::TextElement, Windows::UI::Xaml::Input::AccessKeyDisplayRequestedEventArgs> const& handler) const;
    void AccessKeyDisplayRequested(winrt::event_token const& token) const noexcept;
    winrt::event_token AccessKeyDisplayDismissed(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Documents::TextElement, Windows::UI::Xaml::Input::AccessKeyDisplayDismissedEventArgs> const& handler) const;
    using AccessKeyDisplayDismissed_revoker = impl::event_revoker<Windows::UI::Xaml::Documents::ITextElement4, &impl::abi_t<Windows::UI::Xaml::Documents::ITextElement4>::remove_AccessKeyDisplayDismissed>;
    AccessKeyDisplayDismissed_revoker AccessKeyDisplayDismissed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Documents::TextElement, Windows::UI::Xaml::Input::AccessKeyDisplayDismissedEventArgs> const& handler) const;
    void AccessKeyDisplayDismissed(winrt::event_token const& token) const noexcept;
    winrt::event_token AccessKeyInvoked(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Documents::TextElement, Windows::UI::Xaml::Input::AccessKeyInvokedEventArgs> const& handler) const;
    using AccessKeyInvoked_revoker = impl::event_revoker<Windows::UI::Xaml::Documents::ITextElement4, &impl::abi_t<Windows::UI::Xaml::Documents::ITextElement4>::remove_AccessKeyInvoked>;
    AccessKeyInvoked_revoker AccessKeyInvoked(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Documents::TextElement, Windows::UI::Xaml::Input::AccessKeyInvokedEventArgs> const& handler) const;
    void AccessKeyInvoked(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::UI::Xaml::Documents::ITextElement4> { template <typename D> using type = consume_Windows_UI_Xaml_Documents_ITextElement4<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Documents_ITextElement5
{
    Windows::UI::Xaml::XamlRoot XamlRoot() const;
    void XamlRoot(Windows::UI::Xaml::XamlRoot const& value) const;
};
template <> struct consume<Windows::UI::Xaml::Documents::ITextElement5> { template <typename D> using type = consume_Windows_UI_Xaml_Documents_ITextElement5<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Documents_ITextElementFactory
{
};
template <> struct consume<Windows::UI::Xaml::Documents::ITextElementFactory> { template <typename D> using type = consume_Windows_UI_Xaml_Documents_ITextElementFactory<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Documents_ITextElementOverrides
{
    void OnDisconnectVisualChildren() const;
};
template <> struct consume<Windows::UI::Xaml::Documents::ITextElementOverrides> { template <typename D> using type = consume_Windows_UI_Xaml_Documents_ITextElementOverrides<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Documents_ITextElementStatics
{
    Windows::UI::Xaml::DependencyProperty FontSizeProperty() const;
    Windows::UI::Xaml::DependencyProperty FontFamilyProperty() const;
    Windows::UI::Xaml::DependencyProperty FontWeightProperty() const;
    Windows::UI::Xaml::DependencyProperty FontStyleProperty() const;
    Windows::UI::Xaml::DependencyProperty FontStretchProperty() const;
    Windows::UI::Xaml::DependencyProperty CharacterSpacingProperty() const;
    Windows::UI::Xaml::DependencyProperty ForegroundProperty() const;
    Windows::UI::Xaml::DependencyProperty LanguageProperty() const;
};
template <> struct consume<Windows::UI::Xaml::Documents::ITextElementStatics> { template <typename D> using type = consume_Windows_UI_Xaml_Documents_ITextElementStatics<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Documents_ITextElementStatics2
{
    Windows::UI::Xaml::DependencyProperty IsTextScaleFactorEnabledProperty() const;
};
template <> struct consume<Windows::UI::Xaml::Documents::ITextElementStatics2> { template <typename D> using type = consume_Windows_UI_Xaml_Documents_ITextElementStatics2<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Documents_ITextElementStatics3
{
    Windows::UI::Xaml::DependencyProperty AllowFocusOnInteractionProperty() const;
    Windows::UI::Xaml::DependencyProperty AccessKeyProperty() const;
    Windows::UI::Xaml::DependencyProperty ExitDisplayModeOnAccessKeyInvokedProperty() const;
};
template <> struct consume<Windows::UI::Xaml::Documents::ITextElementStatics3> { template <typename D> using type = consume_Windows_UI_Xaml_Documents_ITextElementStatics3<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Documents_ITextElementStatics4
{
    Windows::UI::Xaml::DependencyProperty TextDecorationsProperty() const;
    Windows::UI::Xaml::DependencyProperty IsAccessKeyScopeProperty() const;
    Windows::UI::Xaml::DependencyProperty AccessKeyScopeOwnerProperty() const;
    Windows::UI::Xaml::DependencyProperty KeyTipPlacementModeProperty() const;
    Windows::UI::Xaml::DependencyProperty KeyTipHorizontalOffsetProperty() const;
    Windows::UI::Xaml::DependencyProperty KeyTipVerticalOffsetProperty() const;
};
template <> struct consume<Windows::UI::Xaml::Documents::ITextElementStatics4> { template <typename D> using type = consume_Windows_UI_Xaml_Documents_ITextElementStatics4<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Documents_ITextHighlighter
{
    Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Documents::TextRange> Ranges() const;
    Windows::UI::Xaml::Media::Brush Foreground() const;
    void Foreground(Windows::UI::Xaml::Media::Brush const& value) const;
    Windows::UI::Xaml::Media::Brush Background() const;
    void Background(Windows::UI::Xaml::Media::Brush const& value) const;
};
template <> struct consume<Windows::UI::Xaml::Documents::ITextHighlighter> { template <typename D> using type = consume_Windows_UI_Xaml_Documents_ITextHighlighter<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Documents_ITextHighlighterBase
{
};
template <> struct consume<Windows::UI::Xaml::Documents::ITextHighlighterBase> { template <typename D> using type = consume_Windows_UI_Xaml_Documents_ITextHighlighterBase<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Documents_ITextHighlighterBaseFactory
{
};
template <> struct consume<Windows::UI::Xaml::Documents::ITextHighlighterBaseFactory> { template <typename D> using type = consume_Windows_UI_Xaml_Documents_ITextHighlighterBaseFactory<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Documents_ITextHighlighterFactory
{
    Windows::UI::Xaml::Documents::TextHighlighter CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const;
};
template <> struct consume<Windows::UI::Xaml::Documents::ITextHighlighterFactory> { template <typename D> using type = consume_Windows_UI_Xaml_Documents_ITextHighlighterFactory<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Documents_ITextHighlighterStatics
{
    Windows::UI::Xaml::DependencyProperty ForegroundProperty() const;
    Windows::UI::Xaml::DependencyProperty BackgroundProperty() const;
};
template <> struct consume<Windows::UI::Xaml::Documents::ITextHighlighterStatics> { template <typename D> using type = consume_Windows_UI_Xaml_Documents_ITextHighlighterStatics<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Documents_ITextPointer
{
    Windows::UI::Xaml::DependencyObject Parent() const;
    Windows::UI::Xaml::FrameworkElement VisualParent() const;
    Windows::UI::Xaml::Documents::LogicalDirection LogicalDirection() const;
    int32_t Offset() const;
    Windows::Foundation::Rect GetCharacterRect(Windows::UI::Xaml::Documents::LogicalDirection const& direction) const;
    Windows::UI::Xaml::Documents::TextPointer GetPositionAtOffset(int32_t offset, Windows::UI::Xaml::Documents::LogicalDirection const& direction) const;
};
template <> struct consume<Windows::UI::Xaml::Documents::ITextPointer> { template <typename D> using type = consume_Windows_UI_Xaml_Documents_ITextPointer<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Documents_ITypography
{
};
template <> struct consume<Windows::UI::Xaml::Documents::ITypography> { template <typename D> using type = consume_Windows_UI_Xaml_Documents_ITypography<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Documents_ITypographyStatics
{
    Windows::UI::Xaml::DependencyProperty AnnotationAlternatesProperty() const;
    int32_t GetAnnotationAlternates(Windows::UI::Xaml::DependencyObject const& element) const;
    void SetAnnotationAlternates(Windows::UI::Xaml::DependencyObject const& element, int32_t value) const;
    Windows::UI::Xaml::DependencyProperty EastAsianExpertFormsProperty() const;
    bool GetEastAsianExpertForms(Windows::UI::Xaml::DependencyObject const& element) const;
    void SetEastAsianExpertForms(Windows::UI::Xaml::DependencyObject const& element, bool value) const;
    Windows::UI::Xaml::DependencyProperty EastAsianLanguageProperty() const;
    Windows::UI::Xaml::FontEastAsianLanguage GetEastAsianLanguage(Windows::UI::Xaml::DependencyObject const& element) const;
    void SetEastAsianLanguage(Windows::UI::Xaml::DependencyObject const& element, Windows::UI::Xaml::FontEastAsianLanguage const& value) const;
    Windows::UI::Xaml::DependencyProperty EastAsianWidthsProperty() const;
    Windows::UI::Xaml::FontEastAsianWidths GetEastAsianWidths(Windows::UI::Xaml::DependencyObject const& element) const;
    void SetEastAsianWidths(Windows::UI::Xaml::DependencyObject const& element, Windows::UI::Xaml::FontEastAsianWidths const& value) const;
    Windows::UI::Xaml::DependencyProperty StandardLigaturesProperty() const;
    bool GetStandardLigatures(Windows::UI::Xaml::DependencyObject const& element) const;
    void SetStandardLigatures(Windows::UI::Xaml::DependencyObject const& element, bool value) const;
    Windows::UI::Xaml::DependencyProperty ContextualLigaturesProperty() const;
    bool GetContextualLigatures(Windows::UI::Xaml::DependencyObject const& element) const;
    void SetContextualLigatures(Windows::UI::Xaml::DependencyObject const& element, bool value) const;
    Windows::UI::Xaml::DependencyProperty DiscretionaryLigaturesProperty() const;
    bool GetDiscretionaryLigatures(Windows::UI::Xaml::DependencyObject const& element) const;
    void SetDiscretionaryLigatures(Windows::UI::Xaml::DependencyObject const& element, bool value) const;
    Windows::UI::Xaml::DependencyProperty HistoricalLigaturesProperty() const;
    bool GetHistoricalLigatures(Windows::UI::Xaml::DependencyObject const& element) const;
    void SetHistoricalLigatures(Windows::UI::Xaml::DependencyObject const& element, bool value) const;
    Windows::UI::Xaml::DependencyProperty StandardSwashesProperty() const;
    int32_t GetStandardSwashes(Windows::UI::Xaml::DependencyObject const& element) const;
    void SetStandardSwashes(Windows::UI::Xaml::DependencyObject const& element, int32_t value) const;
    Windows::UI::Xaml::DependencyProperty ContextualSwashesProperty() const;
    int32_t GetContextualSwashes(Windows::UI::Xaml::DependencyObject const& element) const;
    void SetContextualSwashes(Windows::UI::Xaml::DependencyObject const& element, int32_t value) const;
    Windows::UI::Xaml::DependencyProperty ContextualAlternatesProperty() const;
    bool GetContextualAlternates(Windows::UI::Xaml::DependencyObject const& element) const;
    void SetContextualAlternates(Windows::UI::Xaml::DependencyObject const& element, bool value) const;
    Windows::UI::Xaml::DependencyProperty StylisticAlternatesProperty() const;
    int32_t GetStylisticAlternates(Windows::UI::Xaml::DependencyObject const& element) const;
    void SetStylisticAlternates(Windows::UI::Xaml::DependencyObject const& element, int32_t value) const;
    Windows::UI::Xaml::DependencyProperty StylisticSet1Property() const;
    bool GetStylisticSet1(Windows::UI::Xaml::DependencyObject const& element) const;
    void SetStylisticSet1(Windows::UI::Xaml::DependencyObject const& element, bool value) const;
    Windows::UI::Xaml::DependencyProperty StylisticSet2Property() const;
    bool GetStylisticSet2(Windows::UI::Xaml::DependencyObject const& element) const;
    void SetStylisticSet2(Windows::UI::Xaml::DependencyObject const& element, bool value) const;
    Windows::UI::Xaml::DependencyProperty StylisticSet3Property() const;
    bool GetStylisticSet3(Windows::UI::Xaml::DependencyObject const& element) const;
    void SetStylisticSet3(Windows::UI::Xaml::DependencyObject const& element, bool value) const;
    Windows::UI::Xaml::DependencyProperty StylisticSet4Property() const;
    bool GetStylisticSet4(Windows::UI::Xaml::DependencyObject const& element) const;
    void SetStylisticSet4(Windows::UI::Xaml::DependencyObject const& element, bool value) const;
    Windows::UI::Xaml::DependencyProperty StylisticSet5Property() const;
    bool GetStylisticSet5(Windows::UI::Xaml::DependencyObject const& element) const;
    void SetStylisticSet5(Windows::UI::Xaml::DependencyObject const& element, bool value) const;
    Windows::UI::Xaml::DependencyProperty StylisticSet6Property() const;
    bool GetStylisticSet6(Windows::UI::Xaml::DependencyObject const& element) const;
    void SetStylisticSet6(Windows::UI::Xaml::DependencyObject const& element, bool value) const;
    Windows::UI::Xaml::DependencyProperty StylisticSet7Property() const;
    bool GetStylisticSet7(Windows::UI::Xaml::DependencyObject const& element) const;
    void SetStylisticSet7(Windows::UI::Xaml::DependencyObject const& element, bool value) const;
    Windows::UI::Xaml::DependencyProperty StylisticSet8Property() const;
    bool GetStylisticSet8(Windows::UI::Xaml::DependencyObject const& element) const;
    void SetStylisticSet8(Windows::UI::Xaml::DependencyObject const& element, bool value) const;
    Windows::UI::Xaml::DependencyProperty StylisticSet9Property() const;
    bool GetStylisticSet9(Windows::UI::Xaml::DependencyObject const& element) const;
    void SetStylisticSet9(Windows::UI::Xaml::DependencyObject const& element, bool value) const;
    Windows::UI::Xaml::DependencyProperty StylisticSet10Property() const;
    bool GetStylisticSet10(Windows::UI::Xaml::DependencyObject const& element) const;
    void SetStylisticSet10(Windows::UI::Xaml::DependencyObject const& element, bool value) const;
    Windows::UI::Xaml::DependencyProperty StylisticSet11Property() const;
    bool GetStylisticSet11(Windows::UI::Xaml::DependencyObject const& element) const;
    void SetStylisticSet11(Windows::UI::Xaml::DependencyObject const& element, bool value) const;
    Windows::UI::Xaml::DependencyProperty StylisticSet12Property() const;
    bool GetStylisticSet12(Windows::UI::Xaml::DependencyObject const& element) const;
    void SetStylisticSet12(Windows::UI::Xaml::DependencyObject const& element, bool value) const;
    Windows::UI::Xaml::DependencyProperty StylisticSet13Property() const;
    bool GetStylisticSet13(Windows::UI::Xaml::DependencyObject const& element) const;
    void SetStylisticSet13(Windows::UI::Xaml::DependencyObject const& element, bool value) const;
    Windows::UI::Xaml::DependencyProperty StylisticSet14Property() const;
    bool GetStylisticSet14(Windows::UI::Xaml::DependencyObject const& element) const;
    void SetStylisticSet14(Windows::UI::Xaml::DependencyObject const& element, bool value) const;
    Windows::UI::Xaml::DependencyProperty StylisticSet15Property() const;
    bool GetStylisticSet15(Windows::UI::Xaml::DependencyObject const& element) const;
    void SetStylisticSet15(Windows::UI::Xaml::DependencyObject const& element, bool value) const;
    Windows::UI::Xaml::DependencyProperty StylisticSet16Property() const;
    bool GetStylisticSet16(Windows::UI::Xaml::DependencyObject const& element) const;
    void SetStylisticSet16(Windows::UI::Xaml::DependencyObject const& element, bool value) const;
    Windows::UI::Xaml::DependencyProperty StylisticSet17Property() const;
    bool GetStylisticSet17(Windows::UI::Xaml::DependencyObject const& element) const;
    void SetStylisticSet17(Windows::UI::Xaml::DependencyObject const& element, bool value) const;
    Windows::UI::Xaml::DependencyProperty StylisticSet18Property() const;
    bool GetStylisticSet18(Windows::UI::Xaml::DependencyObject const& element) const;
    void SetStylisticSet18(Windows::UI::Xaml::DependencyObject const& element, bool value) const;
    Windows::UI::Xaml::DependencyProperty StylisticSet19Property() const;
    bool GetStylisticSet19(Windows::UI::Xaml::DependencyObject const& element) const;
    void SetStylisticSet19(Windows::UI::Xaml::DependencyObject const& element, bool value) const;
    Windows::UI::Xaml::DependencyProperty StylisticSet20Property() const;
    bool GetStylisticSet20(Windows::UI::Xaml::DependencyObject const& element) const;
    void SetStylisticSet20(Windows::UI::Xaml::DependencyObject const& element, bool value) const;
    Windows::UI::Xaml::DependencyProperty CapitalsProperty() const;
    Windows::UI::Xaml::FontCapitals GetCapitals(Windows::UI::Xaml::DependencyObject const& element) const;
    void SetCapitals(Windows::UI::Xaml::DependencyObject const& element, Windows::UI::Xaml::FontCapitals const& value) const;
    Windows::UI::Xaml::DependencyProperty CapitalSpacingProperty() const;
    bool GetCapitalSpacing(Windows::UI::Xaml::DependencyObject const& element) const;
    void SetCapitalSpacing(Windows::UI::Xaml::DependencyObject const& element, bool value) const;
    Windows::UI::Xaml::DependencyProperty KerningProperty() const;
    bool GetKerning(Windows::UI::Xaml::DependencyObject const& element) const;
    void SetKerning(Windows::UI::Xaml::DependencyObject const& element, bool value) const;
    Windows::UI::Xaml::DependencyProperty CaseSensitiveFormsProperty() const;
    bool GetCaseSensitiveForms(Windows::UI::Xaml::DependencyObject const& element) const;
    void SetCaseSensitiveForms(Windows::UI::Xaml::DependencyObject const& element, bool value) const;
    Windows::UI::Xaml::DependencyProperty HistoricalFormsProperty() const;
    bool GetHistoricalForms(Windows::UI::Xaml::DependencyObject const& element) const;
    void SetHistoricalForms(Windows::UI::Xaml::DependencyObject const& element, bool value) const;
    Windows::UI::Xaml::DependencyProperty FractionProperty() const;
    Windows::UI::Xaml::FontFraction GetFraction(Windows::UI::Xaml::DependencyObject const& element) const;
    void SetFraction(Windows::UI::Xaml::DependencyObject const& element, Windows::UI::Xaml::FontFraction const& value) const;
    Windows::UI::Xaml::DependencyProperty NumeralStyleProperty() const;
    Windows::UI::Xaml::FontNumeralStyle GetNumeralStyle(Windows::UI::Xaml::DependencyObject const& element) const;
    void SetNumeralStyle(Windows::UI::Xaml::DependencyObject const& element, Windows::UI::Xaml::FontNumeralStyle const& value) const;
    Windows::UI::Xaml::DependencyProperty NumeralAlignmentProperty() const;
    Windows::UI::Xaml::FontNumeralAlignment GetNumeralAlignment(Windows::UI::Xaml::DependencyObject const& element) const;
    void SetNumeralAlignment(Windows::UI::Xaml::DependencyObject const& element, Windows::UI::Xaml::FontNumeralAlignment const& value) const;
    Windows::UI::Xaml::DependencyProperty SlashedZeroProperty() const;
    bool GetSlashedZero(Windows::UI::Xaml::DependencyObject const& element) const;
    void SetSlashedZero(Windows::UI::Xaml::DependencyObject const& element, bool value) const;
    Windows::UI::Xaml::DependencyProperty MathematicalGreekProperty() const;
    bool GetMathematicalGreek(Windows::UI::Xaml::DependencyObject const& element) const;
    void SetMathematicalGreek(Windows::UI::Xaml::DependencyObject const& element, bool value) const;
    Windows::UI::Xaml::DependencyProperty VariantsProperty() const;
    Windows::UI::Xaml::FontVariants GetVariants(Windows::UI::Xaml::DependencyObject const& element) const;
    void SetVariants(Windows::UI::Xaml::DependencyObject const& element, Windows::UI::Xaml::FontVariants const& value) const;
};
template <> struct consume<Windows::UI::Xaml::Documents::ITypographyStatics> { template <typename D> using type = consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>; };

template <typename D>
struct consume_Windows_UI_Xaml_Documents_IUnderline
{
};
template <> struct consume<Windows::UI::Xaml::Documents::IUnderline> { template <typename D> using type = consume_Windows_UI_Xaml_Documents_IUnderline<D>; };

struct struct_Windows_UI_Xaml_Documents_TextRange
{
    int32_t StartIndex;
    int32_t Length;
};
template <> struct abi<Windows::UI::Xaml::Documents::TextRange>{ using type = struct_Windows_UI_Xaml_Documents_TextRange; };


}
