// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.UI.Text.Core.2.h"
#include "winrt/impl/Windows.Data.Text.2.h"

namespace winrt::impl {

template <typename D> Windows::Data::Text::TextSegment consume_Windows_Data_Text_IAlternateWordForm<D>::SourceTextSegment() const
{
    Windows::Data::Text::TextSegment value{};
    check_hresult(WINRT_SHIM(Windows::Data::Text::IAlternateWordForm)->get_SourceTextSegment(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Data_Text_IAlternateWordForm<D>::AlternateText() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Data::Text::IAlternateWordForm)->get_AlternateText(put_abi(value)));
    return value;
}

template <typename D> Windows::Data::Text::AlternateNormalizationFormat consume_Windows_Data_Text_IAlternateWordForm<D>::NormalizationFormat() const
{
    Windows::Data::Text::AlternateNormalizationFormat value{};
    check_hresult(WINRT_SHIM(Windows::Data::Text::IAlternateWordForm)->get_NormalizationFormat(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Data_Text_ISelectableWordSegment<D>::Text() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Data::Text::ISelectableWordSegment)->get_Text(put_abi(value)));
    return value;
}

template <typename D> Windows::Data::Text::TextSegment consume_Windows_Data_Text_ISelectableWordSegment<D>::SourceTextSegment() const
{
    Windows::Data::Text::TextSegment value{};
    check_hresult(WINRT_SHIM(Windows::Data::Text::ISelectableWordSegment)->get_SourceTextSegment(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Data_Text_ISelectableWordsSegmenter<D>::ResolvedLanguage() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Data::Text::ISelectableWordsSegmenter)->get_ResolvedLanguage(put_abi(value)));
    return value;
}

template <typename D> Windows::Data::Text::SelectableWordSegment consume_Windows_Data_Text_ISelectableWordsSegmenter<D>::GetTokenAt(param::hstring const& text, uint32_t startIndex) const
{
    Windows::Data::Text::SelectableWordSegment result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Data::Text::ISelectableWordsSegmenter)->GetTokenAt(get_abi(text), startIndex, put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Data::Text::SelectableWordSegment> consume_Windows_Data_Text_ISelectableWordsSegmenter<D>::GetTokens(param::hstring const& text) const
{
    Windows::Foundation::Collections::IVectorView<Windows::Data::Text::SelectableWordSegment> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Data::Text::ISelectableWordsSegmenter)->GetTokens(get_abi(text), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_Data_Text_ISelectableWordsSegmenter<D>::Tokenize(param::hstring const& text, uint32_t startIndex, Windows::Data::Text::SelectableWordSegmentsTokenizingHandler const& handler) const
{
    check_hresult(WINRT_SHIM(Windows::Data::Text::ISelectableWordsSegmenter)->Tokenize(get_abi(text), startIndex, get_abi(handler)));
}

template <typename D> Windows::Data::Text::SelectableWordsSegmenter consume_Windows_Data_Text_ISelectableWordsSegmenterFactory<D>::CreateWithLanguage(param::hstring const& language) const
{
    Windows::Data::Text::SelectableWordsSegmenter result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Data::Text::ISelectableWordsSegmenterFactory)->CreateWithLanguage(get_abi(language), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Data::Text::TextSegment> consume_Windows_Data_Text_ISemanticTextQuery<D>::Find(param::hstring const& content) const
{
    Windows::Foundation::Collections::IVectorView<Windows::Data::Text::TextSegment> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Data::Text::ISemanticTextQuery)->Find(get_abi(content), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Data::Text::TextSegment> consume_Windows_Data_Text_ISemanticTextQuery<D>::FindInProperty(param::hstring const& propertyContent, param::hstring const& propertyName) const
{
    Windows::Foundation::Collections::IVectorView<Windows::Data::Text::TextSegment> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Data::Text::ISemanticTextQuery)->FindInProperty(get_abi(propertyContent), get_abi(propertyName), put_abi(result)));
    return result;
}

template <typename D> Windows::Data::Text::SemanticTextQuery consume_Windows_Data_Text_ISemanticTextQueryFactory<D>::Create(param::hstring const& aqsFilter) const
{
    Windows::Data::Text::SemanticTextQuery result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Data::Text::ISemanticTextQueryFactory)->Create(get_abi(aqsFilter), put_abi(result)));
    return result;
}

template <typename D> Windows::Data::Text::SemanticTextQuery consume_Windows_Data_Text_ISemanticTextQueryFactory<D>::CreateWithLanguage(param::hstring const& aqsFilter, param::hstring const& filterLanguage) const
{
    Windows::Data::Text::SemanticTextQuery result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Data::Text::ISemanticTextQueryFactory)->CreateWithLanguage(get_abi(aqsFilter), get_abi(filterLanguage), put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Data_Text_ITextConversionGenerator<D>::ResolvedLanguage() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Data::Text::ITextConversionGenerator)->get_ResolvedLanguage(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Data_Text_ITextConversionGenerator<D>::LanguageAvailableButNotInstalled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Data::Text::ITextConversionGenerator)->get_LanguageAvailableButNotInstalled(&value));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<hstring>> consume_Windows_Data_Text_ITextConversionGenerator<D>::GetCandidatesAsync(param::hstring const& input) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<hstring>> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Data::Text::ITextConversionGenerator)->GetCandidatesAsync(get_abi(input), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<hstring>> consume_Windows_Data_Text_ITextConversionGenerator<D>::GetCandidatesAsync(param::hstring const& input, uint32_t maxCandidates) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<hstring>> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Data::Text::ITextConversionGenerator)->GetCandidatesWithMaxCountAsync(get_abi(input), maxCandidates, put_abi(result)));
    return result;
}

template <typename D> Windows::Data::Text::TextConversionGenerator consume_Windows_Data_Text_ITextConversionGeneratorFactory<D>::Create(param::hstring const& languageTag) const
{
    Windows::Data::Text::TextConversionGenerator result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Data::Text::ITextConversionGeneratorFactory)->Create(get_abi(languageTag), put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Data_Text_ITextPhoneme<D>::DisplayText() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Data::Text::ITextPhoneme)->get_DisplayText(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Data_Text_ITextPhoneme<D>::ReadingText() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Data::Text::ITextPhoneme)->get_ReadingText(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Data_Text_ITextPredictionGenerator<D>::ResolvedLanguage() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Data::Text::ITextPredictionGenerator)->get_ResolvedLanguage(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Data_Text_ITextPredictionGenerator<D>::LanguageAvailableButNotInstalled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Data::Text::ITextPredictionGenerator)->get_LanguageAvailableButNotInstalled(&value));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<hstring>> consume_Windows_Data_Text_ITextPredictionGenerator<D>::GetCandidatesAsync(param::hstring const& input) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<hstring>> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Data::Text::ITextPredictionGenerator)->GetCandidatesAsync(get_abi(input), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<hstring>> consume_Windows_Data_Text_ITextPredictionGenerator<D>::GetCandidatesAsync(param::hstring const& input, uint32_t maxCandidates) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<hstring>> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Data::Text::ITextPredictionGenerator)->GetCandidatesWithMaxCountAsync(get_abi(input), maxCandidates, put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<hstring>> consume_Windows_Data_Text_ITextPredictionGenerator2<D>::GetCandidatesAsync(param::hstring const& input, uint32_t maxCandidates, Windows::Data::Text::TextPredictionOptions const& predictionOptions, param::async_iterable<hstring> const& previousStrings) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<hstring>> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Data::Text::ITextPredictionGenerator2)->GetCandidatesWithParametersAsync(get_abi(input), maxCandidates, get_abi(predictionOptions), get_abi(previousStrings), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<hstring>> consume_Windows_Data_Text_ITextPredictionGenerator2<D>::GetNextWordCandidatesAsync(uint32_t maxCandidates, param::async_iterable<hstring> const& previousStrings) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<hstring>> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Data::Text::ITextPredictionGenerator2)->GetNextWordCandidatesAsync(maxCandidates, get_abi(previousStrings), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Text::Core::CoreTextInputScope consume_Windows_Data_Text_ITextPredictionGenerator2<D>::InputScope() const
{
    Windows::UI::Text::Core::CoreTextInputScope value{};
    check_hresult(WINRT_SHIM(Windows::Data::Text::ITextPredictionGenerator2)->get_InputScope(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Data_Text_ITextPredictionGenerator2<D>::InputScope(Windows::UI::Text::Core::CoreTextInputScope const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Data::Text::ITextPredictionGenerator2)->put_InputScope(get_abi(value)));
}

template <typename D> Windows::Data::Text::TextPredictionGenerator consume_Windows_Data_Text_ITextPredictionGeneratorFactory<D>::Create(param::hstring const& languageTag) const
{
    Windows::Data::Text::TextPredictionGenerator result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Data::Text::ITextPredictionGeneratorFactory)->Create(get_abi(languageTag), put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Data_Text_ITextReverseConversionGenerator<D>::ResolvedLanguage() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Data::Text::ITextReverseConversionGenerator)->get_ResolvedLanguage(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Data_Text_ITextReverseConversionGenerator<D>::LanguageAvailableButNotInstalled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Data::Text::ITextReverseConversionGenerator)->get_LanguageAvailableButNotInstalled(&value));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<hstring> consume_Windows_Data_Text_ITextReverseConversionGenerator<D>::ConvertBackAsync(param::hstring const& input) const
{
    Windows::Foundation::IAsyncOperation<hstring> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Data::Text::ITextReverseConversionGenerator)->ConvertBackAsync(get_abi(input), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Data::Text::TextPhoneme>> consume_Windows_Data_Text_ITextReverseConversionGenerator2<D>::GetPhonemesAsync(param::hstring const& input) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Data::Text::TextPhoneme>> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Data::Text::ITextReverseConversionGenerator2)->GetPhonemesAsync(get_abi(input), put_abi(result)));
    return result;
}

template <typename D> Windows::Data::Text::TextReverseConversionGenerator consume_Windows_Data_Text_ITextReverseConversionGeneratorFactory<D>::Create(param::hstring const& languageTag) const
{
    Windows::Data::Text::TextReverseConversionGenerator result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Data::Text::ITextReverseConversionGeneratorFactory)->Create(get_abi(languageTag), put_abi(result)));
    return result;
}

template <typename D> uint32_t consume_Windows_Data_Text_IUnicodeCharactersStatics<D>::GetCodepointFromSurrogatePair(uint32_t highSurrogate, uint32_t lowSurrogate) const
{
    uint32_t codepoint{};
    check_hresult(WINRT_SHIM(Windows::Data::Text::IUnicodeCharactersStatics)->GetCodepointFromSurrogatePair(highSurrogate, lowSurrogate, &codepoint));
    return codepoint;
}

template <typename D> void consume_Windows_Data_Text_IUnicodeCharactersStatics<D>::GetSurrogatePairFromCodepoint(uint32_t codepoint, char16_t& highSurrogate, char16_t& lowSurrogate) const
{
    check_hresult(WINRT_SHIM(Windows::Data::Text::IUnicodeCharactersStatics)->GetSurrogatePairFromCodepoint(codepoint, &highSurrogate, &lowSurrogate));
}

template <typename D> bool consume_Windows_Data_Text_IUnicodeCharactersStatics<D>::IsHighSurrogate(uint32_t codepoint) const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Data::Text::IUnicodeCharactersStatics)->IsHighSurrogate(codepoint, &value));
    return value;
}

template <typename D> bool consume_Windows_Data_Text_IUnicodeCharactersStatics<D>::IsLowSurrogate(uint32_t codepoint) const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Data::Text::IUnicodeCharactersStatics)->IsLowSurrogate(codepoint, &value));
    return value;
}

template <typename D> bool consume_Windows_Data_Text_IUnicodeCharactersStatics<D>::IsSupplementary(uint32_t codepoint) const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Data::Text::IUnicodeCharactersStatics)->IsSupplementary(codepoint, &value));
    return value;
}

template <typename D> bool consume_Windows_Data_Text_IUnicodeCharactersStatics<D>::IsNoncharacter(uint32_t codepoint) const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Data::Text::IUnicodeCharactersStatics)->IsNoncharacter(codepoint, &value));
    return value;
}

template <typename D> bool consume_Windows_Data_Text_IUnicodeCharactersStatics<D>::IsWhitespace(uint32_t codepoint) const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Data::Text::IUnicodeCharactersStatics)->IsWhitespace(codepoint, &value));
    return value;
}

template <typename D> bool consume_Windows_Data_Text_IUnicodeCharactersStatics<D>::IsAlphabetic(uint32_t codepoint) const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Data::Text::IUnicodeCharactersStatics)->IsAlphabetic(codepoint, &value));
    return value;
}

template <typename D> bool consume_Windows_Data_Text_IUnicodeCharactersStatics<D>::IsCased(uint32_t codepoint) const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Data::Text::IUnicodeCharactersStatics)->IsCased(codepoint, &value));
    return value;
}

template <typename D> bool consume_Windows_Data_Text_IUnicodeCharactersStatics<D>::IsUppercase(uint32_t codepoint) const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Data::Text::IUnicodeCharactersStatics)->IsUppercase(codepoint, &value));
    return value;
}

template <typename D> bool consume_Windows_Data_Text_IUnicodeCharactersStatics<D>::IsLowercase(uint32_t codepoint) const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Data::Text::IUnicodeCharactersStatics)->IsLowercase(codepoint, &value));
    return value;
}

template <typename D> bool consume_Windows_Data_Text_IUnicodeCharactersStatics<D>::IsIdStart(uint32_t codepoint) const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Data::Text::IUnicodeCharactersStatics)->IsIdStart(codepoint, &value));
    return value;
}

template <typename D> bool consume_Windows_Data_Text_IUnicodeCharactersStatics<D>::IsIdContinue(uint32_t codepoint) const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Data::Text::IUnicodeCharactersStatics)->IsIdContinue(codepoint, &value));
    return value;
}

template <typename D> bool consume_Windows_Data_Text_IUnicodeCharactersStatics<D>::IsGraphemeBase(uint32_t codepoint) const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Data::Text::IUnicodeCharactersStatics)->IsGraphemeBase(codepoint, &value));
    return value;
}

template <typename D> bool consume_Windows_Data_Text_IUnicodeCharactersStatics<D>::IsGraphemeExtend(uint32_t codepoint) const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Data::Text::IUnicodeCharactersStatics)->IsGraphemeExtend(codepoint, &value));
    return value;
}

template <typename D> Windows::Data::Text::UnicodeNumericType consume_Windows_Data_Text_IUnicodeCharactersStatics<D>::GetNumericType(uint32_t codepoint) const
{
    Windows::Data::Text::UnicodeNumericType value{};
    check_hresult(WINRT_SHIM(Windows::Data::Text::IUnicodeCharactersStatics)->GetNumericType(codepoint, put_abi(value)));
    return value;
}

template <typename D> Windows::Data::Text::UnicodeGeneralCategory consume_Windows_Data_Text_IUnicodeCharactersStatics<D>::GetGeneralCategory(uint32_t codepoint) const
{
    Windows::Data::Text::UnicodeGeneralCategory value{};
    check_hresult(WINRT_SHIM(Windows::Data::Text::IUnicodeCharactersStatics)->GetGeneralCategory(codepoint, put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Data_Text_IWordSegment<D>::Text() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Data::Text::IWordSegment)->get_Text(put_abi(value)));
    return value;
}

template <typename D> Windows::Data::Text::TextSegment consume_Windows_Data_Text_IWordSegment<D>::SourceTextSegment() const
{
    Windows::Data::Text::TextSegment value{};
    check_hresult(WINRT_SHIM(Windows::Data::Text::IWordSegment)->get_SourceTextSegment(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Data::Text::AlternateWordForm> consume_Windows_Data_Text_IWordSegment<D>::AlternateForms() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Data::Text::AlternateWordForm> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Data::Text::IWordSegment)->get_AlternateForms(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Data_Text_IWordsSegmenter<D>::ResolvedLanguage() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Data::Text::IWordsSegmenter)->get_ResolvedLanguage(put_abi(value)));
    return value;
}

template <typename D> Windows::Data::Text::WordSegment consume_Windows_Data_Text_IWordsSegmenter<D>::GetTokenAt(param::hstring const& text, uint32_t startIndex) const
{
    Windows::Data::Text::WordSegment result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Data::Text::IWordsSegmenter)->GetTokenAt(get_abi(text), startIndex, put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Data::Text::WordSegment> consume_Windows_Data_Text_IWordsSegmenter<D>::GetTokens(param::hstring const& text) const
{
    Windows::Foundation::Collections::IVectorView<Windows::Data::Text::WordSegment> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Data::Text::IWordsSegmenter)->GetTokens(get_abi(text), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_Data_Text_IWordsSegmenter<D>::Tokenize(param::hstring const& text, uint32_t startIndex, Windows::Data::Text::WordSegmentsTokenizingHandler const& handler) const
{
    check_hresult(WINRT_SHIM(Windows::Data::Text::IWordsSegmenter)->Tokenize(get_abi(text), startIndex, get_abi(handler)));
}

template <typename D> Windows::Data::Text::WordsSegmenter consume_Windows_Data_Text_IWordsSegmenterFactory<D>::CreateWithLanguage(param::hstring const& language) const
{
    Windows::Data::Text::WordsSegmenter result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Data::Text::IWordsSegmenterFactory)->CreateWithLanguage(get_abi(language), put_abi(result)));
    return result;
}

template <> struct delegate<Windows::Data::Text::SelectableWordSegmentsTokenizingHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::Data::Text::SelectableWordSegmentsTokenizingHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::Data::Text::SelectableWordSegmentsTokenizingHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* precedingWords, void* words) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Data::Text::SelectableWordSegment> const*>(&precedingWords), *reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Data::Text::SelectableWordSegment> const*>(&words));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <> struct delegate<Windows::Data::Text::WordSegmentsTokenizingHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::Data::Text::WordSegmentsTokenizingHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::Data::Text::WordSegmentsTokenizingHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* precedingWords, void* words) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Data::Text::WordSegment> const*>(&precedingWords), *reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Data::Text::WordSegment> const*>(&words));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <typename D>
struct produce<D, Windows::Data::Text::IAlternateWordForm> : produce_base<D, Windows::Data::Text::IAlternateWordForm>
{
    int32_t WINRT_CALL get_SourceTextSegment(struct struct_Windows_Data_Text_TextSegment* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourceTextSegment, WINRT_WRAP(Windows::Data::Text::TextSegment));
            *value = detach_from<Windows::Data::Text::TextSegment>(this->shim().SourceTextSegment());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AlternateText(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AlternateText, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AlternateText());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NormalizationFormat(Windows::Data::Text::AlternateNormalizationFormat* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NormalizationFormat, WINRT_WRAP(Windows::Data::Text::AlternateNormalizationFormat));
            *value = detach_from<Windows::Data::Text::AlternateNormalizationFormat>(this->shim().NormalizationFormat());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Data::Text::ISelectableWordSegment> : produce_base<D, Windows::Data::Text::ISelectableWordSegment>
{
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

    int32_t WINRT_CALL get_SourceTextSegment(struct struct_Windows_Data_Text_TextSegment* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourceTextSegment, WINRT_WRAP(Windows::Data::Text::TextSegment));
            *value = detach_from<Windows::Data::Text::TextSegment>(this->shim().SourceTextSegment());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Data::Text::ISelectableWordsSegmenter> : produce_base<D, Windows::Data::Text::ISelectableWordsSegmenter>
{
    int32_t WINRT_CALL get_ResolvedLanguage(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResolvedLanguage, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ResolvedLanguage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetTokenAt(void* text, uint32_t startIndex, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetTokenAt, WINRT_WRAP(Windows::Data::Text::SelectableWordSegment), hstring const&, uint32_t);
            *result = detach_from<Windows::Data::Text::SelectableWordSegment>(this->shim().GetTokenAt(*reinterpret_cast<hstring const*>(&text), startIndex));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetTokens(void* text, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetTokens, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Data::Text::SelectableWordSegment>), hstring const&);
            *result = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Data::Text::SelectableWordSegment>>(this->shim().GetTokens(*reinterpret_cast<hstring const*>(&text)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Tokenize(void* text, uint32_t startIndex, void* handler) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Tokenize, WINRT_WRAP(void), hstring const&, uint32_t, Windows::Data::Text::SelectableWordSegmentsTokenizingHandler const&);
            this->shim().Tokenize(*reinterpret_cast<hstring const*>(&text), startIndex, *reinterpret_cast<Windows::Data::Text::SelectableWordSegmentsTokenizingHandler const*>(&handler));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Data::Text::ISelectableWordsSegmenterFactory> : produce_base<D, Windows::Data::Text::ISelectableWordsSegmenterFactory>
{
    int32_t WINRT_CALL CreateWithLanguage(void* language, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithLanguage, WINRT_WRAP(Windows::Data::Text::SelectableWordsSegmenter), hstring const&);
            *result = detach_from<Windows::Data::Text::SelectableWordsSegmenter>(this->shim().CreateWithLanguage(*reinterpret_cast<hstring const*>(&language)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Data::Text::ISemanticTextQuery> : produce_base<D, Windows::Data::Text::ISemanticTextQuery>
{
    int32_t WINRT_CALL Find(void* content, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Find, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Data::Text::TextSegment>), hstring const&);
            *result = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Data::Text::TextSegment>>(this->shim().Find(*reinterpret_cast<hstring const*>(&content)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindInProperty(void* propertyContent, void* propertyName, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindInProperty, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Data::Text::TextSegment>), hstring const&, hstring const&);
            *result = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Data::Text::TextSegment>>(this->shim().FindInProperty(*reinterpret_cast<hstring const*>(&propertyContent), *reinterpret_cast<hstring const*>(&propertyName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Data::Text::ISemanticTextQueryFactory> : produce_base<D, Windows::Data::Text::ISemanticTextQueryFactory>
{
    int32_t WINRT_CALL Create(void* aqsFilter, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Data::Text::SemanticTextQuery), hstring const&);
            *result = detach_from<Windows::Data::Text::SemanticTextQuery>(this->shim().Create(*reinterpret_cast<hstring const*>(&aqsFilter)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithLanguage(void* aqsFilter, void* filterLanguage, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithLanguage, WINRT_WRAP(Windows::Data::Text::SemanticTextQuery), hstring const&, hstring const&);
            *result = detach_from<Windows::Data::Text::SemanticTextQuery>(this->shim().CreateWithLanguage(*reinterpret_cast<hstring const*>(&aqsFilter), *reinterpret_cast<hstring const*>(&filterLanguage)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Data::Text::ITextConversionGenerator> : produce_base<D, Windows::Data::Text::ITextConversionGenerator>
{
    int32_t WINRT_CALL get_ResolvedLanguage(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResolvedLanguage, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ResolvedLanguage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LanguageAvailableButNotInstalled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LanguageAvailableButNotInstalled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().LanguageAvailableButNotInstalled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetCandidatesAsync(void* input, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCandidatesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<hstring>>), hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<hstring>>>(this->shim().GetCandidatesAsync(*reinterpret_cast<hstring const*>(&input)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetCandidatesWithMaxCountAsync(void* input, uint32_t maxCandidates, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCandidatesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<hstring>>), hstring const, uint32_t);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<hstring>>>(this->shim().GetCandidatesAsync(*reinterpret_cast<hstring const*>(&input), maxCandidates));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Data::Text::ITextConversionGeneratorFactory> : produce_base<D, Windows::Data::Text::ITextConversionGeneratorFactory>
{
    int32_t WINRT_CALL Create(void* languageTag, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Data::Text::TextConversionGenerator), hstring const&);
            *result = detach_from<Windows::Data::Text::TextConversionGenerator>(this->shim().Create(*reinterpret_cast<hstring const*>(&languageTag)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Data::Text::ITextPhoneme> : produce_base<D, Windows::Data::Text::ITextPhoneme>
{
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

    int32_t WINRT_CALL get_ReadingText(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadingText, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ReadingText());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Data::Text::ITextPredictionGenerator> : produce_base<D, Windows::Data::Text::ITextPredictionGenerator>
{
    int32_t WINRT_CALL get_ResolvedLanguage(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResolvedLanguage, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ResolvedLanguage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LanguageAvailableButNotInstalled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LanguageAvailableButNotInstalled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().LanguageAvailableButNotInstalled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetCandidatesAsync(void* input, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCandidatesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<hstring>>), hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<hstring>>>(this->shim().GetCandidatesAsync(*reinterpret_cast<hstring const*>(&input)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetCandidatesWithMaxCountAsync(void* input, uint32_t maxCandidates, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCandidatesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<hstring>>), hstring const, uint32_t);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<hstring>>>(this->shim().GetCandidatesAsync(*reinterpret_cast<hstring const*>(&input), maxCandidates));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Data::Text::ITextPredictionGenerator2> : produce_base<D, Windows::Data::Text::ITextPredictionGenerator2>
{
    int32_t WINRT_CALL GetCandidatesWithParametersAsync(void* input, uint32_t maxCandidates, Windows::Data::Text::TextPredictionOptions predictionOptions, void* previousStrings, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCandidatesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<hstring>>), hstring const, uint32_t, Windows::Data::Text::TextPredictionOptions const, Windows::Foundation::Collections::IIterable<hstring> const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<hstring>>>(this->shim().GetCandidatesAsync(*reinterpret_cast<hstring const*>(&input), maxCandidates, *reinterpret_cast<Windows::Data::Text::TextPredictionOptions const*>(&predictionOptions), *reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&previousStrings)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetNextWordCandidatesAsync(uint32_t maxCandidates, void* previousStrings, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetNextWordCandidatesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<hstring>>), uint32_t, Windows::Foundation::Collections::IIterable<hstring> const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<hstring>>>(this->shim().GetNextWordCandidatesAsync(maxCandidates, *reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&previousStrings)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InputScope(Windows::UI::Text::Core::CoreTextInputScope* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InputScope, WINRT_WRAP(Windows::UI::Text::Core::CoreTextInputScope));
            *value = detach_from<Windows::UI::Text::Core::CoreTextInputScope>(this->shim().InputScope());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_InputScope(Windows::UI::Text::Core::CoreTextInputScope value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InputScope, WINRT_WRAP(void), Windows::UI::Text::Core::CoreTextInputScope const&);
            this->shim().InputScope(*reinterpret_cast<Windows::UI::Text::Core::CoreTextInputScope const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Data::Text::ITextPredictionGeneratorFactory> : produce_base<D, Windows::Data::Text::ITextPredictionGeneratorFactory>
{
    int32_t WINRT_CALL Create(void* languageTag, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Data::Text::TextPredictionGenerator), hstring const&);
            *result = detach_from<Windows::Data::Text::TextPredictionGenerator>(this->shim().Create(*reinterpret_cast<hstring const*>(&languageTag)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Data::Text::ITextReverseConversionGenerator> : produce_base<D, Windows::Data::Text::ITextReverseConversionGenerator>
{
    int32_t WINRT_CALL get_ResolvedLanguage(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResolvedLanguage, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ResolvedLanguage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LanguageAvailableButNotInstalled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LanguageAvailableButNotInstalled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().LanguageAvailableButNotInstalled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ConvertBackAsync(void* input, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConvertBackAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<hstring>), hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<hstring>>(this->shim().ConvertBackAsync(*reinterpret_cast<hstring const*>(&input)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Data::Text::ITextReverseConversionGenerator2> : produce_base<D, Windows::Data::Text::ITextReverseConversionGenerator2>
{
    int32_t WINRT_CALL GetPhonemesAsync(void* input, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetPhonemesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Data::Text::TextPhoneme>>), hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Data::Text::TextPhoneme>>>(this->shim().GetPhonemesAsync(*reinterpret_cast<hstring const*>(&input)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Data::Text::ITextReverseConversionGeneratorFactory> : produce_base<D, Windows::Data::Text::ITextReverseConversionGeneratorFactory>
{
    int32_t WINRT_CALL Create(void* languageTag, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Data::Text::TextReverseConversionGenerator), hstring const&);
            *result = detach_from<Windows::Data::Text::TextReverseConversionGenerator>(this->shim().Create(*reinterpret_cast<hstring const*>(&languageTag)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Data::Text::IUnicodeCharactersStatics> : produce_base<D, Windows::Data::Text::IUnicodeCharactersStatics>
{
    int32_t WINRT_CALL GetCodepointFromSurrogatePair(uint32_t highSurrogate, uint32_t lowSurrogate, uint32_t* codepoint) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCodepointFromSurrogatePair, WINRT_WRAP(uint32_t), uint32_t, uint32_t);
            *codepoint = detach_from<uint32_t>(this->shim().GetCodepointFromSurrogatePair(highSurrogate, lowSurrogate));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetSurrogatePairFromCodepoint(uint32_t codepoint, char16_t* highSurrogate, char16_t* lowSurrogate) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetSurrogatePairFromCodepoint, WINRT_WRAP(void), uint32_t, char16_t&, char16_t&);
            this->shim().GetSurrogatePairFromCodepoint(codepoint, *highSurrogate, *lowSurrogate);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsHighSurrogate(uint32_t codepoint, bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsHighSurrogate, WINRT_WRAP(bool), uint32_t);
            *value = detach_from<bool>(this->shim().IsHighSurrogate(codepoint));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsLowSurrogate(uint32_t codepoint, bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsLowSurrogate, WINRT_WRAP(bool), uint32_t);
            *value = detach_from<bool>(this->shim().IsLowSurrogate(codepoint));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsSupplementary(uint32_t codepoint, bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSupplementary, WINRT_WRAP(bool), uint32_t);
            *value = detach_from<bool>(this->shim().IsSupplementary(codepoint));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsNoncharacter(uint32_t codepoint, bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsNoncharacter, WINRT_WRAP(bool), uint32_t);
            *value = detach_from<bool>(this->shim().IsNoncharacter(codepoint));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsWhitespace(uint32_t codepoint, bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsWhitespace, WINRT_WRAP(bool), uint32_t);
            *value = detach_from<bool>(this->shim().IsWhitespace(codepoint));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsAlphabetic(uint32_t codepoint, bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsAlphabetic, WINRT_WRAP(bool), uint32_t);
            *value = detach_from<bool>(this->shim().IsAlphabetic(codepoint));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsCased(uint32_t codepoint, bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsCased, WINRT_WRAP(bool), uint32_t);
            *value = detach_from<bool>(this->shim().IsCased(codepoint));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsUppercase(uint32_t codepoint, bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsUppercase, WINRT_WRAP(bool), uint32_t);
            *value = detach_from<bool>(this->shim().IsUppercase(codepoint));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsLowercase(uint32_t codepoint, bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsLowercase, WINRT_WRAP(bool), uint32_t);
            *value = detach_from<bool>(this->shim().IsLowercase(codepoint));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsIdStart(uint32_t codepoint, bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsIdStart, WINRT_WRAP(bool), uint32_t);
            *value = detach_from<bool>(this->shim().IsIdStart(codepoint));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsIdContinue(uint32_t codepoint, bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsIdContinue, WINRT_WRAP(bool), uint32_t);
            *value = detach_from<bool>(this->shim().IsIdContinue(codepoint));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsGraphemeBase(uint32_t codepoint, bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsGraphemeBase, WINRT_WRAP(bool), uint32_t);
            *value = detach_from<bool>(this->shim().IsGraphemeBase(codepoint));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsGraphemeExtend(uint32_t codepoint, bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsGraphemeExtend, WINRT_WRAP(bool), uint32_t);
            *value = detach_from<bool>(this->shim().IsGraphemeExtend(codepoint));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetNumericType(uint32_t codepoint, Windows::Data::Text::UnicodeNumericType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetNumericType, WINRT_WRAP(Windows::Data::Text::UnicodeNumericType), uint32_t);
            *value = detach_from<Windows::Data::Text::UnicodeNumericType>(this->shim().GetNumericType(codepoint));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetGeneralCategory(uint32_t codepoint, Windows::Data::Text::UnicodeGeneralCategory* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetGeneralCategory, WINRT_WRAP(Windows::Data::Text::UnicodeGeneralCategory), uint32_t);
            *value = detach_from<Windows::Data::Text::UnicodeGeneralCategory>(this->shim().GetGeneralCategory(codepoint));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Data::Text::IWordSegment> : produce_base<D, Windows::Data::Text::IWordSegment>
{
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

    int32_t WINRT_CALL get_SourceTextSegment(struct struct_Windows_Data_Text_TextSegment* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourceTextSegment, WINRT_WRAP(Windows::Data::Text::TextSegment));
            *value = detach_from<Windows::Data::Text::TextSegment>(this->shim().SourceTextSegment());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AlternateForms(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AlternateForms, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Data::Text::AlternateWordForm>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Data::Text::AlternateWordForm>>(this->shim().AlternateForms());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Data::Text::IWordsSegmenter> : produce_base<D, Windows::Data::Text::IWordsSegmenter>
{
    int32_t WINRT_CALL get_ResolvedLanguage(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResolvedLanguage, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ResolvedLanguage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetTokenAt(void* text, uint32_t startIndex, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetTokenAt, WINRT_WRAP(Windows::Data::Text::WordSegment), hstring const&, uint32_t);
            *result = detach_from<Windows::Data::Text::WordSegment>(this->shim().GetTokenAt(*reinterpret_cast<hstring const*>(&text), startIndex));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetTokens(void* text, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetTokens, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Data::Text::WordSegment>), hstring const&);
            *result = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Data::Text::WordSegment>>(this->shim().GetTokens(*reinterpret_cast<hstring const*>(&text)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Tokenize(void* text, uint32_t startIndex, void* handler) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Tokenize, WINRT_WRAP(void), hstring const&, uint32_t, Windows::Data::Text::WordSegmentsTokenizingHandler const&);
            this->shim().Tokenize(*reinterpret_cast<hstring const*>(&text), startIndex, *reinterpret_cast<Windows::Data::Text::WordSegmentsTokenizingHandler const*>(&handler));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Data::Text::IWordsSegmenterFactory> : produce_base<D, Windows::Data::Text::IWordsSegmenterFactory>
{
    int32_t WINRT_CALL CreateWithLanguage(void* language, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithLanguage, WINRT_WRAP(Windows::Data::Text::WordsSegmenter), hstring const&);
            *result = detach_from<Windows::Data::Text::WordsSegmenter>(this->shim().CreateWithLanguage(*reinterpret_cast<hstring const*>(&language)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Data::Text {

inline SelectableWordsSegmenter::SelectableWordsSegmenter(param::hstring const& language) :
    SelectableWordsSegmenter(impl::call_factory<SelectableWordsSegmenter, Windows::Data::Text::ISelectableWordsSegmenterFactory>([&](auto&& f) { return f.CreateWithLanguage(language); }))
{}

inline SemanticTextQuery::SemanticTextQuery(param::hstring const& aqsFilter) :
    SemanticTextQuery(impl::call_factory<SemanticTextQuery, Windows::Data::Text::ISemanticTextQueryFactory>([&](auto&& f) { return f.Create(aqsFilter); }))
{}

inline SemanticTextQuery::SemanticTextQuery(param::hstring const& aqsFilter, param::hstring const& filterLanguage) :
    SemanticTextQuery(impl::call_factory<SemanticTextQuery, Windows::Data::Text::ISemanticTextQueryFactory>([&](auto&& f) { return f.CreateWithLanguage(aqsFilter, filterLanguage); }))
{}

inline TextConversionGenerator::TextConversionGenerator(param::hstring const& languageTag) :
    TextConversionGenerator(impl::call_factory<TextConversionGenerator, Windows::Data::Text::ITextConversionGeneratorFactory>([&](auto&& f) { return f.Create(languageTag); }))
{}

inline TextPredictionGenerator::TextPredictionGenerator(param::hstring const& languageTag) :
    TextPredictionGenerator(impl::call_factory<TextPredictionGenerator, Windows::Data::Text::ITextPredictionGeneratorFactory>([&](auto&& f) { return f.Create(languageTag); }))
{}

inline TextReverseConversionGenerator::TextReverseConversionGenerator(param::hstring const& languageTag) :
    TextReverseConversionGenerator(impl::call_factory<TextReverseConversionGenerator, Windows::Data::Text::ITextReverseConversionGeneratorFactory>([&](auto&& f) { return f.Create(languageTag); }))
{}

inline uint32_t UnicodeCharacters::GetCodepointFromSurrogatePair(uint32_t highSurrogate, uint32_t lowSurrogate)
{
    return impl::call_factory<UnicodeCharacters, Windows::Data::Text::IUnicodeCharactersStatics>([&](auto&& f) { return f.GetCodepointFromSurrogatePair(highSurrogate, lowSurrogate); });
}

inline void UnicodeCharacters::GetSurrogatePairFromCodepoint(uint32_t codepoint, char16_t& highSurrogate, char16_t& lowSurrogate)
{
    impl::call_factory<UnicodeCharacters, Windows::Data::Text::IUnicodeCharactersStatics>([&](auto&& f) { return f.GetSurrogatePairFromCodepoint(codepoint, highSurrogate, lowSurrogate); });
}

inline bool UnicodeCharacters::IsHighSurrogate(uint32_t codepoint)
{
    return impl::call_factory<UnicodeCharacters, Windows::Data::Text::IUnicodeCharactersStatics>([&](auto&& f) { return f.IsHighSurrogate(codepoint); });
}

inline bool UnicodeCharacters::IsLowSurrogate(uint32_t codepoint)
{
    return impl::call_factory<UnicodeCharacters, Windows::Data::Text::IUnicodeCharactersStatics>([&](auto&& f) { return f.IsLowSurrogate(codepoint); });
}

inline bool UnicodeCharacters::IsSupplementary(uint32_t codepoint)
{
    return impl::call_factory<UnicodeCharacters, Windows::Data::Text::IUnicodeCharactersStatics>([&](auto&& f) { return f.IsSupplementary(codepoint); });
}

inline bool UnicodeCharacters::IsNoncharacter(uint32_t codepoint)
{
    return impl::call_factory<UnicodeCharacters, Windows::Data::Text::IUnicodeCharactersStatics>([&](auto&& f) { return f.IsNoncharacter(codepoint); });
}

inline bool UnicodeCharacters::IsWhitespace(uint32_t codepoint)
{
    return impl::call_factory<UnicodeCharacters, Windows::Data::Text::IUnicodeCharactersStatics>([&](auto&& f) { return f.IsWhitespace(codepoint); });
}

inline bool UnicodeCharacters::IsAlphabetic(uint32_t codepoint)
{
    return impl::call_factory<UnicodeCharacters, Windows::Data::Text::IUnicodeCharactersStatics>([&](auto&& f) { return f.IsAlphabetic(codepoint); });
}

inline bool UnicodeCharacters::IsCased(uint32_t codepoint)
{
    return impl::call_factory<UnicodeCharacters, Windows::Data::Text::IUnicodeCharactersStatics>([&](auto&& f) { return f.IsCased(codepoint); });
}

inline bool UnicodeCharacters::IsUppercase(uint32_t codepoint)
{
    return impl::call_factory<UnicodeCharacters, Windows::Data::Text::IUnicodeCharactersStatics>([&](auto&& f) { return f.IsUppercase(codepoint); });
}

inline bool UnicodeCharacters::IsLowercase(uint32_t codepoint)
{
    return impl::call_factory<UnicodeCharacters, Windows::Data::Text::IUnicodeCharactersStatics>([&](auto&& f) { return f.IsLowercase(codepoint); });
}

inline bool UnicodeCharacters::IsIdStart(uint32_t codepoint)
{
    return impl::call_factory<UnicodeCharacters, Windows::Data::Text::IUnicodeCharactersStatics>([&](auto&& f) { return f.IsIdStart(codepoint); });
}

inline bool UnicodeCharacters::IsIdContinue(uint32_t codepoint)
{
    return impl::call_factory<UnicodeCharacters, Windows::Data::Text::IUnicodeCharactersStatics>([&](auto&& f) { return f.IsIdContinue(codepoint); });
}

inline bool UnicodeCharacters::IsGraphemeBase(uint32_t codepoint)
{
    return impl::call_factory<UnicodeCharacters, Windows::Data::Text::IUnicodeCharactersStatics>([&](auto&& f) { return f.IsGraphemeBase(codepoint); });
}

inline bool UnicodeCharacters::IsGraphemeExtend(uint32_t codepoint)
{
    return impl::call_factory<UnicodeCharacters, Windows::Data::Text::IUnicodeCharactersStatics>([&](auto&& f) { return f.IsGraphemeExtend(codepoint); });
}

inline Windows::Data::Text::UnicodeNumericType UnicodeCharacters::GetNumericType(uint32_t codepoint)
{
    return impl::call_factory<UnicodeCharacters, Windows::Data::Text::IUnicodeCharactersStatics>([&](auto&& f) { return f.GetNumericType(codepoint); });
}

inline Windows::Data::Text::UnicodeGeneralCategory UnicodeCharacters::GetGeneralCategory(uint32_t codepoint)
{
    return impl::call_factory<UnicodeCharacters, Windows::Data::Text::IUnicodeCharactersStatics>([&](auto&& f) { return f.GetGeneralCategory(codepoint); });
}

inline WordsSegmenter::WordsSegmenter(param::hstring const& language) :
    WordsSegmenter(impl::call_factory<WordsSegmenter, Windows::Data::Text::IWordsSegmenterFactory>([&](auto&& f) { return f.CreateWithLanguage(language); }))
{}

template <typename L> SelectableWordSegmentsTokenizingHandler::SelectableWordSegmentsTokenizingHandler(L handler) :
    SelectableWordSegmentsTokenizingHandler(impl::make_delegate<SelectableWordSegmentsTokenizingHandler>(std::forward<L>(handler)))
{}

template <typename F> SelectableWordSegmentsTokenizingHandler::SelectableWordSegmentsTokenizingHandler(F* handler) :
    SelectableWordSegmentsTokenizingHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> SelectableWordSegmentsTokenizingHandler::SelectableWordSegmentsTokenizingHandler(O* object, M method) :
    SelectableWordSegmentsTokenizingHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> SelectableWordSegmentsTokenizingHandler::SelectableWordSegmentsTokenizingHandler(com_ptr<O>&& object, M method) :
    SelectableWordSegmentsTokenizingHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> SelectableWordSegmentsTokenizingHandler::SelectableWordSegmentsTokenizingHandler(weak_ref<O>&& object, M method) :
    SelectableWordSegmentsTokenizingHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void SelectableWordSegmentsTokenizingHandler::operator()(param::iterable<Windows::Data::Text::SelectableWordSegment> const& precedingWords, param::iterable<Windows::Data::Text::SelectableWordSegment> const& words) const
{
    check_hresult((*(impl::abi_t<SelectableWordSegmentsTokenizingHandler>**)this)->Invoke(get_abi(precedingWords), get_abi(words)));
}

template <typename L> WordSegmentsTokenizingHandler::WordSegmentsTokenizingHandler(L handler) :
    WordSegmentsTokenizingHandler(impl::make_delegate<WordSegmentsTokenizingHandler>(std::forward<L>(handler)))
{}

template <typename F> WordSegmentsTokenizingHandler::WordSegmentsTokenizingHandler(F* handler) :
    WordSegmentsTokenizingHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> WordSegmentsTokenizingHandler::WordSegmentsTokenizingHandler(O* object, M method) :
    WordSegmentsTokenizingHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> WordSegmentsTokenizingHandler::WordSegmentsTokenizingHandler(com_ptr<O>&& object, M method) :
    WordSegmentsTokenizingHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> WordSegmentsTokenizingHandler::WordSegmentsTokenizingHandler(weak_ref<O>&& object, M method) :
    WordSegmentsTokenizingHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void WordSegmentsTokenizingHandler::operator()(param::iterable<Windows::Data::Text::WordSegment> const& precedingWords, param::iterable<Windows::Data::Text::WordSegment> const& words) const
{
    check_hresult((*(impl::abi_t<WordSegmentsTokenizingHandler>**)this)->Invoke(get_abi(precedingWords), get_abi(words)));
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Data::Text::IAlternateWordForm> : winrt::impl::hash_base<winrt::Windows::Data::Text::IAlternateWordForm> {};
template<> struct hash<winrt::Windows::Data::Text::ISelectableWordSegment> : winrt::impl::hash_base<winrt::Windows::Data::Text::ISelectableWordSegment> {};
template<> struct hash<winrt::Windows::Data::Text::ISelectableWordsSegmenter> : winrt::impl::hash_base<winrt::Windows::Data::Text::ISelectableWordsSegmenter> {};
template<> struct hash<winrt::Windows::Data::Text::ISelectableWordsSegmenterFactory> : winrt::impl::hash_base<winrt::Windows::Data::Text::ISelectableWordsSegmenterFactory> {};
template<> struct hash<winrt::Windows::Data::Text::ISemanticTextQuery> : winrt::impl::hash_base<winrt::Windows::Data::Text::ISemanticTextQuery> {};
template<> struct hash<winrt::Windows::Data::Text::ISemanticTextQueryFactory> : winrt::impl::hash_base<winrt::Windows::Data::Text::ISemanticTextQueryFactory> {};
template<> struct hash<winrt::Windows::Data::Text::ITextConversionGenerator> : winrt::impl::hash_base<winrt::Windows::Data::Text::ITextConversionGenerator> {};
template<> struct hash<winrt::Windows::Data::Text::ITextConversionGeneratorFactory> : winrt::impl::hash_base<winrt::Windows::Data::Text::ITextConversionGeneratorFactory> {};
template<> struct hash<winrt::Windows::Data::Text::ITextPhoneme> : winrt::impl::hash_base<winrt::Windows::Data::Text::ITextPhoneme> {};
template<> struct hash<winrt::Windows::Data::Text::ITextPredictionGenerator> : winrt::impl::hash_base<winrt::Windows::Data::Text::ITextPredictionGenerator> {};
template<> struct hash<winrt::Windows::Data::Text::ITextPredictionGenerator2> : winrt::impl::hash_base<winrt::Windows::Data::Text::ITextPredictionGenerator2> {};
template<> struct hash<winrt::Windows::Data::Text::ITextPredictionGeneratorFactory> : winrt::impl::hash_base<winrt::Windows::Data::Text::ITextPredictionGeneratorFactory> {};
template<> struct hash<winrt::Windows::Data::Text::ITextReverseConversionGenerator> : winrt::impl::hash_base<winrt::Windows::Data::Text::ITextReverseConversionGenerator> {};
template<> struct hash<winrt::Windows::Data::Text::ITextReverseConversionGenerator2> : winrt::impl::hash_base<winrt::Windows::Data::Text::ITextReverseConversionGenerator2> {};
template<> struct hash<winrt::Windows::Data::Text::ITextReverseConversionGeneratorFactory> : winrt::impl::hash_base<winrt::Windows::Data::Text::ITextReverseConversionGeneratorFactory> {};
template<> struct hash<winrt::Windows::Data::Text::IUnicodeCharactersStatics> : winrt::impl::hash_base<winrt::Windows::Data::Text::IUnicodeCharactersStatics> {};
template<> struct hash<winrt::Windows::Data::Text::IWordSegment> : winrt::impl::hash_base<winrt::Windows::Data::Text::IWordSegment> {};
template<> struct hash<winrt::Windows::Data::Text::IWordsSegmenter> : winrt::impl::hash_base<winrt::Windows::Data::Text::IWordsSegmenter> {};
template<> struct hash<winrt::Windows::Data::Text::IWordsSegmenterFactory> : winrt::impl::hash_base<winrt::Windows::Data::Text::IWordsSegmenterFactory> {};
template<> struct hash<winrt::Windows::Data::Text::AlternateWordForm> : winrt::impl::hash_base<winrt::Windows::Data::Text::AlternateWordForm> {};
template<> struct hash<winrt::Windows::Data::Text::SelectableWordSegment> : winrt::impl::hash_base<winrt::Windows::Data::Text::SelectableWordSegment> {};
template<> struct hash<winrt::Windows::Data::Text::SelectableWordsSegmenter> : winrt::impl::hash_base<winrt::Windows::Data::Text::SelectableWordsSegmenter> {};
template<> struct hash<winrt::Windows::Data::Text::SemanticTextQuery> : winrt::impl::hash_base<winrt::Windows::Data::Text::SemanticTextQuery> {};
template<> struct hash<winrt::Windows::Data::Text::TextConversionGenerator> : winrt::impl::hash_base<winrt::Windows::Data::Text::TextConversionGenerator> {};
template<> struct hash<winrt::Windows::Data::Text::TextPhoneme> : winrt::impl::hash_base<winrt::Windows::Data::Text::TextPhoneme> {};
template<> struct hash<winrt::Windows::Data::Text::TextPredictionGenerator> : winrt::impl::hash_base<winrt::Windows::Data::Text::TextPredictionGenerator> {};
template<> struct hash<winrt::Windows::Data::Text::TextReverseConversionGenerator> : winrt::impl::hash_base<winrt::Windows::Data::Text::TextReverseConversionGenerator> {};
template<> struct hash<winrt::Windows::Data::Text::UnicodeCharacters> : winrt::impl::hash_base<winrt::Windows::Data::Text::UnicodeCharacters> {};
template<> struct hash<winrt::Windows::Data::Text::WordSegment> : winrt::impl::hash_base<winrt::Windows::Data::Text::WordSegment> {};
template<> struct hash<winrt::Windows::Data::Text::WordsSegmenter> : winrt::impl::hash_base<winrt::Windows::Data::Text::WordsSegmenter> {};

}
