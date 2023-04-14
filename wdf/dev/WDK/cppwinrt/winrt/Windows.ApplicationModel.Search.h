// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Storage.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.ApplicationModel.Search.2.h"
#include "winrt/Windows.ApplicationModel.h"

namespace winrt::impl {

template <typename D> void consume_Windows_ApplicationModel_Search_ILocalContentSuggestionSettings<D>::Enabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::ILocalContentSuggestionSettings)->put_Enabled(value));
}

template <typename D> bool consume_Windows_ApplicationModel_Search_ILocalContentSuggestionSettings<D>::Enabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::ILocalContentSuggestionSettings)->get_Enabled(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::Storage::StorageFolder> consume_Windows_ApplicationModel_Search_ILocalContentSuggestionSettings<D>::Locations() const
{
    Windows::Foundation::Collections::IVector<Windows::Storage::StorageFolder> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::ILocalContentSuggestionSettings)->get_Locations(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Search_ILocalContentSuggestionSettings<D>::AqsFilter(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::ILocalContentSuggestionSettings)->put_AqsFilter(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Search_ILocalContentSuggestionSettings<D>::AqsFilter() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::ILocalContentSuggestionSettings)->get_AqsFilter(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<hstring> consume_Windows_ApplicationModel_Search_ILocalContentSuggestionSettings<D>::PropertiesToMatch() const
{
    Windows::Foundation::Collections::IVector<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::ILocalContentSuggestionSettings)->get_PropertiesToMatch(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Search_ISearchPane<D>::SearchHistoryEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::ISearchPane)->put_SearchHistoryEnabled(value));
}

template <typename D> bool consume_Windows_ApplicationModel_Search_ISearchPane<D>::SearchHistoryEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::ISearchPane)->get_SearchHistoryEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Search_ISearchPane<D>::SearchHistoryContext(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::ISearchPane)->put_SearchHistoryContext(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Search_ISearchPane<D>::SearchHistoryContext() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::ISearchPane)->get_SearchHistoryContext(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Search_ISearchPane<D>::PlaceholderText(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::ISearchPane)->put_PlaceholderText(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Search_ISearchPane<D>::PlaceholderText() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::ISearchPane)->get_PlaceholderText(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Search_ISearchPane<D>::QueryText() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::ISearchPane)->get_QueryText(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Search_ISearchPane<D>::Language() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::ISearchPane)->get_Language(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Search_ISearchPane<D>::Visible() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::ISearchPane)->get_Visible(&value));
    return value;
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Search_ISearchPane<D>::VisibilityChanged(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Search::SearchPane, Windows::ApplicationModel::Search::SearchPaneVisibilityChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::ISearchPane)->add_VisibilityChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Search_ISearchPane<D>::VisibilityChanged_revoker consume_Windows_ApplicationModel_Search_ISearchPane<D>::VisibilityChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Search::SearchPane, Windows::ApplicationModel::Search::SearchPaneVisibilityChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, VisibilityChanged_revoker>(this, VisibilityChanged(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Search_ISearchPane<D>::VisibilityChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Search::ISearchPane)->remove_VisibilityChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Search_ISearchPane<D>::QueryChanged(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Search::SearchPane, Windows::ApplicationModel::Search::SearchPaneQueryChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::ISearchPane)->add_QueryChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Search_ISearchPane<D>::QueryChanged_revoker consume_Windows_ApplicationModel_Search_ISearchPane<D>::QueryChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Search::SearchPane, Windows::ApplicationModel::Search::SearchPaneQueryChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, QueryChanged_revoker>(this, QueryChanged(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Search_ISearchPane<D>::QueryChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Search::ISearchPane)->remove_QueryChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Search_ISearchPane<D>::SuggestionsRequested(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Search::SearchPane, Windows::ApplicationModel::Search::SearchPaneSuggestionsRequestedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::ISearchPane)->add_SuggestionsRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Search_ISearchPane<D>::SuggestionsRequested_revoker consume_Windows_ApplicationModel_Search_ISearchPane<D>::SuggestionsRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Search::SearchPane, Windows::ApplicationModel::Search::SearchPaneSuggestionsRequestedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, SuggestionsRequested_revoker>(this, SuggestionsRequested(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Search_ISearchPane<D>::SuggestionsRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Search::ISearchPane)->remove_SuggestionsRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Search_ISearchPane<D>::QuerySubmitted(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Search::SearchPane, Windows::ApplicationModel::Search::SearchPaneQuerySubmittedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::ISearchPane)->add_QuerySubmitted(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Search_ISearchPane<D>::QuerySubmitted_revoker consume_Windows_ApplicationModel_Search_ISearchPane<D>::QuerySubmitted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Search::SearchPane, Windows::ApplicationModel::Search::SearchPaneQuerySubmittedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, QuerySubmitted_revoker>(this, QuerySubmitted(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Search_ISearchPane<D>::QuerySubmitted(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Search::ISearchPane)->remove_QuerySubmitted(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Search_ISearchPane<D>::ResultSuggestionChosen(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Search::SearchPane, Windows::ApplicationModel::Search::SearchPaneResultSuggestionChosenEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::ISearchPane)->add_ResultSuggestionChosen(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Search_ISearchPane<D>::ResultSuggestionChosen_revoker consume_Windows_ApplicationModel_Search_ISearchPane<D>::ResultSuggestionChosen(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Search::SearchPane, Windows::ApplicationModel::Search::SearchPaneResultSuggestionChosenEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ResultSuggestionChosen_revoker>(this, ResultSuggestionChosen(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Search_ISearchPane<D>::ResultSuggestionChosen(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Search::ISearchPane)->remove_ResultSuggestionChosen(get_abi(token)));
}

template <typename D> void consume_Windows_ApplicationModel_Search_ISearchPane<D>::SetLocalContentSuggestionSettings(Windows::ApplicationModel::Search::LocalContentSuggestionSettings const& settings) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::ISearchPane)->SetLocalContentSuggestionSettings(get_abi(settings)));
}

template <typename D> void consume_Windows_ApplicationModel_Search_ISearchPane<D>::Show() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::ISearchPane)->ShowOverloadDefault());
}

template <typename D> void consume_Windows_ApplicationModel_Search_ISearchPane<D>::Show(param::hstring const& query) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::ISearchPane)->ShowOverloadWithQuery(get_abi(query)));
}

template <typename D> void consume_Windows_ApplicationModel_Search_ISearchPane<D>::ShowOnKeyboardInput(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::ISearchPane)->put_ShowOnKeyboardInput(value));
}

template <typename D> bool consume_Windows_ApplicationModel_Search_ISearchPane<D>::ShowOnKeyboardInput() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::ISearchPane)->get_ShowOnKeyboardInput(&value));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Search_ISearchPane<D>::TrySetQueryText(param::hstring const& query) const
{
    bool succeeded{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::ISearchPane)->TrySetQueryText(get_abi(query), &succeeded));
    return succeeded;
}

template <typename D> hstring consume_Windows_ApplicationModel_Search_ISearchPaneQueryChangedEventArgs<D>::QueryText() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::ISearchPaneQueryChangedEventArgs)->get_QueryText(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Search_ISearchPaneQueryChangedEventArgs<D>::Language() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::ISearchPaneQueryChangedEventArgs)->get_Language(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Search::SearchPaneQueryLinguisticDetails consume_Windows_ApplicationModel_Search_ISearchPaneQueryChangedEventArgs<D>::LinguisticDetails() const
{
    Windows::ApplicationModel::Search::SearchPaneQueryLinguisticDetails value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::ISearchPaneQueryChangedEventArgs)->get_LinguisticDetails(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<hstring> consume_Windows_ApplicationModel_Search_ISearchPaneQueryLinguisticDetails<D>::QueryTextAlternatives() const
{
    Windows::Foundation::Collections::IVectorView<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::ISearchPaneQueryLinguisticDetails)->get_QueryTextAlternatives(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_ApplicationModel_Search_ISearchPaneQueryLinguisticDetails<D>::QueryTextCompositionStart() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::ISearchPaneQueryLinguisticDetails)->get_QueryTextCompositionStart(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_ApplicationModel_Search_ISearchPaneQueryLinguisticDetails<D>::QueryTextCompositionLength() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::ISearchPaneQueryLinguisticDetails)->get_QueryTextCompositionLength(&value));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Search_ISearchPaneQuerySubmittedEventArgs<D>::QueryText() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::ISearchPaneQuerySubmittedEventArgs)->get_QueryText(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Search_ISearchPaneQuerySubmittedEventArgs<D>::Language() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::ISearchPaneQuerySubmittedEventArgs)->get_Language(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Search::SearchPaneQueryLinguisticDetails consume_Windows_ApplicationModel_Search_ISearchPaneQuerySubmittedEventArgsWithLinguisticDetails<D>::LinguisticDetails() const
{
    Windows::ApplicationModel::Search::SearchPaneQueryLinguisticDetails value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::ISearchPaneQuerySubmittedEventArgsWithLinguisticDetails)->get_LinguisticDetails(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Search_ISearchPaneResultSuggestionChosenEventArgs<D>::Tag() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::ISearchPaneResultSuggestionChosenEventArgs)->get_Tag(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Search::SearchPane consume_Windows_ApplicationModel_Search_ISearchPaneStatics<D>::GetForCurrentView() const
{
    Windows::ApplicationModel::Search::SearchPane searchPane{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::ISearchPaneStatics)->GetForCurrentView(put_abi(searchPane)));
    return searchPane;
}

template <typename D> void consume_Windows_ApplicationModel_Search_ISearchPaneStaticsWithHideThisApplication<D>::HideThisApplication() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::ISearchPaneStaticsWithHideThisApplication)->HideThisApplication());
}

template <typename D> bool consume_Windows_ApplicationModel_Search_ISearchPaneSuggestionsRequest<D>::IsCanceled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::ISearchPaneSuggestionsRequest)->get_IsCanceled(&value));
    return value;
}

template <typename D> Windows::ApplicationModel::Search::SearchSuggestionCollection consume_Windows_ApplicationModel_Search_ISearchPaneSuggestionsRequest<D>::SearchSuggestionCollection() const
{
    Windows::ApplicationModel::Search::SearchSuggestionCollection collection{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::ISearchPaneSuggestionsRequest)->get_SearchSuggestionCollection(put_abi(collection)));
    return collection;
}

template <typename D> Windows::ApplicationModel::Search::SearchPaneSuggestionsRequestDeferral consume_Windows_ApplicationModel_Search_ISearchPaneSuggestionsRequest<D>::GetDeferral() const
{
    Windows::ApplicationModel::Search::SearchPaneSuggestionsRequestDeferral deferral{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::ISearchPaneSuggestionsRequest)->GetDeferral(put_abi(deferral)));
    return deferral;
}

template <typename D> void consume_Windows_ApplicationModel_Search_ISearchPaneSuggestionsRequestDeferral<D>::Complete() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::ISearchPaneSuggestionsRequestDeferral)->Complete());
}

template <typename D> Windows::ApplicationModel::Search::SearchPaneSuggestionsRequest consume_Windows_ApplicationModel_Search_ISearchPaneSuggestionsRequestedEventArgs<D>::Request() const
{
    Windows::ApplicationModel::Search::SearchPaneSuggestionsRequest value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::ISearchPaneSuggestionsRequestedEventArgs)->get_Request(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Search_ISearchPaneVisibilityChangedEventArgs<D>::Visible() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::ISearchPaneVisibilityChangedEventArgs)->get_Visible(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<hstring> consume_Windows_ApplicationModel_Search_ISearchQueryLinguisticDetails<D>::QueryTextAlternatives() const
{
    Windows::Foundation::Collections::IVectorView<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::ISearchQueryLinguisticDetails)->get_QueryTextAlternatives(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_ApplicationModel_Search_ISearchQueryLinguisticDetails<D>::QueryTextCompositionStart() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::ISearchQueryLinguisticDetails)->get_QueryTextCompositionStart(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_ApplicationModel_Search_ISearchQueryLinguisticDetails<D>::QueryTextCompositionLength() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::ISearchQueryLinguisticDetails)->get_QueryTextCompositionLength(&value));
    return value;
}

template <typename D> Windows::ApplicationModel::Search::SearchQueryLinguisticDetails consume_Windows_ApplicationModel_Search_ISearchQueryLinguisticDetailsFactory<D>::CreateInstance(param::iterable<hstring> const& queryTextAlternatives, uint32_t queryTextCompositionStart, uint32_t queryTextCompositionLength) const
{
    Windows::ApplicationModel::Search::SearchQueryLinguisticDetails value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::ISearchQueryLinguisticDetailsFactory)->CreateInstance(get_abi(queryTextAlternatives), queryTextCompositionStart, queryTextCompositionLength, put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_ApplicationModel_Search_ISearchSuggestionCollection<D>::Size() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::ISearchSuggestionCollection)->get_Size(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Search_ISearchSuggestionCollection<D>::AppendQuerySuggestion(param::hstring const& text) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::ISearchSuggestionCollection)->AppendQuerySuggestion(get_abi(text)));
}

template <typename D> void consume_Windows_ApplicationModel_Search_ISearchSuggestionCollection<D>::AppendQuerySuggestions(param::iterable<hstring> const& suggestions) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::ISearchSuggestionCollection)->AppendQuerySuggestions(get_abi(suggestions)));
}

template <typename D> void consume_Windows_ApplicationModel_Search_ISearchSuggestionCollection<D>::AppendResultSuggestion(param::hstring const& text, param::hstring const& detailText, param::hstring const& tag, Windows::Storage::Streams::IRandomAccessStreamReference const& image, param::hstring const& imageAlternateText) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::ISearchSuggestionCollection)->AppendResultSuggestion(get_abi(text), get_abi(detailText), get_abi(tag), get_abi(image), get_abi(imageAlternateText)));
}

template <typename D> void consume_Windows_ApplicationModel_Search_ISearchSuggestionCollection<D>::AppendSearchSeparator(param::hstring const& label) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::ISearchSuggestionCollection)->AppendSearchSeparator(get_abi(label)));
}

template <typename D> bool consume_Windows_ApplicationModel_Search_ISearchSuggestionsRequest<D>::IsCanceled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::ISearchSuggestionsRequest)->get_IsCanceled(&value));
    return value;
}

template <typename D> Windows::ApplicationModel::Search::SearchSuggestionCollection consume_Windows_ApplicationModel_Search_ISearchSuggestionsRequest<D>::SearchSuggestionCollection() const
{
    Windows::ApplicationModel::Search::SearchSuggestionCollection collection{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::ISearchSuggestionsRequest)->get_SearchSuggestionCollection(put_abi(collection)));
    return collection;
}

template <typename D> Windows::ApplicationModel::Search::SearchSuggestionsRequestDeferral consume_Windows_ApplicationModel_Search_ISearchSuggestionsRequest<D>::GetDeferral() const
{
    Windows::ApplicationModel::Search::SearchSuggestionsRequestDeferral deferral{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::ISearchSuggestionsRequest)->GetDeferral(put_abi(deferral)));
    return deferral;
}

template <typename D> void consume_Windows_ApplicationModel_Search_ISearchSuggestionsRequestDeferral<D>::Complete() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::ISearchSuggestionsRequestDeferral)->Complete());
}

template <typename D>
struct produce<D, Windows::ApplicationModel::Search::ILocalContentSuggestionSettings> : produce_base<D, Windows::ApplicationModel::Search::ILocalContentSuggestionSettings>
{
    int32_t WINRT_CALL put_Enabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Enabled, WINRT_WRAP(void), bool);
            this->shim().Enabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Enabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Enabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Enabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Locations(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Locations, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::Storage::StorageFolder>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::Storage::StorageFolder>>(this->shim().Locations());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AqsFilter(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AqsFilter, WINRT_WRAP(void), hstring const&);
            this->shim().AqsFilter(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AqsFilter(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AqsFilter, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AqsFilter());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PropertiesToMatch(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PropertiesToMatch, WINRT_WRAP(Windows::Foundation::Collections::IVector<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVector<hstring>>(this->shim().PropertiesToMatch());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Search::ISearchPane> : produce_base<D, Windows::ApplicationModel::Search::ISearchPane>
{
    int32_t WINRT_CALL put_SearchHistoryEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SearchHistoryEnabled, WINRT_WRAP(void), bool);
            this->shim().SearchHistoryEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SearchHistoryEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SearchHistoryEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().SearchHistoryEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SearchHistoryContext(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SearchHistoryContext, WINRT_WRAP(void), hstring const&);
            this->shim().SearchHistoryContext(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SearchHistoryContext(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SearchHistoryContext, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SearchHistoryContext());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PlaceholderText(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PlaceholderText, WINRT_WRAP(void), hstring const&);
            this->shim().PlaceholderText(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PlaceholderText(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PlaceholderText, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().PlaceholderText());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_QueryText(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(QueryText, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().QueryText());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Language(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Language, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Language());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Visible(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Visible, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Visible());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_VisibilityChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VisibilityChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Search::SearchPane, Windows::ApplicationModel::Search::SearchPaneVisibilityChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().VisibilityChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Search::SearchPane, Windows::ApplicationModel::Search::SearchPaneVisibilityChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_VisibilityChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(VisibilityChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().VisibilityChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_QueryChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(QueryChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Search::SearchPane, Windows::ApplicationModel::Search::SearchPaneQueryChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().QueryChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Search::SearchPane, Windows::ApplicationModel::Search::SearchPaneQueryChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_QueryChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(QueryChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().QueryChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_SuggestionsRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SuggestionsRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Search::SearchPane, Windows::ApplicationModel::Search::SearchPaneSuggestionsRequestedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().SuggestionsRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Search::SearchPane, Windows::ApplicationModel::Search::SearchPaneSuggestionsRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_SuggestionsRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(SuggestionsRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().SuggestionsRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_QuerySubmitted(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(QuerySubmitted, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Search::SearchPane, Windows::ApplicationModel::Search::SearchPaneQuerySubmittedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().QuerySubmitted(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Search::SearchPane, Windows::ApplicationModel::Search::SearchPaneQuerySubmittedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_QuerySubmitted(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(QuerySubmitted, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().QuerySubmitted(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_ResultSuggestionChosen(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResultSuggestionChosen, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Search::SearchPane, Windows::ApplicationModel::Search::SearchPaneResultSuggestionChosenEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ResultSuggestionChosen(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Search::SearchPane, Windows::ApplicationModel::Search::SearchPaneResultSuggestionChosenEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ResultSuggestionChosen(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ResultSuggestionChosen, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ResultSuggestionChosen(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL SetLocalContentSuggestionSettings(void* settings) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetLocalContentSuggestionSettings, WINRT_WRAP(void), Windows::ApplicationModel::Search::LocalContentSuggestionSettings const&);
            this->shim().SetLocalContentSuggestionSettings(*reinterpret_cast<Windows::ApplicationModel::Search::LocalContentSuggestionSettings const*>(&settings));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ShowOverloadDefault() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Show, WINRT_WRAP(void));
            this->shim().Show();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ShowOverloadWithQuery(void* query) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Show, WINRT_WRAP(void), hstring const&);
            this->shim().Show(*reinterpret_cast<hstring const*>(&query));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ShowOnKeyboardInput(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowOnKeyboardInput, WINRT_WRAP(void), bool);
            this->shim().ShowOnKeyboardInput(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ShowOnKeyboardInput(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowOnKeyboardInput, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().ShowOnKeyboardInput());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TrySetQueryText(void* query, bool* succeeded) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrySetQueryText, WINRT_WRAP(bool), hstring const&);
            *succeeded = detach_from<bool>(this->shim().TrySetQueryText(*reinterpret_cast<hstring const*>(&query)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Search::ISearchPaneQueryChangedEventArgs> : produce_base<D, Windows::ApplicationModel::Search::ISearchPaneQueryChangedEventArgs>
{
    int32_t WINRT_CALL get_QueryText(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(QueryText, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().QueryText());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Language(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Language, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Language());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LinguisticDetails(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LinguisticDetails, WINRT_WRAP(Windows::ApplicationModel::Search::SearchPaneQueryLinguisticDetails));
            *value = detach_from<Windows::ApplicationModel::Search::SearchPaneQueryLinguisticDetails>(this->shim().LinguisticDetails());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Search::ISearchPaneQueryLinguisticDetails> : produce_base<D, Windows::ApplicationModel::Search::ISearchPaneQueryLinguisticDetails>
{
    int32_t WINRT_CALL get_QueryTextAlternatives(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(QueryTextAlternatives, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().QueryTextAlternatives());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_QueryTextCompositionStart(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(QueryTextCompositionStart, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().QueryTextCompositionStart());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_QueryTextCompositionLength(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(QueryTextCompositionLength, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().QueryTextCompositionLength());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Search::ISearchPaneQuerySubmittedEventArgs> : produce_base<D, Windows::ApplicationModel::Search::ISearchPaneQuerySubmittedEventArgs>
{
    int32_t WINRT_CALL get_QueryText(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(QueryText, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().QueryText());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Language(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Language, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Language());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Search::ISearchPaneQuerySubmittedEventArgsWithLinguisticDetails> : produce_base<D, Windows::ApplicationModel::Search::ISearchPaneQuerySubmittedEventArgsWithLinguisticDetails>
{
    int32_t WINRT_CALL get_LinguisticDetails(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LinguisticDetails, WINRT_WRAP(Windows::ApplicationModel::Search::SearchPaneQueryLinguisticDetails));
            *value = detach_from<Windows::ApplicationModel::Search::SearchPaneQueryLinguisticDetails>(this->shim().LinguisticDetails());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Search::ISearchPaneResultSuggestionChosenEventArgs> : produce_base<D, Windows::ApplicationModel::Search::ISearchPaneResultSuggestionChosenEventArgs>
{
    int32_t WINRT_CALL get_Tag(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Tag, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Tag());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Search::ISearchPaneStatics> : produce_base<D, Windows::ApplicationModel::Search::ISearchPaneStatics>
{
    int32_t WINRT_CALL GetForCurrentView(void** searchPane) noexcept final
    {
        try
        {
            *searchPane = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForCurrentView, WINRT_WRAP(Windows::ApplicationModel::Search::SearchPane));
            *searchPane = detach_from<Windows::ApplicationModel::Search::SearchPane>(this->shim().GetForCurrentView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Search::ISearchPaneStaticsWithHideThisApplication> : produce_base<D, Windows::ApplicationModel::Search::ISearchPaneStaticsWithHideThisApplication>
{
    int32_t WINRT_CALL HideThisApplication() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HideThisApplication, WINRT_WRAP(void));
            this->shim().HideThisApplication();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Search::ISearchPaneSuggestionsRequest> : produce_base<D, Windows::ApplicationModel::Search::ISearchPaneSuggestionsRequest>
{
    int32_t WINRT_CALL get_IsCanceled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsCanceled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsCanceled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SearchSuggestionCollection(void** collection) noexcept final
    {
        try
        {
            *collection = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SearchSuggestionCollection, WINRT_WRAP(Windows::ApplicationModel::Search::SearchSuggestionCollection));
            *collection = detach_from<Windows::ApplicationModel::Search::SearchSuggestionCollection>(this->shim().SearchSuggestionCollection());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeferral(void** deferral) noexcept final
    {
        try
        {
            *deferral = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeferral, WINRT_WRAP(Windows::ApplicationModel::Search::SearchPaneSuggestionsRequestDeferral));
            *deferral = detach_from<Windows::ApplicationModel::Search::SearchPaneSuggestionsRequestDeferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Search::ISearchPaneSuggestionsRequestDeferral> : produce_base<D, Windows::ApplicationModel::Search::ISearchPaneSuggestionsRequestDeferral>
{
    int32_t WINRT_CALL Complete() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Complete, WINRT_WRAP(void));
            this->shim().Complete();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Search::ISearchPaneSuggestionsRequestedEventArgs> : produce_base<D, Windows::ApplicationModel::Search::ISearchPaneSuggestionsRequestedEventArgs>
{
    int32_t WINRT_CALL get_Request(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Request, WINRT_WRAP(Windows::ApplicationModel::Search::SearchPaneSuggestionsRequest));
            *value = detach_from<Windows::ApplicationModel::Search::SearchPaneSuggestionsRequest>(this->shim().Request());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Search::ISearchPaneVisibilityChangedEventArgs> : produce_base<D, Windows::ApplicationModel::Search::ISearchPaneVisibilityChangedEventArgs>
{
    int32_t WINRT_CALL get_Visible(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Visible, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Visible());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Search::ISearchQueryLinguisticDetails> : produce_base<D, Windows::ApplicationModel::Search::ISearchQueryLinguisticDetails>
{
    int32_t WINRT_CALL get_QueryTextAlternatives(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(QueryTextAlternatives, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().QueryTextAlternatives());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_QueryTextCompositionStart(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(QueryTextCompositionStart, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().QueryTextCompositionStart());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_QueryTextCompositionLength(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(QueryTextCompositionLength, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().QueryTextCompositionLength());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Search::ISearchQueryLinguisticDetailsFactory> : produce_base<D, Windows::ApplicationModel::Search::ISearchQueryLinguisticDetailsFactory>
{
    int32_t WINRT_CALL CreateInstance(void* queryTextAlternatives, uint32_t queryTextCompositionStart, uint32_t queryTextCompositionLength, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::ApplicationModel::Search::SearchQueryLinguisticDetails), Windows::Foundation::Collections::IIterable<hstring> const&, uint32_t, uint32_t);
            *value = detach_from<Windows::ApplicationModel::Search::SearchQueryLinguisticDetails>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&queryTextAlternatives), queryTextCompositionStart, queryTextCompositionLength));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Search::ISearchSuggestionCollection> : produce_base<D, Windows::ApplicationModel::Search::ISearchSuggestionCollection>
{
    int32_t WINRT_CALL get_Size(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Size, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Size());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AppendQuerySuggestion(void* text) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppendQuerySuggestion, WINRT_WRAP(void), hstring const&);
            this->shim().AppendQuerySuggestion(*reinterpret_cast<hstring const*>(&text));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AppendQuerySuggestions(void* suggestions) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppendQuerySuggestions, WINRT_WRAP(void), Windows::Foundation::Collections::IIterable<hstring> const&);
            this->shim().AppendQuerySuggestions(*reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&suggestions));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AppendResultSuggestion(void* text, void* detailText, void* tag, void* image, void* imageAlternateText) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppendResultSuggestion, WINRT_WRAP(void), hstring const&, hstring const&, hstring const&, Windows::Storage::Streams::IRandomAccessStreamReference const&, hstring const&);
            this->shim().AppendResultSuggestion(*reinterpret_cast<hstring const*>(&text), *reinterpret_cast<hstring const*>(&detailText), *reinterpret_cast<hstring const*>(&tag), *reinterpret_cast<Windows::Storage::Streams::IRandomAccessStreamReference const*>(&image), *reinterpret_cast<hstring const*>(&imageAlternateText));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AppendSearchSeparator(void* label) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppendSearchSeparator, WINRT_WRAP(void), hstring const&);
            this->shim().AppendSearchSeparator(*reinterpret_cast<hstring const*>(&label));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Search::ISearchSuggestionsRequest> : produce_base<D, Windows::ApplicationModel::Search::ISearchSuggestionsRequest>
{
    int32_t WINRT_CALL get_IsCanceled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsCanceled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsCanceled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SearchSuggestionCollection(void** collection) noexcept final
    {
        try
        {
            *collection = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SearchSuggestionCollection, WINRT_WRAP(Windows::ApplicationModel::Search::SearchSuggestionCollection));
            *collection = detach_from<Windows::ApplicationModel::Search::SearchSuggestionCollection>(this->shim().SearchSuggestionCollection());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeferral(void** deferral) noexcept final
    {
        try
        {
            *deferral = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeferral, WINRT_WRAP(Windows::ApplicationModel::Search::SearchSuggestionsRequestDeferral));
            *deferral = detach_from<Windows::ApplicationModel::Search::SearchSuggestionsRequestDeferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Search::ISearchSuggestionsRequestDeferral> : produce_base<D, Windows::ApplicationModel::Search::ISearchSuggestionsRequestDeferral>
{
    int32_t WINRT_CALL Complete() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Complete, WINRT_WRAP(void));
            this->shim().Complete();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Search {

inline LocalContentSuggestionSettings::LocalContentSuggestionSettings() :
    LocalContentSuggestionSettings(impl::call_factory<LocalContentSuggestionSettings>([](auto&& f) { return f.template ActivateInstance<LocalContentSuggestionSettings>(); }))
{}

inline Windows::ApplicationModel::Search::SearchPane SearchPane::GetForCurrentView()
{
    return impl::call_factory<SearchPane, Windows::ApplicationModel::Search::ISearchPaneStatics>([&](auto&& f) { return f.GetForCurrentView(); });
}

inline void SearchPane::HideThisApplication()
{
    impl::call_factory<SearchPane, Windows::ApplicationModel::Search::ISearchPaneStaticsWithHideThisApplication>([&](auto&& f) { return f.HideThisApplication(); });
}

inline SearchQueryLinguisticDetails::SearchQueryLinguisticDetails(param::iterable<hstring> const& queryTextAlternatives, uint32_t queryTextCompositionStart, uint32_t queryTextCompositionLength) :
    SearchQueryLinguisticDetails(impl::call_factory<SearchQueryLinguisticDetails, Windows::ApplicationModel::Search::ISearchQueryLinguisticDetailsFactory>([&](auto&& f) { return f.CreateInstance(queryTextAlternatives, queryTextCompositionStart, queryTextCompositionLength); }))
{}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::ApplicationModel::Search::ILocalContentSuggestionSettings> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Search::ILocalContentSuggestionSettings> {};
template<> struct hash<winrt::Windows::ApplicationModel::Search::ISearchPane> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Search::ISearchPane> {};
template<> struct hash<winrt::Windows::ApplicationModel::Search::ISearchPaneQueryChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Search::ISearchPaneQueryChangedEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Search::ISearchPaneQueryLinguisticDetails> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Search::ISearchPaneQueryLinguisticDetails> {};
template<> struct hash<winrt::Windows::ApplicationModel::Search::ISearchPaneQuerySubmittedEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Search::ISearchPaneQuerySubmittedEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Search::ISearchPaneQuerySubmittedEventArgsWithLinguisticDetails> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Search::ISearchPaneQuerySubmittedEventArgsWithLinguisticDetails> {};
template<> struct hash<winrt::Windows::ApplicationModel::Search::ISearchPaneResultSuggestionChosenEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Search::ISearchPaneResultSuggestionChosenEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Search::ISearchPaneStatics> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Search::ISearchPaneStatics> {};
template<> struct hash<winrt::Windows::ApplicationModel::Search::ISearchPaneStaticsWithHideThisApplication> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Search::ISearchPaneStaticsWithHideThisApplication> {};
template<> struct hash<winrt::Windows::ApplicationModel::Search::ISearchPaneSuggestionsRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Search::ISearchPaneSuggestionsRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::Search::ISearchPaneSuggestionsRequestDeferral> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Search::ISearchPaneSuggestionsRequestDeferral> {};
template<> struct hash<winrt::Windows::ApplicationModel::Search::ISearchPaneSuggestionsRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Search::ISearchPaneSuggestionsRequestedEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Search::ISearchPaneVisibilityChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Search::ISearchPaneVisibilityChangedEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Search::ISearchQueryLinguisticDetails> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Search::ISearchQueryLinguisticDetails> {};
template<> struct hash<winrt::Windows::ApplicationModel::Search::ISearchQueryLinguisticDetailsFactory> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Search::ISearchQueryLinguisticDetailsFactory> {};
template<> struct hash<winrt::Windows::ApplicationModel::Search::ISearchSuggestionCollection> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Search::ISearchSuggestionCollection> {};
template<> struct hash<winrt::Windows::ApplicationModel::Search::ISearchSuggestionsRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Search::ISearchSuggestionsRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::Search::ISearchSuggestionsRequestDeferral> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Search::ISearchSuggestionsRequestDeferral> {};
template<> struct hash<winrt::Windows::ApplicationModel::Search::LocalContentSuggestionSettings> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Search::LocalContentSuggestionSettings> {};
template<> struct hash<winrt::Windows::ApplicationModel::Search::SearchPane> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Search::SearchPane> {};
template<> struct hash<winrt::Windows::ApplicationModel::Search::SearchPaneQueryChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Search::SearchPaneQueryChangedEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Search::SearchPaneQueryLinguisticDetails> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Search::SearchPaneQueryLinguisticDetails> {};
template<> struct hash<winrt::Windows::ApplicationModel::Search::SearchPaneQuerySubmittedEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Search::SearchPaneQuerySubmittedEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Search::SearchPaneResultSuggestionChosenEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Search::SearchPaneResultSuggestionChosenEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Search::SearchPaneSuggestionsRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Search::SearchPaneSuggestionsRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::Search::SearchPaneSuggestionsRequestDeferral> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Search::SearchPaneSuggestionsRequestDeferral> {};
template<> struct hash<winrt::Windows::ApplicationModel::Search::SearchPaneSuggestionsRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Search::SearchPaneSuggestionsRequestedEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Search::SearchPaneVisibilityChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Search::SearchPaneVisibilityChangedEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Search::SearchQueryLinguisticDetails> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Search::SearchQueryLinguisticDetails> {};
template<> struct hash<winrt::Windows::ApplicationModel::Search::SearchSuggestionCollection> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Search::SearchSuggestionCollection> {};
template<> struct hash<winrt::Windows::ApplicationModel::Search::SearchSuggestionsRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Search::SearchSuggestionsRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::Search::SearchSuggestionsRequestDeferral> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Search::SearchSuggestionsRequestDeferral> {};

}
