// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Storage.1.h"
#include "winrt/impl/Windows.Storage.Streams.1.h"
#include "winrt/impl/Windows.ApplicationModel.Search.1.h"

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Search {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Search {

struct WINRT_EBO LocalContentSuggestionSettings :
    Windows::ApplicationModel::Search::ILocalContentSuggestionSettings
{
    LocalContentSuggestionSettings(std::nullptr_t) noexcept {}
    LocalContentSuggestionSettings();
};

struct WINRT_EBO SearchPane :
    Windows::ApplicationModel::Search::ISearchPane
{
    SearchPane(std::nullptr_t) noexcept {}
    static Windows::ApplicationModel::Search::SearchPane GetForCurrentView();
    static void HideThisApplication();
};

struct WINRT_EBO SearchPaneQueryChangedEventArgs :
    Windows::ApplicationModel::Search::ISearchPaneQueryChangedEventArgs
{
    SearchPaneQueryChangedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO SearchPaneQueryLinguisticDetails :
    Windows::ApplicationModel::Search::ISearchPaneQueryLinguisticDetails
{
    SearchPaneQueryLinguisticDetails(std::nullptr_t) noexcept {}
};

struct WINRT_EBO SearchPaneQuerySubmittedEventArgs :
    Windows::ApplicationModel::Search::ISearchPaneQuerySubmittedEventArgs,
    impl::require<SearchPaneQuerySubmittedEventArgs, Windows::ApplicationModel::Search::ISearchPaneQuerySubmittedEventArgsWithLinguisticDetails>
{
    SearchPaneQuerySubmittedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO SearchPaneResultSuggestionChosenEventArgs :
    Windows::ApplicationModel::Search::ISearchPaneResultSuggestionChosenEventArgs
{
    SearchPaneResultSuggestionChosenEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO SearchPaneSuggestionsRequest :
    Windows::ApplicationModel::Search::ISearchPaneSuggestionsRequest
{
    SearchPaneSuggestionsRequest(std::nullptr_t) noexcept {}
};

struct WINRT_EBO SearchPaneSuggestionsRequestDeferral :
    Windows::ApplicationModel::Search::ISearchPaneSuggestionsRequestDeferral
{
    SearchPaneSuggestionsRequestDeferral(std::nullptr_t) noexcept {}
};

struct WINRT_EBO SearchPaneSuggestionsRequestedEventArgs :
    Windows::ApplicationModel::Search::ISearchPaneSuggestionsRequestedEventArgs
{
    SearchPaneSuggestionsRequestedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO SearchPaneVisibilityChangedEventArgs :
    Windows::ApplicationModel::Search::ISearchPaneVisibilityChangedEventArgs
{
    SearchPaneVisibilityChangedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO SearchQueryLinguisticDetails :
    Windows::ApplicationModel::Search::ISearchQueryLinguisticDetails
{
    SearchQueryLinguisticDetails(std::nullptr_t) noexcept {}
    SearchQueryLinguisticDetails(param::iterable<hstring> const& queryTextAlternatives, uint32_t queryTextCompositionStart, uint32_t queryTextCompositionLength);
};

struct WINRT_EBO SearchSuggestionCollection :
    Windows::ApplicationModel::Search::ISearchSuggestionCollection
{
    SearchSuggestionCollection(std::nullptr_t) noexcept {}
};

struct WINRT_EBO SearchSuggestionsRequest :
    Windows::ApplicationModel::Search::ISearchSuggestionsRequest
{
    SearchSuggestionsRequest(std::nullptr_t) noexcept {}
};

struct WINRT_EBO SearchSuggestionsRequestDeferral :
    Windows::ApplicationModel::Search::ISearchSuggestionsRequestDeferral
{
    SearchSuggestionsRequestDeferral(std::nullptr_t) noexcept {}
};

}
