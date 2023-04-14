// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Storage.0.h"
#include "winrt/impl/Windows.Storage.Streams.0.h"
#include "winrt/impl/Windows.ApplicationModel.Search.0.h"

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Search {

struct WINRT_EBO ILocalContentSuggestionSettings :
    Windows::Foundation::IInspectable,
    impl::consume_t<ILocalContentSuggestionSettings>
{
    ILocalContentSuggestionSettings(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISearchPane :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISearchPane>
{
    ISearchPane(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISearchPaneQueryChangedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISearchPaneQueryChangedEventArgs>
{
    ISearchPaneQueryChangedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISearchPaneQueryLinguisticDetails :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISearchPaneQueryLinguisticDetails>
{
    ISearchPaneQueryLinguisticDetails(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISearchPaneQuerySubmittedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISearchPaneQuerySubmittedEventArgs>
{
    ISearchPaneQuerySubmittedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISearchPaneQuerySubmittedEventArgsWithLinguisticDetails :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISearchPaneQuerySubmittedEventArgsWithLinguisticDetails>
{
    ISearchPaneQuerySubmittedEventArgsWithLinguisticDetails(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISearchPaneResultSuggestionChosenEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISearchPaneResultSuggestionChosenEventArgs>
{
    ISearchPaneResultSuggestionChosenEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISearchPaneStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISearchPaneStatics>
{
    ISearchPaneStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISearchPaneStaticsWithHideThisApplication :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISearchPaneStaticsWithHideThisApplication>
{
    ISearchPaneStaticsWithHideThisApplication(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISearchPaneSuggestionsRequest :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISearchPaneSuggestionsRequest>
{
    ISearchPaneSuggestionsRequest(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISearchPaneSuggestionsRequestDeferral :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISearchPaneSuggestionsRequestDeferral>
{
    ISearchPaneSuggestionsRequestDeferral(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISearchPaneSuggestionsRequestedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISearchPaneSuggestionsRequestedEventArgs>,
    impl::require<ISearchPaneSuggestionsRequestedEventArgs, Windows::ApplicationModel::Search::ISearchPaneQueryChangedEventArgs>
{
    ISearchPaneSuggestionsRequestedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISearchPaneVisibilityChangedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISearchPaneVisibilityChangedEventArgs>
{
    ISearchPaneVisibilityChangedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISearchQueryLinguisticDetails :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISearchQueryLinguisticDetails>
{
    ISearchQueryLinguisticDetails(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISearchQueryLinguisticDetailsFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISearchQueryLinguisticDetailsFactory>
{
    ISearchQueryLinguisticDetailsFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISearchSuggestionCollection :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISearchSuggestionCollection>
{
    ISearchSuggestionCollection(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISearchSuggestionsRequest :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISearchSuggestionsRequest>
{
    ISearchSuggestionsRequest(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISearchSuggestionsRequestDeferral :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISearchSuggestionsRequestDeferral>
{
    ISearchSuggestionsRequestDeferral(std::nullptr_t = nullptr) noexcept {}
};

}
