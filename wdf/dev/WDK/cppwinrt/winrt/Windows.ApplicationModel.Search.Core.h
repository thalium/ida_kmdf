// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.ApplicationModel.Search.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.ApplicationModel.Search.Core.2.h"
#include "winrt/Windows.ApplicationModel.Search.h"

namespace winrt::impl {

template <typename D> Windows::ApplicationModel::Search::Core::SearchSuggestionKind consume_Windows_ApplicationModel_Search_Core_ISearchSuggestion<D>::Kind() const
{
    Windows::ApplicationModel::Search::Core::SearchSuggestionKind value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::Core::ISearchSuggestion)->get_Kind(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Search_Core_ISearchSuggestion<D>::Text() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::Core::ISearchSuggestion)->get_Text(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Search_Core_ISearchSuggestion<D>::Tag() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::Core::ISearchSuggestion)->get_Tag(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Search_Core_ISearchSuggestion<D>::DetailText() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::Core::ISearchSuggestion)->get_DetailText(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IRandomAccessStreamReference consume_Windows_ApplicationModel_Search_Core_ISearchSuggestion<D>::Image() const
{
    Windows::Storage::Streams::IRandomAccessStreamReference value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::Core::ISearchSuggestion)->get_Image(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Search_Core_ISearchSuggestion<D>::ImageAlternateText() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::Core::ISearchSuggestion)->get_ImageAlternateText(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_Search_Core_ISearchSuggestionManager<D>::SearchHistoryEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::Core::ISearchSuggestionManager)->get_SearchHistoryEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Search_Core_ISearchSuggestionManager<D>::SearchHistoryEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::Core::ISearchSuggestionManager)->put_SearchHistoryEnabled(value));
}

template <typename D> hstring consume_Windows_ApplicationModel_Search_Core_ISearchSuggestionManager<D>::SearchHistoryContext() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::Core::ISearchSuggestionManager)->get_SearchHistoryContext(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Search_Core_ISearchSuggestionManager<D>::SearchHistoryContext(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::Core::ISearchSuggestionManager)->put_SearchHistoryContext(get_abi(value)));
}

template <typename D> void consume_Windows_ApplicationModel_Search_Core_ISearchSuggestionManager<D>::SetLocalContentSuggestionSettings(Windows::ApplicationModel::Search::LocalContentSuggestionSettings const& settings) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::Core::ISearchSuggestionManager)->SetLocalContentSuggestionSettings(get_abi(settings)));
}

template <typename D> void consume_Windows_ApplicationModel_Search_Core_ISearchSuggestionManager<D>::SetQuery(param::hstring const& queryText) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::Core::ISearchSuggestionManager)->SetQuery(get_abi(queryText)));
}

template <typename D> void consume_Windows_ApplicationModel_Search_Core_ISearchSuggestionManager<D>::SetQuery(param::hstring const& queryText, param::hstring const& language) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::Core::ISearchSuggestionManager)->SetQueryWithLanguage(get_abi(queryText), get_abi(language)));
}

template <typename D> void consume_Windows_ApplicationModel_Search_Core_ISearchSuggestionManager<D>::SetQuery(param::hstring const& queryText, param::hstring const& language, Windows::ApplicationModel::Search::SearchQueryLinguisticDetails const& linguisticDetails) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::Core::ISearchSuggestionManager)->SetQueryWithSearchQueryLinguisticDetails(get_abi(queryText), get_abi(language), get_abi(linguisticDetails)));
}

template <typename D> Windows::Foundation::Collections::IObservableVector<Windows::ApplicationModel::Search::Core::SearchSuggestion> consume_Windows_ApplicationModel_Search_Core_ISearchSuggestionManager<D>::Suggestions() const
{
    Windows::Foundation::Collections::IObservableVector<Windows::ApplicationModel::Search::Core::SearchSuggestion> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::Core::ISearchSuggestionManager)->get_Suggestions(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Search_Core_ISearchSuggestionManager<D>::AddToHistory(param::hstring const& queryText) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::Core::ISearchSuggestionManager)->AddToHistory(get_abi(queryText)));
}

template <typename D> void consume_Windows_ApplicationModel_Search_Core_ISearchSuggestionManager<D>::AddToHistory(param::hstring const& queryText, param::hstring const& language) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::Core::ISearchSuggestionManager)->AddToHistoryWithLanguage(get_abi(queryText), get_abi(language)));
}

template <typename D> void consume_Windows_ApplicationModel_Search_Core_ISearchSuggestionManager<D>::ClearHistory() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::Core::ISearchSuggestionManager)->ClearHistory());
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Search_Core_ISearchSuggestionManager<D>::SuggestionsRequested(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Search::Core::SearchSuggestionManager, Windows::ApplicationModel::Search::Core::SearchSuggestionsRequestedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::Core::ISearchSuggestionManager)->add_SuggestionsRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Search_Core_ISearchSuggestionManager<D>::SuggestionsRequested_revoker consume_Windows_ApplicationModel_Search_Core_ISearchSuggestionManager<D>::SuggestionsRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Search::Core::SearchSuggestionManager, Windows::ApplicationModel::Search::Core::SearchSuggestionsRequestedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, SuggestionsRequested_revoker>(this, SuggestionsRequested(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Search_Core_ISearchSuggestionManager<D>::SuggestionsRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Search::Core::ISearchSuggestionManager)->remove_SuggestionsRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Search_Core_ISearchSuggestionManager<D>::RequestingFocusOnKeyboardInput(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Search::Core::SearchSuggestionManager, Windows::ApplicationModel::Search::Core::RequestingFocusOnKeyboardInputEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::Core::ISearchSuggestionManager)->add_RequestingFocusOnKeyboardInput(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_Search_Core_ISearchSuggestionManager<D>::RequestingFocusOnKeyboardInput_revoker consume_Windows_ApplicationModel_Search_Core_ISearchSuggestionManager<D>::RequestingFocusOnKeyboardInput(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Search::Core::SearchSuggestionManager, Windows::ApplicationModel::Search::Core::RequestingFocusOnKeyboardInputEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, RequestingFocusOnKeyboardInput_revoker>(this, RequestingFocusOnKeyboardInput(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Search_Core_ISearchSuggestionManager<D>::RequestingFocusOnKeyboardInput(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Search::Core::ISearchSuggestionManager)->remove_RequestingFocusOnKeyboardInput(get_abi(token)));
}

template <typename D> hstring consume_Windows_ApplicationModel_Search_Core_ISearchSuggestionsRequestedEventArgs<D>::QueryText() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::Core::ISearchSuggestionsRequestedEventArgs)->get_QueryText(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Search_Core_ISearchSuggestionsRequestedEventArgs<D>::Language() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::Core::ISearchSuggestionsRequestedEventArgs)->get_Language(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Search::SearchQueryLinguisticDetails consume_Windows_ApplicationModel_Search_Core_ISearchSuggestionsRequestedEventArgs<D>::LinguisticDetails() const
{
    Windows::ApplicationModel::Search::SearchQueryLinguisticDetails value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::Core::ISearchSuggestionsRequestedEventArgs)->get_LinguisticDetails(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Search::SearchSuggestionsRequest consume_Windows_ApplicationModel_Search_Core_ISearchSuggestionsRequestedEventArgs<D>::Request() const
{
    Windows::ApplicationModel::Search::SearchSuggestionsRequest value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Search::Core::ISearchSuggestionsRequestedEventArgs)->get_Request(put_abi(value)));
    return value;
}

template <typename D>
struct produce<D, Windows::ApplicationModel::Search::Core::IRequestingFocusOnKeyboardInputEventArgs> : produce_base<D, Windows::ApplicationModel::Search::Core::IRequestingFocusOnKeyboardInputEventArgs>
{};

template <typename D>
struct produce<D, Windows::ApplicationModel::Search::Core::ISearchSuggestion> : produce_base<D, Windows::ApplicationModel::Search::Core::ISearchSuggestion>
{
    int32_t WINRT_CALL get_Kind(Windows::ApplicationModel::Search::Core::SearchSuggestionKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Kind, WINRT_WRAP(Windows::ApplicationModel::Search::Core::SearchSuggestionKind));
            *value = detach_from<Windows::ApplicationModel::Search::Core::SearchSuggestionKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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

    int32_t WINRT_CALL get_DetailText(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DetailText, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DetailText());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Image(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Image, WINRT_WRAP(Windows::Storage::Streams::IRandomAccessStreamReference));
            *value = detach_from<Windows::Storage::Streams::IRandomAccessStreamReference>(this->shim().Image());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ImageAlternateText(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ImageAlternateText, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ImageAlternateText());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Search::Core::ISearchSuggestionManager> : produce_base<D, Windows::ApplicationModel::Search::Core::ISearchSuggestionManager>
{
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

    int32_t WINRT_CALL SetQuery(void* queryText) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetQuery, WINRT_WRAP(void), hstring const&);
            this->shim().SetQuery(*reinterpret_cast<hstring const*>(&queryText));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetQueryWithLanguage(void* queryText, void* language) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetQuery, WINRT_WRAP(void), hstring const&, hstring const&);
            this->shim().SetQuery(*reinterpret_cast<hstring const*>(&queryText), *reinterpret_cast<hstring const*>(&language));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetQueryWithSearchQueryLinguisticDetails(void* queryText, void* language, void* linguisticDetails) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetQuery, WINRT_WRAP(void), hstring const&, hstring const&, Windows::ApplicationModel::Search::SearchQueryLinguisticDetails const&);
            this->shim().SetQuery(*reinterpret_cast<hstring const*>(&queryText), *reinterpret_cast<hstring const*>(&language), *reinterpret_cast<Windows::ApplicationModel::Search::SearchQueryLinguisticDetails const*>(&linguisticDetails));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Suggestions(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Suggestions, WINRT_WRAP(Windows::Foundation::Collections::IObservableVector<Windows::ApplicationModel::Search::Core::SearchSuggestion>));
            *value = detach_from<Windows::Foundation::Collections::IObservableVector<Windows::ApplicationModel::Search::Core::SearchSuggestion>>(this->shim().Suggestions());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AddToHistory(void* queryText) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddToHistory, WINRT_WRAP(void), hstring const&);
            this->shim().AddToHistory(*reinterpret_cast<hstring const*>(&queryText));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AddToHistoryWithLanguage(void* queryText, void* language) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddToHistory, WINRT_WRAP(void), hstring const&, hstring const&);
            this->shim().AddToHistory(*reinterpret_cast<hstring const*>(&queryText), *reinterpret_cast<hstring const*>(&language));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ClearHistory() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClearHistory, WINRT_WRAP(void));
            this->shim().ClearHistory();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_SuggestionsRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SuggestionsRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Search::Core::SearchSuggestionManager, Windows::ApplicationModel::Search::Core::SearchSuggestionsRequestedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().SuggestionsRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Search::Core::SearchSuggestionManager, Windows::ApplicationModel::Search::Core::SearchSuggestionsRequestedEventArgs> const*>(&handler)));
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

    int32_t WINRT_CALL add_RequestingFocusOnKeyboardInput(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestingFocusOnKeyboardInput, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Search::Core::SearchSuggestionManager, Windows::ApplicationModel::Search::Core::RequestingFocusOnKeyboardInputEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().RequestingFocusOnKeyboardInput(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Search::Core::SearchSuggestionManager, Windows::ApplicationModel::Search::Core::RequestingFocusOnKeyboardInputEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_RequestingFocusOnKeyboardInput(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(RequestingFocusOnKeyboardInput, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().RequestingFocusOnKeyboardInput(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Search::Core::ISearchSuggestionsRequestedEventArgs> : produce_base<D, Windows::ApplicationModel::Search::Core::ISearchSuggestionsRequestedEventArgs>
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
            WINRT_ASSERT_DECLARATION(LinguisticDetails, WINRT_WRAP(Windows::ApplicationModel::Search::SearchQueryLinguisticDetails));
            *value = detach_from<Windows::ApplicationModel::Search::SearchQueryLinguisticDetails>(this->shim().LinguisticDetails());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Request(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Request, WINRT_WRAP(Windows::ApplicationModel::Search::SearchSuggestionsRequest));
            *value = detach_from<Windows::ApplicationModel::Search::SearchSuggestionsRequest>(this->shim().Request());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Search::Core {

inline SearchSuggestionManager::SearchSuggestionManager() :
    SearchSuggestionManager(impl::call_factory<SearchSuggestionManager>([](auto&& f) { return f.template ActivateInstance<SearchSuggestionManager>(); }))
{}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::ApplicationModel::Search::Core::IRequestingFocusOnKeyboardInputEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Search::Core::IRequestingFocusOnKeyboardInputEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Search::Core::ISearchSuggestion> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Search::Core::ISearchSuggestion> {};
template<> struct hash<winrt::Windows::ApplicationModel::Search::Core::ISearchSuggestionManager> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Search::Core::ISearchSuggestionManager> {};
template<> struct hash<winrt::Windows::ApplicationModel::Search::Core::ISearchSuggestionsRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Search::Core::ISearchSuggestionsRequestedEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Search::Core::RequestingFocusOnKeyboardInputEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Search::Core::RequestingFocusOnKeyboardInputEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Search::Core::SearchSuggestion> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Search::Core::SearchSuggestion> {};
template<> struct hash<winrt::Windows::ApplicationModel::Search::Core::SearchSuggestionManager> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Search::Core::SearchSuggestionManager> {};
template<> struct hash<winrt::Windows::ApplicationModel::Search::Core::SearchSuggestionsRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Search::Core::SearchSuggestionsRequestedEventArgs> {};

}
