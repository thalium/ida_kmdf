// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Media.ContentRestrictions.2.h"
#include "winrt/Windows.Media.h"

namespace winrt::impl {

template <typename D> hstring consume_Windows_Media_ContentRestrictions_IContentRestrictionsBrowsePolicy<D>::GeographicRegion() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::ContentRestrictions::IContentRestrictionsBrowsePolicy)->get_GeographicRegion(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<uint32_t> consume_Windows_Media_ContentRestrictions_IContentRestrictionsBrowsePolicy<D>::MaxBrowsableAgeRating() const
{
    Windows::Foundation::IReference<uint32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::ContentRestrictions::IContentRestrictionsBrowsePolicy)->get_MaxBrowsableAgeRating(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<uint32_t> consume_Windows_Media_ContentRestrictions_IContentRestrictionsBrowsePolicy<D>::PreferredAgeRating() const
{
    Windows::Foundation::IReference<uint32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::ContentRestrictions::IContentRestrictionsBrowsePolicy)->get_PreferredAgeRating(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Media_ContentRestrictions_IRatedContentDescription<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::ContentRestrictions::IRatedContentDescription)->get_Id(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_ContentRestrictions_IRatedContentDescription<D>::Id(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::ContentRestrictions::IRatedContentDescription)->put_Id(get_abi(value)));
}

template <typename D> hstring consume_Windows_Media_ContentRestrictions_IRatedContentDescription<D>::Title() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Media::ContentRestrictions::IRatedContentDescription)->get_Title(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_ContentRestrictions_IRatedContentDescription<D>::Title(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::ContentRestrictions::IRatedContentDescription)->put_Title(get_abi(value)));
}

template <typename D> Windows::Storage::Streams::IRandomAccessStreamReference consume_Windows_Media_ContentRestrictions_IRatedContentDescription<D>::Image() const
{
    Windows::Storage::Streams::IRandomAccessStreamReference value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::ContentRestrictions::IRatedContentDescription)->get_Image(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_ContentRestrictions_IRatedContentDescription<D>::Image(Windows::Storage::Streams::IRandomAccessStreamReference const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::ContentRestrictions::IRatedContentDescription)->put_Image(get_abi(value)));
}

template <typename D> Windows::Media::ContentRestrictions::RatedContentCategory consume_Windows_Media_ContentRestrictions_IRatedContentDescription<D>::Category() const
{
    Windows::Media::ContentRestrictions::RatedContentCategory value{};
    check_hresult(WINRT_SHIM(Windows::Media::ContentRestrictions::IRatedContentDescription)->get_Category(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_ContentRestrictions_IRatedContentDescription<D>::Category(Windows::Media::ContentRestrictions::RatedContentCategory const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::ContentRestrictions::IRatedContentDescription)->put_Category(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVector<hstring> consume_Windows_Media_ContentRestrictions_IRatedContentDescription<D>::Ratings() const
{
    Windows::Foundation::Collections::IVector<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::ContentRestrictions::IRatedContentDescription)->get_Ratings(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Media_ContentRestrictions_IRatedContentDescription<D>::Ratings(param::vector<hstring> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Media::ContentRestrictions::IRatedContentDescription)->put_Ratings(get_abi(value)));
}

template <typename D> Windows::Media::ContentRestrictions::RatedContentDescription consume_Windows_Media_ContentRestrictions_IRatedContentDescriptionFactory<D>::Create(param::hstring const& id, param::hstring const& title, Windows::Media::ContentRestrictions::RatedContentCategory const& category) const
{
    Windows::Media::ContentRestrictions::RatedContentDescription RatedContentDescription{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::ContentRestrictions::IRatedContentDescriptionFactory)->Create(get_abi(id), get_abi(title), get_abi(category), put_abi(RatedContentDescription)));
    return RatedContentDescription;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::ContentRestrictions::ContentRestrictionsBrowsePolicy> consume_Windows_Media_ContentRestrictions_IRatedContentRestrictions<D>::GetBrowsePolicyAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::ContentRestrictions::ContentRestrictionsBrowsePolicy> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::ContentRestrictions::IRatedContentRestrictions)->GetBrowsePolicyAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::ContentRestrictions::ContentAccessRestrictionLevel> consume_Windows_Media_ContentRestrictions_IRatedContentRestrictions<D>::GetRestrictionLevelAsync(Windows::Media::ContentRestrictions::RatedContentDescription const& RatedContentDescription) const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::ContentRestrictions::ContentAccessRestrictionLevel> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::ContentRestrictions::IRatedContentRestrictions)->GetRestrictionLevelAsync(get_abi(RatedContentDescription), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Media_ContentRestrictions_IRatedContentRestrictions<D>::RequestContentAccessAsync(Windows::Media::ContentRestrictions::RatedContentDescription const& RatedContentDescription) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::ContentRestrictions::IRatedContentRestrictions)->RequestContentAccessAsync(get_abi(RatedContentDescription), put_abi(operation)));
    return operation;
}

template <typename D> winrt::event_token consume_Windows_Media_ContentRestrictions_IRatedContentRestrictions<D>::RestrictionsChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Media::ContentRestrictions::IRatedContentRestrictions)->add_RestrictionsChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Media_ContentRestrictions_IRatedContentRestrictions<D>::RestrictionsChanged_revoker consume_Windows_Media_ContentRestrictions_IRatedContentRestrictions<D>::RestrictionsChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, RestrictionsChanged_revoker>(this, RestrictionsChanged(handler));
}

template <typename D> void consume_Windows_Media_ContentRestrictions_IRatedContentRestrictions<D>::RestrictionsChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Media::ContentRestrictions::IRatedContentRestrictions)->remove_RestrictionsChanged(get_abi(token)));
}

template <typename D> Windows::Media::ContentRestrictions::RatedContentRestrictions consume_Windows_Media_ContentRestrictions_IRatedContentRestrictionsFactory<D>::CreateWithMaxAgeRating(uint32_t maxAgeRating) const
{
    Windows::Media::ContentRestrictions::RatedContentRestrictions ratedContentRestrictions{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::ContentRestrictions::IRatedContentRestrictionsFactory)->CreateWithMaxAgeRating(maxAgeRating, put_abi(ratedContentRestrictions)));
    return ratedContentRestrictions;
}

template <typename D>
struct produce<D, Windows::Media::ContentRestrictions::IContentRestrictionsBrowsePolicy> : produce_base<D, Windows::Media::ContentRestrictions::IContentRestrictionsBrowsePolicy>
{
    int32_t WINRT_CALL get_GeographicRegion(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GeographicRegion, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().GeographicRegion());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxBrowsableAgeRating(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxBrowsableAgeRating, WINRT_WRAP(Windows::Foundation::IReference<uint32_t>));
            *value = detach_from<Windows::Foundation::IReference<uint32_t>>(this->shim().MaxBrowsableAgeRating());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PreferredAgeRating(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PreferredAgeRating, WINRT_WRAP(Windows::Foundation::IReference<uint32_t>));
            *value = detach_from<Windows::Foundation::IReference<uint32_t>>(this->shim().PreferredAgeRating());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::ContentRestrictions::IRatedContentDescription> : produce_base<D, Windows::Media::ContentRestrictions::IRatedContentDescription>
{
    int32_t WINRT_CALL get_Id(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Id, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Id(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Id, WINRT_WRAP(void), hstring const&);
            this->shim().Id(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Title(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Title, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Title());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Title(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Title, WINRT_WRAP(void), hstring const&);
            this->shim().Title(*reinterpret_cast<hstring const*>(&value));
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

    int32_t WINRT_CALL put_Image(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Image, WINRT_WRAP(void), Windows::Storage::Streams::IRandomAccessStreamReference const&);
            this->shim().Image(*reinterpret_cast<Windows::Storage::Streams::IRandomAccessStreamReference const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Category(Windows::Media::ContentRestrictions::RatedContentCategory* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Category, WINRT_WRAP(Windows::Media::ContentRestrictions::RatedContentCategory));
            *value = detach_from<Windows::Media::ContentRestrictions::RatedContentCategory>(this->shim().Category());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Category(Windows::Media::ContentRestrictions::RatedContentCategory value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Category, WINRT_WRAP(void), Windows::Media::ContentRestrictions::RatedContentCategory const&);
            this->shim().Category(*reinterpret_cast<Windows::Media::ContentRestrictions::RatedContentCategory const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Ratings(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Ratings, WINRT_WRAP(Windows::Foundation::Collections::IVector<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVector<hstring>>(this->shim().Ratings());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Ratings(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Ratings, WINRT_WRAP(void), Windows::Foundation::Collections::IVector<hstring> const&);
            this->shim().Ratings(*reinterpret_cast<Windows::Foundation::Collections::IVector<hstring> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::ContentRestrictions::IRatedContentDescriptionFactory> : produce_base<D, Windows::Media::ContentRestrictions::IRatedContentDescriptionFactory>
{
    int32_t WINRT_CALL Create(void* id, void* title, Windows::Media::ContentRestrictions::RatedContentCategory category, void** RatedContentDescription) noexcept final
    {
        try
        {
            *RatedContentDescription = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Media::ContentRestrictions::RatedContentDescription), hstring const&, hstring const&, Windows::Media::ContentRestrictions::RatedContentCategory const&);
            *RatedContentDescription = detach_from<Windows::Media::ContentRestrictions::RatedContentDescription>(this->shim().Create(*reinterpret_cast<hstring const*>(&id), *reinterpret_cast<hstring const*>(&title), *reinterpret_cast<Windows::Media::ContentRestrictions::RatedContentCategory const*>(&category)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::ContentRestrictions::IRatedContentRestrictions> : produce_base<D, Windows::Media::ContentRestrictions::IRatedContentRestrictions>
{
    int32_t WINRT_CALL GetBrowsePolicyAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetBrowsePolicyAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::ContentRestrictions::ContentRestrictionsBrowsePolicy>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::ContentRestrictions::ContentRestrictionsBrowsePolicy>>(this->shim().GetBrowsePolicyAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetRestrictionLevelAsync(void* RatedContentDescription, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetRestrictionLevelAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::ContentRestrictions::ContentAccessRestrictionLevel>), Windows::Media::ContentRestrictions::RatedContentDescription const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::ContentRestrictions::ContentAccessRestrictionLevel>>(this->shim().GetRestrictionLevelAsync(*reinterpret_cast<Windows::Media::ContentRestrictions::RatedContentDescription const*>(&RatedContentDescription)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestContentAccessAsync(void* RatedContentDescription, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestContentAccessAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::Media::ContentRestrictions::RatedContentDescription const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().RequestContentAccessAsync(*reinterpret_cast<Windows::Media::ContentRestrictions::RatedContentDescription const*>(&RatedContentDescription)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_RestrictionsChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RestrictionsChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().RestrictionsChanged(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_RestrictionsChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(RestrictionsChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().RestrictionsChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Media::ContentRestrictions::IRatedContentRestrictionsFactory> : produce_base<D, Windows::Media::ContentRestrictions::IRatedContentRestrictionsFactory>
{
    int32_t WINRT_CALL CreateWithMaxAgeRating(uint32_t maxAgeRating, void** ratedContentRestrictions) noexcept final
    {
        try
        {
            *ratedContentRestrictions = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithMaxAgeRating, WINRT_WRAP(Windows::Media::ContentRestrictions::RatedContentRestrictions), uint32_t);
            *ratedContentRestrictions = detach_from<Windows::Media::ContentRestrictions::RatedContentRestrictions>(this->shim().CreateWithMaxAgeRating(maxAgeRating));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Media::ContentRestrictions {

inline RatedContentDescription::RatedContentDescription(param::hstring const& id, param::hstring const& title, Windows::Media::ContentRestrictions::RatedContentCategory const& category) :
    RatedContentDescription(impl::call_factory<RatedContentDescription, Windows::Media::ContentRestrictions::IRatedContentDescriptionFactory>([&](auto&& f) { return f.Create(id, title, category); }))
{}

inline RatedContentRestrictions::RatedContentRestrictions() :
    RatedContentRestrictions(impl::call_factory<RatedContentRestrictions>([](auto&& f) { return f.template ActivateInstance<RatedContentRestrictions>(); }))
{}

inline RatedContentRestrictions::RatedContentRestrictions(uint32_t maxAgeRating) :
    RatedContentRestrictions(impl::call_factory<RatedContentRestrictions, Windows::Media::ContentRestrictions::IRatedContentRestrictionsFactory>([&](auto&& f) { return f.CreateWithMaxAgeRating(maxAgeRating); }))
{}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Media::ContentRestrictions::IContentRestrictionsBrowsePolicy> : winrt::impl::hash_base<winrt::Windows::Media::ContentRestrictions::IContentRestrictionsBrowsePolicy> {};
template<> struct hash<winrt::Windows::Media::ContentRestrictions::IRatedContentDescription> : winrt::impl::hash_base<winrt::Windows::Media::ContentRestrictions::IRatedContentDescription> {};
template<> struct hash<winrt::Windows::Media::ContentRestrictions::IRatedContentDescriptionFactory> : winrt::impl::hash_base<winrt::Windows::Media::ContentRestrictions::IRatedContentDescriptionFactory> {};
template<> struct hash<winrt::Windows::Media::ContentRestrictions::IRatedContentRestrictions> : winrt::impl::hash_base<winrt::Windows::Media::ContentRestrictions::IRatedContentRestrictions> {};
template<> struct hash<winrt::Windows::Media::ContentRestrictions::IRatedContentRestrictionsFactory> : winrt::impl::hash_base<winrt::Windows::Media::ContentRestrictions::IRatedContentRestrictionsFactory> {};
template<> struct hash<winrt::Windows::Media::ContentRestrictions::ContentRestrictionsBrowsePolicy> : winrt::impl::hash_base<winrt::Windows::Media::ContentRestrictions::ContentRestrictionsBrowsePolicy> {};
template<> struct hash<winrt::Windows::Media::ContentRestrictions::RatedContentDescription> : winrt::impl::hash_base<winrt::Windows::Media::ContentRestrictions::RatedContentDescription> {};
template<> struct hash<winrt::Windows::Media::ContentRestrictions::RatedContentRestrictions> : winrt::impl::hash_base<winrt::Windows::Media::ContentRestrictions::RatedContentRestrictions> {};

}
