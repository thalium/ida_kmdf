// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Storage::Streams {

struct IRandomAccessStreamReference;

}

WINRT_EXPORT namespace winrt::Windows::Media::ContentRestrictions {

enum class ContentAccessRestrictionLevel : int32_t
{
    Allow = 0,
    Warn = 1,
    Block = 2,
    Hide = 3,
};

enum class RatedContentCategory : int32_t
{
    General = 0,
    Application = 1,
    Game = 2,
    Movie = 3,
    Television = 4,
    Music = 5,
};

struct IContentRestrictionsBrowsePolicy;
struct IRatedContentDescription;
struct IRatedContentDescriptionFactory;
struct IRatedContentRestrictions;
struct IRatedContentRestrictionsFactory;
struct ContentRestrictionsBrowsePolicy;
struct RatedContentDescription;
struct RatedContentRestrictions;

}

namespace winrt::impl {

template <> struct category<Windows::Media::ContentRestrictions::IContentRestrictionsBrowsePolicy>{ using type = interface_category; };
template <> struct category<Windows::Media::ContentRestrictions::IRatedContentDescription>{ using type = interface_category; };
template <> struct category<Windows::Media::ContentRestrictions::IRatedContentDescriptionFactory>{ using type = interface_category; };
template <> struct category<Windows::Media::ContentRestrictions::IRatedContentRestrictions>{ using type = interface_category; };
template <> struct category<Windows::Media::ContentRestrictions::IRatedContentRestrictionsFactory>{ using type = interface_category; };
template <> struct category<Windows::Media::ContentRestrictions::ContentRestrictionsBrowsePolicy>{ using type = class_category; };
template <> struct category<Windows::Media::ContentRestrictions::RatedContentDescription>{ using type = class_category; };
template <> struct category<Windows::Media::ContentRestrictions::RatedContentRestrictions>{ using type = class_category; };
template <> struct category<Windows::Media::ContentRestrictions::ContentAccessRestrictionLevel>{ using type = enum_category; };
template <> struct category<Windows::Media::ContentRestrictions::RatedContentCategory>{ using type = enum_category; };
template <> struct name<Windows::Media::ContentRestrictions::IContentRestrictionsBrowsePolicy>{ static constexpr auto & value{ L"Windows.Media.ContentRestrictions.IContentRestrictionsBrowsePolicy" }; };
template <> struct name<Windows::Media::ContentRestrictions::IRatedContentDescription>{ static constexpr auto & value{ L"Windows.Media.ContentRestrictions.IRatedContentDescription" }; };
template <> struct name<Windows::Media::ContentRestrictions::IRatedContentDescriptionFactory>{ static constexpr auto & value{ L"Windows.Media.ContentRestrictions.IRatedContentDescriptionFactory" }; };
template <> struct name<Windows::Media::ContentRestrictions::IRatedContentRestrictions>{ static constexpr auto & value{ L"Windows.Media.ContentRestrictions.IRatedContentRestrictions" }; };
template <> struct name<Windows::Media::ContentRestrictions::IRatedContentRestrictionsFactory>{ static constexpr auto & value{ L"Windows.Media.ContentRestrictions.IRatedContentRestrictionsFactory" }; };
template <> struct name<Windows::Media::ContentRestrictions::ContentRestrictionsBrowsePolicy>{ static constexpr auto & value{ L"Windows.Media.ContentRestrictions.ContentRestrictionsBrowsePolicy" }; };
template <> struct name<Windows::Media::ContentRestrictions::RatedContentDescription>{ static constexpr auto & value{ L"Windows.Media.ContentRestrictions.RatedContentDescription" }; };
template <> struct name<Windows::Media::ContentRestrictions::RatedContentRestrictions>{ static constexpr auto & value{ L"Windows.Media.ContentRestrictions.RatedContentRestrictions" }; };
template <> struct name<Windows::Media::ContentRestrictions::ContentAccessRestrictionLevel>{ static constexpr auto & value{ L"Windows.Media.ContentRestrictions.ContentAccessRestrictionLevel" }; };
template <> struct name<Windows::Media::ContentRestrictions::RatedContentCategory>{ static constexpr auto & value{ L"Windows.Media.ContentRestrictions.RatedContentCategory" }; };
template <> struct guid_storage<Windows::Media::ContentRestrictions::IContentRestrictionsBrowsePolicy>{ static constexpr guid value{ 0x8C0133A4,0x442E,0x461A,{ 0x87,0x57,0xFA,0xD2,0xF5,0xBD,0x37,0xE4 } }; };
template <> struct guid_storage<Windows::Media::ContentRestrictions::IRatedContentDescription>{ static constexpr guid value{ 0x694866DF,0x66B2,0x4DC3,{ 0x96,0xB1,0xF0,0x90,0xEE,0xDE,0xE2,0x55 } }; };
template <> struct guid_storage<Windows::Media::ContentRestrictions::IRatedContentDescriptionFactory>{ static constexpr guid value{ 0x2E38DF62,0x9B90,0x4FA6,{ 0x89,0xC1,0x4B,0x8D,0x2F,0xFB,0x35,0x73 } }; };
template <> struct guid_storage<Windows::Media::ContentRestrictions::IRatedContentRestrictions>{ static constexpr guid value{ 0x3F7F23CB,0xBA07,0x4401,{ 0xA4,0x9D,0x8B,0x92,0x22,0x20,0x57,0x23 } }; };
template <> struct guid_storage<Windows::Media::ContentRestrictions::IRatedContentRestrictionsFactory>{ static constexpr guid value{ 0xFB4B2996,0xC3BD,0x4910,{ 0x96,0x19,0x97,0xCF,0xD0,0x69,0x4D,0x56 } }; };
template <> struct default_interface<Windows::Media::ContentRestrictions::ContentRestrictionsBrowsePolicy>{ using type = Windows::Media::ContentRestrictions::IContentRestrictionsBrowsePolicy; };
template <> struct default_interface<Windows::Media::ContentRestrictions::RatedContentDescription>{ using type = Windows::Media::ContentRestrictions::IRatedContentDescription; };
template <> struct default_interface<Windows::Media::ContentRestrictions::RatedContentRestrictions>{ using type = Windows::Media::ContentRestrictions::IRatedContentRestrictions; };

template <> struct abi<Windows::Media::ContentRestrictions::IContentRestrictionsBrowsePolicy>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_GeographicRegion(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MaxBrowsableAgeRating(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PreferredAgeRating(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Media::ContentRestrictions::IRatedContentDescription>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Id(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Id(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Title(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Title(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Image(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Image(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Category(Windows::Media::ContentRestrictions::RatedContentCategory* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Category(Windows::Media::ContentRestrictions::RatedContentCategory value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Ratings(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Ratings(void* value) noexcept = 0;
};};

template <> struct abi<Windows::Media::ContentRestrictions::IRatedContentDescriptionFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL Create(void* id, void* title, Windows::Media::ContentRestrictions::RatedContentCategory category, void** RatedContentDescription) noexcept = 0;
};};

template <> struct abi<Windows::Media::ContentRestrictions::IRatedContentRestrictions>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetBrowsePolicyAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetRestrictionLevelAsync(void* RatedContentDescription, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL RequestContentAccessAsync(void* RatedContentDescription, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL add_RestrictionsChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_RestrictionsChanged(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::Media::ContentRestrictions::IRatedContentRestrictionsFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateWithMaxAgeRating(uint32_t maxAgeRating, void** ratedContentRestrictions) noexcept = 0;
};};

template <typename D>
struct consume_Windows_Media_ContentRestrictions_IContentRestrictionsBrowsePolicy
{
    hstring GeographicRegion() const;
    Windows::Foundation::IReference<uint32_t> MaxBrowsableAgeRating() const;
    Windows::Foundation::IReference<uint32_t> PreferredAgeRating() const;
};
template <> struct consume<Windows::Media::ContentRestrictions::IContentRestrictionsBrowsePolicy> { template <typename D> using type = consume_Windows_Media_ContentRestrictions_IContentRestrictionsBrowsePolicy<D>; };

template <typename D>
struct consume_Windows_Media_ContentRestrictions_IRatedContentDescription
{
    hstring Id() const;
    void Id(param::hstring const& value) const;
    hstring Title() const;
    void Title(param::hstring const& value) const;
    Windows::Storage::Streams::IRandomAccessStreamReference Image() const;
    void Image(Windows::Storage::Streams::IRandomAccessStreamReference const& value) const;
    Windows::Media::ContentRestrictions::RatedContentCategory Category() const;
    void Category(Windows::Media::ContentRestrictions::RatedContentCategory const& value) const;
    Windows::Foundation::Collections::IVector<hstring> Ratings() const;
    void Ratings(param::vector<hstring> const& value) const;
};
template <> struct consume<Windows::Media::ContentRestrictions::IRatedContentDescription> { template <typename D> using type = consume_Windows_Media_ContentRestrictions_IRatedContentDescription<D>; };

template <typename D>
struct consume_Windows_Media_ContentRestrictions_IRatedContentDescriptionFactory
{
    Windows::Media::ContentRestrictions::RatedContentDescription Create(param::hstring const& id, param::hstring const& title, Windows::Media::ContentRestrictions::RatedContentCategory const& category) const;
};
template <> struct consume<Windows::Media::ContentRestrictions::IRatedContentDescriptionFactory> { template <typename D> using type = consume_Windows_Media_ContentRestrictions_IRatedContentDescriptionFactory<D>; };

template <typename D>
struct consume_Windows_Media_ContentRestrictions_IRatedContentRestrictions
{
    Windows::Foundation::IAsyncOperation<Windows::Media::ContentRestrictions::ContentRestrictionsBrowsePolicy> GetBrowsePolicyAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::Media::ContentRestrictions::ContentAccessRestrictionLevel> GetRestrictionLevelAsync(Windows::Media::ContentRestrictions::RatedContentDescription const& RatedContentDescription) const;
    Windows::Foundation::IAsyncOperation<bool> RequestContentAccessAsync(Windows::Media::ContentRestrictions::RatedContentDescription const& RatedContentDescription) const;
    winrt::event_token RestrictionsChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const;
    using RestrictionsChanged_revoker = impl::event_revoker<Windows::Media::ContentRestrictions::IRatedContentRestrictions, &impl::abi_t<Windows::Media::ContentRestrictions::IRatedContentRestrictions>::remove_RestrictionsChanged>;
    RestrictionsChanged_revoker RestrictionsChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const;
    void RestrictionsChanged(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::Media::ContentRestrictions::IRatedContentRestrictions> { template <typename D> using type = consume_Windows_Media_ContentRestrictions_IRatedContentRestrictions<D>; };

template <typename D>
struct consume_Windows_Media_ContentRestrictions_IRatedContentRestrictionsFactory
{
    Windows::Media::ContentRestrictions::RatedContentRestrictions CreateWithMaxAgeRating(uint32_t maxAgeRating) const;
};
template <> struct consume<Windows::Media::ContentRestrictions::IRatedContentRestrictionsFactory> { template <typename D> using type = consume_Windows_Media_ContentRestrictions_IRatedContentRestrictionsFactory<D>; };

}
