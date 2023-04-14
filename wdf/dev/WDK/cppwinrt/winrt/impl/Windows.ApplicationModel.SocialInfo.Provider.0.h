// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::SocialInfo {

enum class SocialFeedKind;
enum class SocialFeedUpdateMode;
struct SocialFeedContent;
struct SocialFeedItem;
struct SocialItemThumbnail;

}

WINRT_EXPORT namespace winrt::Windows::Foundation {

struct Uri;

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::SocialInfo::Provider {

struct ISocialDashboardItemUpdater;
struct ISocialFeedUpdater;
struct ISocialInfoProviderManagerStatics;
struct SocialDashboardItemUpdater;
struct SocialFeedUpdater;
struct SocialInfoProviderManager;

}

namespace winrt::impl {

template <> struct category<Windows::ApplicationModel::SocialInfo::Provider::ISocialDashboardItemUpdater>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::SocialInfo::Provider::ISocialFeedUpdater>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::SocialInfo::Provider::ISocialInfoProviderManagerStatics>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::SocialInfo::Provider::SocialDashboardItemUpdater>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::SocialInfo::Provider::SocialFeedUpdater>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::SocialInfo::Provider::SocialInfoProviderManager>{ using type = class_category; };
template <> struct name<Windows::ApplicationModel::SocialInfo::Provider::ISocialDashboardItemUpdater>{ static constexpr auto & value{ L"Windows.ApplicationModel.SocialInfo.Provider.ISocialDashboardItemUpdater" }; };
template <> struct name<Windows::ApplicationModel::SocialInfo::Provider::ISocialFeedUpdater>{ static constexpr auto & value{ L"Windows.ApplicationModel.SocialInfo.Provider.ISocialFeedUpdater" }; };
template <> struct name<Windows::ApplicationModel::SocialInfo::Provider::ISocialInfoProviderManagerStatics>{ static constexpr auto & value{ L"Windows.ApplicationModel.SocialInfo.Provider.ISocialInfoProviderManagerStatics" }; };
template <> struct name<Windows::ApplicationModel::SocialInfo::Provider::SocialDashboardItemUpdater>{ static constexpr auto & value{ L"Windows.ApplicationModel.SocialInfo.Provider.SocialDashboardItemUpdater" }; };
template <> struct name<Windows::ApplicationModel::SocialInfo::Provider::SocialFeedUpdater>{ static constexpr auto & value{ L"Windows.ApplicationModel.SocialInfo.Provider.SocialFeedUpdater" }; };
template <> struct name<Windows::ApplicationModel::SocialInfo::Provider::SocialInfoProviderManager>{ static constexpr auto & value{ L"Windows.ApplicationModel.SocialInfo.Provider.SocialInfoProviderManager" }; };
template <> struct guid_storage<Windows::ApplicationModel::SocialInfo::Provider::ISocialDashboardItemUpdater>{ static constexpr guid value{ 0x3CDE9DC9,0x4800,0x46CD,{ 0x86,0x9B,0x19,0x73,0xEC,0x68,0x5B,0xDE } }; };
template <> struct guid_storage<Windows::ApplicationModel::SocialInfo::Provider::ISocialFeedUpdater>{ static constexpr guid value{ 0x7A0C0AA7,0xED89,0x4BD5,{ 0xA8,0xD9,0x15,0xF4,0xD9,0x86,0x1C,0x10 } }; };
template <> struct guid_storage<Windows::ApplicationModel::SocialInfo::Provider::ISocialInfoProviderManagerStatics>{ static constexpr guid value{ 0x1B88E52B,0x7787,0x48D6,{ 0xAA,0x12,0xD8,0xE8,0xF4,0x7A,0xB8,0x5A } }; };
template <> struct default_interface<Windows::ApplicationModel::SocialInfo::Provider::SocialDashboardItemUpdater>{ using type = Windows::ApplicationModel::SocialInfo::Provider::ISocialDashboardItemUpdater; };
template <> struct default_interface<Windows::ApplicationModel::SocialInfo::Provider::SocialFeedUpdater>{ using type = Windows::ApplicationModel::SocialInfo::Provider::ISocialFeedUpdater; };

template <> struct abi<Windows::ApplicationModel::SocialInfo::Provider::ISocialDashboardItemUpdater>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_OwnerRemoteId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Content(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Timestamp(Windows::Foundation::DateTime* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Timestamp(Windows::Foundation::DateTime value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Thumbnail(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Thumbnail(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CommitAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL get_TargetUri(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_TargetUri(void* value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::SocialInfo::Provider::ISocialFeedUpdater>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_OwnerRemoteId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Kind(Windows::ApplicationModel::SocialInfo::SocialFeedKind* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Items(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CommitAsync(void** operation) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::SocialInfo::Provider::ISocialInfoProviderManagerStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateSocialFeedUpdaterAsync(Windows::ApplicationModel::SocialInfo::SocialFeedKind kind, Windows::ApplicationModel::SocialInfo::SocialFeedUpdateMode mode, void* ownerRemoteId, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL CreateDashboardItemUpdaterAsync(void* ownerRemoteId, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL UpdateBadgeCountValue(void* itemRemoteId, int32_t newCount) noexcept = 0;
    virtual int32_t WINRT_CALL ReportNewContentAvailable(void* contactRemoteId, Windows::ApplicationModel::SocialInfo::SocialFeedKind kind) noexcept = 0;
    virtual int32_t WINRT_CALL ProvisionAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL DeprovisionAsync(void** operation) noexcept = 0;
};};

template <typename D>
struct consume_Windows_ApplicationModel_SocialInfo_Provider_ISocialDashboardItemUpdater
{
    hstring OwnerRemoteId() const;
    Windows::ApplicationModel::SocialInfo::SocialFeedContent Content() const;
    Windows::Foundation::DateTime Timestamp() const;
    void Timestamp(Windows::Foundation::DateTime const& value) const;
    void Thumbnail(Windows::ApplicationModel::SocialInfo::SocialItemThumbnail const& value) const;
    Windows::ApplicationModel::SocialInfo::SocialItemThumbnail Thumbnail() const;
    Windows::Foundation::IAsyncAction CommitAsync() const;
    Windows::Foundation::Uri TargetUri() const;
    void TargetUri(Windows::Foundation::Uri const& value) const;
};
template <> struct consume<Windows::ApplicationModel::SocialInfo::Provider::ISocialDashboardItemUpdater> { template <typename D> using type = consume_Windows_ApplicationModel_SocialInfo_Provider_ISocialDashboardItemUpdater<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_SocialInfo_Provider_ISocialFeedUpdater
{
    hstring OwnerRemoteId() const;
    Windows::ApplicationModel::SocialInfo::SocialFeedKind Kind() const;
    Windows::Foundation::Collections::IVector<Windows::ApplicationModel::SocialInfo::SocialFeedItem> Items() const;
    Windows::Foundation::IAsyncAction CommitAsync() const;
};
template <> struct consume<Windows::ApplicationModel::SocialInfo::Provider::ISocialFeedUpdater> { template <typename D> using type = consume_Windows_ApplicationModel_SocialInfo_Provider_ISocialFeedUpdater<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_SocialInfo_Provider_ISocialInfoProviderManagerStatics
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::SocialInfo::Provider::SocialFeedUpdater> CreateSocialFeedUpdaterAsync(Windows::ApplicationModel::SocialInfo::SocialFeedKind const& kind, Windows::ApplicationModel::SocialInfo::SocialFeedUpdateMode const& mode, param::hstring const& ownerRemoteId) const;
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::SocialInfo::Provider::SocialDashboardItemUpdater> CreateDashboardItemUpdaterAsync(param::hstring const& ownerRemoteId) const;
    void UpdateBadgeCountValue(param::hstring const& itemRemoteId, int32_t newCount) const;
    void ReportNewContentAvailable(param::hstring const& contactRemoteId, Windows::ApplicationModel::SocialInfo::SocialFeedKind const& kind) const;
    Windows::Foundation::IAsyncOperation<bool> ProvisionAsync() const;
    Windows::Foundation::IAsyncAction DeprovisionAsync() const;
};
template <> struct consume<Windows::ApplicationModel::SocialInfo::Provider::ISocialInfoProviderManagerStatics> { template <typename D> using type = consume_Windows_ApplicationModel_SocialInfo_Provider_ISocialInfoProviderManagerStatics<D>; };

}
