// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.ApplicationModel.SocialInfo.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.ApplicationModel.SocialInfo.Provider.2.h"
#include "winrt/Windows.ApplicationModel.SocialInfo.h"

namespace winrt::impl {

template <typename D> hstring consume_Windows_ApplicationModel_SocialInfo_Provider_ISocialDashboardItemUpdater<D>::OwnerRemoteId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::SocialInfo::Provider::ISocialDashboardItemUpdater)->get_OwnerRemoteId(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::SocialInfo::SocialFeedContent consume_Windows_ApplicationModel_SocialInfo_Provider_ISocialDashboardItemUpdater<D>::Content() const
{
    Windows::ApplicationModel::SocialInfo::SocialFeedContent value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::SocialInfo::Provider::ISocialDashboardItemUpdater)->get_Content(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_ApplicationModel_SocialInfo_Provider_ISocialDashboardItemUpdater<D>::Timestamp() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::SocialInfo::Provider::ISocialDashboardItemUpdater)->get_Timestamp(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_SocialInfo_Provider_ISocialDashboardItemUpdater<D>::Timestamp(Windows::Foundation::DateTime const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::SocialInfo::Provider::ISocialDashboardItemUpdater)->put_Timestamp(get_abi(value)));
}

template <typename D> void consume_Windows_ApplicationModel_SocialInfo_Provider_ISocialDashboardItemUpdater<D>::Thumbnail(Windows::ApplicationModel::SocialInfo::SocialItemThumbnail const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::SocialInfo::Provider::ISocialDashboardItemUpdater)->put_Thumbnail(get_abi(value)));
}

template <typename D> Windows::ApplicationModel::SocialInfo::SocialItemThumbnail consume_Windows_ApplicationModel_SocialInfo_Provider_ISocialDashboardItemUpdater<D>::Thumbnail() const
{
    Windows::ApplicationModel::SocialInfo::SocialItemThumbnail value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::SocialInfo::Provider::ISocialDashboardItemUpdater)->get_Thumbnail(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_SocialInfo_Provider_ISocialDashboardItemUpdater<D>::CommitAsync() const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::SocialInfo::Provider::ISocialDashboardItemUpdater)->CommitAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::Uri consume_Windows_ApplicationModel_SocialInfo_Provider_ISocialDashboardItemUpdater<D>::TargetUri() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::SocialInfo::Provider::ISocialDashboardItemUpdater)->get_TargetUri(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_SocialInfo_Provider_ISocialDashboardItemUpdater<D>::TargetUri(Windows::Foundation::Uri const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::SocialInfo::Provider::ISocialDashboardItemUpdater)->put_TargetUri(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_SocialInfo_Provider_ISocialFeedUpdater<D>::OwnerRemoteId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::SocialInfo::Provider::ISocialFeedUpdater)->get_OwnerRemoteId(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::SocialInfo::SocialFeedKind consume_Windows_ApplicationModel_SocialInfo_Provider_ISocialFeedUpdater<D>::Kind() const
{
    Windows::ApplicationModel::SocialInfo::SocialFeedKind value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::SocialInfo::Provider::ISocialFeedUpdater)->get_Kind(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::ApplicationModel::SocialInfo::SocialFeedItem> consume_Windows_ApplicationModel_SocialInfo_Provider_ISocialFeedUpdater<D>::Items() const
{
    Windows::Foundation::Collections::IVector<Windows::ApplicationModel::SocialInfo::SocialFeedItem> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::SocialInfo::Provider::ISocialFeedUpdater)->get_Items(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_SocialInfo_Provider_ISocialFeedUpdater<D>::CommitAsync() const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::SocialInfo::Provider::ISocialFeedUpdater)->CommitAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::SocialInfo::Provider::SocialFeedUpdater> consume_Windows_ApplicationModel_SocialInfo_Provider_ISocialInfoProviderManagerStatics<D>::CreateSocialFeedUpdaterAsync(Windows::ApplicationModel::SocialInfo::SocialFeedKind const& kind, Windows::ApplicationModel::SocialInfo::SocialFeedUpdateMode const& mode, param::hstring const& ownerRemoteId) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::SocialInfo::Provider::SocialFeedUpdater> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::SocialInfo::Provider::ISocialInfoProviderManagerStatics)->CreateSocialFeedUpdaterAsync(get_abi(kind), get_abi(mode), get_abi(ownerRemoteId), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::SocialInfo::Provider::SocialDashboardItemUpdater> consume_Windows_ApplicationModel_SocialInfo_Provider_ISocialInfoProviderManagerStatics<D>::CreateDashboardItemUpdaterAsync(param::hstring const& ownerRemoteId) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::SocialInfo::Provider::SocialDashboardItemUpdater> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::SocialInfo::Provider::ISocialInfoProviderManagerStatics)->CreateDashboardItemUpdaterAsync(get_abi(ownerRemoteId), put_abi(operation)));
    return operation;
}

template <typename D> void consume_Windows_ApplicationModel_SocialInfo_Provider_ISocialInfoProviderManagerStatics<D>::UpdateBadgeCountValue(param::hstring const& itemRemoteId, int32_t newCount) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::SocialInfo::Provider::ISocialInfoProviderManagerStatics)->UpdateBadgeCountValue(get_abi(itemRemoteId), newCount));
}

template <typename D> void consume_Windows_ApplicationModel_SocialInfo_Provider_ISocialInfoProviderManagerStatics<D>::ReportNewContentAvailable(param::hstring const& contactRemoteId, Windows::ApplicationModel::SocialInfo::SocialFeedKind const& kind) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::SocialInfo::Provider::ISocialInfoProviderManagerStatics)->ReportNewContentAvailable(get_abi(contactRemoteId), get_abi(kind)));
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_ApplicationModel_SocialInfo_Provider_ISocialInfoProviderManagerStatics<D>::ProvisionAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::SocialInfo::Provider::ISocialInfoProviderManagerStatics)->ProvisionAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_SocialInfo_Provider_ISocialInfoProviderManagerStatics<D>::DeprovisionAsync() const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::SocialInfo::Provider::ISocialInfoProviderManagerStatics)->DeprovisionAsync(put_abi(operation)));
    return operation;
}

template <typename D>
struct produce<D, Windows::ApplicationModel::SocialInfo::Provider::ISocialDashboardItemUpdater> : produce_base<D, Windows::ApplicationModel::SocialInfo::Provider::ISocialDashboardItemUpdater>
{
    int32_t WINRT_CALL get_OwnerRemoteId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OwnerRemoteId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().OwnerRemoteId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Content(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Content, WINRT_WRAP(Windows::ApplicationModel::SocialInfo::SocialFeedContent));
            *value = detach_from<Windows::ApplicationModel::SocialInfo::SocialFeedContent>(this->shim().Content());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Timestamp(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Timestamp, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().Timestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Timestamp(Windows::Foundation::DateTime value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Timestamp, WINRT_WRAP(void), Windows::Foundation::DateTime const&);
            this->shim().Timestamp(*reinterpret_cast<Windows::Foundation::DateTime const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Thumbnail(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Thumbnail, WINRT_WRAP(void), Windows::ApplicationModel::SocialInfo::SocialItemThumbnail const&);
            this->shim().Thumbnail(*reinterpret_cast<Windows::ApplicationModel::SocialInfo::SocialItemThumbnail const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Thumbnail(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Thumbnail, WINRT_WRAP(Windows::ApplicationModel::SocialInfo::SocialItemThumbnail));
            *value = detach_from<Windows::ApplicationModel::SocialInfo::SocialItemThumbnail>(this->shim().Thumbnail());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CommitAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CommitAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().CommitAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TargetUri(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetUri, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().TargetUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TargetUri(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetUri, WINRT_WRAP(void), Windows::Foundation::Uri const&);
            this->shim().TargetUri(*reinterpret_cast<Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::SocialInfo::Provider::ISocialFeedUpdater> : produce_base<D, Windows::ApplicationModel::SocialInfo::Provider::ISocialFeedUpdater>
{
    int32_t WINRT_CALL get_OwnerRemoteId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OwnerRemoteId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().OwnerRemoteId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Kind(Windows::ApplicationModel::SocialInfo::SocialFeedKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Kind, WINRT_WRAP(Windows::ApplicationModel::SocialInfo::SocialFeedKind));
            *value = detach_from<Windows::ApplicationModel::SocialInfo::SocialFeedKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Items(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Items, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::ApplicationModel::SocialInfo::SocialFeedItem>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::ApplicationModel::SocialInfo::SocialFeedItem>>(this->shim().Items());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CommitAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CommitAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().CommitAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::SocialInfo::Provider::ISocialInfoProviderManagerStatics> : produce_base<D, Windows::ApplicationModel::SocialInfo::Provider::ISocialInfoProviderManagerStatics>
{
    int32_t WINRT_CALL CreateSocialFeedUpdaterAsync(Windows::ApplicationModel::SocialInfo::SocialFeedKind kind, Windows::ApplicationModel::SocialInfo::SocialFeedUpdateMode mode, void* ownerRemoteId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateSocialFeedUpdaterAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::SocialInfo::Provider::SocialFeedUpdater>), Windows::ApplicationModel::SocialInfo::SocialFeedKind const, Windows::ApplicationModel::SocialInfo::SocialFeedUpdateMode const, hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::SocialInfo::Provider::SocialFeedUpdater>>(this->shim().CreateSocialFeedUpdaterAsync(*reinterpret_cast<Windows::ApplicationModel::SocialInfo::SocialFeedKind const*>(&kind), *reinterpret_cast<Windows::ApplicationModel::SocialInfo::SocialFeedUpdateMode const*>(&mode), *reinterpret_cast<hstring const*>(&ownerRemoteId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateDashboardItemUpdaterAsync(void* ownerRemoteId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateDashboardItemUpdaterAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::SocialInfo::Provider::SocialDashboardItemUpdater>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::SocialInfo::Provider::SocialDashboardItemUpdater>>(this->shim().CreateDashboardItemUpdaterAsync(*reinterpret_cast<hstring const*>(&ownerRemoteId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UpdateBadgeCountValue(void* itemRemoteId, int32_t newCount) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpdateBadgeCountValue, WINRT_WRAP(void), hstring const&, int32_t);
            this->shim().UpdateBadgeCountValue(*reinterpret_cast<hstring const*>(&itemRemoteId), newCount);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReportNewContentAvailable(void* contactRemoteId, Windows::ApplicationModel::SocialInfo::SocialFeedKind kind) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportNewContentAvailable, WINRT_WRAP(void), hstring const&, Windows::ApplicationModel::SocialInfo::SocialFeedKind const&);
            this->shim().ReportNewContentAvailable(*reinterpret_cast<hstring const*>(&contactRemoteId), *reinterpret_cast<Windows::ApplicationModel::SocialInfo::SocialFeedKind const*>(&kind));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ProvisionAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProvisionAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().ProvisionAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DeprovisionAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeprovisionAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().DeprovisionAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::SocialInfo::Provider {

inline Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::SocialInfo::Provider::SocialFeedUpdater> SocialInfoProviderManager::CreateSocialFeedUpdaterAsync(Windows::ApplicationModel::SocialInfo::SocialFeedKind const& kind, Windows::ApplicationModel::SocialInfo::SocialFeedUpdateMode const& mode, param::hstring const& ownerRemoteId)
{
    return impl::call_factory<SocialInfoProviderManager, Windows::ApplicationModel::SocialInfo::Provider::ISocialInfoProviderManagerStatics>([&](auto&& f) { return f.CreateSocialFeedUpdaterAsync(kind, mode, ownerRemoteId); });
}

inline Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::SocialInfo::Provider::SocialDashboardItemUpdater> SocialInfoProviderManager::CreateDashboardItemUpdaterAsync(param::hstring const& ownerRemoteId)
{
    return impl::call_factory<SocialInfoProviderManager, Windows::ApplicationModel::SocialInfo::Provider::ISocialInfoProviderManagerStatics>([&](auto&& f) { return f.CreateDashboardItemUpdaterAsync(ownerRemoteId); });
}

inline void SocialInfoProviderManager::UpdateBadgeCountValue(param::hstring const& itemRemoteId, int32_t newCount)
{
    impl::call_factory<SocialInfoProviderManager, Windows::ApplicationModel::SocialInfo::Provider::ISocialInfoProviderManagerStatics>([&](auto&& f) { return f.UpdateBadgeCountValue(itemRemoteId, newCount); });
}

inline void SocialInfoProviderManager::ReportNewContentAvailable(param::hstring const& contactRemoteId, Windows::ApplicationModel::SocialInfo::SocialFeedKind const& kind)
{
    impl::call_factory<SocialInfoProviderManager, Windows::ApplicationModel::SocialInfo::Provider::ISocialInfoProviderManagerStatics>([&](auto&& f) { return f.ReportNewContentAvailable(contactRemoteId, kind); });
}

inline Windows::Foundation::IAsyncOperation<bool> SocialInfoProviderManager::ProvisionAsync()
{
    return impl::call_factory<SocialInfoProviderManager, Windows::ApplicationModel::SocialInfo::Provider::ISocialInfoProviderManagerStatics>([&](auto&& f) { return f.ProvisionAsync(); });
}

inline Windows::Foundation::IAsyncAction SocialInfoProviderManager::DeprovisionAsync()
{
    return impl::call_factory<SocialInfoProviderManager, Windows::ApplicationModel::SocialInfo::Provider::ISocialInfoProviderManagerStatics>([&](auto&& f) { return f.DeprovisionAsync(); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::ApplicationModel::SocialInfo::Provider::ISocialDashboardItemUpdater> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::SocialInfo::Provider::ISocialDashboardItemUpdater> {};
template<> struct hash<winrt::Windows::ApplicationModel::SocialInfo::Provider::ISocialFeedUpdater> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::SocialInfo::Provider::ISocialFeedUpdater> {};
template<> struct hash<winrt::Windows::ApplicationModel::SocialInfo::Provider::ISocialInfoProviderManagerStatics> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::SocialInfo::Provider::ISocialInfoProviderManagerStatics> {};
template<> struct hash<winrt::Windows::ApplicationModel::SocialInfo::Provider::SocialDashboardItemUpdater> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::SocialInfo::Provider::SocialDashboardItemUpdater> {};
template<> struct hash<winrt::Windows::ApplicationModel::SocialInfo::Provider::SocialFeedUpdater> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::SocialInfo::Provider::SocialFeedUpdater> {};
template<> struct hash<winrt::Windows::ApplicationModel::SocialInfo::Provider::SocialInfoProviderManager> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::SocialInfo::Provider::SocialInfoProviderManager> {};

}
