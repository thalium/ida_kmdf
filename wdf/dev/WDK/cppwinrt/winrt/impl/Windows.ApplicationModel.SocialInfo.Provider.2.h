// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.ApplicationModel.SocialInfo.1.h"
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.ApplicationModel.SocialInfo.Provider.1.h"

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::SocialInfo::Provider {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::SocialInfo::Provider {

struct WINRT_EBO SocialDashboardItemUpdater :
    Windows::ApplicationModel::SocialInfo::Provider::ISocialDashboardItemUpdater
{
    SocialDashboardItemUpdater(std::nullptr_t) noexcept {}
};

struct WINRT_EBO SocialFeedUpdater :
    Windows::ApplicationModel::SocialInfo::Provider::ISocialFeedUpdater
{
    SocialFeedUpdater(std::nullptr_t) noexcept {}
};

struct SocialInfoProviderManager
{
    SocialInfoProviderManager() = delete;
    static Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::SocialInfo::Provider::SocialFeedUpdater> CreateSocialFeedUpdaterAsync(Windows::ApplicationModel::SocialInfo::SocialFeedKind const& kind, Windows::ApplicationModel::SocialInfo::SocialFeedUpdateMode const& mode, param::hstring const& ownerRemoteId);
    static Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::SocialInfo::Provider::SocialDashboardItemUpdater> CreateDashboardItemUpdaterAsync(param::hstring const& ownerRemoteId);
    static void UpdateBadgeCountValue(param::hstring const& itemRemoteId, int32_t newCount);
    static void ReportNewContentAvailable(param::hstring const& contactRemoteId, Windows::ApplicationModel::SocialInfo::SocialFeedKind const& kind);
    static Windows::Foundation::IAsyncOperation<bool> ProvisionAsync();
    static Windows::Foundation::IAsyncAction DeprovisionAsync();
};

}
