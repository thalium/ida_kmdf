// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.ApplicationModel.SocialInfo.0.h"
#include "winrt/impl/Windows.Foundation.0.h"
#include "winrt/impl/Windows.ApplicationModel.SocialInfo.Provider.0.h"

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::SocialInfo::Provider {

struct WINRT_EBO ISocialDashboardItemUpdater :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISocialDashboardItemUpdater>
{
    ISocialDashboardItemUpdater(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISocialFeedUpdater :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISocialFeedUpdater>
{
    ISocialFeedUpdater(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISocialInfoProviderManagerStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISocialInfoProviderManagerStatics>
{
    ISocialInfoProviderManagerStatics(std::nullptr_t = nullptr) noexcept {}
};

}
