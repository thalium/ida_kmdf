// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.Graphics.Imaging.1.h"
#include "winrt/impl/Windows.Storage.Streams.1.h"
#include "winrt/impl/Windows.ApplicationModel.SocialInfo.1.h"

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::SocialInfo {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::SocialInfo {

struct WINRT_EBO SocialFeedChildItem :
    Windows::ApplicationModel::SocialInfo::ISocialFeedChildItem
{
    SocialFeedChildItem(std::nullptr_t) noexcept {}
    SocialFeedChildItem();
};

struct WINRT_EBO SocialFeedContent :
    Windows::ApplicationModel::SocialInfo::ISocialFeedContent
{
    SocialFeedContent(std::nullptr_t) noexcept {}
};

struct WINRT_EBO SocialFeedItem :
    Windows::ApplicationModel::SocialInfo::ISocialFeedItem
{
    SocialFeedItem(std::nullptr_t) noexcept {}
    SocialFeedItem();
};

struct WINRT_EBO SocialFeedSharedItem :
    Windows::ApplicationModel::SocialInfo::ISocialFeedSharedItem
{
    SocialFeedSharedItem(std::nullptr_t) noexcept {}
    SocialFeedSharedItem();
};

struct WINRT_EBO SocialItemThumbnail :
    Windows::ApplicationModel::SocialInfo::ISocialItemThumbnail
{
    SocialItemThumbnail(std::nullptr_t) noexcept {}
    SocialItemThumbnail();
};

struct WINRT_EBO SocialUserInfo :
    Windows::ApplicationModel::SocialInfo::ISocialUserInfo
{
    SocialUserInfo(std::nullptr_t) noexcept {}
};

}
