// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Foundation.0.h"
#include "winrt/impl/Windows.Graphics.Imaging.0.h"
#include "winrt/impl/Windows.Storage.Streams.0.h"
#include "winrt/impl/Windows.ApplicationModel.SocialInfo.0.h"

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::SocialInfo {

struct WINRT_EBO ISocialFeedChildItem :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISocialFeedChildItem>
{
    ISocialFeedChildItem(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISocialFeedContent :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISocialFeedContent>
{
    ISocialFeedContent(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISocialFeedItem :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISocialFeedItem>
{
    ISocialFeedItem(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISocialFeedSharedItem :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISocialFeedSharedItem>
{
    ISocialFeedSharedItem(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISocialItemThumbnail :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISocialItemThumbnail>
{
    ISocialItemThumbnail(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISocialUserInfo :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISocialUserInfo>
{
    ISocialUserInfo(std::nullptr_t = nullptr) noexcept {}
};

}
