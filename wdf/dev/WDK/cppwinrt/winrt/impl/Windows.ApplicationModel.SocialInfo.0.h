// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Foundation {

struct Uri;

}

WINRT_EXPORT namespace winrt::Windows::Graphics::Imaging {

struct BitmapSize;

}

WINRT_EXPORT namespace winrt::Windows::Storage::Streams {

struct IInputStream;

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::SocialInfo {

enum class SocialFeedItemStyle : int32_t
{
    Default = 0,
    Photo = 1,
};

enum class SocialFeedKind : int32_t
{
    HomeFeed = 0,
    ContactFeed = 1,
    Dashboard = 2,
};

enum class SocialFeedUpdateMode : int32_t
{
    Append = 0,
    Replace = 1,
};

enum class SocialItemBadgeStyle : int32_t
{
    Hidden = 0,
    Visible = 1,
    VisibleWithCount = 2,
};

struct ISocialFeedChildItem;
struct ISocialFeedContent;
struct ISocialFeedItem;
struct ISocialFeedSharedItem;
struct ISocialItemThumbnail;
struct ISocialUserInfo;
struct SocialFeedChildItem;
struct SocialFeedContent;
struct SocialFeedItem;
struct SocialFeedSharedItem;
struct SocialItemThumbnail;
struct SocialUserInfo;

}

namespace winrt::impl {

template <> struct category<Windows::ApplicationModel::SocialInfo::ISocialFeedChildItem>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::SocialInfo::ISocialFeedContent>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::SocialInfo::ISocialFeedItem>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::SocialInfo::ISocialFeedSharedItem>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::SocialInfo::ISocialItemThumbnail>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::SocialInfo::ISocialUserInfo>{ using type = interface_category; };
template <> struct category<Windows::ApplicationModel::SocialInfo::SocialFeedChildItem>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::SocialInfo::SocialFeedContent>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::SocialInfo::SocialFeedItem>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::SocialInfo::SocialFeedSharedItem>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::SocialInfo::SocialItemThumbnail>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::SocialInfo::SocialUserInfo>{ using type = class_category; };
template <> struct category<Windows::ApplicationModel::SocialInfo::SocialFeedItemStyle>{ using type = enum_category; };
template <> struct category<Windows::ApplicationModel::SocialInfo::SocialFeedKind>{ using type = enum_category; };
template <> struct category<Windows::ApplicationModel::SocialInfo::SocialFeedUpdateMode>{ using type = enum_category; };
template <> struct category<Windows::ApplicationModel::SocialInfo::SocialItemBadgeStyle>{ using type = enum_category; };
template <> struct name<Windows::ApplicationModel::SocialInfo::ISocialFeedChildItem>{ static constexpr auto & value{ L"Windows.ApplicationModel.SocialInfo.ISocialFeedChildItem" }; };
template <> struct name<Windows::ApplicationModel::SocialInfo::ISocialFeedContent>{ static constexpr auto & value{ L"Windows.ApplicationModel.SocialInfo.ISocialFeedContent" }; };
template <> struct name<Windows::ApplicationModel::SocialInfo::ISocialFeedItem>{ static constexpr auto & value{ L"Windows.ApplicationModel.SocialInfo.ISocialFeedItem" }; };
template <> struct name<Windows::ApplicationModel::SocialInfo::ISocialFeedSharedItem>{ static constexpr auto & value{ L"Windows.ApplicationModel.SocialInfo.ISocialFeedSharedItem" }; };
template <> struct name<Windows::ApplicationModel::SocialInfo::ISocialItemThumbnail>{ static constexpr auto & value{ L"Windows.ApplicationModel.SocialInfo.ISocialItemThumbnail" }; };
template <> struct name<Windows::ApplicationModel::SocialInfo::ISocialUserInfo>{ static constexpr auto & value{ L"Windows.ApplicationModel.SocialInfo.ISocialUserInfo" }; };
template <> struct name<Windows::ApplicationModel::SocialInfo::SocialFeedChildItem>{ static constexpr auto & value{ L"Windows.ApplicationModel.SocialInfo.SocialFeedChildItem" }; };
template <> struct name<Windows::ApplicationModel::SocialInfo::SocialFeedContent>{ static constexpr auto & value{ L"Windows.ApplicationModel.SocialInfo.SocialFeedContent" }; };
template <> struct name<Windows::ApplicationModel::SocialInfo::SocialFeedItem>{ static constexpr auto & value{ L"Windows.ApplicationModel.SocialInfo.SocialFeedItem" }; };
template <> struct name<Windows::ApplicationModel::SocialInfo::SocialFeedSharedItem>{ static constexpr auto & value{ L"Windows.ApplicationModel.SocialInfo.SocialFeedSharedItem" }; };
template <> struct name<Windows::ApplicationModel::SocialInfo::SocialItemThumbnail>{ static constexpr auto & value{ L"Windows.ApplicationModel.SocialInfo.SocialItemThumbnail" }; };
template <> struct name<Windows::ApplicationModel::SocialInfo::SocialUserInfo>{ static constexpr auto & value{ L"Windows.ApplicationModel.SocialInfo.SocialUserInfo" }; };
template <> struct name<Windows::ApplicationModel::SocialInfo::SocialFeedItemStyle>{ static constexpr auto & value{ L"Windows.ApplicationModel.SocialInfo.SocialFeedItemStyle" }; };
template <> struct name<Windows::ApplicationModel::SocialInfo::SocialFeedKind>{ static constexpr auto & value{ L"Windows.ApplicationModel.SocialInfo.SocialFeedKind" }; };
template <> struct name<Windows::ApplicationModel::SocialInfo::SocialFeedUpdateMode>{ static constexpr auto & value{ L"Windows.ApplicationModel.SocialInfo.SocialFeedUpdateMode" }; };
template <> struct name<Windows::ApplicationModel::SocialInfo::SocialItemBadgeStyle>{ static constexpr auto & value{ L"Windows.ApplicationModel.SocialInfo.SocialItemBadgeStyle" }; };
template <> struct guid_storage<Windows::ApplicationModel::SocialInfo::ISocialFeedChildItem>{ static constexpr guid value{ 0x0B6A985A,0xD59D,0x40BE,{ 0x98,0x0C,0x48,0x8A,0x2A,0xB3,0x0A,0x83 } }; };
template <> struct guid_storage<Windows::ApplicationModel::SocialInfo::ISocialFeedContent>{ static constexpr guid value{ 0xA234E429,0x3E39,0x494D,{ 0xA3,0x7C,0xF4,0x62,0xA2,0x49,0x45,0x14 } }; };
template <> struct guid_storage<Windows::ApplicationModel::SocialInfo::ISocialFeedItem>{ static constexpr guid value{ 0x4F1392AB,0x1F72,0x4D33,{ 0xB6,0x95,0xDE,0x3E,0x1D,0xB6,0x03,0x17 } }; };
template <> struct guid_storage<Windows::ApplicationModel::SocialInfo::ISocialFeedSharedItem>{ static constexpr guid value{ 0x7BFB9E40,0xA6AA,0x45A7,{ 0x9F,0xF6,0x54,0xC4,0x21,0x05,0xDD,0x1F } }; };
template <> struct guid_storage<Windows::ApplicationModel::SocialInfo::ISocialItemThumbnail>{ static constexpr guid value{ 0x5CBF831A,0x3F08,0x497F,{ 0x91,0x7F,0x57,0xE0,0x9D,0x84,0xB1,0x41 } }; };
template <> struct guid_storage<Windows::ApplicationModel::SocialInfo::ISocialUserInfo>{ static constexpr guid value{ 0x9E5E1BD1,0x90D0,0x4E1D,{ 0x95,0x54,0x84,0x4D,0x46,0x60,0x7F,0x61 } }; };
template <> struct default_interface<Windows::ApplicationModel::SocialInfo::SocialFeedChildItem>{ using type = Windows::ApplicationModel::SocialInfo::ISocialFeedChildItem; };
template <> struct default_interface<Windows::ApplicationModel::SocialInfo::SocialFeedContent>{ using type = Windows::ApplicationModel::SocialInfo::ISocialFeedContent; };
template <> struct default_interface<Windows::ApplicationModel::SocialInfo::SocialFeedItem>{ using type = Windows::ApplicationModel::SocialInfo::ISocialFeedItem; };
template <> struct default_interface<Windows::ApplicationModel::SocialInfo::SocialFeedSharedItem>{ using type = Windows::ApplicationModel::SocialInfo::ISocialFeedSharedItem; };
template <> struct default_interface<Windows::ApplicationModel::SocialInfo::SocialItemThumbnail>{ using type = Windows::ApplicationModel::SocialInfo::ISocialItemThumbnail; };
template <> struct default_interface<Windows::ApplicationModel::SocialInfo::SocialUserInfo>{ using type = Windows::ApplicationModel::SocialInfo::ISocialUserInfo; };

template <> struct abi<Windows::ApplicationModel::SocialInfo::ISocialFeedChildItem>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Author(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PrimaryContent(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SecondaryContent(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Timestamp(Windows::Foundation::DateTime* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Timestamp(Windows::Foundation::DateTime value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TargetUri(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_TargetUri(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Thumbnails(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SharedItem(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_SharedItem(void* value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::SocialInfo::ISocialFeedContent>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Title(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Title(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Message(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Message(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TargetUri(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_TargetUri(void* value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::SocialInfo::ISocialFeedItem>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Author(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PrimaryContent(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SecondaryContent(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Timestamp(Windows::Foundation::DateTime* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Timestamp(Windows::Foundation::DateTime value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TargetUri(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_TargetUri(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Thumbnails(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SharedItem(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_SharedItem(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BadgeStyle(Windows::ApplicationModel::SocialInfo::SocialItemBadgeStyle* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_BadgeStyle(Windows::ApplicationModel::SocialInfo::SocialItemBadgeStyle value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BadgeCountValue(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_BadgeCountValue(int32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RemoteId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_RemoteId(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ChildItem(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ChildItem(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Style(Windows::ApplicationModel::SocialInfo::SocialFeedItemStyle* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Style(Windows::ApplicationModel::SocialInfo::SocialFeedItemStyle value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::SocialInfo::ISocialFeedSharedItem>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_OriginalSource(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_OriginalSource(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Content(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Timestamp(Windows::Foundation::DateTime* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Timestamp(Windows::Foundation::DateTime value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TargetUri(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_TargetUri(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Thumbnail(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Thumbnail(void** value) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::SocialInfo::ISocialItemThumbnail>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_TargetUri(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_TargetUri(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ImageUri(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ImageUri(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BitmapSize(struct struct_Windows_Graphics_Imaging_BitmapSize* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_BitmapSize(struct struct_Windows_Graphics_Imaging_BitmapSize value) noexcept = 0;
    virtual int32_t WINRT_CALL SetImageAsync(void* image, void** operation) noexcept = 0;
};};

template <> struct abi<Windows::ApplicationModel::SocialInfo::ISocialUserInfo>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_DisplayName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_DisplayName(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_UserName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_UserName(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RemoteId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_RemoteId(void* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TargetUri(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL put_TargetUri(void* value) noexcept = 0;
};};

template <typename D>
struct consume_Windows_ApplicationModel_SocialInfo_ISocialFeedChildItem
{
    Windows::ApplicationModel::SocialInfo::SocialUserInfo Author() const;
    Windows::ApplicationModel::SocialInfo::SocialFeedContent PrimaryContent() const;
    Windows::ApplicationModel::SocialInfo::SocialFeedContent SecondaryContent() const;
    Windows::Foundation::DateTime Timestamp() const;
    void Timestamp(Windows::Foundation::DateTime const& value) const;
    Windows::Foundation::Uri TargetUri() const;
    void TargetUri(Windows::Foundation::Uri const& value) const;
    Windows::Foundation::Collections::IVector<Windows::ApplicationModel::SocialInfo::SocialItemThumbnail> Thumbnails() const;
    Windows::ApplicationModel::SocialInfo::SocialFeedSharedItem SharedItem() const;
    void SharedItem(Windows::ApplicationModel::SocialInfo::SocialFeedSharedItem const& value) const;
};
template <> struct consume<Windows::ApplicationModel::SocialInfo::ISocialFeedChildItem> { template <typename D> using type = consume_Windows_ApplicationModel_SocialInfo_ISocialFeedChildItem<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_SocialInfo_ISocialFeedContent
{
    hstring Title() const;
    void Title(param::hstring const& value) const;
    hstring Message() const;
    void Message(param::hstring const& value) const;
    Windows::Foundation::Uri TargetUri() const;
    void TargetUri(Windows::Foundation::Uri const& value) const;
};
template <> struct consume<Windows::ApplicationModel::SocialInfo::ISocialFeedContent> { template <typename D> using type = consume_Windows_ApplicationModel_SocialInfo_ISocialFeedContent<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_SocialInfo_ISocialFeedItem
{
    Windows::ApplicationModel::SocialInfo::SocialUserInfo Author() const;
    Windows::ApplicationModel::SocialInfo::SocialFeedContent PrimaryContent() const;
    Windows::ApplicationModel::SocialInfo::SocialFeedContent SecondaryContent() const;
    Windows::Foundation::DateTime Timestamp() const;
    void Timestamp(Windows::Foundation::DateTime const& value) const;
    Windows::Foundation::Uri TargetUri() const;
    void TargetUri(Windows::Foundation::Uri const& value) const;
    Windows::Foundation::Collections::IVector<Windows::ApplicationModel::SocialInfo::SocialItemThumbnail> Thumbnails() const;
    Windows::ApplicationModel::SocialInfo::SocialFeedSharedItem SharedItem() const;
    void SharedItem(Windows::ApplicationModel::SocialInfo::SocialFeedSharedItem const& value) const;
    Windows::ApplicationModel::SocialInfo::SocialItemBadgeStyle BadgeStyle() const;
    void BadgeStyle(Windows::ApplicationModel::SocialInfo::SocialItemBadgeStyle const& value) const;
    int32_t BadgeCountValue() const;
    void BadgeCountValue(int32_t value) const;
    hstring RemoteId() const;
    void RemoteId(param::hstring const& value) const;
    Windows::ApplicationModel::SocialInfo::SocialFeedChildItem ChildItem() const;
    void ChildItem(Windows::ApplicationModel::SocialInfo::SocialFeedChildItem const& value) const;
    Windows::ApplicationModel::SocialInfo::SocialFeedItemStyle Style() const;
    void Style(Windows::ApplicationModel::SocialInfo::SocialFeedItemStyle const& value) const;
};
template <> struct consume<Windows::ApplicationModel::SocialInfo::ISocialFeedItem> { template <typename D> using type = consume_Windows_ApplicationModel_SocialInfo_ISocialFeedItem<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_SocialInfo_ISocialFeedSharedItem
{
    Windows::Foundation::Uri OriginalSource() const;
    void OriginalSource(Windows::Foundation::Uri const& value) const;
    Windows::ApplicationModel::SocialInfo::SocialFeedContent Content() const;
    Windows::Foundation::DateTime Timestamp() const;
    void Timestamp(Windows::Foundation::DateTime const& value) const;
    Windows::Foundation::Uri TargetUri() const;
    void TargetUri(Windows::Foundation::Uri const& value) const;
    void Thumbnail(Windows::ApplicationModel::SocialInfo::SocialItemThumbnail const& value) const;
    Windows::ApplicationModel::SocialInfo::SocialItemThumbnail Thumbnail() const;
};
template <> struct consume<Windows::ApplicationModel::SocialInfo::ISocialFeedSharedItem> { template <typename D> using type = consume_Windows_ApplicationModel_SocialInfo_ISocialFeedSharedItem<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_SocialInfo_ISocialItemThumbnail
{
    Windows::Foundation::Uri TargetUri() const;
    void TargetUri(Windows::Foundation::Uri const& value) const;
    Windows::Foundation::Uri ImageUri() const;
    void ImageUri(Windows::Foundation::Uri const& value) const;
    Windows::Graphics::Imaging::BitmapSize BitmapSize() const;
    void BitmapSize(Windows::Graphics::Imaging::BitmapSize const& value) const;
    Windows::Foundation::IAsyncAction SetImageAsync(Windows::Storage::Streams::IInputStream const& image) const;
};
template <> struct consume<Windows::ApplicationModel::SocialInfo::ISocialItemThumbnail> { template <typename D> using type = consume_Windows_ApplicationModel_SocialInfo_ISocialItemThumbnail<D>; };

template <typename D>
struct consume_Windows_ApplicationModel_SocialInfo_ISocialUserInfo
{
    hstring DisplayName() const;
    void DisplayName(param::hstring const& value) const;
    hstring UserName() const;
    void UserName(param::hstring const& value) const;
    hstring RemoteId() const;
    void RemoteId(param::hstring const& value) const;
    Windows::Foundation::Uri TargetUri() const;
    void TargetUri(Windows::Foundation::Uri const& value) const;
};
template <> struct consume<Windows::ApplicationModel::SocialInfo::ISocialUserInfo> { template <typename D> using type = consume_Windows_ApplicationModel_SocialInfo_ISocialUserInfo<D>; };

}
