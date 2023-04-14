// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Storage {

enum class NameCollisionOption;
struct IStorageFile;
struct IStorageFolder;
struct StorageFile;

}

WINRT_EXPORT namespace winrt::Windows::Media::Playlists {

enum class PlaylistFormat : int32_t
{
    WindowsMedia = 0,
    Zune = 1,
    M3u = 2,
};

struct IPlaylist;
struct IPlaylistStatics;
struct Playlist;

}

namespace winrt::impl {

template <> struct category<Windows::Media::Playlists::IPlaylist>{ using type = interface_category; };
template <> struct category<Windows::Media::Playlists::IPlaylistStatics>{ using type = interface_category; };
template <> struct category<Windows::Media::Playlists::Playlist>{ using type = class_category; };
template <> struct category<Windows::Media::Playlists::PlaylistFormat>{ using type = enum_category; };
template <> struct name<Windows::Media::Playlists::IPlaylist>{ static constexpr auto & value{ L"Windows.Media.Playlists.IPlaylist" }; };
template <> struct name<Windows::Media::Playlists::IPlaylistStatics>{ static constexpr auto & value{ L"Windows.Media.Playlists.IPlaylistStatics" }; };
template <> struct name<Windows::Media::Playlists::Playlist>{ static constexpr auto & value{ L"Windows.Media.Playlists.Playlist" }; };
template <> struct name<Windows::Media::Playlists::PlaylistFormat>{ static constexpr auto & value{ L"Windows.Media.Playlists.PlaylistFormat" }; };
template <> struct guid_storage<Windows::Media::Playlists::IPlaylist>{ static constexpr guid value{ 0x803736F5,0xCF44,0x4D97,{ 0x83,0xB3,0x7A,0x08,0x9E,0x9A,0xB6,0x63 } }; };
template <> struct guid_storage<Windows::Media::Playlists::IPlaylistStatics>{ static constexpr guid value{ 0xC5C331CD,0x81F9,0x4FF3,{ 0x95,0xB9,0x70,0xB6,0xFF,0x04,0x6B,0x68 } }; };
template <> struct default_interface<Windows::Media::Playlists::Playlist>{ using type = Windows::Media::Playlists::IPlaylist; };

template <> struct abi<Windows::Media::Playlists::IPlaylist>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Files(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL SaveAsync(void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL SaveAsAsync(void* saveLocation, void* desiredName, Windows::Storage::NameCollisionOption option, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL SaveAsWithFormatAsync(void* saveLocation, void* desiredName, Windows::Storage::NameCollisionOption option, Windows::Media::Playlists::PlaylistFormat playlistFormat, void** operation) noexcept = 0;
};};

template <> struct abi<Windows::Media::Playlists::IPlaylistStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL LoadAsync(void* file, void** operation) noexcept = 0;
};};

template <typename D>
struct consume_Windows_Media_Playlists_IPlaylist
{
    Windows::Foundation::Collections::IVector<Windows::Storage::StorageFile> Files() const;
    Windows::Foundation::IAsyncAction SaveAsync() const;
    Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile> SaveAsAsync(Windows::Storage::IStorageFolder const& saveLocation, param::hstring const& desiredName, Windows::Storage::NameCollisionOption const& option) const;
    Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile> SaveAsAsync(Windows::Storage::IStorageFolder const& saveLocation, param::hstring const& desiredName, Windows::Storage::NameCollisionOption const& option, Windows::Media::Playlists::PlaylistFormat const& playlistFormat) const;
};
template <> struct consume<Windows::Media::Playlists::IPlaylist> { template <typename D> using type = consume_Windows_Media_Playlists_IPlaylist<D>; };

template <typename D>
struct consume_Windows_Media_Playlists_IPlaylistStatics
{
    Windows::Foundation::IAsyncOperation<Windows::Media::Playlists::Playlist> LoadAsync(Windows::Storage::IStorageFile const& file) const;
};
template <> struct consume<Windows::Media::Playlists::IPlaylistStatics> { template <typename D> using type = consume_Windows_Media_Playlists_IPlaylistStatics<D>; };

}
