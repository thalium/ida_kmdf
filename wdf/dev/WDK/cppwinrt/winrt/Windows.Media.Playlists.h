// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Storage.2.h"
#include "winrt/impl/Windows.Media.Playlists.2.h"
#include "winrt/Windows.Media.h"

namespace winrt::impl {

template <typename D> Windows::Foundation::Collections::IVector<Windows::Storage::StorageFile> consume_Windows_Media_Playlists_IPlaylist<D>::Files() const
{
    Windows::Foundation::Collections::IVector<Windows::Storage::StorageFile> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playlists::IPlaylist)->get_Files(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Media_Playlists_IPlaylist<D>::SaveAsync() const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playlists::IPlaylist)->SaveAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile> consume_Windows_Media_Playlists_IPlaylist<D>::SaveAsAsync(Windows::Storage::IStorageFolder const& saveLocation, param::hstring const& desiredName, Windows::Storage::NameCollisionOption const& option) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playlists::IPlaylist)->SaveAsAsync(get_abi(saveLocation), get_abi(desiredName), get_abi(option), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile> consume_Windows_Media_Playlists_IPlaylist<D>::SaveAsAsync(Windows::Storage::IStorageFolder const& saveLocation, param::hstring const& desiredName, Windows::Storage::NameCollisionOption const& option, Windows::Media::Playlists::PlaylistFormat const& playlistFormat) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playlists::IPlaylist)->SaveAsWithFormatAsync(get_abi(saveLocation), get_abi(desiredName), get_abi(option), get_abi(playlistFormat), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Media::Playlists::Playlist> consume_Windows_Media_Playlists_IPlaylistStatics<D>::LoadAsync(Windows::Storage::IStorageFile const& file) const
{
    Windows::Foundation::IAsyncOperation<Windows::Media::Playlists::Playlist> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Media::Playlists::IPlaylistStatics)->LoadAsync(get_abi(file), put_abi(operation)));
    return operation;
}

template <typename D>
struct produce<D, Windows::Media::Playlists::IPlaylist> : produce_base<D, Windows::Media::Playlists::IPlaylist>
{
    int32_t WINRT_CALL get_Files(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Files, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::Storage::StorageFile>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::Storage::StorageFile>>(this->shim().Files());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SaveAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SaveAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SaveAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SaveAsAsync(void* saveLocation, void* desiredName, Windows::Storage::NameCollisionOption option, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SaveAsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile>), Windows::Storage::IStorageFolder const, hstring const, Windows::Storage::NameCollisionOption const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile>>(this->shim().SaveAsAsync(*reinterpret_cast<Windows::Storage::IStorageFolder const*>(&saveLocation), *reinterpret_cast<hstring const*>(&desiredName), *reinterpret_cast<Windows::Storage::NameCollisionOption const*>(&option)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SaveAsWithFormatAsync(void* saveLocation, void* desiredName, Windows::Storage::NameCollisionOption option, Windows::Media::Playlists::PlaylistFormat playlistFormat, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SaveAsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile>), Windows::Storage::IStorageFolder const, hstring const, Windows::Storage::NameCollisionOption const, Windows::Media::Playlists::PlaylistFormat const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile>>(this->shim().SaveAsAsync(*reinterpret_cast<Windows::Storage::IStorageFolder const*>(&saveLocation), *reinterpret_cast<hstring const*>(&desiredName), *reinterpret_cast<Windows::Storage::NameCollisionOption const*>(&option), *reinterpret_cast<Windows::Media::Playlists::PlaylistFormat const*>(&playlistFormat)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Media::Playlists::IPlaylistStatics> : produce_base<D, Windows::Media::Playlists::IPlaylistStatics>
{
    int32_t WINRT_CALL LoadAsync(void* file, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LoadAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Media::Playlists::Playlist>), Windows::Storage::IStorageFile const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Media::Playlists::Playlist>>(this->shim().LoadAsync(*reinterpret_cast<Windows::Storage::IStorageFile const*>(&file)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Media::Playlists {

inline Playlist::Playlist() :
    Playlist(impl::call_factory<Playlist>([](auto&& f) { return f.template ActivateInstance<Playlist>(); }))
{}

inline Windows::Foundation::IAsyncOperation<Windows::Media::Playlists::Playlist> Playlist::LoadAsync(Windows::Storage::IStorageFile const& file)
{
    return impl::call_factory<Playlist, Windows::Media::Playlists::IPlaylistStatics>([&](auto&& f) { return f.LoadAsync(file); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Media::Playlists::IPlaylist> : winrt::impl::hash_base<winrt::Windows::Media::Playlists::IPlaylist> {};
template<> struct hash<winrt::Windows::Media::Playlists::IPlaylistStatics> : winrt::impl::hash_base<winrt::Windows::Media::Playlists::IPlaylistStatics> {};
template<> struct hash<winrt::Windows::Media::Playlists::Playlist> : winrt::impl::hash_base<winrt::Windows::Media::Playlists::Playlist> {};

}
