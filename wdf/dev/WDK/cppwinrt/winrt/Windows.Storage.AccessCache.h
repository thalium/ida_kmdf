// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Storage.2.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.Storage.AccessCache.2.h"
#include "winrt/Windows.Storage.h"

namespace winrt::impl {

template <typename D> Windows::Storage::AccessCache::AccessListEntry consume_Windows_Storage_AccessCache_IItemRemovedEventArgs<D>::RemovedEntry() const
{
    Windows::Storage::AccessCache::AccessListEntry value{};
    check_hresult(WINRT_SHIM(Windows::Storage::AccessCache::IItemRemovedEventArgs)->get_RemovedEntry(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::AccessCache::StorageItemAccessList consume_Windows_Storage_AccessCache_IStorageApplicationPermissionsStatics<D>::FutureAccessList() const
{
    Windows::Storage::AccessCache::StorageItemAccessList value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::AccessCache::IStorageApplicationPermissionsStatics)->get_FutureAccessList(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::AccessCache::StorageItemMostRecentlyUsedList consume_Windows_Storage_AccessCache_IStorageApplicationPermissionsStatics<D>::MostRecentlyUsedList() const
{
    Windows::Storage::AccessCache::StorageItemMostRecentlyUsedList value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::AccessCache::IStorageApplicationPermissionsStatics)->get_MostRecentlyUsedList(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::AccessCache::StorageItemAccessList consume_Windows_Storage_AccessCache_IStorageApplicationPermissionsStatics2<D>::GetFutureAccessListForUser(Windows::System::User const& user) const
{
    Windows::Storage::AccessCache::StorageItemAccessList value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::AccessCache::IStorageApplicationPermissionsStatics2)->GetFutureAccessListForUser(get_abi(user), put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::AccessCache::StorageItemMostRecentlyUsedList consume_Windows_Storage_AccessCache_IStorageApplicationPermissionsStatics2<D>::GetMostRecentlyUsedListForUser(Windows::System::User const& user) const
{
    Windows::Storage::AccessCache::StorageItemMostRecentlyUsedList value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::AccessCache::IStorageApplicationPermissionsStatics2)->GetMostRecentlyUsedListForUser(get_abi(user), put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_AccessCache_IStorageItemAccessList<D>::Add(Windows::Storage::IStorageItem const& file) const
{
    hstring token{};
    check_hresult(WINRT_SHIM(Windows::Storage::AccessCache::IStorageItemAccessList)->AddOverloadDefaultMetadata(get_abi(file), put_abi(token)));
    return token;
}

template <typename D> hstring consume_Windows_Storage_AccessCache_IStorageItemAccessList<D>::Add(Windows::Storage::IStorageItem const& file, param::hstring const& metadata) const
{
    hstring token{};
    check_hresult(WINRT_SHIM(Windows::Storage::AccessCache::IStorageItemAccessList)->Add(get_abi(file), get_abi(metadata), put_abi(token)));
    return token;
}

template <typename D> void consume_Windows_Storage_AccessCache_IStorageItemAccessList<D>::AddOrReplace(param::hstring const& token, Windows::Storage::IStorageItem const& file) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::AccessCache::IStorageItemAccessList)->AddOrReplaceOverloadDefaultMetadata(get_abi(token), get_abi(file)));
}

template <typename D> void consume_Windows_Storage_AccessCache_IStorageItemAccessList<D>::AddOrReplace(param::hstring const& token, Windows::Storage::IStorageItem const& file, param::hstring const& metadata) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::AccessCache::IStorageItemAccessList)->AddOrReplace(get_abi(token), get_abi(file), get_abi(metadata)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::IStorageItem> consume_Windows_Storage_AccessCache_IStorageItemAccessList<D>::GetItemAsync(param::hstring const& token) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::IStorageItem> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::AccessCache::IStorageItemAccessList)->GetItemAsync(get_abi(token), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile> consume_Windows_Storage_AccessCache_IStorageItemAccessList<D>::GetFileAsync(param::hstring const& token) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::AccessCache::IStorageItemAccessList)->GetFileAsync(get_abi(token), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFolder> consume_Windows_Storage_AccessCache_IStorageItemAccessList<D>::GetFolderAsync(param::hstring const& token) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFolder> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::AccessCache::IStorageItemAccessList)->GetFolderAsync(get_abi(token), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::IStorageItem> consume_Windows_Storage_AccessCache_IStorageItemAccessList<D>::GetItemAsync(param::hstring const& token, Windows::Storage::AccessCache::AccessCacheOptions const& options) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::IStorageItem> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::AccessCache::IStorageItemAccessList)->GetItemWithOptionsAsync(get_abi(token), get_abi(options), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile> consume_Windows_Storage_AccessCache_IStorageItemAccessList<D>::GetFileAsync(param::hstring const& token, Windows::Storage::AccessCache::AccessCacheOptions const& options) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::AccessCache::IStorageItemAccessList)->GetFileWithOptionsAsync(get_abi(token), get_abi(options), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFolder> consume_Windows_Storage_AccessCache_IStorageItemAccessList<D>::GetFolderAsync(param::hstring const& token, Windows::Storage::AccessCache::AccessCacheOptions const& options) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFolder> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::AccessCache::IStorageItemAccessList)->GetFolderWithOptionsAsync(get_abi(token), get_abi(options), put_abi(operation)));
    return operation;
}

template <typename D> void consume_Windows_Storage_AccessCache_IStorageItemAccessList<D>::Remove(param::hstring const& token) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::AccessCache::IStorageItemAccessList)->Remove(get_abi(token)));
}

template <typename D> bool consume_Windows_Storage_AccessCache_IStorageItemAccessList<D>::ContainsItem(param::hstring const& token) const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Storage::AccessCache::IStorageItemAccessList)->ContainsItem(get_abi(token), &value));
    return value;
}

template <typename D> void consume_Windows_Storage_AccessCache_IStorageItemAccessList<D>::Clear() const
{
    check_hresult(WINRT_SHIM(Windows::Storage::AccessCache::IStorageItemAccessList)->Clear());
}

template <typename D> bool consume_Windows_Storage_AccessCache_IStorageItemAccessList<D>::CheckAccess(Windows::Storage::IStorageItem const& file) const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Storage::AccessCache::IStorageItemAccessList)->CheckAccess(get_abi(file), &value));
    return value;
}

template <typename D> Windows::Storage::AccessCache::AccessListEntryView consume_Windows_Storage_AccessCache_IStorageItemAccessList<D>::Entries() const
{
    Windows::Storage::AccessCache::AccessListEntryView entries{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::AccessCache::IStorageItemAccessList)->get_Entries(put_abi(entries)));
    return entries;
}

template <typename D> uint32_t consume_Windows_Storage_AccessCache_IStorageItemAccessList<D>::MaximumItemsAllowed() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Storage::AccessCache::IStorageItemAccessList)->get_MaximumItemsAllowed(&value));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Storage_AccessCache_IStorageItemMostRecentlyUsedList<D>::ItemRemoved(Windows::Foundation::TypedEventHandler<Windows::Storage::AccessCache::StorageItemMostRecentlyUsedList, Windows::Storage::AccessCache::ItemRemovedEventArgs> const& handler) const
{
    winrt::event_token eventCookie{};
    check_hresult(WINRT_SHIM(Windows::Storage::AccessCache::IStorageItemMostRecentlyUsedList)->add_ItemRemoved(get_abi(handler), put_abi(eventCookie)));
    return eventCookie;
}

template <typename D> typename consume_Windows_Storage_AccessCache_IStorageItemMostRecentlyUsedList<D>::ItemRemoved_revoker consume_Windows_Storage_AccessCache_IStorageItemMostRecentlyUsedList<D>::ItemRemoved(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Storage::AccessCache::StorageItemMostRecentlyUsedList, Windows::Storage::AccessCache::ItemRemovedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ItemRemoved_revoker>(this, ItemRemoved(handler));
}

template <typename D> void consume_Windows_Storage_AccessCache_IStorageItemMostRecentlyUsedList<D>::ItemRemoved(winrt::event_token const& eventCookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Storage::AccessCache::IStorageItemMostRecentlyUsedList)->remove_ItemRemoved(get_abi(eventCookie)));
}

template <typename D> hstring consume_Windows_Storage_AccessCache_IStorageItemMostRecentlyUsedList2<D>::Add(Windows::Storage::IStorageItem const& file, param::hstring const& metadata, Windows::Storage::AccessCache::RecentStorageItemVisibility const& visibility) const
{
    hstring token{};
    check_hresult(WINRT_SHIM(Windows::Storage::AccessCache::IStorageItemMostRecentlyUsedList2)->AddWithMetadataAndVisibility(get_abi(file), get_abi(metadata), get_abi(visibility), put_abi(token)));
    return token;
}

template <typename D> void consume_Windows_Storage_AccessCache_IStorageItemMostRecentlyUsedList2<D>::AddOrReplace(param::hstring const& token, Windows::Storage::IStorageItem const& file, param::hstring const& metadata, Windows::Storage::AccessCache::RecentStorageItemVisibility const& visibility) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::AccessCache::IStorageItemMostRecentlyUsedList2)->AddOrReplaceWithMetadataAndVisibility(get_abi(token), get_abi(file), get_abi(metadata), get_abi(visibility)));
}

template <typename D>
struct produce<D, Windows::Storage::AccessCache::IItemRemovedEventArgs> : produce_base<D, Windows::Storage::AccessCache::IItemRemovedEventArgs>
{
    int32_t WINRT_CALL get_RemovedEntry(struct struct_Windows_Storage_AccessCache_AccessListEntry* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemovedEntry, WINRT_WRAP(Windows::Storage::AccessCache::AccessListEntry));
            *value = detach_from<Windows::Storage::AccessCache::AccessListEntry>(this->shim().RemovedEntry());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::AccessCache::IStorageApplicationPermissionsStatics> : produce_base<D, Windows::Storage::AccessCache::IStorageApplicationPermissionsStatics>
{
    int32_t WINRT_CALL get_FutureAccessList(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FutureAccessList, WINRT_WRAP(Windows::Storage::AccessCache::StorageItemAccessList));
            *value = detach_from<Windows::Storage::AccessCache::StorageItemAccessList>(this->shim().FutureAccessList());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MostRecentlyUsedList(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MostRecentlyUsedList, WINRT_WRAP(Windows::Storage::AccessCache::StorageItemMostRecentlyUsedList));
            *value = detach_from<Windows::Storage::AccessCache::StorageItemMostRecentlyUsedList>(this->shim().MostRecentlyUsedList());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::AccessCache::IStorageApplicationPermissionsStatics2> : produce_base<D, Windows::Storage::AccessCache::IStorageApplicationPermissionsStatics2>
{
    int32_t WINRT_CALL GetFutureAccessListForUser(void* user, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetFutureAccessListForUser, WINRT_WRAP(Windows::Storage::AccessCache::StorageItemAccessList), Windows::System::User const&);
            *value = detach_from<Windows::Storage::AccessCache::StorageItemAccessList>(this->shim().GetFutureAccessListForUser(*reinterpret_cast<Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetMostRecentlyUsedListForUser(void* user, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetMostRecentlyUsedListForUser, WINRT_WRAP(Windows::Storage::AccessCache::StorageItemMostRecentlyUsedList), Windows::System::User const&);
            *value = detach_from<Windows::Storage::AccessCache::StorageItemMostRecentlyUsedList>(this->shim().GetMostRecentlyUsedListForUser(*reinterpret_cast<Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::AccessCache::IStorageItemAccessList> : produce_base<D, Windows::Storage::AccessCache::IStorageItemAccessList>
{
    int32_t WINRT_CALL AddOverloadDefaultMetadata(void* file, void** token) noexcept final
    {
        try
        {
            *token = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Add, WINRT_WRAP(hstring), Windows::Storage::IStorageItem const&);
            *token = detach_from<hstring>(this->shim().Add(*reinterpret_cast<Windows::Storage::IStorageItem const*>(&file)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Add(void* file, void* metadata, void** token) noexcept final
    {
        try
        {
            *token = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Add, WINRT_WRAP(hstring), Windows::Storage::IStorageItem const&, hstring const&);
            *token = detach_from<hstring>(this->shim().Add(*reinterpret_cast<Windows::Storage::IStorageItem const*>(&file), *reinterpret_cast<hstring const*>(&metadata)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AddOrReplaceOverloadDefaultMetadata(void* token, void* file) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddOrReplace, WINRT_WRAP(void), hstring const&, Windows::Storage::IStorageItem const&);
            this->shim().AddOrReplace(*reinterpret_cast<hstring const*>(&token), *reinterpret_cast<Windows::Storage::IStorageItem const*>(&file));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AddOrReplace(void* token, void* file, void* metadata) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddOrReplace, WINRT_WRAP(void), hstring const&, Windows::Storage::IStorageItem const&, hstring const&);
            this->shim().AddOrReplace(*reinterpret_cast<hstring const*>(&token), *reinterpret_cast<Windows::Storage::IStorageItem const*>(&file), *reinterpret_cast<hstring const*>(&metadata));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetItemAsync(void* token, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetItemAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::IStorageItem>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::IStorageItem>>(this->shim().GetItemAsync(*reinterpret_cast<hstring const*>(&token)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetFileAsync(void* token, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetFileAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile>>(this->shim().GetFileAsync(*reinterpret_cast<hstring const*>(&token)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetFolderAsync(void* token, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetFolderAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFolder>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFolder>>(this->shim().GetFolderAsync(*reinterpret_cast<hstring const*>(&token)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetItemWithOptionsAsync(void* token, Windows::Storage::AccessCache::AccessCacheOptions options, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetItemAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::IStorageItem>), hstring const, Windows::Storage::AccessCache::AccessCacheOptions const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::IStorageItem>>(this->shim().GetItemAsync(*reinterpret_cast<hstring const*>(&token), *reinterpret_cast<Windows::Storage::AccessCache::AccessCacheOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetFileWithOptionsAsync(void* token, Windows::Storage::AccessCache::AccessCacheOptions options, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetFileAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile>), hstring const, Windows::Storage::AccessCache::AccessCacheOptions const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFile>>(this->shim().GetFileAsync(*reinterpret_cast<hstring const*>(&token), *reinterpret_cast<Windows::Storage::AccessCache::AccessCacheOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetFolderWithOptionsAsync(void* token, Windows::Storage::AccessCache::AccessCacheOptions options, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetFolderAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFolder>), hstring const, Windows::Storage::AccessCache::AccessCacheOptions const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::StorageFolder>>(this->shim().GetFolderAsync(*reinterpret_cast<hstring const*>(&token), *reinterpret_cast<Windows::Storage::AccessCache::AccessCacheOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Remove(void* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Remove, WINRT_WRAP(void), hstring const&);
            this->shim().Remove(*reinterpret_cast<hstring const*>(&token));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ContainsItem(void* token, bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContainsItem, WINRT_WRAP(bool), hstring const&);
            *value = detach_from<bool>(this->shim().ContainsItem(*reinterpret_cast<hstring const*>(&token)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Clear() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Clear, WINRT_WRAP(void));
            this->shim().Clear();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CheckAccess(void* file, bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CheckAccess, WINRT_WRAP(bool), Windows::Storage::IStorageItem const&);
            *value = detach_from<bool>(this->shim().CheckAccess(*reinterpret_cast<Windows::Storage::IStorageItem const*>(&file)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Entries(void** entries) noexcept final
    {
        try
        {
            *entries = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Entries, WINRT_WRAP(Windows::Storage::AccessCache::AccessListEntryView));
            *entries = detach_from<Windows::Storage::AccessCache::AccessListEntryView>(this->shim().Entries());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaximumItemsAllowed(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaximumItemsAllowed, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().MaximumItemsAllowed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::AccessCache::IStorageItemMostRecentlyUsedList> : produce_base<D, Windows::Storage::AccessCache::IStorageItemMostRecentlyUsedList>
{
    int32_t WINRT_CALL add_ItemRemoved(void* handler, winrt::event_token* eventCookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ItemRemoved, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Storage::AccessCache::StorageItemMostRecentlyUsedList, Windows::Storage::AccessCache::ItemRemovedEventArgs> const&);
            *eventCookie = detach_from<winrt::event_token>(this->shim().ItemRemoved(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Storage::AccessCache::StorageItemMostRecentlyUsedList, Windows::Storage::AccessCache::ItemRemovedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ItemRemoved(winrt::event_token eventCookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ItemRemoved, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ItemRemoved(*reinterpret_cast<winrt::event_token const*>(&eventCookie));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Storage::AccessCache::IStorageItemMostRecentlyUsedList2> : produce_base<D, Windows::Storage::AccessCache::IStorageItemMostRecentlyUsedList2>
{
    int32_t WINRT_CALL AddWithMetadataAndVisibility(void* file, void* metadata, Windows::Storage::AccessCache::RecentStorageItemVisibility visibility, void** token) noexcept final
    {
        try
        {
            *token = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Add, WINRT_WRAP(hstring), Windows::Storage::IStorageItem const&, hstring const&, Windows::Storage::AccessCache::RecentStorageItemVisibility const&);
            *token = detach_from<hstring>(this->shim().Add(*reinterpret_cast<Windows::Storage::IStorageItem const*>(&file), *reinterpret_cast<hstring const*>(&metadata), *reinterpret_cast<Windows::Storage::AccessCache::RecentStorageItemVisibility const*>(&visibility)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AddOrReplaceWithMetadataAndVisibility(void* token, void* file, void* metadata, Windows::Storage::AccessCache::RecentStorageItemVisibility visibility) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddOrReplace, WINRT_WRAP(void), hstring const&, Windows::Storage::IStorageItem const&, hstring const&, Windows::Storage::AccessCache::RecentStorageItemVisibility const&);
            this->shim().AddOrReplace(*reinterpret_cast<hstring const*>(&token), *reinterpret_cast<Windows::Storage::IStorageItem const*>(&file), *reinterpret_cast<hstring const*>(&metadata), *reinterpret_cast<Windows::Storage::AccessCache::RecentStorageItemVisibility const*>(&visibility));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Storage::AccessCache {

inline Windows::Storage::AccessCache::StorageItemAccessList StorageApplicationPermissions::FutureAccessList()
{
    return impl::call_factory<StorageApplicationPermissions, Windows::Storage::AccessCache::IStorageApplicationPermissionsStatics>([&](auto&& f) { return f.FutureAccessList(); });
}

inline Windows::Storage::AccessCache::StorageItemMostRecentlyUsedList StorageApplicationPermissions::MostRecentlyUsedList()
{
    return impl::call_factory<StorageApplicationPermissions, Windows::Storage::AccessCache::IStorageApplicationPermissionsStatics>([&](auto&& f) { return f.MostRecentlyUsedList(); });
}

inline Windows::Storage::AccessCache::StorageItemAccessList StorageApplicationPermissions::GetFutureAccessListForUser(Windows::System::User const& user)
{
    return impl::call_factory<StorageApplicationPermissions, Windows::Storage::AccessCache::IStorageApplicationPermissionsStatics2>([&](auto&& f) { return f.GetFutureAccessListForUser(user); });
}

inline Windows::Storage::AccessCache::StorageItemMostRecentlyUsedList StorageApplicationPermissions::GetMostRecentlyUsedListForUser(Windows::System::User const& user)
{
    return impl::call_factory<StorageApplicationPermissions, Windows::Storage::AccessCache::IStorageApplicationPermissionsStatics2>([&](auto&& f) { return f.GetMostRecentlyUsedListForUser(user); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Storage::AccessCache::IItemRemovedEventArgs> : winrt::impl::hash_base<winrt::Windows::Storage::AccessCache::IItemRemovedEventArgs> {};
template<> struct hash<winrt::Windows::Storage::AccessCache::IStorageApplicationPermissionsStatics> : winrt::impl::hash_base<winrt::Windows::Storage::AccessCache::IStorageApplicationPermissionsStatics> {};
template<> struct hash<winrt::Windows::Storage::AccessCache::IStorageApplicationPermissionsStatics2> : winrt::impl::hash_base<winrt::Windows::Storage::AccessCache::IStorageApplicationPermissionsStatics2> {};
template<> struct hash<winrt::Windows::Storage::AccessCache::IStorageItemAccessList> : winrt::impl::hash_base<winrt::Windows::Storage::AccessCache::IStorageItemAccessList> {};
template<> struct hash<winrt::Windows::Storage::AccessCache::IStorageItemMostRecentlyUsedList> : winrt::impl::hash_base<winrt::Windows::Storage::AccessCache::IStorageItemMostRecentlyUsedList> {};
template<> struct hash<winrt::Windows::Storage::AccessCache::IStorageItemMostRecentlyUsedList2> : winrt::impl::hash_base<winrt::Windows::Storage::AccessCache::IStorageItemMostRecentlyUsedList2> {};
template<> struct hash<winrt::Windows::Storage::AccessCache::AccessListEntryView> : winrt::impl::hash_base<winrt::Windows::Storage::AccessCache::AccessListEntryView> {};
template<> struct hash<winrt::Windows::Storage::AccessCache::ItemRemovedEventArgs> : winrt::impl::hash_base<winrt::Windows::Storage::AccessCache::ItemRemovedEventArgs> {};
template<> struct hash<winrt::Windows::Storage::AccessCache::StorageApplicationPermissions> : winrt::impl::hash_base<winrt::Windows::Storage::AccessCache::StorageApplicationPermissions> {};
template<> struct hash<winrt::Windows::Storage::AccessCache::StorageItemAccessList> : winrt::impl::hash_base<winrt::Windows::Storage::AccessCache::StorageItemAccessList> {};
template<> struct hash<winrt::Windows::Storage::AccessCache::StorageItemMostRecentlyUsedList> : winrt::impl::hash_base<winrt::Windows::Storage::AccessCache::StorageItemMostRecentlyUsedList> {};

}
