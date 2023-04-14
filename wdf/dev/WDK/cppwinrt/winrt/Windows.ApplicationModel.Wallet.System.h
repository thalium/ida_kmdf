// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.ApplicationModel.Wallet.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.ApplicationModel.Wallet.System.2.h"
#include "winrt/Windows.ApplicationModel.Wallet.h"

namespace winrt::impl {

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Wallet::WalletItem>> consume_Windows_ApplicationModel_Wallet_System_IWalletItemSystemStore<D>::GetItemsAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Wallet::WalletItem>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::System::IWalletItemSystemStore)->GetItemsAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_ApplicationModel_Wallet_System_IWalletItemSystemStore<D>::DeleteAsync(Windows::ApplicationModel::Wallet::WalletItem const& item) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::System::IWalletItemSystemStore)->DeleteAsync(get_abi(item), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Wallet::WalletItem> consume_Windows_ApplicationModel_Wallet_System_IWalletItemSystemStore<D>::ImportItemAsync(Windows::Storage::Streams::IRandomAccessStreamReference const& stream) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Wallet::WalletItem> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::System::IWalletItemSystemStore)->ImportItemAsync(get_abi(stream), put_abi(operation)));
    return operation;
}

template <typename D> Windows::ApplicationModel::Wallet::System::WalletItemAppAssociation consume_Windows_ApplicationModel_Wallet_System_IWalletItemSystemStore<D>::GetAppStatusForItem(Windows::ApplicationModel::Wallet::WalletItem const& item) const
{
    Windows::ApplicationModel::Wallet::System::WalletItemAppAssociation result{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::System::IWalletItemSystemStore)->GetAppStatusForItem(get_abi(item), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_ApplicationModel_Wallet_System_IWalletItemSystemStore<D>::LaunchAppForItemAsync(Windows::ApplicationModel::Wallet::WalletItem const& item) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::System::IWalletItemSystemStore)->LaunchAppForItemAsync(get_abi(item), put_abi(operation)));
    return operation;
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_Wallet_System_IWalletItemSystemStore2<D>::ItemsChanged(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Wallet::System::WalletItemSystemStore, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::System::IWalletItemSystemStore2)->add_ItemsChanged(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_ApplicationModel_Wallet_System_IWalletItemSystemStore2<D>::ItemsChanged_revoker consume_Windows_ApplicationModel_Wallet_System_IWalletItemSystemStore2<D>::ItemsChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Wallet::System::WalletItemSystemStore, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, ItemsChanged_revoker>(this, ItemsChanged(handler));
}

template <typename D> void consume_Windows_ApplicationModel_Wallet_System_IWalletItemSystemStore2<D>::ItemsChanged(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::Wallet::System::IWalletItemSystemStore2)->remove_ItemsChanged(get_abi(cookie)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Wallet::System::WalletItemSystemStore> consume_Windows_ApplicationModel_Wallet_System_IWalletManagerSystemStatics<D>::RequestStoreAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Wallet::System::WalletItemSystemStore> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Wallet::System::IWalletManagerSystemStatics)->RequestStoreAsync(put_abi(operation)));
    return operation;
}

template <typename D>
struct produce<D, Windows::ApplicationModel::Wallet::System::IWalletItemSystemStore> : produce_base<D, Windows::ApplicationModel::Wallet::System::IWalletItemSystemStore>
{
    int32_t WINRT_CALL GetItemsAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetItemsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Wallet::WalletItem>>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::Wallet::WalletItem>>>(this->shim().GetItemsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DeleteAsync(void* item, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeleteAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::ApplicationModel::Wallet::WalletItem const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().DeleteAsync(*reinterpret_cast<Windows::ApplicationModel::Wallet::WalletItem const*>(&item)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ImportItemAsync(void* stream, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ImportItemAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Wallet::WalletItem>), Windows::Storage::Streams::IRandomAccessStreamReference const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Wallet::WalletItem>>(this->shim().ImportItemAsync(*reinterpret_cast<Windows::Storage::Streams::IRandomAccessStreamReference const*>(&stream)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetAppStatusForItem(void* item, Windows::ApplicationModel::Wallet::System::WalletItemAppAssociation* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAppStatusForItem, WINRT_WRAP(Windows::ApplicationModel::Wallet::System::WalletItemAppAssociation), Windows::ApplicationModel::Wallet::WalletItem const&);
            *result = detach_from<Windows::ApplicationModel::Wallet::System::WalletItemAppAssociation>(this->shim().GetAppStatusForItem(*reinterpret_cast<Windows::ApplicationModel::Wallet::WalletItem const*>(&item)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL LaunchAppForItemAsync(void* item, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LaunchAppForItemAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::ApplicationModel::Wallet::WalletItem const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().LaunchAppForItemAsync(*reinterpret_cast<Windows::ApplicationModel::Wallet::WalletItem const*>(&item)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Wallet::System::IWalletItemSystemStore2> : produce_base<D, Windows::ApplicationModel::Wallet::System::IWalletItemSystemStore2>
{
    int32_t WINRT_CALL add_ItemsChanged(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ItemsChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Wallet::System::WalletItemSystemStore, Windows::Foundation::IInspectable> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().ItemsChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::Wallet::System::WalletItemSystemStore, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ItemsChanged(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ItemsChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ItemsChanged(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Wallet::System::IWalletManagerSystemStatics> : produce_base<D, Windows::ApplicationModel::Wallet::System::IWalletManagerSystemStatics>
{
    int32_t WINRT_CALL RequestStoreAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestStoreAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Wallet::System::WalletItemSystemStore>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Wallet::System::WalletItemSystemStore>>(this->shim().RequestStoreAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Wallet::System {

inline Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Wallet::System::WalletItemSystemStore> WalletManagerSystem::RequestStoreAsync()
{
    return impl::call_factory<WalletManagerSystem, Windows::ApplicationModel::Wallet::System::IWalletManagerSystemStatics>([&](auto&& f) { return f.RequestStoreAsync(); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::ApplicationModel::Wallet::System::IWalletItemSystemStore> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Wallet::System::IWalletItemSystemStore> {};
template<> struct hash<winrt::Windows::ApplicationModel::Wallet::System::IWalletItemSystemStore2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Wallet::System::IWalletItemSystemStore2> {};
template<> struct hash<winrt::Windows::ApplicationModel::Wallet::System::IWalletManagerSystemStatics> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Wallet::System::IWalletManagerSystemStatics> {};
template<> struct hash<winrt::Windows::ApplicationModel::Wallet::System::WalletItemSystemStore> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Wallet::System::WalletItemSystemStore> {};
template<> struct hash<winrt::Windows::ApplicationModel::Wallet::System::WalletManagerSystem> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Wallet::System::WalletManagerSystem> {};

}
