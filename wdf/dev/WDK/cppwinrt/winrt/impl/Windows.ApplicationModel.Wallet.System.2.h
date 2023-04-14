// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.ApplicationModel.Wallet.1.h"
#include "winrt/impl/Windows.Storage.Streams.1.h"
#include "winrt/impl/Windows.ApplicationModel.Wallet.System.1.h"

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Wallet::System {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Wallet::System {

struct WINRT_EBO WalletItemSystemStore :
    Windows::ApplicationModel::Wallet::System::IWalletItemSystemStore,
    impl::require<WalletItemSystemStore, Windows::ApplicationModel::Wallet::System::IWalletItemSystemStore2>
{
    WalletItemSystemStore(std::nullptr_t) noexcept {}
};

struct WalletManagerSystem
{
    WalletManagerSystem() = delete;
    static Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::Wallet::System::WalletItemSystemStore> RequestStoreAsync();
};

}
