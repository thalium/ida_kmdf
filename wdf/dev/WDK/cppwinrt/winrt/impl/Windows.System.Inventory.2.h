// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.System.Inventory.1.h"

WINRT_EXPORT namespace winrt::Windows::System::Inventory {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::System::Inventory {

struct WINRT_EBO InstalledDesktopApp :
    Windows::System::Inventory::IInstalledDesktopApp,
    impl::require<InstalledDesktopApp, Windows::Foundation::IStringable>
{
    InstalledDesktopApp(std::nullptr_t) noexcept {}
    static Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::System::Inventory::InstalledDesktopApp>> GetInventoryAsync();
};

}
