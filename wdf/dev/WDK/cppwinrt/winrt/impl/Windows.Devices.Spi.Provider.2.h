// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.Devices.Spi.Provider.1.h"

WINRT_EXPORT namespace winrt::Windows::Devices::Spi::Provider {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::Devices::Spi::Provider {

struct WINRT_EBO ProviderSpiConnectionSettings :
    Windows::Devices::Spi::Provider::IProviderSpiConnectionSettings
{
    ProviderSpiConnectionSettings(std::nullptr_t) noexcept {}
    ProviderSpiConnectionSettings(int32_t chipSelectLine);
};

}
