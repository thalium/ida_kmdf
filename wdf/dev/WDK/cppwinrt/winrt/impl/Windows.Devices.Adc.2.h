// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Devices.Adc.Provider.1.h"
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.Devices.Adc.1.h"

WINRT_EXPORT namespace winrt::Windows::Devices::Adc {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::Devices::Adc {

struct WINRT_EBO AdcChannel :
    Windows::Devices::Adc::IAdcChannel
{
    AdcChannel(std::nullptr_t) noexcept {}
};

struct WINRT_EBO AdcController :
    Windows::Devices::Adc::IAdcController
{
    AdcController(std::nullptr_t) noexcept {}
    static Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Adc::AdcController>> GetControllersAsync(Windows::Devices::Adc::Provider::IAdcProvider const& provider);
    static Windows::Foundation::IAsyncOperation<Windows::Devices::Adc::AdcController> GetDefaultAsync();
};

}
