// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Storage.1.h"
#include "winrt/impl/Windows.ApplicationModel.Calls.Provider.1.h"

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Calls::Provider {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Calls::Provider {

struct WINRT_EBO PhoneCallOrigin :
    Windows::ApplicationModel::Calls::Provider::IPhoneCallOrigin,
    impl::require<PhoneCallOrigin, Windows::ApplicationModel::Calls::Provider::IPhoneCallOrigin2, Windows::ApplicationModel::Calls::Provider::IPhoneCallOrigin3>
{
    PhoneCallOrigin(std::nullptr_t) noexcept {}
    PhoneCallOrigin();
};

struct PhoneCallOriginManager
{
    PhoneCallOriginManager() = delete;
    static bool IsCurrentAppActiveCallOriginApp();
    static void ShowPhoneCallOriginSettingsUI();
    static void SetCallOrigin(winrt::guid const& requestId, Windows::ApplicationModel::Calls::Provider::PhoneCallOrigin const& callOrigin);
    static Windows::Foundation::IAsyncOperation<bool> RequestSetAsActiveCallOriginAppAsync();
    static bool IsSupported();
};

}
