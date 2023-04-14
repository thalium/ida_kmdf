// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Management.Deployment.Preview.1.h"

WINRT_EXPORT namespace winrt::Windows::Management::Deployment::Preview {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::Management::Deployment::Preview {

struct ClassicAppManager
{
    ClassicAppManager() = delete;
    static Windows::Management::Deployment::Preview::InstalledClassicAppInfo FindInstalledApp(param::hstring const& appUninstallKey);
};

struct WINRT_EBO InstalledClassicAppInfo :
    Windows::Management::Deployment::Preview::IInstalledClassicAppInfo
{
    InstalledClassicAppInfo(std::nullptr_t) noexcept {}
};

}
