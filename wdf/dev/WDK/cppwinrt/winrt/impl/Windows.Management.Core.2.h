// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Storage.1.h"
#include "winrt/impl/Windows.Management.Core.1.h"

WINRT_EXPORT namespace winrt::Windows::Management::Core {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::Management::Core {

struct WINRT_EBO ApplicationDataManager :
    Windows::Management::Core::IApplicationDataManager
{
    ApplicationDataManager(std::nullptr_t) noexcept {}
    static Windows::Storage::ApplicationData CreateForPackageFamily(param::hstring const& packageFamilyName);
};

}
