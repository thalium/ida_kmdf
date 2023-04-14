// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Foundation.Collections.1.h"
#include "winrt/impl/Windows.Management.Update.1.h"

WINRT_EXPORT namespace winrt::Windows::Management::Update {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::Management::Update {

struct WINRT_EBO PreviewBuildsManager :
    Windows::Management::Update::IPreviewBuildsManager
{
    PreviewBuildsManager(std::nullptr_t) noexcept {}
    static Windows::Management::Update::PreviewBuildsManager GetDefault();
    static bool IsSupported();
};

struct WINRT_EBO PreviewBuildsState :
    Windows::Management::Update::IPreviewBuildsState
{
    PreviewBuildsState(std::nullptr_t) noexcept {}
};

}
