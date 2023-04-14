// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Graphics.Imaging.1.h"
#include "winrt/impl/Windows.ApplicationModel.Preview.InkWorkspace.1.h"

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Preview::InkWorkspace {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Preview::InkWorkspace {

struct WINRT_EBO InkWorkspaceHostedAppManager :
    Windows::ApplicationModel::Preview::InkWorkspace::IInkWorkspaceHostedAppManager
{
    InkWorkspaceHostedAppManager(std::nullptr_t) noexcept {}
    static Windows::ApplicationModel::Preview::InkWorkspace::InkWorkspaceHostedAppManager GetForCurrentApp();
};

}
