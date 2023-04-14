// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Graphics.Imaging.0.h"
#include "winrt/impl/Windows.ApplicationModel.Preview.InkWorkspace.0.h"

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Preview::InkWorkspace {

struct WINRT_EBO IInkWorkspaceHostedAppManager :
    Windows::Foundation::IInspectable,
    impl::consume_t<IInkWorkspaceHostedAppManager>
{
    IInkWorkspaceHostedAppManager(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IInkWorkspaceHostedAppManagerStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IInkWorkspaceHostedAppManagerStatics>
{
    IInkWorkspaceHostedAppManagerStatics(std::nullptr_t = nullptr) noexcept {}
};

}
