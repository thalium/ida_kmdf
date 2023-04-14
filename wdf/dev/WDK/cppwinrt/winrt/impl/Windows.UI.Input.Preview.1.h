// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.UI.Input.0.h"
#include "winrt/impl/Windows.UI.WindowManagement.0.h"
#include "winrt/impl/Windows.UI.Input.Preview.0.h"

WINRT_EXPORT namespace winrt::Windows::UI::Input::Preview {

struct WINRT_EBO IInputActivationListenerPreviewStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IInputActivationListenerPreviewStatics>
{
    IInputActivationListenerPreviewStatics(std::nullptr_t = nullptr) noexcept {}
};

}
