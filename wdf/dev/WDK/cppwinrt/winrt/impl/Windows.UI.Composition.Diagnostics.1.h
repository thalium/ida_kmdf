// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.UI.Composition.0.h"
#include "winrt/impl/Windows.UI.Composition.Diagnostics.0.h"

WINRT_EXPORT namespace winrt::Windows::UI::Composition::Diagnostics {

struct WINRT_EBO ICompositionDebugHeatMaps :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionDebugHeatMaps>
{
    ICompositionDebugHeatMaps(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionDebugSettings :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionDebugSettings>
{
    ICompositionDebugSettings(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ICompositionDebugSettingsStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<ICompositionDebugSettingsStatics>
{
    ICompositionDebugSettingsStatics(std::nullptr_t = nullptr) noexcept {}
};

}
