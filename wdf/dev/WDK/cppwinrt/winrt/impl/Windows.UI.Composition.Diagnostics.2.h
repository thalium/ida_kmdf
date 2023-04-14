// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.UI.Composition.1.h"
#include "winrt/impl/Windows.UI.Composition.Diagnostics.1.h"

WINRT_EXPORT namespace winrt::Windows::UI::Composition::Diagnostics {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::UI::Composition::Diagnostics {

struct WINRT_EBO CompositionDebugHeatMaps :
    Windows::UI::Composition::Diagnostics::ICompositionDebugHeatMaps
{
    CompositionDebugHeatMaps(std::nullptr_t) noexcept {}
};

struct WINRT_EBO CompositionDebugSettings :
    Windows::UI::Composition::Diagnostics::ICompositionDebugSettings
{
    CompositionDebugSettings(std::nullptr_t) noexcept {}
    static Windows::UI::Composition::Diagnostics::CompositionDebugSettings TryGetSettings(Windows::UI::Composition::Compositor const& compositor);
};

}
