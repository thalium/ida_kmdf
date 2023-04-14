// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.ApplicationModel.Core.1.h"
#include "winrt/impl/Windows.System.1.h"
#include "winrt/impl/Windows.UI.Core.1.h"
#include "winrt/impl/Windows.UI.Input.1.h"
#include "winrt/impl/Windows.UI.Input.Core.1.h"

WINRT_EXPORT namespace winrt::Windows::UI::Input::Core {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::UI::Input::Core {

struct WINRT_EBO RadialControllerIndependentInputSource :
    Windows::UI::Input::Core::IRadialControllerIndependentInputSource,
    impl::require<RadialControllerIndependentInputSource, Windows::UI::Input::Core::IRadialControllerIndependentInputSource2>
{
    RadialControllerIndependentInputSource(std::nullptr_t) noexcept {}
    static Windows::UI::Input::Core::RadialControllerIndependentInputSource CreateForView(Windows::ApplicationModel::Core::CoreApplicationView const& view);
};

}
