// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.UI.Composition.1.h"
#include "winrt/impl/Windows.UI.Composition.Desktop.1.h"

WINRT_EXPORT namespace winrt::Windows::UI::Composition::Desktop {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::UI::Composition::Desktop {

struct WINRT_EBO DesktopWindowTarget :
    Windows::UI::Composition::Desktop::IDesktopWindowTarget,
    impl::base<DesktopWindowTarget, Windows::UI::Composition::CompositionTarget, Windows::UI::Composition::CompositionObject>,
    impl::require<DesktopWindowTarget, Windows::Foundation::IClosable, Windows::UI::Composition::IAnimationObject, Windows::UI::Composition::ICompositionObject, Windows::UI::Composition::ICompositionObject2, Windows::UI::Composition::ICompositionObject3, Windows::UI::Composition::ICompositionObject4, Windows::UI::Composition::ICompositionTarget>
{
    DesktopWindowTarget(std::nullptr_t) noexcept {}
};

}
