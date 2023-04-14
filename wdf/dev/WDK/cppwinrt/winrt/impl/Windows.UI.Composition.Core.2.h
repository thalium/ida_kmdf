// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.UI.Composition.1.h"
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.UI.Composition.Core.1.h"

WINRT_EXPORT namespace winrt::Windows::UI::Composition::Core {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::UI::Composition::Core {

struct WINRT_EBO CompositorController :
    Windows::UI::Composition::Core::ICompositorController,
    impl::require<CompositorController, Windows::Foundation::IClosable>
{
    CompositorController(std::nullptr_t) noexcept {}
    CompositorController();
};

}
