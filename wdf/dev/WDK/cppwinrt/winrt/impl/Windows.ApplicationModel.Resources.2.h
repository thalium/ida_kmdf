// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.UI.1.h"
#include "winrt/impl/Windows.ApplicationModel.Resources.1.h"

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Resources {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Resources {

struct WINRT_EBO ResourceLoader :
    Windows::ApplicationModel::Resources::IResourceLoader,
    impl::require<ResourceLoader, Windows::ApplicationModel::Resources::IResourceLoader2>
{
    ResourceLoader(std::nullptr_t) noexcept {}
    ResourceLoader();
    ResourceLoader(param::hstring const& name);
    static hstring GetStringForReference(Windows::Foundation::Uri const& uri);
    static Windows::ApplicationModel::Resources::ResourceLoader GetForCurrentView();
    static Windows::ApplicationModel::Resources::ResourceLoader GetForCurrentView(param::hstring const& name);
    static Windows::ApplicationModel::Resources::ResourceLoader GetForViewIndependentUse();
    static Windows::ApplicationModel::Resources::ResourceLoader GetForViewIndependentUse(param::hstring const& name);
    static Windows::ApplicationModel::Resources::ResourceLoader GetForUIContext(Windows::UI::UIContext const& context);
};

}
