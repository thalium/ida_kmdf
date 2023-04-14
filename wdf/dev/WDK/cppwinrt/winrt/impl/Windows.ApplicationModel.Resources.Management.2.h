// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.ApplicationModel.Resources.Management.1.h"

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Resources::Management {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Resources::Management {

struct WINRT_EBO IndexedResourceCandidate :
    Windows::ApplicationModel::Resources::Management::IIndexedResourceCandidate
{
    IndexedResourceCandidate(std::nullptr_t) noexcept {}
};

struct WINRT_EBO IndexedResourceQualifier :
    Windows::ApplicationModel::Resources::Management::IIndexedResourceQualifier
{
    IndexedResourceQualifier(std::nullptr_t) noexcept {}
};

struct WINRT_EBO ResourceIndexer :
    Windows::ApplicationModel::Resources::Management::IResourceIndexer
{
    ResourceIndexer(std::nullptr_t) noexcept {}
    ResourceIndexer(Windows::Foundation::Uri const& projectRoot);
    ResourceIndexer(Windows::Foundation::Uri const& projectRoot, Windows::Foundation::Uri const& extensionDllPath);
};

}
