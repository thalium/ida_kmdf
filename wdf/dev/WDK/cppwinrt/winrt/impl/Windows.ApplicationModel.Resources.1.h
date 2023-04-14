// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Foundation.0.h"
#include "winrt/impl/Windows.UI.0.h"
#include "winrt/impl/Windows.ApplicationModel.Resources.0.h"

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Resources {

struct WINRT_EBO IResourceLoader :
    Windows::Foundation::IInspectable,
    impl::consume_t<IResourceLoader>
{
    IResourceLoader(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IResourceLoader2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IResourceLoader2>
{
    IResourceLoader2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IResourceLoaderFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<IResourceLoaderFactory>
{
    IResourceLoaderFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IResourceLoaderStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IResourceLoaderStatics>
{
    IResourceLoaderStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IResourceLoaderStatics2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IResourceLoaderStatics2>
{
    IResourceLoaderStatics2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IResourceLoaderStatics3 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IResourceLoaderStatics3>
{
    IResourceLoaderStatics3(std::nullptr_t = nullptr) noexcept {}
};

}
