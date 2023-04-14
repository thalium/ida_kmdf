// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.ApplicationModel.Contacts.0.h"
#include "winrt/impl/Windows.ApplicationModel.DataTransfer.0.h"
#include "winrt/impl/Windows.Storage.Streams.0.h"
#include "winrt/impl/Windows.ApplicationModel.DataTransfer.ShareTarget.0.h"

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::DataTransfer::ShareTarget {

struct WINRT_EBO IQuickLink :
    Windows::Foundation::IInspectable,
    impl::consume_t<IQuickLink>
{
    IQuickLink(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IShareOperation :
    Windows::Foundation::IInspectable,
    impl::consume_t<IShareOperation>
{
    IShareOperation(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IShareOperation2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IShareOperation2>
{
    IShareOperation2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IShareOperation3 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IShareOperation3>
{
    IShareOperation3(std::nullptr_t = nullptr) noexcept {}
};

}
