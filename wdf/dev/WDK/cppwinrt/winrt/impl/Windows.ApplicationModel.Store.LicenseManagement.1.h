// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Storage.Streams.0.h"
#include "winrt/impl/Windows.ApplicationModel.Store.LicenseManagement.0.h"

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Store::LicenseManagement {

struct WINRT_EBO ILicenseManagerStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<ILicenseManagerStatics>
{
    ILicenseManagerStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ILicenseManagerStatics2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<ILicenseManagerStatics2>
{
    ILicenseManagerStatics2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ILicenseSatisfactionInfo :
    Windows::Foundation::IInspectable,
    impl::consume_t<ILicenseSatisfactionInfo>
{
    ILicenseSatisfactionInfo(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ILicenseSatisfactionResult :
    Windows::Foundation::IInspectable,
    impl::consume_t<ILicenseSatisfactionResult>
{
    ILicenseSatisfactionResult(std::nullptr_t = nullptr) noexcept {}
};

}
