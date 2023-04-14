// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Security.Authentication.Identity.0.h"

WINRT_EXPORT namespace winrt::Windows::Security::Authentication::Identity {

struct WINRT_EBO IEnterpriseKeyCredentialRegistrationInfo :
    Windows::Foundation::IInspectable,
    impl::consume_t<IEnterpriseKeyCredentialRegistrationInfo>
{
    IEnterpriseKeyCredentialRegistrationInfo(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IEnterpriseKeyCredentialRegistrationManager :
    Windows::Foundation::IInspectable,
    impl::consume_t<IEnterpriseKeyCredentialRegistrationManager>
{
    IEnterpriseKeyCredentialRegistrationManager(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IEnterpriseKeyCredentialRegistrationManagerStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IEnterpriseKeyCredentialRegistrationManagerStatics>
{
    IEnterpriseKeyCredentialRegistrationManagerStatics(std::nullptr_t = nullptr) noexcept {}
};

}
