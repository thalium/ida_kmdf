// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Security.Authentication.Identity.1.h"

WINRT_EXPORT namespace winrt::Windows::Security::Authentication::Identity {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::Security::Authentication::Identity {

struct WINRT_EBO EnterpriseKeyCredentialRegistrationInfo :
    Windows::Security::Authentication::Identity::IEnterpriseKeyCredentialRegistrationInfo
{
    EnterpriseKeyCredentialRegistrationInfo(std::nullptr_t) noexcept {}
};

struct WINRT_EBO EnterpriseKeyCredentialRegistrationManager :
    Windows::Security::Authentication::Identity::IEnterpriseKeyCredentialRegistrationManager
{
    EnterpriseKeyCredentialRegistrationManager(std::nullptr_t) noexcept {}
    static Windows::Security::Authentication::Identity::EnterpriseKeyCredentialRegistrationManager Current();
};

}
