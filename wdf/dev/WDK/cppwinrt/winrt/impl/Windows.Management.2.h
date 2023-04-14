// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Management.1.h"

WINRT_EXPORT namespace winrt::Windows::Management {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::Management {

struct WINRT_EBO MdmAlert :
    Windows::Management::IMdmAlert
{
    MdmAlert(std::nullptr_t) noexcept {}
    MdmAlert();
};

struct WINRT_EBO MdmSession :
    Windows::Management::IMdmSession
{
    MdmSession(std::nullptr_t) noexcept {}
};

struct MdmSessionManager
{
    MdmSessionManager() = delete;
    static Windows::Foundation::Collections::IVectorView<hstring> SessionIds();
    static Windows::Management::MdmSession TryCreateSession();
    static void DeleteSessionById(param::hstring const& sessionId);
    static Windows::Management::MdmSession GetSessionById(param::hstring const& sessionId);
};

}
