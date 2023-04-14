// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.Storage.Streams.1.h"
#include "winrt/impl/Windows.Web.1.h"

WINRT_EXPORT namespace winrt::Windows::Web {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::Web {

struct WebError
{
    WebError() = delete;
    static Windows::Web::WebErrorStatus GetStatus(int32_t hresult);
};

}
