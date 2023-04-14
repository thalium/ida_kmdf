// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Foundation.Collections.1.h"
#include "winrt/impl/Windows.Foundation.Collections.1.h"

WINRT_EXPORT namespace winrt::Windows::Foundation::Collections {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::Foundation::Collections {

struct WINRT_EBO PropertySet :
    Windows::Foundation::Collections::IPropertySet
{
    PropertySet(std::nullptr_t) noexcept {}
    PropertySet();
};

struct WINRT_EBO StringMap :
    Windows::Foundation::Collections::IMap<hstring, hstring>,
    impl::require<StringMap, Windows::Foundation::Collections::IObservableMap<hstring, hstring>>
{
    StringMap(std::nullptr_t) noexcept {}
    StringMap();
};

struct WINRT_EBO ValueSet :
    Windows::Foundation::Collections::IPropertySet
{
    ValueSet(std::nullptr_t) noexcept {}
    ValueSet();
};

}
