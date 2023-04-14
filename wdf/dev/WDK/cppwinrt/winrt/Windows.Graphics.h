// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Graphics.2.h"

namespace winrt::impl {

template <typename D>
struct produce<D, Windows::Graphics::IGeometrySource2D> : produce_base<D, Windows::Graphics::IGeometrySource2D>
{};

}

WINRT_EXPORT namespace winrt::Windows::Graphics {

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Graphics::IGeometrySource2D> : winrt::impl::hash_base<winrt::Windows::Graphics::IGeometrySource2D> {};

}
