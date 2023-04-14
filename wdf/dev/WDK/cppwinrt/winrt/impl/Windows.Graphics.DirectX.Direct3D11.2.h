// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Graphics.DirectX.1.h"
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.Graphics.DirectX.Direct3D11.1.h"
#include "winrt/impl/Windows.Graphics.DirectX.Direct3D11.2.h"

WINRT_EXPORT namespace winrt::Windows::Graphics::DirectX::Direct3D11 {

struct Direct3DMultisampleDescription
{
    int32_t Count;
    int32_t Quality;
};

inline bool operator==(Direct3DMultisampleDescription const& left, Direct3DMultisampleDescription const& right) noexcept
{
    return left.Count == right.Count && left.Quality == right.Quality;
}

inline bool operator!=(Direct3DMultisampleDescription const& left, Direct3DMultisampleDescription const& right) noexcept
{
    return !(left == right);
}

struct Direct3DSurfaceDescription
{
    int32_t Width;
    int32_t Height;
    Windows::Graphics::DirectX::DirectXPixelFormat Format;
    Windows::Graphics::DirectX::Direct3D11::Direct3DMultisampleDescription MultisampleDescription;
};

inline bool operator==(Direct3DSurfaceDescription const& left, Direct3DSurfaceDescription const& right) noexcept
{
    return left.Width == right.Width && left.Height == right.Height && left.Format == right.Format && left.MultisampleDescription == right.MultisampleDescription;
}

inline bool operator!=(Direct3DSurfaceDescription const& left, Direct3DSurfaceDescription const& right) noexcept
{
    return !(left == right);
}

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::Graphics::DirectX::Direct3D11 {

}
