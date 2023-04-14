// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Graphics.1.h"

WINRT_EXPORT namespace winrt::Windows::Graphics {

struct DisplayAdapterId
{
    uint32_t LowPart;
    int32_t HighPart;
};

inline bool operator==(DisplayAdapterId const& left, DisplayAdapterId const& right) noexcept
{
    return left.LowPart == right.LowPart && left.HighPart == right.HighPart;
}

inline bool operator!=(DisplayAdapterId const& left, DisplayAdapterId const& right) noexcept
{
    return !(left == right);
}

struct PointInt32
{
    int32_t X;
    int32_t Y;
};

inline bool operator==(PointInt32 const& left, PointInt32 const& right) noexcept
{
    return left.X == right.X && left.Y == right.Y;
}

inline bool operator!=(PointInt32 const& left, PointInt32 const& right) noexcept
{
    return !(left == right);
}

struct RectInt32
{
    int32_t X;
    int32_t Y;
    int32_t Width;
    int32_t Height;
};

inline bool operator==(RectInt32 const& left, RectInt32 const& right) noexcept
{
    return left.X == right.X && left.Y == right.Y && left.Width == right.Width && left.Height == right.Height;
}

inline bool operator!=(RectInt32 const& left, RectInt32 const& right) noexcept
{
    return !(left == right);
}

struct SizeInt32
{
    int32_t Width;
    int32_t Height;
};

inline bool operator==(SizeInt32 const& left, SizeInt32 const& right) noexcept
{
    return left.Width == right.Width && left.Height == right.Height;
}

inline bool operator!=(SizeInt32 const& left, SizeInt32 const& right) noexcept
{
    return !(left == right);
}

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::Graphics {

}
