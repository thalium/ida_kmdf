// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Foundation.Numerics.1.h"

WINRT_EXPORT namespace winrt::Windows::Foundation::Numerics {

struct Rational
{
    uint32_t Numerator;
    uint32_t Denominator;
};

inline bool operator==(Rational const& left, Rational const& right) noexcept
{
    return left.Numerator == right.Numerator && left.Denominator == right.Denominator;
}

inline bool operator!=(Rational const& left, Rational const& right) noexcept
{
    return !(left == right);
}

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::Foundation::Numerics {

}
