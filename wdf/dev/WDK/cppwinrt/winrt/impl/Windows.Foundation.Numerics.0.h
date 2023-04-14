// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Foundation::Numerics {

struct Rational;

}

namespace winrt::impl {

template <> struct category<Windows::Foundation::Numerics::Rational>{ using type = struct_category<uint32_t,uint32_t>; };
template <> struct name<Windows::Foundation::Numerics::Rational>{ static constexpr auto & value{ L"Windows.Foundation.Numerics.Rational" }; };

struct struct_Windows_Foundation_Numerics_Rational
{
    uint32_t Numerator;
    uint32_t Denominator;
};
template <> struct abi<Windows::Foundation::Numerics::Rational>{ using type = struct_Windows_Foundation_Numerics_Rational; };


}
