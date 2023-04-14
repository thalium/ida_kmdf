// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Graphics {

struct IGeometrySource2D;
struct DisplayAdapterId;
struct PointInt32;
struct RectInt32;
struct SizeInt32;

}

namespace winrt::impl {

template <> struct category<Windows::Graphics::IGeometrySource2D>{ using type = interface_category; };
template <> struct category<Windows::Graphics::DisplayAdapterId>{ using type = struct_category<uint32_t,int32_t>; };
template <> struct category<Windows::Graphics::PointInt32>{ using type = struct_category<int32_t,int32_t>; };
template <> struct category<Windows::Graphics::RectInt32>{ using type = struct_category<int32_t,int32_t,int32_t,int32_t>; };
template <> struct category<Windows::Graphics::SizeInt32>{ using type = struct_category<int32_t,int32_t>; };
template <> struct name<Windows::Graphics::IGeometrySource2D>{ static constexpr auto & value{ L"Windows.Graphics.IGeometrySource2D" }; };
template <> struct name<Windows::Graphics::DisplayAdapterId>{ static constexpr auto & value{ L"Windows.Graphics.DisplayAdapterId" }; };
template <> struct name<Windows::Graphics::PointInt32>{ static constexpr auto & value{ L"Windows.Graphics.PointInt32" }; };
template <> struct name<Windows::Graphics::RectInt32>{ static constexpr auto & value{ L"Windows.Graphics.RectInt32" }; };
template <> struct name<Windows::Graphics::SizeInt32>{ static constexpr auto & value{ L"Windows.Graphics.SizeInt32" }; };
template <> struct guid_storage<Windows::Graphics::IGeometrySource2D>{ static constexpr guid value{ 0xCAFF7902,0x670C,0x4181,{ 0xA6,0x24,0xDA,0x97,0x72,0x03,0xB8,0x45 } }; };

template <> struct abi<Windows::Graphics::IGeometrySource2D>{ struct type : IInspectable
{
};};

template <typename D>
struct consume_Windows_Graphics_IGeometrySource2D
{
};
template <> struct consume<Windows::Graphics::IGeometrySource2D> { template <typename D> using type = consume_Windows_Graphics_IGeometrySource2D<D>; };

struct struct_Windows_Graphics_DisplayAdapterId
{
    uint32_t LowPart;
    int32_t HighPart;
};
template <> struct abi<Windows::Graphics::DisplayAdapterId>{ using type = struct_Windows_Graphics_DisplayAdapterId; };


struct struct_Windows_Graphics_PointInt32
{
    int32_t X;
    int32_t Y;
};
template <> struct abi<Windows::Graphics::PointInt32>{ using type = struct_Windows_Graphics_PointInt32; };


struct struct_Windows_Graphics_RectInt32
{
    int32_t X;
    int32_t Y;
    int32_t Width;
    int32_t Height;
};
template <> struct abi<Windows::Graphics::RectInt32>{ using type = struct_Windows_Graphics_RectInt32; };


struct struct_Windows_Graphics_SizeInt32
{
    int32_t Width;
    int32_t Height;
};
template <> struct abi<Windows::Graphics::SizeInt32>{ using type = struct_Windows_Graphics_SizeInt32; };


}
