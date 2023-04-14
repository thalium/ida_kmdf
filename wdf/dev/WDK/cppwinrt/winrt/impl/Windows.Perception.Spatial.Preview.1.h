// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Perception.Spatial.0.h"
#include "winrt/impl/Windows.Perception.Spatial.Preview.0.h"

WINRT_EXPORT namespace winrt::Windows::Perception::Spatial::Preview {

struct WINRT_EBO ISpatialGraphInteropFrameOfReferencePreview :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISpatialGraphInteropFrameOfReferencePreview>
{
    ISpatialGraphInteropFrameOfReferencePreview(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISpatialGraphInteropPreviewStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISpatialGraphInteropPreviewStatics>
{
    ISpatialGraphInteropPreviewStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISpatialGraphInteropPreviewStatics2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISpatialGraphInteropPreviewStatics2>
{
    ISpatialGraphInteropPreviewStatics2(std::nullptr_t = nullptr) noexcept {}
};

}
