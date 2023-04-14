// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Perception.0.h"
#include "winrt/impl/Windows.Perception.Spatial.0.h"
#include "winrt/impl/Windows.UI.Input.0.h"
#include "winrt/impl/Windows.UI.Input.Spatial.0.h"
#include "winrt/impl/Windows.Perception.People.0.h"

WINRT_EXPORT namespace winrt::Windows::Perception::People {

struct WINRT_EBO IEyesPose :
    Windows::Foundation::IInspectable,
    impl::consume_t<IEyesPose>
{
    IEyesPose(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IEyesPoseStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IEyesPoseStatics>
{
    IEyesPoseStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHandMeshObserver :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHandMeshObserver>
{
    IHandMeshObserver(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHandMeshVertexState :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHandMeshVertexState>
{
    IHandMeshVertexState(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHandPose :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHandPose>
{
    IHandPose(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IHeadPose :
    Windows::Foundation::IInspectable,
    impl::consume_t<IHeadPose>
{
    IHeadPose(std::nullptr_t = nullptr) noexcept {}
};

}
