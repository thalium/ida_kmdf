// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Perception.1.h"
#include "winrt/impl/Windows.Perception.Spatial.1.h"
#include "winrt/impl/Windows.UI.Input.1.h"
#include "winrt/impl/Windows.UI.Input.Spatial.1.h"
#include "winrt/impl/Windows.Perception.People.1.h"

WINRT_EXPORT namespace winrt::Windows::Perception::People {

struct HandMeshVertex
{
    Windows::Foundation::Numerics::float3 Position;
    Windows::Foundation::Numerics::float3 Normal;
};

inline bool operator==(HandMeshVertex const& left, HandMeshVertex const& right) noexcept
{
    return left.Position == right.Position && left.Normal == right.Normal;
}

inline bool operator!=(HandMeshVertex const& left, HandMeshVertex const& right) noexcept
{
    return !(left == right);
}

struct JointPose
{
    Windows::Foundation::Numerics::quaternion Orientation;
    Windows::Foundation::Numerics::float3 Position;
    float Radius;
    Windows::Perception::People::JointPoseAccuracy Accuracy;
};

inline bool operator==(JointPose const& left, JointPose const& right) noexcept
{
    return left.Orientation == right.Orientation && left.Position == right.Position && left.Radius == right.Radius && left.Accuracy == right.Accuracy;
}

inline bool operator!=(JointPose const& left, JointPose const& right) noexcept
{
    return !(left == right);
}

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::Perception::People {

struct WINRT_EBO EyesPose :
    Windows::Perception::People::IEyesPose
{
    EyesPose(std::nullptr_t) noexcept {}
    static bool IsSupported();
    static Windows::Foundation::IAsyncOperation<Windows::UI::Input::GazeInputAccessStatus> RequestAccessAsync();
};

struct WINRT_EBO HandMeshObserver :
    Windows::Perception::People::IHandMeshObserver
{
    HandMeshObserver(std::nullptr_t) noexcept {}
};

struct WINRT_EBO HandMeshVertexState :
    Windows::Perception::People::IHandMeshVertexState
{
    HandMeshVertexState(std::nullptr_t) noexcept {}
};

struct WINRT_EBO HandPose :
    Windows::Perception::People::IHandPose
{
    HandPose(std::nullptr_t) noexcept {}
};

struct WINRT_EBO HeadPose :
    Windows::Perception::People::IHeadPose
{
    HeadPose(std::nullptr_t) noexcept {}
};

}
