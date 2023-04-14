// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Perception {

struct PerceptionTimestamp;

}

WINRT_EXPORT namespace winrt::Windows::Perception::Spatial {

struct SpatialCoordinateSystem;
struct SpatialRay;

}

WINRT_EXPORT namespace winrt::Windows::UI::Input {

enum class GazeInputAccessStatus;

}

WINRT_EXPORT namespace winrt::Windows::UI::Input::Spatial {

struct SpatialInteractionSource;

}

WINRT_EXPORT namespace winrt::Windows::Perception::People {

enum class HandJointKind : int32_t
{
    Palm = 0,
    Wrist = 1,
    ThumbMetacarpal = 2,
    ThumbProximal = 3,
    ThumbDistal = 4,
    ThumbTip = 5,
    IndexMetacarpal = 6,
    IndexProximal = 7,
    IndexIntermediate = 8,
    IndexDistal = 9,
    IndexTip = 10,
    MiddleMetacarpal = 11,
    MiddleProximal = 12,
    MiddleIntermediate = 13,
    MiddleDistal = 14,
    MiddleTip = 15,
    RingMetacarpal = 16,
    RingProximal = 17,
    RingIntermediate = 18,
    RingDistal = 19,
    RingTip = 20,
    LittleMetacarpal = 21,
    LittleProximal = 22,
    LittleIntermediate = 23,
    LittleDistal = 24,
    LittleTip = 25,
};

enum class JointPoseAccuracy : int32_t
{
    High = 0,
    Approximate = 1,
};

struct IEyesPose;
struct IEyesPoseStatics;
struct IHandMeshObserver;
struct IHandMeshVertexState;
struct IHandPose;
struct IHeadPose;
struct EyesPose;
struct HandMeshObserver;
struct HandMeshVertexState;
struct HandPose;
struct HeadPose;
struct HandMeshVertex;
struct JointPose;

}

namespace winrt::impl {

template <> struct category<Windows::Perception::People::IEyesPose>{ using type = interface_category; };
template <> struct category<Windows::Perception::People::IEyesPoseStatics>{ using type = interface_category; };
template <> struct category<Windows::Perception::People::IHandMeshObserver>{ using type = interface_category; };
template <> struct category<Windows::Perception::People::IHandMeshVertexState>{ using type = interface_category; };
template <> struct category<Windows::Perception::People::IHandPose>{ using type = interface_category; };
template <> struct category<Windows::Perception::People::IHeadPose>{ using type = interface_category; };
template <> struct category<Windows::Perception::People::EyesPose>{ using type = class_category; };
template <> struct category<Windows::Perception::People::HandMeshObserver>{ using type = class_category; };
template <> struct category<Windows::Perception::People::HandMeshVertexState>{ using type = class_category; };
template <> struct category<Windows::Perception::People::HandPose>{ using type = class_category; };
template <> struct category<Windows::Perception::People::HeadPose>{ using type = class_category; };
template <> struct category<Windows::Perception::People::HandJointKind>{ using type = enum_category; };
template <> struct category<Windows::Perception::People::JointPoseAccuracy>{ using type = enum_category; };
template <> struct category<Windows::Perception::People::HandMeshVertex>{ using type = struct_category<Windows::Foundation::Numerics::float3,Windows::Foundation::Numerics::float3>; };
template <> struct category<Windows::Perception::People::JointPose>{ using type = struct_category<Windows::Foundation::Numerics::quaternion,Windows::Foundation::Numerics::float3,float,Windows::Perception::People::JointPoseAccuracy>; };
template <> struct name<Windows::Perception::People::IEyesPose>{ static constexpr auto & value{ L"Windows.Perception.People.IEyesPose" }; };
template <> struct name<Windows::Perception::People::IEyesPoseStatics>{ static constexpr auto & value{ L"Windows.Perception.People.IEyesPoseStatics" }; };
template <> struct name<Windows::Perception::People::IHandMeshObserver>{ static constexpr auto & value{ L"Windows.Perception.People.IHandMeshObserver" }; };
template <> struct name<Windows::Perception::People::IHandMeshVertexState>{ static constexpr auto & value{ L"Windows.Perception.People.IHandMeshVertexState" }; };
template <> struct name<Windows::Perception::People::IHandPose>{ static constexpr auto & value{ L"Windows.Perception.People.IHandPose" }; };
template <> struct name<Windows::Perception::People::IHeadPose>{ static constexpr auto & value{ L"Windows.Perception.People.IHeadPose" }; };
template <> struct name<Windows::Perception::People::EyesPose>{ static constexpr auto & value{ L"Windows.Perception.People.EyesPose" }; };
template <> struct name<Windows::Perception::People::HandMeshObserver>{ static constexpr auto & value{ L"Windows.Perception.People.HandMeshObserver" }; };
template <> struct name<Windows::Perception::People::HandMeshVertexState>{ static constexpr auto & value{ L"Windows.Perception.People.HandMeshVertexState" }; };
template <> struct name<Windows::Perception::People::HandPose>{ static constexpr auto & value{ L"Windows.Perception.People.HandPose" }; };
template <> struct name<Windows::Perception::People::HeadPose>{ static constexpr auto & value{ L"Windows.Perception.People.HeadPose" }; };
template <> struct name<Windows::Perception::People::HandJointKind>{ static constexpr auto & value{ L"Windows.Perception.People.HandJointKind" }; };
template <> struct name<Windows::Perception::People::JointPoseAccuracy>{ static constexpr auto & value{ L"Windows.Perception.People.JointPoseAccuracy" }; };
template <> struct name<Windows::Perception::People::HandMeshVertex>{ static constexpr auto & value{ L"Windows.Perception.People.HandMeshVertex" }; };
template <> struct name<Windows::Perception::People::JointPose>{ static constexpr auto & value{ L"Windows.Perception.People.JointPose" }; };
template <> struct guid_storage<Windows::Perception::People::IEyesPose>{ static constexpr guid value{ 0x682A9B23,0x8A1E,0x5B86,{ 0xA0,0x60,0x90,0x6F,0xFA,0xCB,0x62,0xA4 } }; };
template <> struct guid_storage<Windows::Perception::People::IEyesPoseStatics>{ static constexpr guid value{ 0x1CFF7413,0xB21F,0x54C0,{ 0x80,0xC1,0xE6,0x0D,0x99,0x4C,0xA5,0x8C } }; };
template <> struct guid_storage<Windows::Perception::People::IHandMeshObserver>{ static constexpr guid value{ 0x85AE30CB,0x6FC3,0x55C4,{ 0xA7,0xB4,0x29,0xE3,0x38,0x96,0xCA,0x69 } }; };
template <> struct guid_storage<Windows::Perception::People::IHandMeshVertexState>{ static constexpr guid value{ 0x046C5FEF,0x1D8B,0x55DE,{ 0xAB,0x2C,0x1C,0xD4,0x24,0x88,0x6D,0x8F } }; };
template <> struct guid_storage<Windows::Perception::People::IHandPose>{ static constexpr guid value{ 0x4D98E79A,0xBB08,0x5D09,{ 0x91,0xDE,0xDF,0x0D,0xD3,0xFA,0xE4,0x6C } }; };
template <> struct guid_storage<Windows::Perception::People::IHeadPose>{ static constexpr guid value{ 0x7F5AC5A5,0x49DB,0x379F,{ 0x94,0x29,0x32,0xA2,0xFA,0xF3,0x4F,0xA6 } }; };
template <> struct default_interface<Windows::Perception::People::EyesPose>{ using type = Windows::Perception::People::IEyesPose; };
template <> struct default_interface<Windows::Perception::People::HandMeshObserver>{ using type = Windows::Perception::People::IHandMeshObserver; };
template <> struct default_interface<Windows::Perception::People::HandMeshVertexState>{ using type = Windows::Perception::People::IHandMeshVertexState; };
template <> struct default_interface<Windows::Perception::People::HandPose>{ using type = Windows::Perception::People::IHandPose; };
template <> struct default_interface<Windows::Perception::People::HeadPose>{ using type = Windows::Perception::People::IHeadPose; };

template <> struct abi<Windows::Perception::People::IEyesPose>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsCalibrationValid(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Gaze(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_UpdateTimestamp(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Perception::People::IEyesPoseStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL IsSupported(bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL RequestAccessAsync(void** operation) noexcept = 0;
};};

template <> struct abi<Windows::Perception::People::IHandMeshObserver>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Source(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TriangleIndexCount(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_VertexCount(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL GetTriangleIndices(uint32_t __indicesSize, uint16_t* indices) noexcept = 0;
    virtual int32_t WINRT_CALL GetVertexStateForPose(void* handPose, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL get_NeutralPose(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_NeutralPoseVersion(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ModelId(int32_t* value) noexcept = 0;
};};

template <> struct abi<Windows::Perception::People::IHandMeshVertexState>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_CoordinateSystem(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetVertices(uint32_t __verticesSize, struct struct_Windows_Perception_People_HandMeshVertex* vertices) noexcept = 0;
    virtual int32_t WINRT_CALL get_UpdateTimestamp(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Perception::People::IHandPose>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL TryGetJoint(void* coordinateSystem, Windows::Perception::People::HandJointKind joint, struct struct_Windows_Perception_People_JointPose* jointPose, bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL TryGetJoints(void* coordinateSystem, uint32_t __jointsSize, Windows::Perception::People::HandJointKind* joints, uint32_t __jointPosesSize, struct struct_Windows_Perception_People_JointPose* jointPoses, bool* result) noexcept = 0;
    virtual int32_t WINRT_CALL GetRelativeJoint(Windows::Perception::People::HandJointKind joint, Windows::Perception::People::HandJointKind referenceJoint, struct struct_Windows_Perception_People_JointPose* result) noexcept = 0;
    virtual int32_t WINRT_CALL GetRelativeJoints(uint32_t __jointsSize, Windows::Perception::People::HandJointKind* joints, uint32_t __referenceJointsSize, Windows::Perception::People::HandJointKind* referenceJoints, uint32_t __jointPosesSize, struct struct_Windows_Perception_People_JointPose* jointPoses) noexcept = 0;
};};

template <> struct abi<Windows::Perception::People::IHeadPose>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Position(Windows::Foundation::Numerics::float3* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ForwardDirection(Windows::Foundation::Numerics::float3* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_UpDirection(Windows::Foundation::Numerics::float3* value) noexcept = 0;
};};

template <typename D>
struct consume_Windows_Perception_People_IEyesPose
{
    bool IsCalibrationValid() const;
    Windows::Foundation::IReference<Windows::Perception::Spatial::SpatialRay> Gaze() const;
    Windows::Perception::PerceptionTimestamp UpdateTimestamp() const;
};
template <> struct consume<Windows::Perception::People::IEyesPose> { template <typename D> using type = consume_Windows_Perception_People_IEyesPose<D>; };

template <typename D>
struct consume_Windows_Perception_People_IEyesPoseStatics
{
    bool IsSupported() const;
    Windows::Foundation::IAsyncOperation<Windows::UI::Input::GazeInputAccessStatus> RequestAccessAsync() const;
};
template <> struct consume<Windows::Perception::People::IEyesPoseStatics> { template <typename D> using type = consume_Windows_Perception_People_IEyesPoseStatics<D>; };

template <typename D>
struct consume_Windows_Perception_People_IHandMeshObserver
{
    Windows::UI::Input::Spatial::SpatialInteractionSource Source() const;
    uint32_t TriangleIndexCount() const;
    uint32_t VertexCount() const;
    void GetTriangleIndices(array_view<uint16_t> indices) const;
    Windows::Perception::People::HandMeshVertexState GetVertexStateForPose(Windows::Perception::People::HandPose const& handPose) const;
    Windows::Perception::People::HandPose NeutralPose() const;
    int32_t NeutralPoseVersion() const;
    int32_t ModelId() const;
};
template <> struct consume<Windows::Perception::People::IHandMeshObserver> { template <typename D> using type = consume_Windows_Perception_People_IHandMeshObserver<D>; };

template <typename D>
struct consume_Windows_Perception_People_IHandMeshVertexState
{
    Windows::Perception::Spatial::SpatialCoordinateSystem CoordinateSystem() const;
    void GetVertices(array_view<Windows::Perception::People::HandMeshVertex> vertices) const;
    Windows::Perception::PerceptionTimestamp UpdateTimestamp() const;
};
template <> struct consume<Windows::Perception::People::IHandMeshVertexState> { template <typename D> using type = consume_Windows_Perception_People_IHandMeshVertexState<D>; };

template <typename D>
struct consume_Windows_Perception_People_IHandPose
{
    bool TryGetJoint(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem, Windows::Perception::People::HandJointKind const& joint, Windows::Perception::People::JointPose& jointPose) const;
    bool TryGetJoints(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem, array_view<Windows::Perception::People::HandJointKind const> joints, array_view<Windows::Perception::People::JointPose> jointPoses) const;
    Windows::Perception::People::JointPose GetRelativeJoint(Windows::Perception::People::HandJointKind const& joint, Windows::Perception::People::HandJointKind const& referenceJoint) const;
    void GetRelativeJoints(array_view<Windows::Perception::People::HandJointKind const> joints, array_view<Windows::Perception::People::HandJointKind const> referenceJoints, array_view<Windows::Perception::People::JointPose> jointPoses) const;
};
template <> struct consume<Windows::Perception::People::IHandPose> { template <typename D> using type = consume_Windows_Perception_People_IHandPose<D>; };

template <typename D>
struct consume_Windows_Perception_People_IHeadPose
{
    Windows::Foundation::Numerics::float3 Position() const;
    Windows::Foundation::Numerics::float3 ForwardDirection() const;
    Windows::Foundation::Numerics::float3 UpDirection() const;
};
template <> struct consume<Windows::Perception::People::IHeadPose> { template <typename D> using type = consume_Windows_Perception_People_IHeadPose<D>; };

struct struct_Windows_Perception_People_HandMeshVertex
{
    Windows::Foundation::Numerics::float3 Position;
    Windows::Foundation::Numerics::float3 Normal;
};
template <> struct abi<Windows::Perception::People::HandMeshVertex>{ using type = struct_Windows_Perception_People_HandMeshVertex; };


struct struct_Windows_Perception_People_JointPose
{
    Windows::Foundation::Numerics::quaternion Orientation;
    Windows::Foundation::Numerics::float3 Position;
    float Radius;
    Windows::Perception::People::JointPoseAccuracy Accuracy;
};
template <> struct abi<Windows::Perception::People::JointPose>{ using type = struct_Windows_Perception_People_JointPose; };


}
