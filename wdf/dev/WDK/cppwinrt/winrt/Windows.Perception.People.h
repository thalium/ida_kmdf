// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Perception.2.h"
#include "winrt/impl/Windows.Perception.Spatial.2.h"
#include "winrt/impl/Windows.UI.Input.2.h"
#include "winrt/impl/Windows.UI.Input.Spatial.2.h"
#include "winrt/impl/Windows.Perception.People.2.h"
#include "winrt/Windows.Perception.h"

namespace winrt::impl {

template <typename D> bool consume_Windows_Perception_People_IEyesPose<D>::IsCalibrationValid() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Perception::People::IEyesPose)->get_IsCalibrationValid(&value));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Perception::Spatial::SpatialRay> consume_Windows_Perception_People_IEyesPose<D>::Gaze() const
{
    Windows::Foundation::IReference<Windows::Perception::Spatial::SpatialRay> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Perception::People::IEyesPose)->get_Gaze(put_abi(value)));
    return value;
}

template <typename D> Windows::Perception::PerceptionTimestamp consume_Windows_Perception_People_IEyesPose<D>::UpdateTimestamp() const
{
    Windows::Perception::PerceptionTimestamp value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Perception::People::IEyesPose)->get_UpdateTimestamp(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Perception_People_IEyesPoseStatics<D>::IsSupported() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::Perception::People::IEyesPoseStatics)->IsSupported(&result));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::UI::Input::GazeInputAccessStatus> consume_Windows_Perception_People_IEyesPoseStatics<D>::RequestAccessAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::UI::Input::GazeInputAccessStatus> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Perception::People::IEyesPoseStatics)->RequestAccessAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::UI::Input::Spatial::SpatialInteractionSource consume_Windows_Perception_People_IHandMeshObserver<D>::Source() const
{
    Windows::UI::Input::Spatial::SpatialInteractionSource value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Perception::People::IHandMeshObserver)->get_Source(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Perception_People_IHandMeshObserver<D>::TriangleIndexCount() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Perception::People::IHandMeshObserver)->get_TriangleIndexCount(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Perception_People_IHandMeshObserver<D>::VertexCount() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Perception::People::IHandMeshObserver)->get_VertexCount(&value));
    return value;
}

template <typename D> void consume_Windows_Perception_People_IHandMeshObserver<D>::GetTriangleIndices(array_view<uint16_t> indices) const
{
    check_hresult(WINRT_SHIM(Windows::Perception::People::IHandMeshObserver)->GetTriangleIndices(indices.size(), get_abi(indices)));
}

template <typename D> Windows::Perception::People::HandMeshVertexState consume_Windows_Perception_People_IHandMeshObserver<D>::GetVertexStateForPose(Windows::Perception::People::HandPose const& handPose) const
{
    Windows::Perception::People::HandMeshVertexState result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Perception::People::IHandMeshObserver)->GetVertexStateForPose(get_abi(handPose), put_abi(result)));
    return result;
}

template <typename D> Windows::Perception::People::HandPose consume_Windows_Perception_People_IHandMeshObserver<D>::NeutralPose() const
{
    Windows::Perception::People::HandPose value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Perception::People::IHandMeshObserver)->get_NeutralPose(put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_Perception_People_IHandMeshObserver<D>::NeutralPoseVersion() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Perception::People::IHandMeshObserver)->get_NeutralPoseVersion(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Perception_People_IHandMeshObserver<D>::ModelId() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Perception::People::IHandMeshObserver)->get_ModelId(&value));
    return value;
}

template <typename D> Windows::Perception::Spatial::SpatialCoordinateSystem consume_Windows_Perception_People_IHandMeshVertexState<D>::CoordinateSystem() const
{
    Windows::Perception::Spatial::SpatialCoordinateSystem value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Perception::People::IHandMeshVertexState)->get_CoordinateSystem(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Perception_People_IHandMeshVertexState<D>::GetVertices(array_view<Windows::Perception::People::HandMeshVertex> vertices) const
{
    check_hresult(WINRT_SHIM(Windows::Perception::People::IHandMeshVertexState)->GetVertices(vertices.size(), get_abi(vertices)));
}

template <typename D> Windows::Perception::PerceptionTimestamp consume_Windows_Perception_People_IHandMeshVertexState<D>::UpdateTimestamp() const
{
    Windows::Perception::PerceptionTimestamp value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Perception::People::IHandMeshVertexState)->get_UpdateTimestamp(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Perception_People_IHandPose<D>::TryGetJoint(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem, Windows::Perception::People::HandJointKind const& joint, Windows::Perception::People::JointPose& jointPose) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::Perception::People::IHandPose)->TryGetJoint(get_abi(coordinateSystem), get_abi(joint), put_abi(jointPose), &result));
    return result;
}

template <typename D> bool consume_Windows_Perception_People_IHandPose<D>::TryGetJoints(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem, array_view<Windows::Perception::People::HandJointKind const> joints, array_view<Windows::Perception::People::JointPose> jointPoses) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::Perception::People::IHandPose)->TryGetJoints(get_abi(coordinateSystem), joints.size(), get_abi(joints), jointPoses.size(), get_abi(jointPoses), &result));
    return result;
}

template <typename D> Windows::Perception::People::JointPose consume_Windows_Perception_People_IHandPose<D>::GetRelativeJoint(Windows::Perception::People::HandJointKind const& joint, Windows::Perception::People::HandJointKind const& referenceJoint) const
{
    Windows::Perception::People::JointPose result{};
    check_hresult(WINRT_SHIM(Windows::Perception::People::IHandPose)->GetRelativeJoint(get_abi(joint), get_abi(referenceJoint), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_Perception_People_IHandPose<D>::GetRelativeJoints(array_view<Windows::Perception::People::HandJointKind const> joints, array_view<Windows::Perception::People::HandJointKind const> referenceJoints, array_view<Windows::Perception::People::JointPose> jointPoses) const
{
    check_hresult(WINRT_SHIM(Windows::Perception::People::IHandPose)->GetRelativeJoints(joints.size(), get_abi(joints), referenceJoints.size(), get_abi(referenceJoints), jointPoses.size(), get_abi(jointPoses)));
}

template <typename D> Windows::Foundation::Numerics::float3 consume_Windows_Perception_People_IHeadPose<D>::Position() const
{
    Windows::Foundation::Numerics::float3 value{};
    check_hresult(WINRT_SHIM(Windows::Perception::People::IHeadPose)->get_Position(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Numerics::float3 consume_Windows_Perception_People_IHeadPose<D>::ForwardDirection() const
{
    Windows::Foundation::Numerics::float3 value{};
    check_hresult(WINRT_SHIM(Windows::Perception::People::IHeadPose)->get_ForwardDirection(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Numerics::float3 consume_Windows_Perception_People_IHeadPose<D>::UpDirection() const
{
    Windows::Foundation::Numerics::float3 value{};
    check_hresult(WINRT_SHIM(Windows::Perception::People::IHeadPose)->get_UpDirection(put_abi(value)));
    return value;
}

template <typename D>
struct produce<D, Windows::Perception::People::IEyesPose> : produce_base<D, Windows::Perception::People::IEyesPose>
{
    int32_t WINRT_CALL get_IsCalibrationValid(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsCalibrationValid, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsCalibrationValid());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Gaze(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Gaze, WINRT_WRAP(Windows::Foundation::IReference<Windows::Perception::Spatial::SpatialRay>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Perception::Spatial::SpatialRay>>(this->shim().Gaze());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UpdateTimestamp(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpdateTimestamp, WINRT_WRAP(Windows::Perception::PerceptionTimestamp));
            *value = detach_from<Windows::Perception::PerceptionTimestamp>(this->shim().UpdateTimestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Perception::People::IEyesPoseStatics> : produce_base<D, Windows::Perception::People::IEyesPoseStatics>
{
    int32_t WINRT_CALL IsSupported(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSupported, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().IsSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestAccessAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestAccessAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::UI::Input::GazeInputAccessStatus>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::UI::Input::GazeInputAccessStatus>>(this->shim().RequestAccessAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Perception::People::IHandMeshObserver> : produce_base<D, Windows::Perception::People::IHandMeshObserver>
{
    int32_t WINRT_CALL get_Source(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Source, WINRT_WRAP(Windows::UI::Input::Spatial::SpatialInteractionSource));
            *value = detach_from<Windows::UI::Input::Spatial::SpatialInteractionSource>(this->shim().Source());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TriangleIndexCount(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TriangleIndexCount, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().TriangleIndexCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VertexCount(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VertexCount, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().VertexCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetTriangleIndices(uint32_t __indicesSize, uint16_t* indices) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetTriangleIndices, WINRT_WRAP(void), array_view<uint16_t>);
            this->shim().GetTriangleIndices(array_view<uint16_t>(reinterpret_cast<uint16_t*>(indices), reinterpret_cast<uint16_t*>(indices) + __indicesSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetVertexStateForPose(void* handPose, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetVertexStateForPose, WINRT_WRAP(Windows::Perception::People::HandMeshVertexState), Windows::Perception::People::HandPose const&);
            *result = detach_from<Windows::Perception::People::HandMeshVertexState>(this->shim().GetVertexStateForPose(*reinterpret_cast<Windows::Perception::People::HandPose const*>(&handPose)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NeutralPose(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NeutralPose, WINRT_WRAP(Windows::Perception::People::HandPose));
            *value = detach_from<Windows::Perception::People::HandPose>(this->shim().NeutralPose());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NeutralPoseVersion(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NeutralPoseVersion, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().NeutralPoseVersion());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ModelId(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ModelId, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().ModelId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Perception::People::IHandMeshVertexState> : produce_base<D, Windows::Perception::People::IHandMeshVertexState>
{
    int32_t WINRT_CALL get_CoordinateSystem(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CoordinateSystem, WINRT_WRAP(Windows::Perception::Spatial::SpatialCoordinateSystem));
            *value = detach_from<Windows::Perception::Spatial::SpatialCoordinateSystem>(this->shim().CoordinateSystem());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetVertices(uint32_t __verticesSize, struct struct_Windows_Perception_People_HandMeshVertex* vertices) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetVertices, WINRT_WRAP(void), array_view<Windows::Perception::People::HandMeshVertex>);
            this->shim().GetVertices(array_view<Windows::Perception::People::HandMeshVertex>(reinterpret_cast<Windows::Perception::People::HandMeshVertex*>(vertices), reinterpret_cast<Windows::Perception::People::HandMeshVertex*>(vertices) + __verticesSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UpdateTimestamp(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpdateTimestamp, WINRT_WRAP(Windows::Perception::PerceptionTimestamp));
            *value = detach_from<Windows::Perception::PerceptionTimestamp>(this->shim().UpdateTimestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Perception::People::IHandPose> : produce_base<D, Windows::Perception::People::IHandPose>
{
    int32_t WINRT_CALL TryGetJoint(void* coordinateSystem, Windows::Perception::People::HandJointKind joint, struct struct_Windows_Perception_People_JointPose* jointPose, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryGetJoint, WINRT_WRAP(bool), Windows::Perception::Spatial::SpatialCoordinateSystem const&, Windows::Perception::People::HandJointKind const&, Windows::Perception::People::JointPose&);
            *result = detach_from<bool>(this->shim().TryGetJoint(*reinterpret_cast<Windows::Perception::Spatial::SpatialCoordinateSystem const*>(&coordinateSystem), *reinterpret_cast<Windows::Perception::People::HandJointKind const*>(&joint), *reinterpret_cast<Windows::Perception::People::JointPose*>(jointPose)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryGetJoints(void* coordinateSystem, uint32_t __jointsSize, Windows::Perception::People::HandJointKind* joints, uint32_t __jointPosesSize, struct struct_Windows_Perception_People_JointPose* jointPoses, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryGetJoints, WINRT_WRAP(bool), Windows::Perception::Spatial::SpatialCoordinateSystem const&, array_view<Windows::Perception::People::HandJointKind const>, array_view<Windows::Perception::People::JointPose>);
            *result = detach_from<bool>(this->shim().TryGetJoints(*reinterpret_cast<Windows::Perception::Spatial::SpatialCoordinateSystem const*>(&coordinateSystem), array_view<Windows::Perception::People::HandJointKind const>(reinterpret_cast<Windows::Perception::People::HandJointKind const *>(joints), reinterpret_cast<Windows::Perception::People::HandJointKind const *>(joints) + __jointsSize), array_view<Windows::Perception::People::JointPose>(reinterpret_cast<Windows::Perception::People::JointPose*>(jointPoses), reinterpret_cast<Windows::Perception::People::JointPose*>(jointPoses) + __jointPosesSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetRelativeJoint(Windows::Perception::People::HandJointKind joint, Windows::Perception::People::HandJointKind referenceJoint, struct struct_Windows_Perception_People_JointPose* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetRelativeJoint, WINRT_WRAP(Windows::Perception::People::JointPose), Windows::Perception::People::HandJointKind const&, Windows::Perception::People::HandJointKind const&);
            *result = detach_from<Windows::Perception::People::JointPose>(this->shim().GetRelativeJoint(*reinterpret_cast<Windows::Perception::People::HandJointKind const*>(&joint), *reinterpret_cast<Windows::Perception::People::HandJointKind const*>(&referenceJoint)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetRelativeJoints(uint32_t __jointsSize, Windows::Perception::People::HandJointKind* joints, uint32_t __referenceJointsSize, Windows::Perception::People::HandJointKind* referenceJoints, uint32_t __jointPosesSize, struct struct_Windows_Perception_People_JointPose* jointPoses) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetRelativeJoints, WINRT_WRAP(void), array_view<Windows::Perception::People::HandJointKind const>, array_view<Windows::Perception::People::HandJointKind const>, array_view<Windows::Perception::People::JointPose>);
            this->shim().GetRelativeJoints(array_view<Windows::Perception::People::HandJointKind const>(reinterpret_cast<Windows::Perception::People::HandJointKind const *>(joints), reinterpret_cast<Windows::Perception::People::HandJointKind const *>(joints) + __jointsSize), array_view<Windows::Perception::People::HandJointKind const>(reinterpret_cast<Windows::Perception::People::HandJointKind const *>(referenceJoints), reinterpret_cast<Windows::Perception::People::HandJointKind const *>(referenceJoints) + __referenceJointsSize), array_view<Windows::Perception::People::JointPose>(reinterpret_cast<Windows::Perception::People::JointPose*>(jointPoses), reinterpret_cast<Windows::Perception::People::JointPose*>(jointPoses) + __jointPosesSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Perception::People::IHeadPose> : produce_base<D, Windows::Perception::People::IHeadPose>
{
    int32_t WINRT_CALL get_Position(Windows::Foundation::Numerics::float3* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Position, WINRT_WRAP(Windows::Foundation::Numerics::float3));
            *value = detach_from<Windows::Foundation::Numerics::float3>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ForwardDirection(Windows::Foundation::Numerics::float3* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ForwardDirection, WINRT_WRAP(Windows::Foundation::Numerics::float3));
            *value = detach_from<Windows::Foundation::Numerics::float3>(this->shim().ForwardDirection());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UpDirection(Windows::Foundation::Numerics::float3* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpDirection, WINRT_WRAP(Windows::Foundation::Numerics::float3));
            *value = detach_from<Windows::Foundation::Numerics::float3>(this->shim().UpDirection());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Perception::People {

inline bool EyesPose::IsSupported()
{
    return impl::call_factory<EyesPose, Windows::Perception::People::IEyesPoseStatics>([&](auto&& f) { return f.IsSupported(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::UI::Input::GazeInputAccessStatus> EyesPose::RequestAccessAsync()
{
    return impl::call_factory<EyesPose, Windows::Perception::People::IEyesPoseStatics>([&](auto&& f) { return f.RequestAccessAsync(); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Perception::People::IEyesPose> : winrt::impl::hash_base<winrt::Windows::Perception::People::IEyesPose> {};
template<> struct hash<winrt::Windows::Perception::People::IEyesPoseStatics> : winrt::impl::hash_base<winrt::Windows::Perception::People::IEyesPoseStatics> {};
template<> struct hash<winrt::Windows::Perception::People::IHandMeshObserver> : winrt::impl::hash_base<winrt::Windows::Perception::People::IHandMeshObserver> {};
template<> struct hash<winrt::Windows::Perception::People::IHandMeshVertexState> : winrt::impl::hash_base<winrt::Windows::Perception::People::IHandMeshVertexState> {};
template<> struct hash<winrt::Windows::Perception::People::IHandPose> : winrt::impl::hash_base<winrt::Windows::Perception::People::IHandPose> {};
template<> struct hash<winrt::Windows::Perception::People::IHeadPose> : winrt::impl::hash_base<winrt::Windows::Perception::People::IHeadPose> {};
template<> struct hash<winrt::Windows::Perception::People::EyesPose> : winrt::impl::hash_base<winrt::Windows::Perception::People::EyesPose> {};
template<> struct hash<winrt::Windows::Perception::People::HandMeshObserver> : winrt::impl::hash_base<winrt::Windows::Perception::People::HandMeshObserver> {};
template<> struct hash<winrt::Windows::Perception::People::HandMeshVertexState> : winrt::impl::hash_base<winrt::Windows::Perception::People::HandMeshVertexState> {};
template<> struct hash<winrt::Windows::Perception::People::HandPose> : winrt::impl::hash_base<winrt::Windows::Perception::People::HandPose> {};
template<> struct hash<winrt::Windows::Perception::People::HeadPose> : winrt::impl::hash_base<winrt::Windows::Perception::People::HeadPose> {};

}
