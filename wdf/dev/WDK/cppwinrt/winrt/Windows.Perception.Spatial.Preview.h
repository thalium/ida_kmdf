// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Perception.Spatial.2.h"
#include "winrt/impl/Windows.Perception.Spatial.Preview.2.h"
#include "winrt/Windows.Perception.Spatial.h"

namespace winrt::impl {

template <typename D> Windows::Perception::Spatial::SpatialCoordinateSystem consume_Windows_Perception_Spatial_Preview_ISpatialGraphInteropFrameOfReferencePreview<D>::CoordinateSystem() const
{
    Windows::Perception::Spatial::SpatialCoordinateSystem value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::Preview::ISpatialGraphInteropFrameOfReferencePreview)->get_CoordinateSystem(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Perception_Spatial_Preview_ISpatialGraphInteropFrameOfReferencePreview<D>::NodeId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::Preview::ISpatialGraphInteropFrameOfReferencePreview)->get_NodeId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Numerics::float4x4 consume_Windows_Perception_Spatial_Preview_ISpatialGraphInteropFrameOfReferencePreview<D>::CoordinateSystemToNodeTransform() const
{
    Windows::Foundation::Numerics::float4x4 value{};
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::Preview::ISpatialGraphInteropFrameOfReferencePreview)->get_CoordinateSystemToNodeTransform(put_abi(value)));
    return value;
}

template <typename D> Windows::Perception::Spatial::SpatialCoordinateSystem consume_Windows_Perception_Spatial_Preview_ISpatialGraphInteropPreviewStatics<D>::CreateCoordinateSystemForNode(winrt::guid const& nodeId) const
{
    Windows::Perception::Spatial::SpatialCoordinateSystem result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::Preview::ISpatialGraphInteropPreviewStatics)->CreateCoordinateSystemForNode(get_abi(nodeId), put_abi(result)));
    return result;
}

template <typename D> Windows::Perception::Spatial::SpatialCoordinateSystem consume_Windows_Perception_Spatial_Preview_ISpatialGraphInteropPreviewStatics<D>::CreateCoordinateSystemForNode(winrt::guid const& nodeId, Windows::Foundation::Numerics::float3 const& relativePosition) const
{
    Windows::Perception::Spatial::SpatialCoordinateSystem result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::Preview::ISpatialGraphInteropPreviewStatics)->CreateCoordinateSystemForNodeWithPosition(get_abi(nodeId), get_abi(relativePosition), put_abi(result)));
    return result;
}

template <typename D> Windows::Perception::Spatial::SpatialCoordinateSystem consume_Windows_Perception_Spatial_Preview_ISpatialGraphInteropPreviewStatics<D>::CreateCoordinateSystemForNode(winrt::guid const& nodeId, Windows::Foundation::Numerics::float3 const& relativePosition, Windows::Foundation::Numerics::quaternion const& relativeOrientation) const
{
    Windows::Perception::Spatial::SpatialCoordinateSystem result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::Preview::ISpatialGraphInteropPreviewStatics)->CreateCoordinateSystemForNodeWithPositionAndOrientation(get_abi(nodeId), get_abi(relativePosition), get_abi(relativeOrientation), put_abi(result)));
    return result;
}

template <typename D> Windows::Perception::Spatial::SpatialLocator consume_Windows_Perception_Spatial_Preview_ISpatialGraphInteropPreviewStatics<D>::CreateLocatorForNode(winrt::guid const& nodeId) const
{
    Windows::Perception::Spatial::SpatialLocator result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::Preview::ISpatialGraphInteropPreviewStatics)->CreateLocatorForNode(get_abi(nodeId), put_abi(result)));
    return result;
}

template <typename D> Windows::Perception::Spatial::Preview::SpatialGraphInteropFrameOfReferencePreview consume_Windows_Perception_Spatial_Preview_ISpatialGraphInteropPreviewStatics2<D>::TryCreateFrameOfReference(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem) const
{
    Windows::Perception::Spatial::Preview::SpatialGraphInteropFrameOfReferencePreview result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::Preview::ISpatialGraphInteropPreviewStatics2)->TryCreateFrameOfReference(get_abi(coordinateSystem), put_abi(result)));
    return result;
}

template <typename D> Windows::Perception::Spatial::Preview::SpatialGraphInteropFrameOfReferencePreview consume_Windows_Perception_Spatial_Preview_ISpatialGraphInteropPreviewStatics2<D>::TryCreateFrameOfReference(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem, Windows::Foundation::Numerics::float3 const& relativePosition) const
{
    Windows::Perception::Spatial::Preview::SpatialGraphInteropFrameOfReferencePreview result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::Preview::ISpatialGraphInteropPreviewStatics2)->TryCreateFrameOfReferenceWithPosition(get_abi(coordinateSystem), get_abi(relativePosition), put_abi(result)));
    return result;
}

template <typename D> Windows::Perception::Spatial::Preview::SpatialGraphInteropFrameOfReferencePreview consume_Windows_Perception_Spatial_Preview_ISpatialGraphInteropPreviewStatics2<D>::TryCreateFrameOfReference(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem, Windows::Foundation::Numerics::float3 const& relativePosition, Windows::Foundation::Numerics::quaternion const& relativeOrientation) const
{
    Windows::Perception::Spatial::Preview::SpatialGraphInteropFrameOfReferencePreview result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::Preview::ISpatialGraphInteropPreviewStatics2)->TryCreateFrameOfReferenceWithPositionAndOrientation(get_abi(coordinateSystem), get_abi(relativePosition), get_abi(relativeOrientation), put_abi(result)));
    return result;
}

template <typename D>
struct produce<D, Windows::Perception::Spatial::Preview::ISpatialGraphInteropFrameOfReferencePreview> : produce_base<D, Windows::Perception::Spatial::Preview::ISpatialGraphInteropFrameOfReferencePreview>
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

    int32_t WINRT_CALL get_NodeId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NodeId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().NodeId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CoordinateSystemToNodeTransform(Windows::Foundation::Numerics::float4x4* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CoordinateSystemToNodeTransform, WINRT_WRAP(Windows::Foundation::Numerics::float4x4));
            *value = detach_from<Windows::Foundation::Numerics::float4x4>(this->shim().CoordinateSystemToNodeTransform());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Perception::Spatial::Preview::ISpatialGraphInteropPreviewStatics> : produce_base<D, Windows::Perception::Spatial::Preview::ISpatialGraphInteropPreviewStatics>
{
    int32_t WINRT_CALL CreateCoordinateSystemForNode(winrt::guid nodeId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateCoordinateSystemForNode, WINRT_WRAP(Windows::Perception::Spatial::SpatialCoordinateSystem), winrt::guid const&);
            *result = detach_from<Windows::Perception::Spatial::SpatialCoordinateSystem>(this->shim().CreateCoordinateSystemForNode(*reinterpret_cast<winrt::guid const*>(&nodeId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateCoordinateSystemForNodeWithPosition(winrt::guid nodeId, Windows::Foundation::Numerics::float3 relativePosition, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateCoordinateSystemForNode, WINRT_WRAP(Windows::Perception::Spatial::SpatialCoordinateSystem), winrt::guid const&, Windows::Foundation::Numerics::float3 const&);
            *result = detach_from<Windows::Perception::Spatial::SpatialCoordinateSystem>(this->shim().CreateCoordinateSystemForNode(*reinterpret_cast<winrt::guid const*>(&nodeId), *reinterpret_cast<Windows::Foundation::Numerics::float3 const*>(&relativePosition)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateCoordinateSystemForNodeWithPositionAndOrientation(winrt::guid nodeId, Windows::Foundation::Numerics::float3 relativePosition, Windows::Foundation::Numerics::quaternion relativeOrientation, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateCoordinateSystemForNode, WINRT_WRAP(Windows::Perception::Spatial::SpatialCoordinateSystem), winrt::guid const&, Windows::Foundation::Numerics::float3 const&, Windows::Foundation::Numerics::quaternion const&);
            *result = detach_from<Windows::Perception::Spatial::SpatialCoordinateSystem>(this->shim().CreateCoordinateSystemForNode(*reinterpret_cast<winrt::guid const*>(&nodeId), *reinterpret_cast<Windows::Foundation::Numerics::float3 const*>(&relativePosition), *reinterpret_cast<Windows::Foundation::Numerics::quaternion const*>(&relativeOrientation)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateLocatorForNode(winrt::guid nodeId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateLocatorForNode, WINRT_WRAP(Windows::Perception::Spatial::SpatialLocator), winrt::guid const&);
            *result = detach_from<Windows::Perception::Spatial::SpatialLocator>(this->shim().CreateLocatorForNode(*reinterpret_cast<winrt::guid const*>(&nodeId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Perception::Spatial::Preview::ISpatialGraphInteropPreviewStatics2> : produce_base<D, Windows::Perception::Spatial::Preview::ISpatialGraphInteropPreviewStatics2>
{
    int32_t WINRT_CALL TryCreateFrameOfReference(void* coordinateSystem, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryCreateFrameOfReference, WINRT_WRAP(Windows::Perception::Spatial::Preview::SpatialGraphInteropFrameOfReferencePreview), Windows::Perception::Spatial::SpatialCoordinateSystem const&);
            *result = detach_from<Windows::Perception::Spatial::Preview::SpatialGraphInteropFrameOfReferencePreview>(this->shim().TryCreateFrameOfReference(*reinterpret_cast<Windows::Perception::Spatial::SpatialCoordinateSystem const*>(&coordinateSystem)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryCreateFrameOfReferenceWithPosition(void* coordinateSystem, Windows::Foundation::Numerics::float3 relativePosition, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryCreateFrameOfReference, WINRT_WRAP(Windows::Perception::Spatial::Preview::SpatialGraphInteropFrameOfReferencePreview), Windows::Perception::Spatial::SpatialCoordinateSystem const&, Windows::Foundation::Numerics::float3 const&);
            *result = detach_from<Windows::Perception::Spatial::Preview::SpatialGraphInteropFrameOfReferencePreview>(this->shim().TryCreateFrameOfReference(*reinterpret_cast<Windows::Perception::Spatial::SpatialCoordinateSystem const*>(&coordinateSystem), *reinterpret_cast<Windows::Foundation::Numerics::float3 const*>(&relativePosition)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryCreateFrameOfReferenceWithPositionAndOrientation(void* coordinateSystem, Windows::Foundation::Numerics::float3 relativePosition, Windows::Foundation::Numerics::quaternion relativeOrientation, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryCreateFrameOfReference, WINRT_WRAP(Windows::Perception::Spatial::Preview::SpatialGraphInteropFrameOfReferencePreview), Windows::Perception::Spatial::SpatialCoordinateSystem const&, Windows::Foundation::Numerics::float3 const&, Windows::Foundation::Numerics::quaternion const&);
            *result = detach_from<Windows::Perception::Spatial::Preview::SpatialGraphInteropFrameOfReferencePreview>(this->shim().TryCreateFrameOfReference(*reinterpret_cast<Windows::Perception::Spatial::SpatialCoordinateSystem const*>(&coordinateSystem), *reinterpret_cast<Windows::Foundation::Numerics::float3 const*>(&relativePosition), *reinterpret_cast<Windows::Foundation::Numerics::quaternion const*>(&relativeOrientation)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Perception::Spatial::Preview {

inline Windows::Perception::Spatial::SpatialCoordinateSystem SpatialGraphInteropPreview::CreateCoordinateSystemForNode(winrt::guid const& nodeId)
{
    return impl::call_factory<SpatialGraphInteropPreview, Windows::Perception::Spatial::Preview::ISpatialGraphInteropPreviewStatics>([&](auto&& f) { return f.CreateCoordinateSystemForNode(nodeId); });
}

inline Windows::Perception::Spatial::SpatialCoordinateSystem SpatialGraphInteropPreview::CreateCoordinateSystemForNode(winrt::guid const& nodeId, Windows::Foundation::Numerics::float3 const& relativePosition)
{
    return impl::call_factory<SpatialGraphInteropPreview, Windows::Perception::Spatial::Preview::ISpatialGraphInteropPreviewStatics>([&](auto&& f) { return f.CreateCoordinateSystemForNode(nodeId, relativePosition); });
}

inline Windows::Perception::Spatial::SpatialCoordinateSystem SpatialGraphInteropPreview::CreateCoordinateSystemForNode(winrt::guid const& nodeId, Windows::Foundation::Numerics::float3 const& relativePosition, Windows::Foundation::Numerics::quaternion const& relativeOrientation)
{
    return impl::call_factory<SpatialGraphInteropPreview, Windows::Perception::Spatial::Preview::ISpatialGraphInteropPreviewStatics>([&](auto&& f) { return f.CreateCoordinateSystemForNode(nodeId, relativePosition, relativeOrientation); });
}

inline Windows::Perception::Spatial::SpatialLocator SpatialGraphInteropPreview::CreateLocatorForNode(winrt::guid const& nodeId)
{
    return impl::call_factory<SpatialGraphInteropPreview, Windows::Perception::Spatial::Preview::ISpatialGraphInteropPreviewStatics>([&](auto&& f) { return f.CreateLocatorForNode(nodeId); });
}

inline Windows::Perception::Spatial::Preview::SpatialGraphInteropFrameOfReferencePreview SpatialGraphInteropPreview::TryCreateFrameOfReference(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem)
{
    return impl::call_factory<SpatialGraphInteropPreview, Windows::Perception::Spatial::Preview::ISpatialGraphInteropPreviewStatics2>([&](auto&& f) { return f.TryCreateFrameOfReference(coordinateSystem); });
}

inline Windows::Perception::Spatial::Preview::SpatialGraphInteropFrameOfReferencePreview SpatialGraphInteropPreview::TryCreateFrameOfReference(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem, Windows::Foundation::Numerics::float3 const& relativePosition)
{
    return impl::call_factory<SpatialGraphInteropPreview, Windows::Perception::Spatial::Preview::ISpatialGraphInteropPreviewStatics2>([&](auto&& f) { return f.TryCreateFrameOfReference(coordinateSystem, relativePosition); });
}

inline Windows::Perception::Spatial::Preview::SpatialGraphInteropFrameOfReferencePreview SpatialGraphInteropPreview::TryCreateFrameOfReference(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem, Windows::Foundation::Numerics::float3 const& relativePosition, Windows::Foundation::Numerics::quaternion const& relativeOrientation)
{
    return impl::call_factory<SpatialGraphInteropPreview, Windows::Perception::Spatial::Preview::ISpatialGraphInteropPreviewStatics2>([&](auto&& f) { return f.TryCreateFrameOfReference(coordinateSystem, relativePosition, relativeOrientation); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Perception::Spatial::Preview::ISpatialGraphInteropFrameOfReferencePreview> : winrt::impl::hash_base<winrt::Windows::Perception::Spatial::Preview::ISpatialGraphInteropFrameOfReferencePreview> {};
template<> struct hash<winrt::Windows::Perception::Spatial::Preview::ISpatialGraphInteropPreviewStatics> : winrt::impl::hash_base<winrt::Windows::Perception::Spatial::Preview::ISpatialGraphInteropPreviewStatics> {};
template<> struct hash<winrt::Windows::Perception::Spatial::Preview::ISpatialGraphInteropPreviewStatics2> : winrt::impl::hash_base<winrt::Windows::Perception::Spatial::Preview::ISpatialGraphInteropPreviewStatics2> {};
template<> struct hash<winrt::Windows::Perception::Spatial::Preview::SpatialGraphInteropFrameOfReferencePreview> : winrt::impl::hash_base<winrt::Windows::Perception::Spatial::Preview::SpatialGraphInteropFrameOfReferencePreview> {};
template<> struct hash<winrt::Windows::Perception::Spatial::Preview::SpatialGraphInteropPreview> : winrt::impl::hash_base<winrt::Windows::Perception::Spatial::Preview::SpatialGraphInteropPreview> {};

}
