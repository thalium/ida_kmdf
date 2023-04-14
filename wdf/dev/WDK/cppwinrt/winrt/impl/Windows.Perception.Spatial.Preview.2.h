// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Perception.Spatial.1.h"
#include "winrt/impl/Windows.Perception.Spatial.Preview.1.h"

WINRT_EXPORT namespace winrt::Windows::Perception::Spatial::Preview {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::Perception::Spatial::Preview {

struct WINRT_EBO SpatialGraphInteropFrameOfReferencePreview :
    Windows::Perception::Spatial::Preview::ISpatialGraphInteropFrameOfReferencePreview
{
    SpatialGraphInteropFrameOfReferencePreview(std::nullptr_t) noexcept {}
};

struct SpatialGraphInteropPreview
{
    SpatialGraphInteropPreview() = delete;
    static Windows::Perception::Spatial::SpatialCoordinateSystem CreateCoordinateSystemForNode(winrt::guid const& nodeId);
    static Windows::Perception::Spatial::SpatialCoordinateSystem CreateCoordinateSystemForNode(winrt::guid const& nodeId, Windows::Foundation::Numerics::float3 const& relativePosition);
    static Windows::Perception::Spatial::SpatialCoordinateSystem CreateCoordinateSystemForNode(winrt::guid const& nodeId, Windows::Foundation::Numerics::float3 const& relativePosition, Windows::Foundation::Numerics::quaternion const& relativeOrientation);
    static Windows::Perception::Spatial::SpatialLocator CreateLocatorForNode(winrt::guid const& nodeId);
    static Windows::Perception::Spatial::Preview::SpatialGraphInteropFrameOfReferencePreview TryCreateFrameOfReference(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem);
    static Windows::Perception::Spatial::Preview::SpatialGraphInteropFrameOfReferencePreview TryCreateFrameOfReference(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem, Windows::Foundation::Numerics::float3 const& relativePosition);
    static Windows::Perception::Spatial::Preview::SpatialGraphInteropFrameOfReferencePreview TryCreateFrameOfReference(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem, Windows::Foundation::Numerics::float3 const& relativePosition, Windows::Foundation::Numerics::quaternion const& relativeOrientation);
};

}
