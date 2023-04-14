// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Foundation::Collections {

struct ValueSet;

}

WINRT_EXPORT namespace winrt::Windows::Perception {

struct PerceptionTimestamp;

}

WINRT_EXPORT namespace winrt::Windows::Storage::Streams {

struct IInputStream;
struct IOutputStream;

}

WINRT_EXPORT namespace winrt::Windows::System::RemoteSystems {

struct RemoteSystemSession;

}

WINRT_EXPORT namespace winrt::Windows::Perception::Spatial {

enum class SpatialAnchorExportPurpose : int32_t
{
    Relocalization = 0,
    Sharing = 1,
};

enum class SpatialEntityWatcherStatus : int32_t
{
    Created = 0,
    Started = 1,
    EnumerationCompleted = 2,
    Stopping = 3,
    Stopped = 4,
    Aborted = 5,
};

enum class SpatialLocatability : int32_t
{
    Unavailable = 0,
    OrientationOnly = 1,
    PositionalTrackingActivating = 2,
    PositionalTrackingActive = 3,
    PositionalTrackingInhibited = 4,
};

enum class SpatialLookDirectionRange : int32_t
{
    ForwardOnly = 0,
    Omnidirectional = 1,
};

enum class SpatialMovementRange : int32_t
{
    NoMovement = 0,
    Bounded = 1,
};

enum class SpatialPerceptionAccessStatus : int32_t
{
    Unspecified = 0,
    Allowed = 1,
    DeniedByUser = 2,
    DeniedBySystem = 3,
};

struct ISpatialAnchor;
struct ISpatialAnchor2;
struct ISpatialAnchorExportSufficiency;
struct ISpatialAnchorExporter;
struct ISpatialAnchorExporterStatics;
struct ISpatialAnchorManagerStatics;
struct ISpatialAnchorRawCoordinateSystemAdjustedEventArgs;
struct ISpatialAnchorStatics;
struct ISpatialAnchorStore;
struct ISpatialAnchorTransferManagerStatics;
struct ISpatialBoundingVolume;
struct ISpatialBoundingVolumeStatics;
struct ISpatialCoordinateSystem;
struct ISpatialEntity;
struct ISpatialEntityAddedEventArgs;
struct ISpatialEntityFactory;
struct ISpatialEntityRemovedEventArgs;
struct ISpatialEntityStore;
struct ISpatialEntityStoreStatics;
struct ISpatialEntityUpdatedEventArgs;
struct ISpatialEntityWatcher;
struct ISpatialLocation;
struct ISpatialLocation2;
struct ISpatialLocator;
struct ISpatialLocatorAttachedFrameOfReference;
struct ISpatialLocatorPositionalTrackingDeactivatingEventArgs;
struct ISpatialLocatorStatics;
struct ISpatialStageFrameOfReference;
struct ISpatialStageFrameOfReferenceStatics;
struct ISpatialStationaryFrameOfReference;
struct SpatialAnchor;
struct SpatialAnchorExportSufficiency;
struct SpatialAnchorExporter;
struct SpatialAnchorManager;
struct SpatialAnchorRawCoordinateSystemAdjustedEventArgs;
struct SpatialAnchorStore;
struct SpatialAnchorTransferManager;
struct SpatialBoundingVolume;
struct SpatialCoordinateSystem;
struct SpatialEntity;
struct SpatialEntityAddedEventArgs;
struct SpatialEntityRemovedEventArgs;
struct SpatialEntityStore;
struct SpatialEntityUpdatedEventArgs;
struct SpatialEntityWatcher;
struct SpatialLocation;
struct SpatialLocator;
struct SpatialLocatorAttachedFrameOfReference;
struct SpatialLocatorPositionalTrackingDeactivatingEventArgs;
struct SpatialStageFrameOfReference;
struct SpatialStationaryFrameOfReference;
struct SpatialBoundingBox;
struct SpatialBoundingFrustum;
struct SpatialBoundingOrientedBox;
struct SpatialBoundingSphere;
struct SpatialRay;

}

namespace winrt::impl {

template <> struct category<Windows::Perception::Spatial::ISpatialAnchor>{ using type = interface_category; };
template <> struct category<Windows::Perception::Spatial::ISpatialAnchor2>{ using type = interface_category; };
template <> struct category<Windows::Perception::Spatial::ISpatialAnchorExportSufficiency>{ using type = interface_category; };
template <> struct category<Windows::Perception::Spatial::ISpatialAnchorExporter>{ using type = interface_category; };
template <> struct category<Windows::Perception::Spatial::ISpatialAnchorExporterStatics>{ using type = interface_category; };
template <> struct category<Windows::Perception::Spatial::ISpatialAnchorManagerStatics>{ using type = interface_category; };
template <> struct category<Windows::Perception::Spatial::ISpatialAnchorRawCoordinateSystemAdjustedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Perception::Spatial::ISpatialAnchorStatics>{ using type = interface_category; };
template <> struct category<Windows::Perception::Spatial::ISpatialAnchorStore>{ using type = interface_category; };
template <> struct category<Windows::Perception::Spatial::ISpatialAnchorTransferManagerStatics>{ using type = interface_category; };
template <> struct category<Windows::Perception::Spatial::ISpatialBoundingVolume>{ using type = interface_category; };
template <> struct category<Windows::Perception::Spatial::ISpatialBoundingVolumeStatics>{ using type = interface_category; };
template <> struct category<Windows::Perception::Spatial::ISpatialCoordinateSystem>{ using type = interface_category; };
template <> struct category<Windows::Perception::Spatial::ISpatialEntity>{ using type = interface_category; };
template <> struct category<Windows::Perception::Spatial::ISpatialEntityAddedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Perception::Spatial::ISpatialEntityFactory>{ using type = interface_category; };
template <> struct category<Windows::Perception::Spatial::ISpatialEntityRemovedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Perception::Spatial::ISpatialEntityStore>{ using type = interface_category; };
template <> struct category<Windows::Perception::Spatial::ISpatialEntityStoreStatics>{ using type = interface_category; };
template <> struct category<Windows::Perception::Spatial::ISpatialEntityUpdatedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Perception::Spatial::ISpatialEntityWatcher>{ using type = interface_category; };
template <> struct category<Windows::Perception::Spatial::ISpatialLocation>{ using type = interface_category; };
template <> struct category<Windows::Perception::Spatial::ISpatialLocation2>{ using type = interface_category; };
template <> struct category<Windows::Perception::Spatial::ISpatialLocator>{ using type = interface_category; };
template <> struct category<Windows::Perception::Spatial::ISpatialLocatorAttachedFrameOfReference>{ using type = interface_category; };
template <> struct category<Windows::Perception::Spatial::ISpatialLocatorPositionalTrackingDeactivatingEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Perception::Spatial::ISpatialLocatorStatics>{ using type = interface_category; };
template <> struct category<Windows::Perception::Spatial::ISpatialStageFrameOfReference>{ using type = interface_category; };
template <> struct category<Windows::Perception::Spatial::ISpatialStageFrameOfReferenceStatics>{ using type = interface_category; };
template <> struct category<Windows::Perception::Spatial::ISpatialStationaryFrameOfReference>{ using type = interface_category; };
template <> struct category<Windows::Perception::Spatial::SpatialAnchor>{ using type = class_category; };
template <> struct category<Windows::Perception::Spatial::SpatialAnchorExportSufficiency>{ using type = class_category; };
template <> struct category<Windows::Perception::Spatial::SpatialAnchorExporter>{ using type = class_category; };
template <> struct category<Windows::Perception::Spatial::SpatialAnchorManager>{ using type = class_category; };
template <> struct category<Windows::Perception::Spatial::SpatialAnchorRawCoordinateSystemAdjustedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Perception::Spatial::SpatialAnchorStore>{ using type = class_category; };
template <> struct category<Windows::Perception::Spatial::SpatialAnchorTransferManager>{ using type = class_category; };
template <> struct category<Windows::Perception::Spatial::SpatialBoundingVolume>{ using type = class_category; };
template <> struct category<Windows::Perception::Spatial::SpatialCoordinateSystem>{ using type = class_category; };
template <> struct category<Windows::Perception::Spatial::SpatialEntity>{ using type = class_category; };
template <> struct category<Windows::Perception::Spatial::SpatialEntityAddedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Perception::Spatial::SpatialEntityRemovedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Perception::Spatial::SpatialEntityStore>{ using type = class_category; };
template <> struct category<Windows::Perception::Spatial::SpatialEntityUpdatedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Perception::Spatial::SpatialEntityWatcher>{ using type = class_category; };
template <> struct category<Windows::Perception::Spatial::SpatialLocation>{ using type = class_category; };
template <> struct category<Windows::Perception::Spatial::SpatialLocator>{ using type = class_category; };
template <> struct category<Windows::Perception::Spatial::SpatialLocatorAttachedFrameOfReference>{ using type = class_category; };
template <> struct category<Windows::Perception::Spatial::SpatialLocatorPositionalTrackingDeactivatingEventArgs>{ using type = class_category; };
template <> struct category<Windows::Perception::Spatial::SpatialStageFrameOfReference>{ using type = class_category; };
template <> struct category<Windows::Perception::Spatial::SpatialStationaryFrameOfReference>{ using type = class_category; };
template <> struct category<Windows::Perception::Spatial::SpatialAnchorExportPurpose>{ using type = enum_category; };
template <> struct category<Windows::Perception::Spatial::SpatialEntityWatcherStatus>{ using type = enum_category; };
template <> struct category<Windows::Perception::Spatial::SpatialLocatability>{ using type = enum_category; };
template <> struct category<Windows::Perception::Spatial::SpatialLookDirectionRange>{ using type = enum_category; };
template <> struct category<Windows::Perception::Spatial::SpatialMovementRange>{ using type = enum_category; };
template <> struct category<Windows::Perception::Spatial::SpatialPerceptionAccessStatus>{ using type = enum_category; };
template <> struct category<Windows::Perception::Spatial::SpatialBoundingBox>{ using type = struct_category<Windows::Foundation::Numerics::float3,Windows::Foundation::Numerics::float3>; };
template <> struct category<Windows::Perception::Spatial::SpatialBoundingFrustum>{ using type = struct_category<Windows::Foundation::Numerics::plane,Windows::Foundation::Numerics::plane,Windows::Foundation::Numerics::plane,Windows::Foundation::Numerics::plane,Windows::Foundation::Numerics::plane,Windows::Foundation::Numerics::plane>; };
template <> struct category<Windows::Perception::Spatial::SpatialBoundingOrientedBox>{ using type = struct_category<Windows::Foundation::Numerics::float3,Windows::Foundation::Numerics::float3,Windows::Foundation::Numerics::quaternion>; };
template <> struct category<Windows::Perception::Spatial::SpatialBoundingSphere>{ using type = struct_category<Windows::Foundation::Numerics::float3,float>; };
template <> struct category<Windows::Perception::Spatial::SpatialRay>{ using type = struct_category<Windows::Foundation::Numerics::float3,Windows::Foundation::Numerics::float3>; };
template <> struct name<Windows::Perception::Spatial::ISpatialAnchor>{ static constexpr auto & value{ L"Windows.Perception.Spatial.ISpatialAnchor" }; };
template <> struct name<Windows::Perception::Spatial::ISpatialAnchor2>{ static constexpr auto & value{ L"Windows.Perception.Spatial.ISpatialAnchor2" }; };
template <> struct name<Windows::Perception::Spatial::ISpatialAnchorExportSufficiency>{ static constexpr auto & value{ L"Windows.Perception.Spatial.ISpatialAnchorExportSufficiency" }; };
template <> struct name<Windows::Perception::Spatial::ISpatialAnchorExporter>{ static constexpr auto & value{ L"Windows.Perception.Spatial.ISpatialAnchorExporter" }; };
template <> struct name<Windows::Perception::Spatial::ISpatialAnchorExporterStatics>{ static constexpr auto & value{ L"Windows.Perception.Spatial.ISpatialAnchorExporterStatics" }; };
template <> struct name<Windows::Perception::Spatial::ISpatialAnchorManagerStatics>{ static constexpr auto & value{ L"Windows.Perception.Spatial.ISpatialAnchorManagerStatics" }; };
template <> struct name<Windows::Perception::Spatial::ISpatialAnchorRawCoordinateSystemAdjustedEventArgs>{ static constexpr auto & value{ L"Windows.Perception.Spatial.ISpatialAnchorRawCoordinateSystemAdjustedEventArgs" }; };
template <> struct name<Windows::Perception::Spatial::ISpatialAnchorStatics>{ static constexpr auto & value{ L"Windows.Perception.Spatial.ISpatialAnchorStatics" }; };
template <> struct name<Windows::Perception::Spatial::ISpatialAnchorStore>{ static constexpr auto & value{ L"Windows.Perception.Spatial.ISpatialAnchorStore" }; };
template <> struct name<Windows::Perception::Spatial::ISpatialAnchorTransferManagerStatics>{ static constexpr auto & value{ L"Windows.Perception.Spatial.ISpatialAnchorTransferManagerStatics" }; };
template <> struct name<Windows::Perception::Spatial::ISpatialBoundingVolume>{ static constexpr auto & value{ L"Windows.Perception.Spatial.ISpatialBoundingVolume" }; };
template <> struct name<Windows::Perception::Spatial::ISpatialBoundingVolumeStatics>{ static constexpr auto & value{ L"Windows.Perception.Spatial.ISpatialBoundingVolumeStatics" }; };
template <> struct name<Windows::Perception::Spatial::ISpatialCoordinateSystem>{ static constexpr auto & value{ L"Windows.Perception.Spatial.ISpatialCoordinateSystem" }; };
template <> struct name<Windows::Perception::Spatial::ISpatialEntity>{ static constexpr auto & value{ L"Windows.Perception.Spatial.ISpatialEntity" }; };
template <> struct name<Windows::Perception::Spatial::ISpatialEntityAddedEventArgs>{ static constexpr auto & value{ L"Windows.Perception.Spatial.ISpatialEntityAddedEventArgs" }; };
template <> struct name<Windows::Perception::Spatial::ISpatialEntityFactory>{ static constexpr auto & value{ L"Windows.Perception.Spatial.ISpatialEntityFactory" }; };
template <> struct name<Windows::Perception::Spatial::ISpatialEntityRemovedEventArgs>{ static constexpr auto & value{ L"Windows.Perception.Spatial.ISpatialEntityRemovedEventArgs" }; };
template <> struct name<Windows::Perception::Spatial::ISpatialEntityStore>{ static constexpr auto & value{ L"Windows.Perception.Spatial.ISpatialEntityStore" }; };
template <> struct name<Windows::Perception::Spatial::ISpatialEntityStoreStatics>{ static constexpr auto & value{ L"Windows.Perception.Spatial.ISpatialEntityStoreStatics" }; };
template <> struct name<Windows::Perception::Spatial::ISpatialEntityUpdatedEventArgs>{ static constexpr auto & value{ L"Windows.Perception.Spatial.ISpatialEntityUpdatedEventArgs" }; };
template <> struct name<Windows::Perception::Spatial::ISpatialEntityWatcher>{ static constexpr auto & value{ L"Windows.Perception.Spatial.ISpatialEntityWatcher" }; };
template <> struct name<Windows::Perception::Spatial::ISpatialLocation>{ static constexpr auto & value{ L"Windows.Perception.Spatial.ISpatialLocation" }; };
template <> struct name<Windows::Perception::Spatial::ISpatialLocation2>{ static constexpr auto & value{ L"Windows.Perception.Spatial.ISpatialLocation2" }; };
template <> struct name<Windows::Perception::Spatial::ISpatialLocator>{ static constexpr auto & value{ L"Windows.Perception.Spatial.ISpatialLocator" }; };
template <> struct name<Windows::Perception::Spatial::ISpatialLocatorAttachedFrameOfReference>{ static constexpr auto & value{ L"Windows.Perception.Spatial.ISpatialLocatorAttachedFrameOfReference" }; };
template <> struct name<Windows::Perception::Spatial::ISpatialLocatorPositionalTrackingDeactivatingEventArgs>{ static constexpr auto & value{ L"Windows.Perception.Spatial.ISpatialLocatorPositionalTrackingDeactivatingEventArgs" }; };
template <> struct name<Windows::Perception::Spatial::ISpatialLocatorStatics>{ static constexpr auto & value{ L"Windows.Perception.Spatial.ISpatialLocatorStatics" }; };
template <> struct name<Windows::Perception::Spatial::ISpatialStageFrameOfReference>{ static constexpr auto & value{ L"Windows.Perception.Spatial.ISpatialStageFrameOfReference" }; };
template <> struct name<Windows::Perception::Spatial::ISpatialStageFrameOfReferenceStatics>{ static constexpr auto & value{ L"Windows.Perception.Spatial.ISpatialStageFrameOfReferenceStatics" }; };
template <> struct name<Windows::Perception::Spatial::ISpatialStationaryFrameOfReference>{ static constexpr auto & value{ L"Windows.Perception.Spatial.ISpatialStationaryFrameOfReference" }; };
template <> struct name<Windows::Perception::Spatial::SpatialAnchor>{ static constexpr auto & value{ L"Windows.Perception.Spatial.SpatialAnchor" }; };
template <> struct name<Windows::Perception::Spatial::SpatialAnchorExportSufficiency>{ static constexpr auto & value{ L"Windows.Perception.Spatial.SpatialAnchorExportSufficiency" }; };
template <> struct name<Windows::Perception::Spatial::SpatialAnchorExporter>{ static constexpr auto & value{ L"Windows.Perception.Spatial.SpatialAnchorExporter" }; };
template <> struct name<Windows::Perception::Spatial::SpatialAnchorManager>{ static constexpr auto & value{ L"Windows.Perception.Spatial.SpatialAnchorManager" }; };
template <> struct name<Windows::Perception::Spatial::SpatialAnchorRawCoordinateSystemAdjustedEventArgs>{ static constexpr auto & value{ L"Windows.Perception.Spatial.SpatialAnchorRawCoordinateSystemAdjustedEventArgs" }; };
template <> struct name<Windows::Perception::Spatial::SpatialAnchorStore>{ static constexpr auto & value{ L"Windows.Perception.Spatial.SpatialAnchorStore" }; };
template <> struct name<Windows::Perception::Spatial::SpatialAnchorTransferManager>{ static constexpr auto & value{ L"Windows.Perception.Spatial.SpatialAnchorTransferManager" }; };
template <> struct name<Windows::Perception::Spatial::SpatialBoundingVolume>{ static constexpr auto & value{ L"Windows.Perception.Spatial.SpatialBoundingVolume" }; };
template <> struct name<Windows::Perception::Spatial::SpatialCoordinateSystem>{ static constexpr auto & value{ L"Windows.Perception.Spatial.SpatialCoordinateSystem" }; };
template <> struct name<Windows::Perception::Spatial::SpatialEntity>{ static constexpr auto & value{ L"Windows.Perception.Spatial.SpatialEntity" }; };
template <> struct name<Windows::Perception::Spatial::SpatialEntityAddedEventArgs>{ static constexpr auto & value{ L"Windows.Perception.Spatial.SpatialEntityAddedEventArgs" }; };
template <> struct name<Windows::Perception::Spatial::SpatialEntityRemovedEventArgs>{ static constexpr auto & value{ L"Windows.Perception.Spatial.SpatialEntityRemovedEventArgs" }; };
template <> struct name<Windows::Perception::Spatial::SpatialEntityStore>{ static constexpr auto & value{ L"Windows.Perception.Spatial.SpatialEntityStore" }; };
template <> struct name<Windows::Perception::Spatial::SpatialEntityUpdatedEventArgs>{ static constexpr auto & value{ L"Windows.Perception.Spatial.SpatialEntityUpdatedEventArgs" }; };
template <> struct name<Windows::Perception::Spatial::SpatialEntityWatcher>{ static constexpr auto & value{ L"Windows.Perception.Spatial.SpatialEntityWatcher" }; };
template <> struct name<Windows::Perception::Spatial::SpatialLocation>{ static constexpr auto & value{ L"Windows.Perception.Spatial.SpatialLocation" }; };
template <> struct name<Windows::Perception::Spatial::SpatialLocator>{ static constexpr auto & value{ L"Windows.Perception.Spatial.SpatialLocator" }; };
template <> struct name<Windows::Perception::Spatial::SpatialLocatorAttachedFrameOfReference>{ static constexpr auto & value{ L"Windows.Perception.Spatial.SpatialLocatorAttachedFrameOfReference" }; };
template <> struct name<Windows::Perception::Spatial::SpatialLocatorPositionalTrackingDeactivatingEventArgs>{ static constexpr auto & value{ L"Windows.Perception.Spatial.SpatialLocatorPositionalTrackingDeactivatingEventArgs" }; };
template <> struct name<Windows::Perception::Spatial::SpatialStageFrameOfReference>{ static constexpr auto & value{ L"Windows.Perception.Spatial.SpatialStageFrameOfReference" }; };
template <> struct name<Windows::Perception::Spatial::SpatialStationaryFrameOfReference>{ static constexpr auto & value{ L"Windows.Perception.Spatial.SpatialStationaryFrameOfReference" }; };
template <> struct name<Windows::Perception::Spatial::SpatialAnchorExportPurpose>{ static constexpr auto & value{ L"Windows.Perception.Spatial.SpatialAnchorExportPurpose" }; };
template <> struct name<Windows::Perception::Spatial::SpatialEntityWatcherStatus>{ static constexpr auto & value{ L"Windows.Perception.Spatial.SpatialEntityWatcherStatus" }; };
template <> struct name<Windows::Perception::Spatial::SpatialLocatability>{ static constexpr auto & value{ L"Windows.Perception.Spatial.SpatialLocatability" }; };
template <> struct name<Windows::Perception::Spatial::SpatialLookDirectionRange>{ static constexpr auto & value{ L"Windows.Perception.Spatial.SpatialLookDirectionRange" }; };
template <> struct name<Windows::Perception::Spatial::SpatialMovementRange>{ static constexpr auto & value{ L"Windows.Perception.Spatial.SpatialMovementRange" }; };
template <> struct name<Windows::Perception::Spatial::SpatialPerceptionAccessStatus>{ static constexpr auto & value{ L"Windows.Perception.Spatial.SpatialPerceptionAccessStatus" }; };
template <> struct name<Windows::Perception::Spatial::SpatialBoundingBox>{ static constexpr auto & value{ L"Windows.Perception.Spatial.SpatialBoundingBox" }; };
template <> struct name<Windows::Perception::Spatial::SpatialBoundingFrustum>{ static constexpr auto & value{ L"Windows.Perception.Spatial.SpatialBoundingFrustum" }; };
template <> struct name<Windows::Perception::Spatial::SpatialBoundingOrientedBox>{ static constexpr auto & value{ L"Windows.Perception.Spatial.SpatialBoundingOrientedBox" }; };
template <> struct name<Windows::Perception::Spatial::SpatialBoundingSphere>{ static constexpr auto & value{ L"Windows.Perception.Spatial.SpatialBoundingSphere" }; };
template <> struct name<Windows::Perception::Spatial::SpatialRay>{ static constexpr auto & value{ L"Windows.Perception.Spatial.SpatialRay" }; };
template <> struct guid_storage<Windows::Perception::Spatial::ISpatialAnchor>{ static constexpr guid value{ 0x0529E5CE,0x1D34,0x3702,{ 0xBC,0xEC,0xEA,0xBF,0xF5,0x78,0xA8,0x69 } }; };
template <> struct guid_storage<Windows::Perception::Spatial::ISpatialAnchor2>{ static constexpr guid value{ 0xED17C908,0xA695,0x4CF6,{ 0x92,0xFD,0x97,0x26,0x3B,0xA7,0x10,0x47 } }; };
template <> struct guid_storage<Windows::Perception::Spatial::ISpatialAnchorExportSufficiency>{ static constexpr guid value{ 0x77C25B2B,0x3409,0x4088,{ 0xB9,0x1B,0xFD,0xFD,0x05,0xD1,0x64,0x8F } }; };
template <> struct guid_storage<Windows::Perception::Spatial::ISpatialAnchorExporter>{ static constexpr guid value{ 0x9A2A4338,0x24FB,0x4269,{ 0x89,0xC5,0x88,0x30,0x4A,0xEE,0xF2,0x0F } }; };
template <> struct guid_storage<Windows::Perception::Spatial::ISpatialAnchorExporterStatics>{ static constexpr guid value{ 0xED2507B8,0x2475,0x439C,{ 0x85,0xFF,0x7F,0xED,0x34,0x1F,0xDC,0x88 } }; };
template <> struct guid_storage<Windows::Perception::Spatial::ISpatialAnchorManagerStatics>{ static constexpr guid value{ 0x88E30EAB,0xF3B7,0x420B,{ 0xB0,0x86,0x8A,0x80,0xC0,0x7D,0x91,0x0D } }; };
template <> struct guid_storage<Windows::Perception::Spatial::ISpatialAnchorRawCoordinateSystemAdjustedEventArgs>{ static constexpr guid value{ 0xA1E81EB8,0x56C7,0x3117,{ 0xA2,0xE4,0x81,0xE0,0xFC,0xF2,0x8E,0x00 } }; };
template <> struct guid_storage<Windows::Perception::Spatial::ISpatialAnchorStatics>{ static constexpr guid value{ 0xA9928642,0x0174,0x311C,{ 0xAE,0x79,0x0E,0x51,0x07,0x66,0x9F,0x16 } }; };
template <> struct guid_storage<Windows::Perception::Spatial::ISpatialAnchorStore>{ static constexpr guid value{ 0xB0BC3636,0x486A,0x3CB0,{ 0x9E,0x6F,0x12,0x45,0x16,0x5C,0x4D,0xB6 } }; };
template <> struct guid_storage<Windows::Perception::Spatial::ISpatialAnchorTransferManagerStatics>{ static constexpr guid value{ 0x03BBF9B9,0x12D8,0x4BCE,{ 0x88,0x35,0xC5,0xDF,0x3A,0xC0,0xAD,0xAB } }; };
template <> struct guid_storage<Windows::Perception::Spatial::ISpatialBoundingVolume>{ static constexpr guid value{ 0xFB2065DA,0x68C3,0x33DF,{ 0xB7,0xAF,0x4C,0x78,0x72,0x07,0x99,0x9C } }; };
template <> struct guid_storage<Windows::Perception::Spatial::ISpatialBoundingVolumeStatics>{ static constexpr guid value{ 0x05889117,0xB3E1,0x36D8,{ 0xB0,0x17,0x56,0x61,0x81,0xA5,0xB1,0x96 } }; };
template <> struct guid_storage<Windows::Perception::Spatial::ISpatialCoordinateSystem>{ static constexpr guid value{ 0x69EBCA4B,0x60A3,0x3586,{ 0xA6,0x53,0x59,0xA7,0xBD,0x67,0x6D,0x07 } }; };
template <> struct guid_storage<Windows::Perception::Spatial::ISpatialEntity>{ static constexpr guid value{ 0x166DE955,0xE1EB,0x454C,{ 0xBA,0x08,0xE6,0xC0,0x66,0x8D,0xDC,0x65 } }; };
template <> struct guid_storage<Windows::Perception::Spatial::ISpatialEntityAddedEventArgs>{ static constexpr guid value{ 0xA397F49B,0x156A,0x4707,{ 0xAC,0x2C,0xD3,0x1D,0x57,0x0E,0xD3,0x99 } }; };
template <> struct guid_storage<Windows::Perception::Spatial::ISpatialEntityFactory>{ static constexpr guid value{ 0xE1F1E325,0x349F,0x4225,{ 0xA2,0xF3,0x4B,0x01,0xC1,0x5F,0xE0,0x56 } }; };
template <> struct guid_storage<Windows::Perception::Spatial::ISpatialEntityRemovedEventArgs>{ static constexpr guid value{ 0x91741800,0x536D,0x4E9F,{ 0xAB,0xF6,0x41,0x5B,0x54,0x44,0xD6,0x51 } }; };
template <> struct guid_storage<Windows::Perception::Spatial::ISpatialEntityStore>{ static constexpr guid value{ 0x329788BA,0xE513,0x4F06,{ 0x88,0x9D,0x1B,0xE3,0x0E,0xCF,0x43,0xE6 } }; };
template <> struct guid_storage<Windows::Perception::Spatial::ISpatialEntityStoreStatics>{ static constexpr guid value{ 0x6B4B389E,0x7C50,0x4E92,{ 0x8A,0x62,0x4D,0x1D,0x4B,0x7C,0xCD,0x3E } }; };
template <> struct guid_storage<Windows::Perception::Spatial::ISpatialEntityUpdatedEventArgs>{ static constexpr guid value{ 0xE5671766,0x627B,0x43CB,{ 0xA4,0x9F,0xB3,0xBE,0x6D,0x47,0xDE,0xED } }; };
template <> struct guid_storage<Windows::Perception::Spatial::ISpatialEntityWatcher>{ static constexpr guid value{ 0xB3B85FA0,0x6D5E,0x4BBC,{ 0x80,0x5D,0x5F,0xE5,0xB9,0xBA,0x19,0x59 } }; };
template <> struct guid_storage<Windows::Perception::Spatial::ISpatialLocation>{ static constexpr guid value{ 0x1D81D29D,0x24A1,0x37D5,{ 0x8F,0xA1,0x39,0xB4,0xF9,0xAD,0x67,0xE2 } }; };
template <> struct guid_storage<Windows::Perception::Spatial::ISpatialLocation2>{ static constexpr guid value{ 0x117F2416,0x38A7,0x4A18,{ 0xB4,0x04,0xAB,0x8F,0xAB,0xE1,0xD7,0x8B } }; };
template <> struct guid_storage<Windows::Perception::Spatial::ISpatialLocator>{ static constexpr guid value{ 0xF6478925,0x9E0C,0x3BB6,{ 0x99,0x7E,0xB6,0x4E,0xCC,0xA2,0x4C,0xF4 } }; };
template <> struct guid_storage<Windows::Perception::Spatial::ISpatialLocatorAttachedFrameOfReference>{ static constexpr guid value{ 0xE1774EF6,0x1F4F,0x499C,{ 0x96,0x25,0xEF,0x5E,0x6E,0xD7,0xA0,0x48 } }; };
template <> struct guid_storage<Windows::Perception::Spatial::ISpatialLocatorPositionalTrackingDeactivatingEventArgs>{ static constexpr guid value{ 0xB8A84063,0xE3F4,0x368B,{ 0x90,0x61,0x9E,0xA9,0xD1,0xD6,0xCC,0x16 } }; };
template <> struct guid_storage<Windows::Perception::Spatial::ISpatialLocatorStatics>{ static constexpr guid value{ 0xB76E3340,0xA7C2,0x361B,{ 0xBB,0x82,0x56,0xE9,0x3B,0x89,0xB1,0xBB } }; };
template <> struct guid_storage<Windows::Perception::Spatial::ISpatialStageFrameOfReference>{ static constexpr guid value{ 0x7A8A3464,0xAD0D,0x4590,{ 0xAB,0x86,0x33,0x06,0x2B,0x67,0x49,0x26 } }; };
template <> struct guid_storage<Windows::Perception::Spatial::ISpatialStageFrameOfReferenceStatics>{ static constexpr guid value{ 0xF78D5C4D,0xA0A4,0x499C,{ 0x8D,0x91,0xA8,0xC9,0x65,0xD4,0x06,0x54 } }; };
template <> struct guid_storage<Windows::Perception::Spatial::ISpatialStationaryFrameOfReference>{ static constexpr guid value{ 0x09DBCCB9,0xBCF8,0x3E7F,{ 0xBE,0x7E,0x7E,0xDC,0xCB,0xB1,0x78,0xA8 } }; };
template <> struct default_interface<Windows::Perception::Spatial::SpatialAnchor>{ using type = Windows::Perception::Spatial::ISpatialAnchor; };
template <> struct default_interface<Windows::Perception::Spatial::SpatialAnchorExportSufficiency>{ using type = Windows::Perception::Spatial::ISpatialAnchorExportSufficiency; };
template <> struct default_interface<Windows::Perception::Spatial::SpatialAnchorExporter>{ using type = Windows::Perception::Spatial::ISpatialAnchorExporter; };
template <> struct default_interface<Windows::Perception::Spatial::SpatialAnchorRawCoordinateSystemAdjustedEventArgs>{ using type = Windows::Perception::Spatial::ISpatialAnchorRawCoordinateSystemAdjustedEventArgs; };
template <> struct default_interface<Windows::Perception::Spatial::SpatialAnchorStore>{ using type = Windows::Perception::Spatial::ISpatialAnchorStore; };
template <> struct default_interface<Windows::Perception::Spatial::SpatialBoundingVolume>{ using type = Windows::Perception::Spatial::ISpatialBoundingVolume; };
template <> struct default_interface<Windows::Perception::Spatial::SpatialCoordinateSystem>{ using type = Windows::Perception::Spatial::ISpatialCoordinateSystem; };
template <> struct default_interface<Windows::Perception::Spatial::SpatialEntity>{ using type = Windows::Perception::Spatial::ISpatialEntity; };
template <> struct default_interface<Windows::Perception::Spatial::SpatialEntityAddedEventArgs>{ using type = Windows::Perception::Spatial::ISpatialEntityAddedEventArgs; };
template <> struct default_interface<Windows::Perception::Spatial::SpatialEntityRemovedEventArgs>{ using type = Windows::Perception::Spatial::ISpatialEntityRemovedEventArgs; };
template <> struct default_interface<Windows::Perception::Spatial::SpatialEntityStore>{ using type = Windows::Perception::Spatial::ISpatialEntityStore; };
template <> struct default_interface<Windows::Perception::Spatial::SpatialEntityUpdatedEventArgs>{ using type = Windows::Perception::Spatial::ISpatialEntityUpdatedEventArgs; };
template <> struct default_interface<Windows::Perception::Spatial::SpatialEntityWatcher>{ using type = Windows::Perception::Spatial::ISpatialEntityWatcher; };
template <> struct default_interface<Windows::Perception::Spatial::SpatialLocation>{ using type = Windows::Perception::Spatial::ISpatialLocation; };
template <> struct default_interface<Windows::Perception::Spatial::SpatialLocator>{ using type = Windows::Perception::Spatial::ISpatialLocator; };
template <> struct default_interface<Windows::Perception::Spatial::SpatialLocatorAttachedFrameOfReference>{ using type = Windows::Perception::Spatial::ISpatialLocatorAttachedFrameOfReference; };
template <> struct default_interface<Windows::Perception::Spatial::SpatialLocatorPositionalTrackingDeactivatingEventArgs>{ using type = Windows::Perception::Spatial::ISpatialLocatorPositionalTrackingDeactivatingEventArgs; };
template <> struct default_interface<Windows::Perception::Spatial::SpatialStageFrameOfReference>{ using type = Windows::Perception::Spatial::ISpatialStageFrameOfReference; };
template <> struct default_interface<Windows::Perception::Spatial::SpatialStationaryFrameOfReference>{ using type = Windows::Perception::Spatial::ISpatialStationaryFrameOfReference; };

template <> struct abi<Windows::Perception::Spatial::ISpatialAnchor>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_CoordinateSystem(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RawCoordinateSystem(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL add_RawCoordinateSystemAdjusted(void* handler, winrt::event_token* cookie) noexcept = 0;
    virtual int32_t WINRT_CALL remove_RawCoordinateSystemAdjusted(winrt::event_token cookie) noexcept = 0;
};};

template <> struct abi<Windows::Perception::Spatial::ISpatialAnchor2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_RemovedByUser(bool* value) noexcept = 0;
};};

template <> struct abi<Windows::Perception::Spatial::ISpatialAnchorExportSufficiency>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsMinimallySufficient(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SufficiencyLevel(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RecommendedSufficiencyLevel(double* value) noexcept = 0;
};};

template <> struct abi<Windows::Perception::Spatial::ISpatialAnchorExporter>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetAnchorExportSufficiencyAsync(void* anchor, Windows::Perception::Spatial::SpatialAnchorExportPurpose purpose, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL TryExportAnchorAsync(void* anchor, Windows::Perception::Spatial::SpatialAnchorExportPurpose purpose, void* stream, void** operation) noexcept = 0;
};};

template <> struct abi<Windows::Perception::Spatial::ISpatialAnchorExporterStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetDefault(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL RequestAccessAsync(void** result) noexcept = 0;
};};

template <> struct abi<Windows::Perception::Spatial::ISpatialAnchorManagerStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL RequestStoreAsync(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Perception::Spatial::ISpatialAnchorRawCoordinateSystemAdjustedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_OldRawCoordinateSystemToNewRawCoordinateSystemTransform(Windows::Foundation::Numerics::float4x4* value) noexcept = 0;
};};

template <> struct abi<Windows::Perception::Spatial::ISpatialAnchorStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL TryCreateRelativeTo(void* coordinateSystem, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL TryCreateWithPositionRelativeTo(void* coordinateSystem, Windows::Foundation::Numerics::float3 position, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL TryCreateWithPositionAndOrientationRelativeTo(void* coordinateSystem, Windows::Foundation::Numerics::float3 position, Windows::Foundation::Numerics::quaternion orientation, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Perception::Spatial::ISpatialAnchorStore>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetAllSavedAnchors(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL TrySave(void* id, void* anchor, bool* succeeded) noexcept = 0;
    virtual int32_t WINRT_CALL Remove(void* id) noexcept = 0;
    virtual int32_t WINRT_CALL Clear() noexcept = 0;
};};

template <> struct abi<Windows::Perception::Spatial::ISpatialAnchorTransferManagerStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL TryImportAnchorsAsync(void* stream, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL TryExportAnchorsAsync(void* anchors, void* stream, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL RequestAccessAsync(void** result) noexcept = 0;
};};

template <> struct abi<Windows::Perception::Spatial::ISpatialBoundingVolume>{ struct type : IInspectable
{
};};

template <> struct abi<Windows::Perception::Spatial::ISpatialBoundingVolumeStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL FromBox(void* coordinateSystem, struct struct_Windows_Perception_Spatial_SpatialBoundingBox box, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL FromOrientedBox(void* coordinateSystem, struct struct_Windows_Perception_Spatial_SpatialBoundingOrientedBox box, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL FromSphere(void* coordinateSystem, struct struct_Windows_Perception_Spatial_SpatialBoundingSphere sphere, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL FromFrustum(void* coordinateSystem, struct struct_Windows_Perception_Spatial_SpatialBoundingFrustum frustum, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Perception::Spatial::ISpatialCoordinateSystem>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL TryGetTransformTo(void* target, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Perception::Spatial::ISpatialEntity>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Id(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Anchor(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Properties(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Perception::Spatial::ISpatialEntityAddedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Entity(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Perception::Spatial::ISpatialEntityFactory>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL CreateWithSpatialAnchor(void* spatialAnchor, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateWithSpatialAnchorAndProperties(void* spatialAnchor, void* propertySet, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Perception::Spatial::ISpatialEntityRemovedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Entity(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Perception::Spatial::ISpatialEntityStore>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL SaveAsync(void* entity, void** action) noexcept = 0;
    virtual int32_t WINRT_CALL RemoveAsync(void* entity, void** action) noexcept = 0;
    virtual int32_t WINRT_CALL CreateEntityWatcher(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Perception::Spatial::ISpatialEntityStoreStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsSupported(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL TryGetForRemoteSystemSession(void* session, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Perception::Spatial::ISpatialEntityUpdatedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Entity(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Perception::Spatial::ISpatialEntityWatcher>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Status(Windows::Perception::Spatial::SpatialEntityWatcherStatus* value) noexcept = 0;
    virtual int32_t WINRT_CALL add_Added(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_Added(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_Updated(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_Updated(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_Removed(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_Removed(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_EnumerationCompleted(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_EnumerationCompleted(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL Start() noexcept = 0;
    virtual int32_t WINRT_CALL Stop() noexcept = 0;
};};

template <> struct abi<Windows::Perception::Spatial::ISpatialLocation>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Position(Windows::Foundation::Numerics::float3* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Orientation(Windows::Foundation::Numerics::quaternion* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AbsoluteLinearVelocity(Windows::Foundation::Numerics::float3* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AbsoluteLinearAcceleration(Windows::Foundation::Numerics::float3* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AbsoluteAngularVelocity(Windows::Foundation::Numerics::quaternion* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AbsoluteAngularAcceleration(Windows::Foundation::Numerics::quaternion* value) noexcept = 0;
};};

template <> struct abi<Windows::Perception::Spatial::ISpatialLocation2>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_AbsoluteAngularVelocityAxisAngle(Windows::Foundation::Numerics::float3* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_AbsoluteAngularAccelerationAxisAngle(Windows::Foundation::Numerics::float3* value) noexcept = 0;
};};

template <> struct abi<Windows::Perception::Spatial::ISpatialLocator>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Locatability(Windows::Perception::Spatial::SpatialLocatability* value) noexcept = 0;
    virtual int32_t WINRT_CALL add_LocatabilityChanged(void* handler, winrt::event_token* cookie) noexcept = 0;
    virtual int32_t WINRT_CALL remove_LocatabilityChanged(winrt::event_token cookie) noexcept = 0;
    virtual int32_t WINRT_CALL add_PositionalTrackingDeactivating(void* handler, winrt::event_token* cookie) noexcept = 0;
    virtual int32_t WINRT_CALL remove_PositionalTrackingDeactivating(winrt::event_token cookie) noexcept = 0;
    virtual int32_t WINRT_CALL TryLocateAtTimestamp(void* timestamp, void* coordinateSystem, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateAttachedFrameOfReferenceAtCurrentHeading(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateAttachedFrameOfReferenceAtCurrentHeadingWithPosition(Windows::Foundation::Numerics::float3 relativePosition, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateAttachedFrameOfReferenceAtCurrentHeadingWithPositionAndOrientation(Windows::Foundation::Numerics::float3 relativePosition, Windows::Foundation::Numerics::quaternion relativeOrientation, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateAttachedFrameOfReferenceAtCurrentHeadingWithPositionAndOrientationAndRelativeHeading(Windows::Foundation::Numerics::float3 relativePosition, Windows::Foundation::Numerics::quaternion relativeOrientation, double relativeHeadingInRadians, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateStationaryFrameOfReferenceAtCurrentLocation(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateStationaryFrameOfReferenceAtCurrentLocationWithPosition(Windows::Foundation::Numerics::float3 relativePosition, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateStationaryFrameOfReferenceAtCurrentLocationWithPositionAndOrientation(Windows::Foundation::Numerics::float3 relativePosition, Windows::Foundation::Numerics::quaternion relativeOrientation, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL CreateStationaryFrameOfReferenceAtCurrentLocationWithPositionAndOrientationAndRelativeHeading(Windows::Foundation::Numerics::float3 relativePosition, Windows::Foundation::Numerics::quaternion relativeOrientation, double relativeHeadingInRadians, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Perception::Spatial::ISpatialLocatorAttachedFrameOfReference>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_RelativePosition(Windows::Foundation::Numerics::float3* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_RelativePosition(Windows::Foundation::Numerics::float3 value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RelativeOrientation(Windows::Foundation::Numerics::quaternion* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_RelativeOrientation(Windows::Foundation::Numerics::quaternion value) noexcept = 0;
    virtual int32_t WINRT_CALL AdjustHeading(double headingOffsetInRadians) noexcept = 0;
    virtual int32_t WINRT_CALL GetStationaryCoordinateSystemAtTimestamp(void* timestamp, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL TryGetRelativeHeadingAtTimestamp(void* timestamp, void** value) noexcept = 0;
};};

template <> struct abi<Windows::Perception::Spatial::ISpatialLocatorPositionalTrackingDeactivatingEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Canceled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Canceled(bool value) noexcept = 0;
};};

template <> struct abi<Windows::Perception::Spatial::ISpatialLocatorStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetDefault(void** value) noexcept = 0;
};};

template <> struct abi<Windows::Perception::Spatial::ISpatialStageFrameOfReference>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_CoordinateSystem(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MovementRange(Windows::Perception::Spatial::SpatialMovementRange* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LookDirectionRange(Windows::Perception::Spatial::SpatialLookDirectionRange* value) noexcept = 0;
    virtual int32_t WINRT_CALL GetCoordinateSystemAtCurrentLocation(void* locator, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL TryGetMovementBounds(void* coordinateSystem, uint32_t* __valueSize, Windows::Foundation::Numerics::float3** value) noexcept = 0;
};};

template <> struct abi<Windows::Perception::Spatial::ISpatialStageFrameOfReferenceStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Current(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL add_CurrentChanged(void* handler, winrt::event_token* cookie) noexcept = 0;
    virtual int32_t WINRT_CALL remove_CurrentChanged(winrt::event_token cookie) noexcept = 0;
    virtual int32_t WINRT_CALL RequestNewStageAsync(void** result) noexcept = 0;
};};

template <> struct abi<Windows::Perception::Spatial::ISpatialStationaryFrameOfReference>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_CoordinateSystem(void** value) noexcept = 0;
};};

template <typename D>
struct consume_Windows_Perception_Spatial_ISpatialAnchor
{
    Windows::Perception::Spatial::SpatialCoordinateSystem CoordinateSystem() const;
    Windows::Perception::Spatial::SpatialCoordinateSystem RawCoordinateSystem() const;
    winrt::event_token RawCoordinateSystemAdjusted(Windows::Foundation::TypedEventHandler<Windows::Perception::Spatial::SpatialAnchor, Windows::Perception::Spatial::SpatialAnchorRawCoordinateSystemAdjustedEventArgs> const& handler) const;
    using RawCoordinateSystemAdjusted_revoker = impl::event_revoker<Windows::Perception::Spatial::ISpatialAnchor, &impl::abi_t<Windows::Perception::Spatial::ISpatialAnchor>::remove_RawCoordinateSystemAdjusted>;
    RawCoordinateSystemAdjusted_revoker RawCoordinateSystemAdjusted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Perception::Spatial::SpatialAnchor, Windows::Perception::Spatial::SpatialAnchorRawCoordinateSystemAdjustedEventArgs> const& handler) const;
    void RawCoordinateSystemAdjusted(winrt::event_token const& cookie) const noexcept;
};
template <> struct consume<Windows::Perception::Spatial::ISpatialAnchor> { template <typename D> using type = consume_Windows_Perception_Spatial_ISpatialAnchor<D>; };

template <typename D>
struct consume_Windows_Perception_Spatial_ISpatialAnchor2
{
    bool RemovedByUser() const;
};
template <> struct consume<Windows::Perception::Spatial::ISpatialAnchor2> { template <typename D> using type = consume_Windows_Perception_Spatial_ISpatialAnchor2<D>; };

template <typename D>
struct consume_Windows_Perception_Spatial_ISpatialAnchorExportSufficiency
{
    bool IsMinimallySufficient() const;
    double SufficiencyLevel() const;
    double RecommendedSufficiencyLevel() const;
};
template <> struct consume<Windows::Perception::Spatial::ISpatialAnchorExportSufficiency> { template <typename D> using type = consume_Windows_Perception_Spatial_ISpatialAnchorExportSufficiency<D>; };

template <typename D>
struct consume_Windows_Perception_Spatial_ISpatialAnchorExporter
{
    Windows::Foundation::IAsyncOperation<Windows::Perception::Spatial::SpatialAnchorExportSufficiency> GetAnchorExportSufficiencyAsync(Windows::Perception::Spatial::SpatialAnchor const& anchor, Windows::Perception::Spatial::SpatialAnchorExportPurpose const& purpose) const;
    Windows::Foundation::IAsyncOperation<bool> TryExportAnchorAsync(Windows::Perception::Spatial::SpatialAnchor const& anchor, Windows::Perception::Spatial::SpatialAnchorExportPurpose const& purpose, Windows::Storage::Streams::IOutputStream const& stream) const;
};
template <> struct consume<Windows::Perception::Spatial::ISpatialAnchorExporter> { template <typename D> using type = consume_Windows_Perception_Spatial_ISpatialAnchorExporter<D>; };

template <typename D>
struct consume_Windows_Perception_Spatial_ISpatialAnchorExporterStatics
{
    Windows::Perception::Spatial::SpatialAnchorExporter GetDefault() const;
    Windows::Foundation::IAsyncOperation<Windows::Perception::Spatial::SpatialPerceptionAccessStatus> RequestAccessAsync() const;
};
template <> struct consume<Windows::Perception::Spatial::ISpatialAnchorExporterStatics> { template <typename D> using type = consume_Windows_Perception_Spatial_ISpatialAnchorExporterStatics<D>; };

template <typename D>
struct consume_Windows_Perception_Spatial_ISpatialAnchorManagerStatics
{
    Windows::Foundation::IAsyncOperation<Windows::Perception::Spatial::SpatialAnchorStore> RequestStoreAsync() const;
};
template <> struct consume<Windows::Perception::Spatial::ISpatialAnchorManagerStatics> { template <typename D> using type = consume_Windows_Perception_Spatial_ISpatialAnchorManagerStatics<D>; };

template <typename D>
struct consume_Windows_Perception_Spatial_ISpatialAnchorRawCoordinateSystemAdjustedEventArgs
{
    Windows::Foundation::Numerics::float4x4 OldRawCoordinateSystemToNewRawCoordinateSystemTransform() const;
};
template <> struct consume<Windows::Perception::Spatial::ISpatialAnchorRawCoordinateSystemAdjustedEventArgs> { template <typename D> using type = consume_Windows_Perception_Spatial_ISpatialAnchorRawCoordinateSystemAdjustedEventArgs<D>; };

template <typename D>
struct consume_Windows_Perception_Spatial_ISpatialAnchorStatics
{
    Windows::Perception::Spatial::SpatialAnchor TryCreateRelativeTo(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem) const;
    Windows::Perception::Spatial::SpatialAnchor TryCreateRelativeTo(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem, Windows::Foundation::Numerics::float3 const& position) const;
    Windows::Perception::Spatial::SpatialAnchor TryCreateRelativeTo(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem, Windows::Foundation::Numerics::float3 const& position, Windows::Foundation::Numerics::quaternion const& orientation) const;
};
template <> struct consume<Windows::Perception::Spatial::ISpatialAnchorStatics> { template <typename D> using type = consume_Windows_Perception_Spatial_ISpatialAnchorStatics<D>; };

template <typename D>
struct consume_Windows_Perception_Spatial_ISpatialAnchorStore
{
    Windows::Foundation::Collections::IMapView<hstring, Windows::Perception::Spatial::SpatialAnchor> GetAllSavedAnchors() const;
    bool TrySave(param::hstring const& id, Windows::Perception::Spatial::SpatialAnchor const& anchor) const;
    void Remove(param::hstring const& id) const;
    void Clear() const;
};
template <> struct consume<Windows::Perception::Spatial::ISpatialAnchorStore> { template <typename D> using type = consume_Windows_Perception_Spatial_ISpatialAnchorStore<D>; };

template <typename D>
struct consume_Windows_Perception_Spatial_ISpatialAnchorTransferManagerStatics
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IMapView<hstring, Windows::Perception::Spatial::SpatialAnchor>> TryImportAnchorsAsync(Windows::Storage::Streams::IInputStream const& stream) const;
    Windows::Foundation::IAsyncOperation<bool> TryExportAnchorsAsync(param::async_iterable<Windows::Foundation::Collections::IKeyValuePair<hstring, Windows::Perception::Spatial::SpatialAnchor>> const& anchors, Windows::Storage::Streams::IOutputStream const& stream) const;
    Windows::Foundation::IAsyncOperation<Windows::Perception::Spatial::SpatialPerceptionAccessStatus> RequestAccessAsync() const;
};
template <> struct consume<Windows::Perception::Spatial::ISpatialAnchorTransferManagerStatics> { template <typename D> using type = consume_Windows_Perception_Spatial_ISpatialAnchorTransferManagerStatics<D>; };

template <typename D>
struct consume_Windows_Perception_Spatial_ISpatialBoundingVolume
{
};
template <> struct consume<Windows::Perception::Spatial::ISpatialBoundingVolume> { template <typename D> using type = consume_Windows_Perception_Spatial_ISpatialBoundingVolume<D>; };

template <typename D>
struct consume_Windows_Perception_Spatial_ISpatialBoundingVolumeStatics
{
    Windows::Perception::Spatial::SpatialBoundingVolume FromBox(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem, Windows::Perception::Spatial::SpatialBoundingBox const& box) const;
    Windows::Perception::Spatial::SpatialBoundingVolume FromOrientedBox(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem, Windows::Perception::Spatial::SpatialBoundingOrientedBox const& box) const;
    Windows::Perception::Spatial::SpatialBoundingVolume FromSphere(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem, Windows::Perception::Spatial::SpatialBoundingSphere const& sphere) const;
    Windows::Perception::Spatial::SpatialBoundingVolume FromFrustum(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem, Windows::Perception::Spatial::SpatialBoundingFrustum const& frustum) const;
};
template <> struct consume<Windows::Perception::Spatial::ISpatialBoundingVolumeStatics> { template <typename D> using type = consume_Windows_Perception_Spatial_ISpatialBoundingVolumeStatics<D>; };

template <typename D>
struct consume_Windows_Perception_Spatial_ISpatialCoordinateSystem
{
    Windows::Foundation::IReference<Windows::Foundation::Numerics::float4x4> TryGetTransformTo(Windows::Perception::Spatial::SpatialCoordinateSystem const& target) const;
};
template <> struct consume<Windows::Perception::Spatial::ISpatialCoordinateSystem> { template <typename D> using type = consume_Windows_Perception_Spatial_ISpatialCoordinateSystem<D>; };

template <typename D>
struct consume_Windows_Perception_Spatial_ISpatialEntity
{
    hstring Id() const;
    Windows::Perception::Spatial::SpatialAnchor Anchor() const;
    Windows::Foundation::Collections::ValueSet Properties() const;
};
template <> struct consume<Windows::Perception::Spatial::ISpatialEntity> { template <typename D> using type = consume_Windows_Perception_Spatial_ISpatialEntity<D>; };

template <typename D>
struct consume_Windows_Perception_Spatial_ISpatialEntityAddedEventArgs
{
    Windows::Perception::Spatial::SpatialEntity Entity() const;
};
template <> struct consume<Windows::Perception::Spatial::ISpatialEntityAddedEventArgs> { template <typename D> using type = consume_Windows_Perception_Spatial_ISpatialEntityAddedEventArgs<D>; };

template <typename D>
struct consume_Windows_Perception_Spatial_ISpatialEntityFactory
{
    Windows::Perception::Spatial::SpatialEntity CreateWithSpatialAnchor(Windows::Perception::Spatial::SpatialAnchor const& spatialAnchor) const;
    Windows::Perception::Spatial::SpatialEntity CreateWithSpatialAnchorAndProperties(Windows::Perception::Spatial::SpatialAnchor const& spatialAnchor, Windows::Foundation::Collections::ValueSet const& propertySet) const;
};
template <> struct consume<Windows::Perception::Spatial::ISpatialEntityFactory> { template <typename D> using type = consume_Windows_Perception_Spatial_ISpatialEntityFactory<D>; };

template <typename D>
struct consume_Windows_Perception_Spatial_ISpatialEntityRemovedEventArgs
{
    Windows::Perception::Spatial::SpatialEntity Entity() const;
};
template <> struct consume<Windows::Perception::Spatial::ISpatialEntityRemovedEventArgs> { template <typename D> using type = consume_Windows_Perception_Spatial_ISpatialEntityRemovedEventArgs<D>; };

template <typename D>
struct consume_Windows_Perception_Spatial_ISpatialEntityStore
{
    Windows::Foundation::IAsyncAction SaveAsync(Windows::Perception::Spatial::SpatialEntity const& entity) const;
    Windows::Foundation::IAsyncAction RemoveAsync(Windows::Perception::Spatial::SpatialEntity const& entity) const;
    Windows::Perception::Spatial::SpatialEntityWatcher CreateEntityWatcher() const;
};
template <> struct consume<Windows::Perception::Spatial::ISpatialEntityStore> { template <typename D> using type = consume_Windows_Perception_Spatial_ISpatialEntityStore<D>; };

template <typename D>
struct consume_Windows_Perception_Spatial_ISpatialEntityStoreStatics
{
    bool IsSupported() const;
    Windows::Perception::Spatial::SpatialEntityStore TryGet(Windows::System::RemoteSystems::RemoteSystemSession const& session) const;
};
template <> struct consume<Windows::Perception::Spatial::ISpatialEntityStoreStatics> { template <typename D> using type = consume_Windows_Perception_Spatial_ISpatialEntityStoreStatics<D>; };

template <typename D>
struct consume_Windows_Perception_Spatial_ISpatialEntityUpdatedEventArgs
{
    Windows::Perception::Spatial::SpatialEntity Entity() const;
};
template <> struct consume<Windows::Perception::Spatial::ISpatialEntityUpdatedEventArgs> { template <typename D> using type = consume_Windows_Perception_Spatial_ISpatialEntityUpdatedEventArgs<D>; };

template <typename D>
struct consume_Windows_Perception_Spatial_ISpatialEntityWatcher
{
    Windows::Perception::Spatial::SpatialEntityWatcherStatus Status() const;
    winrt::event_token Added(Windows::Foundation::TypedEventHandler<Windows::Perception::Spatial::SpatialEntityWatcher, Windows::Perception::Spatial::SpatialEntityAddedEventArgs> const& handler) const;
    using Added_revoker = impl::event_revoker<Windows::Perception::Spatial::ISpatialEntityWatcher, &impl::abi_t<Windows::Perception::Spatial::ISpatialEntityWatcher>::remove_Added>;
    Added_revoker Added(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Perception::Spatial::SpatialEntityWatcher, Windows::Perception::Spatial::SpatialEntityAddedEventArgs> const& handler) const;
    void Added(winrt::event_token const& token) const noexcept;
    winrt::event_token Updated(Windows::Foundation::TypedEventHandler<Windows::Perception::Spatial::SpatialEntityWatcher, Windows::Perception::Spatial::SpatialEntityUpdatedEventArgs> const& handler) const;
    using Updated_revoker = impl::event_revoker<Windows::Perception::Spatial::ISpatialEntityWatcher, &impl::abi_t<Windows::Perception::Spatial::ISpatialEntityWatcher>::remove_Updated>;
    Updated_revoker Updated(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Perception::Spatial::SpatialEntityWatcher, Windows::Perception::Spatial::SpatialEntityUpdatedEventArgs> const& handler) const;
    void Updated(winrt::event_token const& token) const noexcept;
    winrt::event_token Removed(Windows::Foundation::TypedEventHandler<Windows::Perception::Spatial::SpatialEntityWatcher, Windows::Perception::Spatial::SpatialEntityRemovedEventArgs> const& handler) const;
    using Removed_revoker = impl::event_revoker<Windows::Perception::Spatial::ISpatialEntityWatcher, &impl::abi_t<Windows::Perception::Spatial::ISpatialEntityWatcher>::remove_Removed>;
    Removed_revoker Removed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Perception::Spatial::SpatialEntityWatcher, Windows::Perception::Spatial::SpatialEntityRemovedEventArgs> const& handler) const;
    void Removed(winrt::event_token const& token) const noexcept;
    winrt::event_token EnumerationCompleted(Windows::Foundation::TypedEventHandler<Windows::Perception::Spatial::SpatialEntityWatcher, Windows::Foundation::IInspectable> const& handler) const;
    using EnumerationCompleted_revoker = impl::event_revoker<Windows::Perception::Spatial::ISpatialEntityWatcher, &impl::abi_t<Windows::Perception::Spatial::ISpatialEntityWatcher>::remove_EnumerationCompleted>;
    EnumerationCompleted_revoker EnumerationCompleted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Perception::Spatial::SpatialEntityWatcher, Windows::Foundation::IInspectable> const& handler) const;
    void EnumerationCompleted(winrt::event_token const& token) const noexcept;
    void Start() const;
    void Stop() const;
};
template <> struct consume<Windows::Perception::Spatial::ISpatialEntityWatcher> { template <typename D> using type = consume_Windows_Perception_Spatial_ISpatialEntityWatcher<D>; };

template <typename D>
struct consume_Windows_Perception_Spatial_ISpatialLocation
{
    Windows::Foundation::Numerics::float3 Position() const;
    Windows::Foundation::Numerics::quaternion Orientation() const;
    Windows::Foundation::Numerics::float3 AbsoluteLinearVelocity() const;
    Windows::Foundation::Numerics::float3 AbsoluteLinearAcceleration() const;
    Windows::Foundation::Numerics::quaternion AbsoluteAngularVelocity() const;
    Windows::Foundation::Numerics::quaternion AbsoluteAngularAcceleration() const;
};
template <> struct consume<Windows::Perception::Spatial::ISpatialLocation> { template <typename D> using type = consume_Windows_Perception_Spatial_ISpatialLocation<D>; };

template <typename D>
struct consume_Windows_Perception_Spatial_ISpatialLocation2
{
    Windows::Foundation::Numerics::float3 AbsoluteAngularVelocityAxisAngle() const;
    Windows::Foundation::Numerics::float3 AbsoluteAngularAccelerationAxisAngle() const;
};
template <> struct consume<Windows::Perception::Spatial::ISpatialLocation2> { template <typename D> using type = consume_Windows_Perception_Spatial_ISpatialLocation2<D>; };

template <typename D>
struct consume_Windows_Perception_Spatial_ISpatialLocator
{
    Windows::Perception::Spatial::SpatialLocatability Locatability() const;
    winrt::event_token LocatabilityChanged(Windows::Foundation::TypedEventHandler<Windows::Perception::Spatial::SpatialLocator, Windows::Foundation::IInspectable> const& handler) const;
    using LocatabilityChanged_revoker = impl::event_revoker<Windows::Perception::Spatial::ISpatialLocator, &impl::abi_t<Windows::Perception::Spatial::ISpatialLocator>::remove_LocatabilityChanged>;
    LocatabilityChanged_revoker LocatabilityChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Perception::Spatial::SpatialLocator, Windows::Foundation::IInspectable> const& handler) const;
    void LocatabilityChanged(winrt::event_token const& cookie) const noexcept;
    winrt::event_token PositionalTrackingDeactivating(Windows::Foundation::TypedEventHandler<Windows::Perception::Spatial::SpatialLocator, Windows::Perception::Spatial::SpatialLocatorPositionalTrackingDeactivatingEventArgs> const& handler) const;
    using PositionalTrackingDeactivating_revoker = impl::event_revoker<Windows::Perception::Spatial::ISpatialLocator, &impl::abi_t<Windows::Perception::Spatial::ISpatialLocator>::remove_PositionalTrackingDeactivating>;
    PositionalTrackingDeactivating_revoker PositionalTrackingDeactivating(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Perception::Spatial::SpatialLocator, Windows::Perception::Spatial::SpatialLocatorPositionalTrackingDeactivatingEventArgs> const& handler) const;
    void PositionalTrackingDeactivating(winrt::event_token const& cookie) const noexcept;
    Windows::Perception::Spatial::SpatialLocation TryLocateAtTimestamp(Windows::Perception::PerceptionTimestamp const& timestamp, Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem) const;
    Windows::Perception::Spatial::SpatialLocatorAttachedFrameOfReference CreateAttachedFrameOfReferenceAtCurrentHeading() const;
    Windows::Perception::Spatial::SpatialLocatorAttachedFrameOfReference CreateAttachedFrameOfReferenceAtCurrentHeading(Windows::Foundation::Numerics::float3 const& relativePosition) const;
    Windows::Perception::Spatial::SpatialLocatorAttachedFrameOfReference CreateAttachedFrameOfReferenceAtCurrentHeading(Windows::Foundation::Numerics::float3 const& relativePosition, Windows::Foundation::Numerics::quaternion const& relativeOrientation) const;
    Windows::Perception::Spatial::SpatialLocatorAttachedFrameOfReference CreateAttachedFrameOfReferenceAtCurrentHeading(Windows::Foundation::Numerics::float3 const& relativePosition, Windows::Foundation::Numerics::quaternion const& relativeOrientation, double relativeHeadingInRadians) const;
    Windows::Perception::Spatial::SpatialStationaryFrameOfReference CreateStationaryFrameOfReferenceAtCurrentLocation() const;
    Windows::Perception::Spatial::SpatialStationaryFrameOfReference CreateStationaryFrameOfReferenceAtCurrentLocation(Windows::Foundation::Numerics::float3 const& relativePosition) const;
    Windows::Perception::Spatial::SpatialStationaryFrameOfReference CreateStationaryFrameOfReferenceAtCurrentLocation(Windows::Foundation::Numerics::float3 const& relativePosition, Windows::Foundation::Numerics::quaternion const& relativeOrientation) const;
    Windows::Perception::Spatial::SpatialStationaryFrameOfReference CreateStationaryFrameOfReferenceAtCurrentLocation(Windows::Foundation::Numerics::float3 const& relativePosition, Windows::Foundation::Numerics::quaternion const& relativeOrientation, double relativeHeadingInRadians) const;
};
template <> struct consume<Windows::Perception::Spatial::ISpatialLocator> { template <typename D> using type = consume_Windows_Perception_Spatial_ISpatialLocator<D>; };

template <typename D>
struct consume_Windows_Perception_Spatial_ISpatialLocatorAttachedFrameOfReference
{
    Windows::Foundation::Numerics::float3 RelativePosition() const;
    void RelativePosition(Windows::Foundation::Numerics::float3 const& value) const;
    Windows::Foundation::Numerics::quaternion RelativeOrientation() const;
    void RelativeOrientation(Windows::Foundation::Numerics::quaternion const& value) const;
    void AdjustHeading(double headingOffsetInRadians) const;
    Windows::Perception::Spatial::SpatialCoordinateSystem GetStationaryCoordinateSystemAtTimestamp(Windows::Perception::PerceptionTimestamp const& timestamp) const;
    Windows::Foundation::IReference<double> TryGetRelativeHeadingAtTimestamp(Windows::Perception::PerceptionTimestamp const& timestamp) const;
};
template <> struct consume<Windows::Perception::Spatial::ISpatialLocatorAttachedFrameOfReference> { template <typename D> using type = consume_Windows_Perception_Spatial_ISpatialLocatorAttachedFrameOfReference<D>; };

template <typename D>
struct consume_Windows_Perception_Spatial_ISpatialLocatorPositionalTrackingDeactivatingEventArgs
{
    bool Canceled() const;
    void Canceled(bool value) const;
};
template <> struct consume<Windows::Perception::Spatial::ISpatialLocatorPositionalTrackingDeactivatingEventArgs> { template <typename D> using type = consume_Windows_Perception_Spatial_ISpatialLocatorPositionalTrackingDeactivatingEventArgs<D>; };

template <typename D>
struct consume_Windows_Perception_Spatial_ISpatialLocatorStatics
{
    Windows::Perception::Spatial::SpatialLocator GetDefault() const;
};
template <> struct consume<Windows::Perception::Spatial::ISpatialLocatorStatics> { template <typename D> using type = consume_Windows_Perception_Spatial_ISpatialLocatorStatics<D>; };

template <typename D>
struct consume_Windows_Perception_Spatial_ISpatialStageFrameOfReference
{
    Windows::Perception::Spatial::SpatialCoordinateSystem CoordinateSystem() const;
    Windows::Perception::Spatial::SpatialMovementRange MovementRange() const;
    Windows::Perception::Spatial::SpatialLookDirectionRange LookDirectionRange() const;
    Windows::Perception::Spatial::SpatialCoordinateSystem GetCoordinateSystemAtCurrentLocation(Windows::Perception::Spatial::SpatialLocator const& locator) const;
    com_array<Windows::Foundation::Numerics::float3> TryGetMovementBounds(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem) const;
};
template <> struct consume<Windows::Perception::Spatial::ISpatialStageFrameOfReference> { template <typename D> using type = consume_Windows_Perception_Spatial_ISpatialStageFrameOfReference<D>; };

template <typename D>
struct consume_Windows_Perception_Spatial_ISpatialStageFrameOfReferenceStatics
{
    Windows::Perception::Spatial::SpatialStageFrameOfReference Current() const;
    winrt::event_token CurrentChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const;
    using CurrentChanged_revoker = impl::event_revoker<Windows::Perception::Spatial::ISpatialStageFrameOfReferenceStatics, &impl::abi_t<Windows::Perception::Spatial::ISpatialStageFrameOfReferenceStatics>::remove_CurrentChanged>;
    CurrentChanged_revoker CurrentChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const;
    void CurrentChanged(winrt::event_token const& cookie) const noexcept;
    Windows::Foundation::IAsyncOperation<Windows::Perception::Spatial::SpatialStageFrameOfReference> RequestNewStageAsync() const;
};
template <> struct consume<Windows::Perception::Spatial::ISpatialStageFrameOfReferenceStatics> { template <typename D> using type = consume_Windows_Perception_Spatial_ISpatialStageFrameOfReferenceStatics<D>; };

template <typename D>
struct consume_Windows_Perception_Spatial_ISpatialStationaryFrameOfReference
{
    Windows::Perception::Spatial::SpatialCoordinateSystem CoordinateSystem() const;
};
template <> struct consume<Windows::Perception::Spatial::ISpatialStationaryFrameOfReference> { template <typename D> using type = consume_Windows_Perception_Spatial_ISpatialStationaryFrameOfReference<D>; };

struct struct_Windows_Perception_Spatial_SpatialBoundingBox
{
    Windows::Foundation::Numerics::float3 Center;
    Windows::Foundation::Numerics::float3 Extents;
};
template <> struct abi<Windows::Perception::Spatial::SpatialBoundingBox>{ using type = struct_Windows_Perception_Spatial_SpatialBoundingBox; };


struct struct_Windows_Perception_Spatial_SpatialBoundingFrustum
{
    Windows::Foundation::Numerics::plane Near;
    Windows::Foundation::Numerics::plane Far;
    Windows::Foundation::Numerics::plane Right;
    Windows::Foundation::Numerics::plane Left;
    Windows::Foundation::Numerics::plane Top;
    Windows::Foundation::Numerics::plane Bottom;
};
template <> struct abi<Windows::Perception::Spatial::SpatialBoundingFrustum>{ using type = struct_Windows_Perception_Spatial_SpatialBoundingFrustum; };


struct struct_Windows_Perception_Spatial_SpatialBoundingOrientedBox
{
    Windows::Foundation::Numerics::float3 Center;
    Windows::Foundation::Numerics::float3 Extents;
    Windows::Foundation::Numerics::quaternion Orientation;
};
template <> struct abi<Windows::Perception::Spatial::SpatialBoundingOrientedBox>{ using type = struct_Windows_Perception_Spatial_SpatialBoundingOrientedBox; };


struct struct_Windows_Perception_Spatial_SpatialBoundingSphere
{
    Windows::Foundation::Numerics::float3 Center;
    float Radius;
};
template <> struct abi<Windows::Perception::Spatial::SpatialBoundingSphere>{ using type = struct_Windows_Perception_Spatial_SpatialBoundingSphere; };


struct struct_Windows_Perception_Spatial_SpatialRay
{
    Windows::Foundation::Numerics::float3 Origin;
    Windows::Foundation::Numerics::float3 Direction;
};
template <> struct abi<Windows::Perception::Spatial::SpatialRay>{ using type = struct_Windows_Perception_Spatial_SpatialRay; };


}
