// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Foundation.Collections.0.h"
#include "winrt/impl/Windows.Perception.0.h"
#include "winrt/impl/Windows.Storage.Streams.0.h"
#include "winrt/impl/Windows.System.RemoteSystems.0.h"
#include "winrt/impl/Windows.Perception.Spatial.0.h"

WINRT_EXPORT namespace winrt::Windows::Perception::Spatial {

struct WINRT_EBO ISpatialAnchor :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISpatialAnchor>
{
    ISpatialAnchor(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISpatialAnchor2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISpatialAnchor2>
{
    ISpatialAnchor2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISpatialAnchorExportSufficiency :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISpatialAnchorExportSufficiency>
{
    ISpatialAnchorExportSufficiency(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISpatialAnchorExporter :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISpatialAnchorExporter>
{
    ISpatialAnchorExporter(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISpatialAnchorExporterStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISpatialAnchorExporterStatics>
{
    ISpatialAnchorExporterStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISpatialAnchorManagerStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISpatialAnchorManagerStatics>
{
    ISpatialAnchorManagerStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISpatialAnchorRawCoordinateSystemAdjustedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISpatialAnchorRawCoordinateSystemAdjustedEventArgs>
{
    ISpatialAnchorRawCoordinateSystemAdjustedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISpatialAnchorStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISpatialAnchorStatics>
{
    ISpatialAnchorStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISpatialAnchorStore :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISpatialAnchorStore>
{
    ISpatialAnchorStore(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISpatialAnchorTransferManagerStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISpatialAnchorTransferManagerStatics>
{
    ISpatialAnchorTransferManagerStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISpatialBoundingVolume :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISpatialBoundingVolume>
{
    ISpatialBoundingVolume(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISpatialBoundingVolumeStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISpatialBoundingVolumeStatics>
{
    ISpatialBoundingVolumeStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISpatialCoordinateSystem :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISpatialCoordinateSystem>
{
    ISpatialCoordinateSystem(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISpatialEntity :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISpatialEntity>
{
    ISpatialEntity(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISpatialEntityAddedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISpatialEntityAddedEventArgs>
{
    ISpatialEntityAddedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISpatialEntityFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISpatialEntityFactory>
{
    ISpatialEntityFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISpatialEntityRemovedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISpatialEntityRemovedEventArgs>
{
    ISpatialEntityRemovedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISpatialEntityStore :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISpatialEntityStore>
{
    ISpatialEntityStore(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISpatialEntityStoreStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISpatialEntityStoreStatics>
{
    ISpatialEntityStoreStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISpatialEntityUpdatedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISpatialEntityUpdatedEventArgs>
{
    ISpatialEntityUpdatedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISpatialEntityWatcher :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISpatialEntityWatcher>
{
    ISpatialEntityWatcher(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISpatialLocation :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISpatialLocation>
{
    ISpatialLocation(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISpatialLocation2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISpatialLocation2>
{
    ISpatialLocation2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISpatialLocator :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISpatialLocator>
{
    ISpatialLocator(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISpatialLocatorAttachedFrameOfReference :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISpatialLocatorAttachedFrameOfReference>
{
    ISpatialLocatorAttachedFrameOfReference(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISpatialLocatorPositionalTrackingDeactivatingEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISpatialLocatorPositionalTrackingDeactivatingEventArgs>
{
    ISpatialLocatorPositionalTrackingDeactivatingEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISpatialLocatorStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISpatialLocatorStatics>
{
    ISpatialLocatorStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISpatialStageFrameOfReference :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISpatialStageFrameOfReference>
{
    ISpatialStageFrameOfReference(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISpatialStageFrameOfReferenceStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISpatialStageFrameOfReferenceStatics>
{
    ISpatialStageFrameOfReferenceStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO ISpatialStationaryFrameOfReference :
    Windows::Foundation::IInspectable,
    impl::consume_t<ISpatialStationaryFrameOfReference>
{
    ISpatialStationaryFrameOfReference(std::nullptr_t = nullptr) noexcept {}
};

}
