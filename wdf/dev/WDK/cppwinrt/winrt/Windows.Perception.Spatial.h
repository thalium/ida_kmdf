// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Perception.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.System.RemoteSystems.2.h"
#include "winrt/impl/Windows.Perception.Spatial.2.h"
#include "winrt/Windows.Perception.h"

namespace winrt::impl {

template <typename D> Windows::Perception::Spatial::SpatialCoordinateSystem consume_Windows_Perception_Spatial_ISpatialAnchor<D>::CoordinateSystem() const
{
    Windows::Perception::Spatial::SpatialCoordinateSystem value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialAnchor)->get_CoordinateSystem(put_abi(value)));
    return value;
}

template <typename D> Windows::Perception::Spatial::SpatialCoordinateSystem consume_Windows_Perception_Spatial_ISpatialAnchor<D>::RawCoordinateSystem() const
{
    Windows::Perception::Spatial::SpatialCoordinateSystem value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialAnchor)->get_RawCoordinateSystem(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Perception_Spatial_ISpatialAnchor<D>::RawCoordinateSystemAdjusted(Windows::Foundation::TypedEventHandler<Windows::Perception::Spatial::SpatialAnchor, Windows::Perception::Spatial::SpatialAnchorRawCoordinateSystemAdjustedEventArgs> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialAnchor)->add_RawCoordinateSystemAdjusted(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_Perception_Spatial_ISpatialAnchor<D>::RawCoordinateSystemAdjusted_revoker consume_Windows_Perception_Spatial_ISpatialAnchor<D>::RawCoordinateSystemAdjusted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Perception::Spatial::SpatialAnchor, Windows::Perception::Spatial::SpatialAnchorRawCoordinateSystemAdjustedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, RawCoordinateSystemAdjusted_revoker>(this, RawCoordinateSystemAdjusted(handler));
}

template <typename D> void consume_Windows_Perception_Spatial_ISpatialAnchor<D>::RawCoordinateSystemAdjusted(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Perception::Spatial::ISpatialAnchor)->remove_RawCoordinateSystemAdjusted(get_abi(cookie)));
}

template <typename D> bool consume_Windows_Perception_Spatial_ISpatialAnchor2<D>::RemovedByUser() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialAnchor2)->get_RemovedByUser(&value));
    return value;
}

template <typename D> bool consume_Windows_Perception_Spatial_ISpatialAnchorExportSufficiency<D>::IsMinimallySufficient() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialAnchorExportSufficiency)->get_IsMinimallySufficient(&value));
    return value;
}

template <typename D> double consume_Windows_Perception_Spatial_ISpatialAnchorExportSufficiency<D>::SufficiencyLevel() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialAnchorExportSufficiency)->get_SufficiencyLevel(&value));
    return value;
}

template <typename D> double consume_Windows_Perception_Spatial_ISpatialAnchorExportSufficiency<D>::RecommendedSufficiencyLevel() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialAnchorExportSufficiency)->get_RecommendedSufficiencyLevel(&value));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Perception::Spatial::SpatialAnchorExportSufficiency> consume_Windows_Perception_Spatial_ISpatialAnchorExporter<D>::GetAnchorExportSufficiencyAsync(Windows::Perception::Spatial::SpatialAnchor const& anchor, Windows::Perception::Spatial::SpatialAnchorExportPurpose const& purpose) const
{
    Windows::Foundation::IAsyncOperation<Windows::Perception::Spatial::SpatialAnchorExportSufficiency> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialAnchorExporter)->GetAnchorExportSufficiencyAsync(get_abi(anchor), get_abi(purpose), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Perception_Spatial_ISpatialAnchorExporter<D>::TryExportAnchorAsync(Windows::Perception::Spatial::SpatialAnchor const& anchor, Windows::Perception::Spatial::SpatialAnchorExportPurpose const& purpose, Windows::Storage::Streams::IOutputStream const& stream) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialAnchorExporter)->TryExportAnchorAsync(get_abi(anchor), get_abi(purpose), get_abi(stream), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Perception::Spatial::SpatialAnchorExporter consume_Windows_Perception_Spatial_ISpatialAnchorExporterStatics<D>::GetDefault() const
{
    Windows::Perception::Spatial::SpatialAnchorExporter value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialAnchorExporterStatics)->GetDefault(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Perception::Spatial::SpatialPerceptionAccessStatus> consume_Windows_Perception_Spatial_ISpatialAnchorExporterStatics<D>::RequestAccessAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Perception::Spatial::SpatialPerceptionAccessStatus> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialAnchorExporterStatics)->RequestAccessAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Perception::Spatial::SpatialAnchorStore> consume_Windows_Perception_Spatial_ISpatialAnchorManagerStatics<D>::RequestStoreAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Perception::Spatial::SpatialAnchorStore> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialAnchorManagerStatics)->RequestStoreAsync(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Numerics::float4x4 consume_Windows_Perception_Spatial_ISpatialAnchorRawCoordinateSystemAdjustedEventArgs<D>::OldRawCoordinateSystemToNewRawCoordinateSystemTransform() const
{
    Windows::Foundation::Numerics::float4x4 value{};
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialAnchorRawCoordinateSystemAdjustedEventArgs)->get_OldRawCoordinateSystemToNewRawCoordinateSystemTransform(put_abi(value)));
    return value;
}

template <typename D> Windows::Perception::Spatial::SpatialAnchor consume_Windows_Perception_Spatial_ISpatialAnchorStatics<D>::TryCreateRelativeTo(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem) const
{
    Windows::Perception::Spatial::SpatialAnchor value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialAnchorStatics)->TryCreateRelativeTo(get_abi(coordinateSystem), put_abi(value)));
    return value;
}

template <typename D> Windows::Perception::Spatial::SpatialAnchor consume_Windows_Perception_Spatial_ISpatialAnchorStatics<D>::TryCreateRelativeTo(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem, Windows::Foundation::Numerics::float3 const& position) const
{
    Windows::Perception::Spatial::SpatialAnchor value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialAnchorStatics)->TryCreateWithPositionRelativeTo(get_abi(coordinateSystem), get_abi(position), put_abi(value)));
    return value;
}

template <typename D> Windows::Perception::Spatial::SpatialAnchor consume_Windows_Perception_Spatial_ISpatialAnchorStatics<D>::TryCreateRelativeTo(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem, Windows::Foundation::Numerics::float3 const& position, Windows::Foundation::Numerics::quaternion const& orientation) const
{
    Windows::Perception::Spatial::SpatialAnchor value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialAnchorStatics)->TryCreateWithPositionAndOrientationRelativeTo(get_abi(coordinateSystem), get_abi(position), get_abi(orientation), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IMapView<hstring, Windows::Perception::Spatial::SpatialAnchor> consume_Windows_Perception_Spatial_ISpatialAnchorStore<D>::GetAllSavedAnchors() const
{
    Windows::Foundation::Collections::IMapView<hstring, Windows::Perception::Spatial::SpatialAnchor> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialAnchorStore)->GetAllSavedAnchors(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Perception_Spatial_ISpatialAnchorStore<D>::TrySave(param::hstring const& id, Windows::Perception::Spatial::SpatialAnchor const& anchor) const
{
    bool succeeded{};
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialAnchorStore)->TrySave(get_abi(id), get_abi(anchor), &succeeded));
    return succeeded;
}

template <typename D> void consume_Windows_Perception_Spatial_ISpatialAnchorStore<D>::Remove(param::hstring const& id) const
{
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialAnchorStore)->Remove(get_abi(id)));
}

template <typename D> void consume_Windows_Perception_Spatial_ISpatialAnchorStore<D>::Clear() const
{
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialAnchorStore)->Clear());
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IMapView<hstring, Windows::Perception::Spatial::SpatialAnchor>> consume_Windows_Perception_Spatial_ISpatialAnchorTransferManagerStatics<D>::TryImportAnchorsAsync(Windows::Storage::Streams::IInputStream const& stream) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IMapView<hstring, Windows::Perception::Spatial::SpatialAnchor>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialAnchorTransferManagerStatics)->TryImportAnchorsAsync(get_abi(stream), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Perception_Spatial_ISpatialAnchorTransferManagerStatics<D>::TryExportAnchorsAsync(param::async_iterable<Windows::Foundation::Collections::IKeyValuePair<hstring, Windows::Perception::Spatial::SpatialAnchor>> const& anchors, Windows::Storage::Streams::IOutputStream const& stream) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialAnchorTransferManagerStatics)->TryExportAnchorsAsync(get_abi(anchors), get_abi(stream), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Perception::Spatial::SpatialPerceptionAccessStatus> consume_Windows_Perception_Spatial_ISpatialAnchorTransferManagerStatics<D>::RequestAccessAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Perception::Spatial::SpatialPerceptionAccessStatus> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialAnchorTransferManagerStatics)->RequestAccessAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Perception::Spatial::SpatialBoundingVolume consume_Windows_Perception_Spatial_ISpatialBoundingVolumeStatics<D>::FromBox(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem, Windows::Perception::Spatial::SpatialBoundingBox const& box) const
{
    Windows::Perception::Spatial::SpatialBoundingVolume value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialBoundingVolumeStatics)->FromBox(get_abi(coordinateSystem), get_abi(box), put_abi(value)));
    return value;
}

template <typename D> Windows::Perception::Spatial::SpatialBoundingVolume consume_Windows_Perception_Spatial_ISpatialBoundingVolumeStatics<D>::FromOrientedBox(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem, Windows::Perception::Spatial::SpatialBoundingOrientedBox const& box) const
{
    Windows::Perception::Spatial::SpatialBoundingVolume value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialBoundingVolumeStatics)->FromOrientedBox(get_abi(coordinateSystem), get_abi(box), put_abi(value)));
    return value;
}

template <typename D> Windows::Perception::Spatial::SpatialBoundingVolume consume_Windows_Perception_Spatial_ISpatialBoundingVolumeStatics<D>::FromSphere(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem, Windows::Perception::Spatial::SpatialBoundingSphere const& sphere) const
{
    Windows::Perception::Spatial::SpatialBoundingVolume value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialBoundingVolumeStatics)->FromSphere(get_abi(coordinateSystem), get_abi(sphere), put_abi(value)));
    return value;
}

template <typename D> Windows::Perception::Spatial::SpatialBoundingVolume consume_Windows_Perception_Spatial_ISpatialBoundingVolumeStatics<D>::FromFrustum(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem, Windows::Perception::Spatial::SpatialBoundingFrustum const& frustum) const
{
    Windows::Perception::Spatial::SpatialBoundingVolume value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialBoundingVolumeStatics)->FromFrustum(get_abi(coordinateSystem), get_abi(frustum), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::Numerics::float4x4> consume_Windows_Perception_Spatial_ISpatialCoordinateSystem<D>::TryGetTransformTo(Windows::Perception::Spatial::SpatialCoordinateSystem const& target) const
{
    Windows::Foundation::IReference<Windows::Foundation::Numerics::float4x4> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialCoordinateSystem)->TryGetTransformTo(get_abi(target), put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Perception_Spatial_ISpatialEntity<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialEntity)->get_Id(put_abi(value)));
    return value;
}

template <typename D> Windows::Perception::Spatial::SpatialAnchor consume_Windows_Perception_Spatial_ISpatialEntity<D>::Anchor() const
{
    Windows::Perception::Spatial::SpatialAnchor value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialEntity)->get_Anchor(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::ValueSet consume_Windows_Perception_Spatial_ISpatialEntity<D>::Properties() const
{
    Windows::Foundation::Collections::ValueSet value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialEntity)->get_Properties(put_abi(value)));
    return value;
}

template <typename D> Windows::Perception::Spatial::SpatialEntity consume_Windows_Perception_Spatial_ISpatialEntityAddedEventArgs<D>::Entity() const
{
    Windows::Perception::Spatial::SpatialEntity value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialEntityAddedEventArgs)->get_Entity(put_abi(value)));
    return value;
}

template <typename D> Windows::Perception::Spatial::SpatialEntity consume_Windows_Perception_Spatial_ISpatialEntityFactory<D>::CreateWithSpatialAnchor(Windows::Perception::Spatial::SpatialAnchor const& spatialAnchor) const
{
    Windows::Perception::Spatial::SpatialEntity value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialEntityFactory)->CreateWithSpatialAnchor(get_abi(spatialAnchor), put_abi(value)));
    return value;
}

template <typename D> Windows::Perception::Spatial::SpatialEntity consume_Windows_Perception_Spatial_ISpatialEntityFactory<D>::CreateWithSpatialAnchorAndProperties(Windows::Perception::Spatial::SpatialAnchor const& spatialAnchor, Windows::Foundation::Collections::ValueSet const& propertySet) const
{
    Windows::Perception::Spatial::SpatialEntity value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialEntityFactory)->CreateWithSpatialAnchorAndProperties(get_abi(spatialAnchor), get_abi(propertySet), put_abi(value)));
    return value;
}

template <typename D> Windows::Perception::Spatial::SpatialEntity consume_Windows_Perception_Spatial_ISpatialEntityRemovedEventArgs<D>::Entity() const
{
    Windows::Perception::Spatial::SpatialEntity value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialEntityRemovedEventArgs)->get_Entity(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Perception_Spatial_ISpatialEntityStore<D>::SaveAsync(Windows::Perception::Spatial::SpatialEntity const& entity) const
{
    Windows::Foundation::IAsyncAction action{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialEntityStore)->SaveAsync(get_abi(entity), put_abi(action)));
    return action;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Perception_Spatial_ISpatialEntityStore<D>::RemoveAsync(Windows::Perception::Spatial::SpatialEntity const& entity) const
{
    Windows::Foundation::IAsyncAction action{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialEntityStore)->RemoveAsync(get_abi(entity), put_abi(action)));
    return action;
}

template <typename D> Windows::Perception::Spatial::SpatialEntityWatcher consume_Windows_Perception_Spatial_ISpatialEntityStore<D>::CreateEntityWatcher() const
{
    Windows::Perception::Spatial::SpatialEntityWatcher value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialEntityStore)->CreateEntityWatcher(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Perception_Spatial_ISpatialEntityStoreStatics<D>::IsSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialEntityStoreStatics)->get_IsSupported(&value));
    return value;
}

template <typename D> Windows::Perception::Spatial::SpatialEntityStore consume_Windows_Perception_Spatial_ISpatialEntityStoreStatics<D>::TryGet(Windows::System::RemoteSystems::RemoteSystemSession const& session) const
{
    Windows::Perception::Spatial::SpatialEntityStore value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialEntityStoreStatics)->TryGetForRemoteSystemSession(get_abi(session), put_abi(value)));
    return value;
}

template <typename D> Windows::Perception::Spatial::SpatialEntity consume_Windows_Perception_Spatial_ISpatialEntityUpdatedEventArgs<D>::Entity() const
{
    Windows::Perception::Spatial::SpatialEntity value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialEntityUpdatedEventArgs)->get_Entity(put_abi(value)));
    return value;
}

template <typename D> Windows::Perception::Spatial::SpatialEntityWatcherStatus consume_Windows_Perception_Spatial_ISpatialEntityWatcher<D>::Status() const
{
    Windows::Perception::Spatial::SpatialEntityWatcherStatus value{};
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialEntityWatcher)->get_Status(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Perception_Spatial_ISpatialEntityWatcher<D>::Added(Windows::Foundation::TypedEventHandler<Windows::Perception::Spatial::SpatialEntityWatcher, Windows::Perception::Spatial::SpatialEntityAddedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialEntityWatcher)->add_Added(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Perception_Spatial_ISpatialEntityWatcher<D>::Added_revoker consume_Windows_Perception_Spatial_ISpatialEntityWatcher<D>::Added(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Perception::Spatial::SpatialEntityWatcher, Windows::Perception::Spatial::SpatialEntityAddedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Added_revoker>(this, Added(handler));
}

template <typename D> void consume_Windows_Perception_Spatial_ISpatialEntityWatcher<D>::Added(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Perception::Spatial::ISpatialEntityWatcher)->remove_Added(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Perception_Spatial_ISpatialEntityWatcher<D>::Updated(Windows::Foundation::TypedEventHandler<Windows::Perception::Spatial::SpatialEntityWatcher, Windows::Perception::Spatial::SpatialEntityUpdatedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialEntityWatcher)->add_Updated(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Perception_Spatial_ISpatialEntityWatcher<D>::Updated_revoker consume_Windows_Perception_Spatial_ISpatialEntityWatcher<D>::Updated(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Perception::Spatial::SpatialEntityWatcher, Windows::Perception::Spatial::SpatialEntityUpdatedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Updated_revoker>(this, Updated(handler));
}

template <typename D> void consume_Windows_Perception_Spatial_ISpatialEntityWatcher<D>::Updated(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Perception::Spatial::ISpatialEntityWatcher)->remove_Updated(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Perception_Spatial_ISpatialEntityWatcher<D>::Removed(Windows::Foundation::TypedEventHandler<Windows::Perception::Spatial::SpatialEntityWatcher, Windows::Perception::Spatial::SpatialEntityRemovedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialEntityWatcher)->add_Removed(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Perception_Spatial_ISpatialEntityWatcher<D>::Removed_revoker consume_Windows_Perception_Spatial_ISpatialEntityWatcher<D>::Removed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Perception::Spatial::SpatialEntityWatcher, Windows::Perception::Spatial::SpatialEntityRemovedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Removed_revoker>(this, Removed(handler));
}

template <typename D> void consume_Windows_Perception_Spatial_ISpatialEntityWatcher<D>::Removed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Perception::Spatial::ISpatialEntityWatcher)->remove_Removed(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Perception_Spatial_ISpatialEntityWatcher<D>::EnumerationCompleted(Windows::Foundation::TypedEventHandler<Windows::Perception::Spatial::SpatialEntityWatcher, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialEntityWatcher)->add_EnumerationCompleted(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Perception_Spatial_ISpatialEntityWatcher<D>::EnumerationCompleted_revoker consume_Windows_Perception_Spatial_ISpatialEntityWatcher<D>::EnumerationCompleted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Perception::Spatial::SpatialEntityWatcher, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, EnumerationCompleted_revoker>(this, EnumerationCompleted(handler));
}

template <typename D> void consume_Windows_Perception_Spatial_ISpatialEntityWatcher<D>::EnumerationCompleted(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Perception::Spatial::ISpatialEntityWatcher)->remove_EnumerationCompleted(get_abi(token)));
}

template <typename D> void consume_Windows_Perception_Spatial_ISpatialEntityWatcher<D>::Start() const
{
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialEntityWatcher)->Start());
}

template <typename D> void consume_Windows_Perception_Spatial_ISpatialEntityWatcher<D>::Stop() const
{
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialEntityWatcher)->Stop());
}

template <typename D> Windows::Foundation::Numerics::float3 consume_Windows_Perception_Spatial_ISpatialLocation<D>::Position() const
{
    Windows::Foundation::Numerics::float3 value{};
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialLocation)->get_Position(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Numerics::quaternion consume_Windows_Perception_Spatial_ISpatialLocation<D>::Orientation() const
{
    Windows::Foundation::Numerics::quaternion value{};
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialLocation)->get_Orientation(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Numerics::float3 consume_Windows_Perception_Spatial_ISpatialLocation<D>::AbsoluteLinearVelocity() const
{
    Windows::Foundation::Numerics::float3 value{};
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialLocation)->get_AbsoluteLinearVelocity(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Numerics::float3 consume_Windows_Perception_Spatial_ISpatialLocation<D>::AbsoluteLinearAcceleration() const
{
    Windows::Foundation::Numerics::float3 value{};
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialLocation)->get_AbsoluteLinearAcceleration(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Numerics::quaternion consume_Windows_Perception_Spatial_ISpatialLocation<D>::AbsoluteAngularVelocity() const
{
    Windows::Foundation::Numerics::quaternion value{};
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialLocation)->get_AbsoluteAngularVelocity(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Numerics::quaternion consume_Windows_Perception_Spatial_ISpatialLocation<D>::AbsoluteAngularAcceleration() const
{
    Windows::Foundation::Numerics::quaternion value{};
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialLocation)->get_AbsoluteAngularAcceleration(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Numerics::float3 consume_Windows_Perception_Spatial_ISpatialLocation2<D>::AbsoluteAngularVelocityAxisAngle() const
{
    Windows::Foundation::Numerics::float3 value{};
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialLocation2)->get_AbsoluteAngularVelocityAxisAngle(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Numerics::float3 consume_Windows_Perception_Spatial_ISpatialLocation2<D>::AbsoluteAngularAccelerationAxisAngle() const
{
    Windows::Foundation::Numerics::float3 value{};
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialLocation2)->get_AbsoluteAngularAccelerationAxisAngle(put_abi(value)));
    return value;
}

template <typename D> Windows::Perception::Spatial::SpatialLocatability consume_Windows_Perception_Spatial_ISpatialLocator<D>::Locatability() const
{
    Windows::Perception::Spatial::SpatialLocatability value{};
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialLocator)->get_Locatability(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Perception_Spatial_ISpatialLocator<D>::LocatabilityChanged(Windows::Foundation::TypedEventHandler<Windows::Perception::Spatial::SpatialLocator, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialLocator)->add_LocatabilityChanged(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_Perception_Spatial_ISpatialLocator<D>::LocatabilityChanged_revoker consume_Windows_Perception_Spatial_ISpatialLocator<D>::LocatabilityChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Perception::Spatial::SpatialLocator, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, LocatabilityChanged_revoker>(this, LocatabilityChanged(handler));
}

template <typename D> void consume_Windows_Perception_Spatial_ISpatialLocator<D>::LocatabilityChanged(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Perception::Spatial::ISpatialLocator)->remove_LocatabilityChanged(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_Perception_Spatial_ISpatialLocator<D>::PositionalTrackingDeactivating(Windows::Foundation::TypedEventHandler<Windows::Perception::Spatial::SpatialLocator, Windows::Perception::Spatial::SpatialLocatorPositionalTrackingDeactivatingEventArgs> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialLocator)->add_PositionalTrackingDeactivating(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_Perception_Spatial_ISpatialLocator<D>::PositionalTrackingDeactivating_revoker consume_Windows_Perception_Spatial_ISpatialLocator<D>::PositionalTrackingDeactivating(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Perception::Spatial::SpatialLocator, Windows::Perception::Spatial::SpatialLocatorPositionalTrackingDeactivatingEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, PositionalTrackingDeactivating_revoker>(this, PositionalTrackingDeactivating(handler));
}

template <typename D> void consume_Windows_Perception_Spatial_ISpatialLocator<D>::PositionalTrackingDeactivating(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Perception::Spatial::ISpatialLocator)->remove_PositionalTrackingDeactivating(get_abi(cookie)));
}

template <typename D> Windows::Perception::Spatial::SpatialLocation consume_Windows_Perception_Spatial_ISpatialLocator<D>::TryLocateAtTimestamp(Windows::Perception::PerceptionTimestamp const& timestamp, Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem) const
{
    Windows::Perception::Spatial::SpatialLocation value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialLocator)->TryLocateAtTimestamp(get_abi(timestamp), get_abi(coordinateSystem), put_abi(value)));
    return value;
}

template <typename D> Windows::Perception::Spatial::SpatialLocatorAttachedFrameOfReference consume_Windows_Perception_Spatial_ISpatialLocator<D>::CreateAttachedFrameOfReferenceAtCurrentHeading() const
{
    Windows::Perception::Spatial::SpatialLocatorAttachedFrameOfReference value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialLocator)->CreateAttachedFrameOfReferenceAtCurrentHeading(put_abi(value)));
    return value;
}

template <typename D> Windows::Perception::Spatial::SpatialLocatorAttachedFrameOfReference consume_Windows_Perception_Spatial_ISpatialLocator<D>::CreateAttachedFrameOfReferenceAtCurrentHeading(Windows::Foundation::Numerics::float3 const& relativePosition) const
{
    Windows::Perception::Spatial::SpatialLocatorAttachedFrameOfReference value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialLocator)->CreateAttachedFrameOfReferenceAtCurrentHeadingWithPosition(get_abi(relativePosition), put_abi(value)));
    return value;
}

template <typename D> Windows::Perception::Spatial::SpatialLocatorAttachedFrameOfReference consume_Windows_Perception_Spatial_ISpatialLocator<D>::CreateAttachedFrameOfReferenceAtCurrentHeading(Windows::Foundation::Numerics::float3 const& relativePosition, Windows::Foundation::Numerics::quaternion const& relativeOrientation) const
{
    Windows::Perception::Spatial::SpatialLocatorAttachedFrameOfReference value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialLocator)->CreateAttachedFrameOfReferenceAtCurrentHeadingWithPositionAndOrientation(get_abi(relativePosition), get_abi(relativeOrientation), put_abi(value)));
    return value;
}

template <typename D> Windows::Perception::Spatial::SpatialLocatorAttachedFrameOfReference consume_Windows_Perception_Spatial_ISpatialLocator<D>::CreateAttachedFrameOfReferenceAtCurrentHeading(Windows::Foundation::Numerics::float3 const& relativePosition, Windows::Foundation::Numerics::quaternion const& relativeOrientation, double relativeHeadingInRadians) const
{
    Windows::Perception::Spatial::SpatialLocatorAttachedFrameOfReference value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialLocator)->CreateAttachedFrameOfReferenceAtCurrentHeadingWithPositionAndOrientationAndRelativeHeading(get_abi(relativePosition), get_abi(relativeOrientation), relativeHeadingInRadians, put_abi(value)));
    return value;
}

template <typename D> Windows::Perception::Spatial::SpatialStationaryFrameOfReference consume_Windows_Perception_Spatial_ISpatialLocator<D>::CreateStationaryFrameOfReferenceAtCurrentLocation() const
{
    Windows::Perception::Spatial::SpatialStationaryFrameOfReference value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialLocator)->CreateStationaryFrameOfReferenceAtCurrentLocation(put_abi(value)));
    return value;
}

template <typename D> Windows::Perception::Spatial::SpatialStationaryFrameOfReference consume_Windows_Perception_Spatial_ISpatialLocator<D>::CreateStationaryFrameOfReferenceAtCurrentLocation(Windows::Foundation::Numerics::float3 const& relativePosition) const
{
    Windows::Perception::Spatial::SpatialStationaryFrameOfReference value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialLocator)->CreateStationaryFrameOfReferenceAtCurrentLocationWithPosition(get_abi(relativePosition), put_abi(value)));
    return value;
}

template <typename D> Windows::Perception::Spatial::SpatialStationaryFrameOfReference consume_Windows_Perception_Spatial_ISpatialLocator<D>::CreateStationaryFrameOfReferenceAtCurrentLocation(Windows::Foundation::Numerics::float3 const& relativePosition, Windows::Foundation::Numerics::quaternion const& relativeOrientation) const
{
    Windows::Perception::Spatial::SpatialStationaryFrameOfReference value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialLocator)->CreateStationaryFrameOfReferenceAtCurrentLocationWithPositionAndOrientation(get_abi(relativePosition), get_abi(relativeOrientation), put_abi(value)));
    return value;
}

template <typename D> Windows::Perception::Spatial::SpatialStationaryFrameOfReference consume_Windows_Perception_Spatial_ISpatialLocator<D>::CreateStationaryFrameOfReferenceAtCurrentLocation(Windows::Foundation::Numerics::float3 const& relativePosition, Windows::Foundation::Numerics::quaternion const& relativeOrientation, double relativeHeadingInRadians) const
{
    Windows::Perception::Spatial::SpatialStationaryFrameOfReference value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialLocator)->CreateStationaryFrameOfReferenceAtCurrentLocationWithPositionAndOrientationAndRelativeHeading(get_abi(relativePosition), get_abi(relativeOrientation), relativeHeadingInRadians, put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Numerics::float3 consume_Windows_Perception_Spatial_ISpatialLocatorAttachedFrameOfReference<D>::RelativePosition() const
{
    Windows::Foundation::Numerics::float3 value{};
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialLocatorAttachedFrameOfReference)->get_RelativePosition(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Perception_Spatial_ISpatialLocatorAttachedFrameOfReference<D>::RelativePosition(Windows::Foundation::Numerics::float3 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialLocatorAttachedFrameOfReference)->put_RelativePosition(get_abi(value)));
}

template <typename D> Windows::Foundation::Numerics::quaternion consume_Windows_Perception_Spatial_ISpatialLocatorAttachedFrameOfReference<D>::RelativeOrientation() const
{
    Windows::Foundation::Numerics::quaternion value{};
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialLocatorAttachedFrameOfReference)->get_RelativeOrientation(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Perception_Spatial_ISpatialLocatorAttachedFrameOfReference<D>::RelativeOrientation(Windows::Foundation::Numerics::quaternion const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialLocatorAttachedFrameOfReference)->put_RelativeOrientation(get_abi(value)));
}

template <typename D> void consume_Windows_Perception_Spatial_ISpatialLocatorAttachedFrameOfReference<D>::AdjustHeading(double headingOffsetInRadians) const
{
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialLocatorAttachedFrameOfReference)->AdjustHeading(headingOffsetInRadians));
}

template <typename D> Windows::Perception::Spatial::SpatialCoordinateSystem consume_Windows_Perception_Spatial_ISpatialLocatorAttachedFrameOfReference<D>::GetStationaryCoordinateSystemAtTimestamp(Windows::Perception::PerceptionTimestamp const& timestamp) const
{
    Windows::Perception::Spatial::SpatialCoordinateSystem value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialLocatorAttachedFrameOfReference)->GetStationaryCoordinateSystemAtTimestamp(get_abi(timestamp), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<double> consume_Windows_Perception_Spatial_ISpatialLocatorAttachedFrameOfReference<D>::TryGetRelativeHeadingAtTimestamp(Windows::Perception::PerceptionTimestamp const& timestamp) const
{
    Windows::Foundation::IReference<double> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialLocatorAttachedFrameOfReference)->TryGetRelativeHeadingAtTimestamp(get_abi(timestamp), put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Perception_Spatial_ISpatialLocatorPositionalTrackingDeactivatingEventArgs<D>::Canceled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialLocatorPositionalTrackingDeactivatingEventArgs)->get_Canceled(&value));
    return value;
}

template <typename D> void consume_Windows_Perception_Spatial_ISpatialLocatorPositionalTrackingDeactivatingEventArgs<D>::Canceled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialLocatorPositionalTrackingDeactivatingEventArgs)->put_Canceled(value));
}

template <typename D> Windows::Perception::Spatial::SpatialLocator consume_Windows_Perception_Spatial_ISpatialLocatorStatics<D>::GetDefault() const
{
    Windows::Perception::Spatial::SpatialLocator value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialLocatorStatics)->GetDefault(put_abi(value)));
    return value;
}

template <typename D> Windows::Perception::Spatial::SpatialCoordinateSystem consume_Windows_Perception_Spatial_ISpatialStageFrameOfReference<D>::CoordinateSystem() const
{
    Windows::Perception::Spatial::SpatialCoordinateSystem value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialStageFrameOfReference)->get_CoordinateSystem(put_abi(value)));
    return value;
}

template <typename D> Windows::Perception::Spatial::SpatialMovementRange consume_Windows_Perception_Spatial_ISpatialStageFrameOfReference<D>::MovementRange() const
{
    Windows::Perception::Spatial::SpatialMovementRange value{};
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialStageFrameOfReference)->get_MovementRange(put_abi(value)));
    return value;
}

template <typename D> Windows::Perception::Spatial::SpatialLookDirectionRange consume_Windows_Perception_Spatial_ISpatialStageFrameOfReference<D>::LookDirectionRange() const
{
    Windows::Perception::Spatial::SpatialLookDirectionRange value{};
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialStageFrameOfReference)->get_LookDirectionRange(put_abi(value)));
    return value;
}

template <typename D> Windows::Perception::Spatial::SpatialCoordinateSystem consume_Windows_Perception_Spatial_ISpatialStageFrameOfReference<D>::GetCoordinateSystemAtCurrentLocation(Windows::Perception::Spatial::SpatialLocator const& locator) const
{
    Windows::Perception::Spatial::SpatialCoordinateSystem result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialStageFrameOfReference)->GetCoordinateSystemAtCurrentLocation(get_abi(locator), put_abi(result)));
    return result;
}

template <typename D> com_array<Windows::Foundation::Numerics::float3> consume_Windows_Perception_Spatial_ISpatialStageFrameOfReference<D>::TryGetMovementBounds(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem) const
{
    com_array<Windows::Foundation::Numerics::float3> value;
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialStageFrameOfReference)->TryGetMovementBounds(get_abi(coordinateSystem), impl::put_size_abi(value), put_abi(value)));
    return value;
}

template <typename D> Windows::Perception::Spatial::SpatialStageFrameOfReference consume_Windows_Perception_Spatial_ISpatialStageFrameOfReferenceStatics<D>::Current() const
{
    Windows::Perception::Spatial::SpatialStageFrameOfReference value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialStageFrameOfReferenceStatics)->get_Current(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Perception_Spatial_ISpatialStageFrameOfReferenceStatics<D>::CurrentChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialStageFrameOfReferenceStatics)->add_CurrentChanged(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_Perception_Spatial_ISpatialStageFrameOfReferenceStatics<D>::CurrentChanged_revoker consume_Windows_Perception_Spatial_ISpatialStageFrameOfReferenceStatics<D>::CurrentChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, CurrentChanged_revoker>(this, CurrentChanged(handler));
}

template <typename D> void consume_Windows_Perception_Spatial_ISpatialStageFrameOfReferenceStatics<D>::CurrentChanged(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Perception::Spatial::ISpatialStageFrameOfReferenceStatics)->remove_CurrentChanged(get_abi(cookie)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Perception::Spatial::SpatialStageFrameOfReference> consume_Windows_Perception_Spatial_ISpatialStageFrameOfReferenceStatics<D>::RequestNewStageAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Perception::Spatial::SpatialStageFrameOfReference> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialStageFrameOfReferenceStatics)->RequestNewStageAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Perception::Spatial::SpatialCoordinateSystem consume_Windows_Perception_Spatial_ISpatialStationaryFrameOfReference<D>::CoordinateSystem() const
{
    Windows::Perception::Spatial::SpatialCoordinateSystem value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Perception::Spatial::ISpatialStationaryFrameOfReference)->get_CoordinateSystem(put_abi(value)));
    return value;
}

template <typename D>
struct produce<D, Windows::Perception::Spatial::ISpatialAnchor> : produce_base<D, Windows::Perception::Spatial::ISpatialAnchor>
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

    int32_t WINRT_CALL get_RawCoordinateSystem(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RawCoordinateSystem, WINRT_WRAP(Windows::Perception::Spatial::SpatialCoordinateSystem));
            *value = detach_from<Windows::Perception::Spatial::SpatialCoordinateSystem>(this->shim().RawCoordinateSystem());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_RawCoordinateSystemAdjusted(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RawCoordinateSystemAdjusted, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Perception::Spatial::SpatialAnchor, Windows::Perception::Spatial::SpatialAnchorRawCoordinateSystemAdjustedEventArgs> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().RawCoordinateSystemAdjusted(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Perception::Spatial::SpatialAnchor, Windows::Perception::Spatial::SpatialAnchorRawCoordinateSystemAdjustedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_RawCoordinateSystemAdjusted(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(RawCoordinateSystemAdjusted, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().RawCoordinateSystemAdjusted(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Perception::Spatial::ISpatialAnchor2> : produce_base<D, Windows::Perception::Spatial::ISpatialAnchor2>
{
    int32_t WINRT_CALL get_RemovedByUser(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemovedByUser, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().RemovedByUser());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Perception::Spatial::ISpatialAnchorExportSufficiency> : produce_base<D, Windows::Perception::Spatial::ISpatialAnchorExportSufficiency>
{
    int32_t WINRT_CALL get_IsMinimallySufficient(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsMinimallySufficient, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsMinimallySufficient());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SufficiencyLevel(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SufficiencyLevel, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().SufficiencyLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RecommendedSufficiencyLevel(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RecommendedSufficiencyLevel, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().RecommendedSufficiencyLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Perception::Spatial::ISpatialAnchorExporter> : produce_base<D, Windows::Perception::Spatial::ISpatialAnchorExporter>
{
    int32_t WINRT_CALL GetAnchorExportSufficiencyAsync(void* anchor, Windows::Perception::Spatial::SpatialAnchorExportPurpose purpose, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAnchorExportSufficiencyAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Perception::Spatial::SpatialAnchorExportSufficiency>), Windows::Perception::Spatial::SpatialAnchor const, Windows::Perception::Spatial::SpatialAnchorExportPurpose const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Perception::Spatial::SpatialAnchorExportSufficiency>>(this->shim().GetAnchorExportSufficiencyAsync(*reinterpret_cast<Windows::Perception::Spatial::SpatialAnchor const*>(&anchor), *reinterpret_cast<Windows::Perception::Spatial::SpatialAnchorExportPurpose const*>(&purpose)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryExportAnchorAsync(void* anchor, Windows::Perception::Spatial::SpatialAnchorExportPurpose purpose, void* stream, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryExportAnchorAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::Perception::Spatial::SpatialAnchor const, Windows::Perception::Spatial::SpatialAnchorExportPurpose const, Windows::Storage::Streams::IOutputStream const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryExportAnchorAsync(*reinterpret_cast<Windows::Perception::Spatial::SpatialAnchor const*>(&anchor), *reinterpret_cast<Windows::Perception::Spatial::SpatialAnchorExportPurpose const*>(&purpose), *reinterpret_cast<Windows::Storage::Streams::IOutputStream const*>(&stream)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Perception::Spatial::ISpatialAnchorExporterStatics> : produce_base<D, Windows::Perception::Spatial::ISpatialAnchorExporterStatics>
{
    int32_t WINRT_CALL GetDefault(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefault, WINRT_WRAP(Windows::Perception::Spatial::SpatialAnchorExporter));
            *value = detach_from<Windows::Perception::Spatial::SpatialAnchorExporter>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestAccessAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestAccessAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Perception::Spatial::SpatialPerceptionAccessStatus>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Perception::Spatial::SpatialPerceptionAccessStatus>>(this->shim().RequestAccessAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Perception::Spatial::ISpatialAnchorManagerStatics> : produce_base<D, Windows::Perception::Spatial::ISpatialAnchorManagerStatics>
{
    int32_t WINRT_CALL RequestStoreAsync(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestStoreAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Perception::Spatial::SpatialAnchorStore>));
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Perception::Spatial::SpatialAnchorStore>>(this->shim().RequestStoreAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Perception::Spatial::ISpatialAnchorRawCoordinateSystemAdjustedEventArgs> : produce_base<D, Windows::Perception::Spatial::ISpatialAnchorRawCoordinateSystemAdjustedEventArgs>
{
    int32_t WINRT_CALL get_OldRawCoordinateSystemToNewRawCoordinateSystemTransform(Windows::Foundation::Numerics::float4x4* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OldRawCoordinateSystemToNewRawCoordinateSystemTransform, WINRT_WRAP(Windows::Foundation::Numerics::float4x4));
            *value = detach_from<Windows::Foundation::Numerics::float4x4>(this->shim().OldRawCoordinateSystemToNewRawCoordinateSystemTransform());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Perception::Spatial::ISpatialAnchorStatics> : produce_base<D, Windows::Perception::Spatial::ISpatialAnchorStatics>
{
    int32_t WINRT_CALL TryCreateRelativeTo(void* coordinateSystem, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryCreateRelativeTo, WINRT_WRAP(Windows::Perception::Spatial::SpatialAnchor), Windows::Perception::Spatial::SpatialCoordinateSystem const&);
            *value = detach_from<Windows::Perception::Spatial::SpatialAnchor>(this->shim().TryCreateRelativeTo(*reinterpret_cast<Windows::Perception::Spatial::SpatialCoordinateSystem const*>(&coordinateSystem)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryCreateWithPositionRelativeTo(void* coordinateSystem, Windows::Foundation::Numerics::float3 position, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryCreateRelativeTo, WINRT_WRAP(Windows::Perception::Spatial::SpatialAnchor), Windows::Perception::Spatial::SpatialCoordinateSystem const&, Windows::Foundation::Numerics::float3 const&);
            *value = detach_from<Windows::Perception::Spatial::SpatialAnchor>(this->shim().TryCreateRelativeTo(*reinterpret_cast<Windows::Perception::Spatial::SpatialCoordinateSystem const*>(&coordinateSystem), *reinterpret_cast<Windows::Foundation::Numerics::float3 const*>(&position)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryCreateWithPositionAndOrientationRelativeTo(void* coordinateSystem, Windows::Foundation::Numerics::float3 position, Windows::Foundation::Numerics::quaternion orientation, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryCreateRelativeTo, WINRT_WRAP(Windows::Perception::Spatial::SpatialAnchor), Windows::Perception::Spatial::SpatialCoordinateSystem const&, Windows::Foundation::Numerics::float3 const&, Windows::Foundation::Numerics::quaternion const&);
            *value = detach_from<Windows::Perception::Spatial::SpatialAnchor>(this->shim().TryCreateRelativeTo(*reinterpret_cast<Windows::Perception::Spatial::SpatialCoordinateSystem const*>(&coordinateSystem), *reinterpret_cast<Windows::Foundation::Numerics::float3 const*>(&position), *reinterpret_cast<Windows::Foundation::Numerics::quaternion const*>(&orientation)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Perception::Spatial::ISpatialAnchorStore> : produce_base<D, Windows::Perception::Spatial::ISpatialAnchorStore>
{
    int32_t WINRT_CALL GetAllSavedAnchors(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAllSavedAnchors, WINRT_WRAP(Windows::Foundation::Collections::IMapView<hstring, Windows::Perception::Spatial::SpatialAnchor>));
            *value = detach_from<Windows::Foundation::Collections::IMapView<hstring, Windows::Perception::Spatial::SpatialAnchor>>(this->shim().GetAllSavedAnchors());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TrySave(void* id, void* anchor, bool* succeeded) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrySave, WINRT_WRAP(bool), hstring const&, Windows::Perception::Spatial::SpatialAnchor const&);
            *succeeded = detach_from<bool>(this->shim().TrySave(*reinterpret_cast<hstring const*>(&id), *reinterpret_cast<Windows::Perception::Spatial::SpatialAnchor const*>(&anchor)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Remove(void* id) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Remove, WINRT_WRAP(void), hstring const&);
            this->shim().Remove(*reinterpret_cast<hstring const*>(&id));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Clear() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Clear, WINRT_WRAP(void));
            this->shim().Clear();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Perception::Spatial::ISpatialAnchorTransferManagerStatics> : produce_base<D, Windows::Perception::Spatial::ISpatialAnchorTransferManagerStatics>
{
    int32_t WINRT_CALL TryImportAnchorsAsync(void* stream, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryImportAnchorsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IMapView<hstring, Windows::Perception::Spatial::SpatialAnchor>>), Windows::Storage::Streams::IInputStream const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IMapView<hstring, Windows::Perception::Spatial::SpatialAnchor>>>(this->shim().TryImportAnchorsAsync(*reinterpret_cast<Windows::Storage::Streams::IInputStream const*>(&stream)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryExportAnchorsAsync(void* anchors, void* stream, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryExportAnchorsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::Foundation::Collections::IIterable<Windows::Foundation::Collections::IKeyValuePair<hstring, Windows::Perception::Spatial::SpatialAnchor>> const, Windows::Storage::Streams::IOutputStream const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryExportAnchorsAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Foundation::Collections::IKeyValuePair<hstring, Windows::Perception::Spatial::SpatialAnchor>> const*>(&anchors), *reinterpret_cast<Windows::Storage::Streams::IOutputStream const*>(&stream)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestAccessAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestAccessAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Perception::Spatial::SpatialPerceptionAccessStatus>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Perception::Spatial::SpatialPerceptionAccessStatus>>(this->shim().RequestAccessAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Perception::Spatial::ISpatialBoundingVolume> : produce_base<D, Windows::Perception::Spatial::ISpatialBoundingVolume>
{};

template <typename D>
struct produce<D, Windows::Perception::Spatial::ISpatialBoundingVolumeStatics> : produce_base<D, Windows::Perception::Spatial::ISpatialBoundingVolumeStatics>
{
    int32_t WINRT_CALL FromBox(void* coordinateSystem, struct struct_Windows_Perception_Spatial_SpatialBoundingBox box, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromBox, WINRT_WRAP(Windows::Perception::Spatial::SpatialBoundingVolume), Windows::Perception::Spatial::SpatialCoordinateSystem const&, Windows::Perception::Spatial::SpatialBoundingBox const&);
            *value = detach_from<Windows::Perception::Spatial::SpatialBoundingVolume>(this->shim().FromBox(*reinterpret_cast<Windows::Perception::Spatial::SpatialCoordinateSystem const*>(&coordinateSystem), *reinterpret_cast<Windows::Perception::Spatial::SpatialBoundingBox const*>(&box)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FromOrientedBox(void* coordinateSystem, struct struct_Windows_Perception_Spatial_SpatialBoundingOrientedBox box, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromOrientedBox, WINRT_WRAP(Windows::Perception::Spatial::SpatialBoundingVolume), Windows::Perception::Spatial::SpatialCoordinateSystem const&, Windows::Perception::Spatial::SpatialBoundingOrientedBox const&);
            *value = detach_from<Windows::Perception::Spatial::SpatialBoundingVolume>(this->shim().FromOrientedBox(*reinterpret_cast<Windows::Perception::Spatial::SpatialCoordinateSystem const*>(&coordinateSystem), *reinterpret_cast<Windows::Perception::Spatial::SpatialBoundingOrientedBox const*>(&box)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FromSphere(void* coordinateSystem, struct struct_Windows_Perception_Spatial_SpatialBoundingSphere sphere, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromSphere, WINRT_WRAP(Windows::Perception::Spatial::SpatialBoundingVolume), Windows::Perception::Spatial::SpatialCoordinateSystem const&, Windows::Perception::Spatial::SpatialBoundingSphere const&);
            *value = detach_from<Windows::Perception::Spatial::SpatialBoundingVolume>(this->shim().FromSphere(*reinterpret_cast<Windows::Perception::Spatial::SpatialCoordinateSystem const*>(&coordinateSystem), *reinterpret_cast<Windows::Perception::Spatial::SpatialBoundingSphere const*>(&sphere)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FromFrustum(void* coordinateSystem, struct struct_Windows_Perception_Spatial_SpatialBoundingFrustum frustum, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromFrustum, WINRT_WRAP(Windows::Perception::Spatial::SpatialBoundingVolume), Windows::Perception::Spatial::SpatialCoordinateSystem const&, Windows::Perception::Spatial::SpatialBoundingFrustum const&);
            *value = detach_from<Windows::Perception::Spatial::SpatialBoundingVolume>(this->shim().FromFrustum(*reinterpret_cast<Windows::Perception::Spatial::SpatialCoordinateSystem const*>(&coordinateSystem), *reinterpret_cast<Windows::Perception::Spatial::SpatialBoundingFrustum const*>(&frustum)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Perception::Spatial::ISpatialCoordinateSystem> : produce_base<D, Windows::Perception::Spatial::ISpatialCoordinateSystem>
{
    int32_t WINRT_CALL TryGetTransformTo(void* target, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryGetTransformTo, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::Numerics::float4x4>), Windows::Perception::Spatial::SpatialCoordinateSystem const&);
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::Numerics::float4x4>>(this->shim().TryGetTransformTo(*reinterpret_cast<Windows::Perception::Spatial::SpatialCoordinateSystem const*>(&target)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Perception::Spatial::ISpatialEntity> : produce_base<D, Windows::Perception::Spatial::ISpatialEntity>
{
    int32_t WINRT_CALL get_Id(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Id, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Anchor(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Anchor, WINRT_WRAP(Windows::Perception::Spatial::SpatialAnchor));
            *value = detach_from<Windows::Perception::Spatial::SpatialAnchor>(this->shim().Anchor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Properties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Properties, WINRT_WRAP(Windows::Foundation::Collections::ValueSet));
            *value = detach_from<Windows::Foundation::Collections::ValueSet>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Perception::Spatial::ISpatialEntityAddedEventArgs> : produce_base<D, Windows::Perception::Spatial::ISpatialEntityAddedEventArgs>
{
    int32_t WINRT_CALL get_Entity(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Entity, WINRT_WRAP(Windows::Perception::Spatial::SpatialEntity));
            *value = detach_from<Windows::Perception::Spatial::SpatialEntity>(this->shim().Entity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Perception::Spatial::ISpatialEntityFactory> : produce_base<D, Windows::Perception::Spatial::ISpatialEntityFactory>
{
    int32_t WINRT_CALL CreateWithSpatialAnchor(void* spatialAnchor, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithSpatialAnchor, WINRT_WRAP(Windows::Perception::Spatial::SpatialEntity), Windows::Perception::Spatial::SpatialAnchor const&);
            *value = detach_from<Windows::Perception::Spatial::SpatialEntity>(this->shim().CreateWithSpatialAnchor(*reinterpret_cast<Windows::Perception::Spatial::SpatialAnchor const*>(&spatialAnchor)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithSpatialAnchorAndProperties(void* spatialAnchor, void* propertySet, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithSpatialAnchorAndProperties, WINRT_WRAP(Windows::Perception::Spatial::SpatialEntity), Windows::Perception::Spatial::SpatialAnchor const&, Windows::Foundation::Collections::ValueSet const&);
            *value = detach_from<Windows::Perception::Spatial::SpatialEntity>(this->shim().CreateWithSpatialAnchorAndProperties(*reinterpret_cast<Windows::Perception::Spatial::SpatialAnchor const*>(&spatialAnchor), *reinterpret_cast<Windows::Foundation::Collections::ValueSet const*>(&propertySet)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Perception::Spatial::ISpatialEntityRemovedEventArgs> : produce_base<D, Windows::Perception::Spatial::ISpatialEntityRemovedEventArgs>
{
    int32_t WINRT_CALL get_Entity(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Entity, WINRT_WRAP(Windows::Perception::Spatial::SpatialEntity));
            *value = detach_from<Windows::Perception::Spatial::SpatialEntity>(this->shim().Entity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Perception::Spatial::ISpatialEntityStore> : produce_base<D, Windows::Perception::Spatial::ISpatialEntityStore>
{
    int32_t WINRT_CALL SaveAsync(void* entity, void** action) noexcept final
    {
        try
        {
            *action = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SaveAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Perception::Spatial::SpatialEntity const);
            *action = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SaveAsync(*reinterpret_cast<Windows::Perception::Spatial::SpatialEntity const*>(&entity)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RemoveAsync(void* entity, void** action) noexcept final
    {
        try
        {
            *action = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoveAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Perception::Spatial::SpatialEntity const);
            *action = detach_from<Windows::Foundation::IAsyncAction>(this->shim().RemoveAsync(*reinterpret_cast<Windows::Perception::Spatial::SpatialEntity const*>(&entity)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateEntityWatcher(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateEntityWatcher, WINRT_WRAP(Windows::Perception::Spatial::SpatialEntityWatcher));
            *value = detach_from<Windows::Perception::Spatial::SpatialEntityWatcher>(this->shim().CreateEntityWatcher());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Perception::Spatial::ISpatialEntityStoreStatics> : produce_base<D, Windows::Perception::Spatial::ISpatialEntityStoreStatics>
{
    int32_t WINRT_CALL get_IsSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryGetForRemoteSystemSession(void* session, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryGet, WINRT_WRAP(Windows::Perception::Spatial::SpatialEntityStore), Windows::System::RemoteSystems::RemoteSystemSession const&);
            *value = detach_from<Windows::Perception::Spatial::SpatialEntityStore>(this->shim().TryGet(*reinterpret_cast<Windows::System::RemoteSystems::RemoteSystemSession const*>(&session)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Perception::Spatial::ISpatialEntityUpdatedEventArgs> : produce_base<D, Windows::Perception::Spatial::ISpatialEntityUpdatedEventArgs>
{
    int32_t WINRT_CALL get_Entity(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Entity, WINRT_WRAP(Windows::Perception::Spatial::SpatialEntity));
            *value = detach_from<Windows::Perception::Spatial::SpatialEntity>(this->shim().Entity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Perception::Spatial::ISpatialEntityWatcher> : produce_base<D, Windows::Perception::Spatial::ISpatialEntityWatcher>
{
    int32_t WINRT_CALL get_Status(Windows::Perception::Spatial::SpatialEntityWatcherStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Perception::Spatial::SpatialEntityWatcherStatus));
            *value = detach_from<Windows::Perception::Spatial::SpatialEntityWatcherStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_Added(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Added, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Perception::Spatial::SpatialEntityWatcher, Windows::Perception::Spatial::SpatialEntityAddedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Added(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Perception::Spatial::SpatialEntityWatcher, Windows::Perception::Spatial::SpatialEntityAddedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Added(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Added, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Added(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_Updated(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Updated, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Perception::Spatial::SpatialEntityWatcher, Windows::Perception::Spatial::SpatialEntityUpdatedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Updated(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Perception::Spatial::SpatialEntityWatcher, Windows::Perception::Spatial::SpatialEntityUpdatedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Updated(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Updated, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Updated(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_Removed(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Removed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Perception::Spatial::SpatialEntityWatcher, Windows::Perception::Spatial::SpatialEntityRemovedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Removed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Perception::Spatial::SpatialEntityWatcher, Windows::Perception::Spatial::SpatialEntityRemovedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Removed(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Removed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Removed(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_EnumerationCompleted(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnumerationCompleted, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Perception::Spatial::SpatialEntityWatcher, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().EnumerationCompleted(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Perception::Spatial::SpatialEntityWatcher, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_EnumerationCompleted(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(EnumerationCompleted, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().EnumerationCompleted(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL Start() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Start, WINRT_WRAP(void));
            this->shim().Start();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Stop() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Stop, WINRT_WRAP(void));
            this->shim().Stop();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Perception::Spatial::ISpatialLocation> : produce_base<D, Windows::Perception::Spatial::ISpatialLocation>
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

    int32_t WINRT_CALL get_Orientation(Windows::Foundation::Numerics::quaternion* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Orientation, WINRT_WRAP(Windows::Foundation::Numerics::quaternion));
            *value = detach_from<Windows::Foundation::Numerics::quaternion>(this->shim().Orientation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AbsoluteLinearVelocity(Windows::Foundation::Numerics::float3* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AbsoluteLinearVelocity, WINRT_WRAP(Windows::Foundation::Numerics::float3));
            *value = detach_from<Windows::Foundation::Numerics::float3>(this->shim().AbsoluteLinearVelocity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AbsoluteLinearAcceleration(Windows::Foundation::Numerics::float3* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AbsoluteLinearAcceleration, WINRT_WRAP(Windows::Foundation::Numerics::float3));
            *value = detach_from<Windows::Foundation::Numerics::float3>(this->shim().AbsoluteLinearAcceleration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AbsoluteAngularVelocity(Windows::Foundation::Numerics::quaternion* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AbsoluteAngularVelocity, WINRT_WRAP(Windows::Foundation::Numerics::quaternion));
            *value = detach_from<Windows::Foundation::Numerics::quaternion>(this->shim().AbsoluteAngularVelocity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AbsoluteAngularAcceleration(Windows::Foundation::Numerics::quaternion* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AbsoluteAngularAcceleration, WINRT_WRAP(Windows::Foundation::Numerics::quaternion));
            *value = detach_from<Windows::Foundation::Numerics::quaternion>(this->shim().AbsoluteAngularAcceleration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Perception::Spatial::ISpatialLocation2> : produce_base<D, Windows::Perception::Spatial::ISpatialLocation2>
{
    int32_t WINRT_CALL get_AbsoluteAngularVelocityAxisAngle(Windows::Foundation::Numerics::float3* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AbsoluteAngularVelocityAxisAngle, WINRT_WRAP(Windows::Foundation::Numerics::float3));
            *value = detach_from<Windows::Foundation::Numerics::float3>(this->shim().AbsoluteAngularVelocityAxisAngle());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AbsoluteAngularAccelerationAxisAngle(Windows::Foundation::Numerics::float3* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AbsoluteAngularAccelerationAxisAngle, WINRT_WRAP(Windows::Foundation::Numerics::float3));
            *value = detach_from<Windows::Foundation::Numerics::float3>(this->shim().AbsoluteAngularAccelerationAxisAngle());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Perception::Spatial::ISpatialLocator> : produce_base<D, Windows::Perception::Spatial::ISpatialLocator>
{
    int32_t WINRT_CALL get_Locatability(Windows::Perception::Spatial::SpatialLocatability* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Locatability, WINRT_WRAP(Windows::Perception::Spatial::SpatialLocatability));
            *value = detach_from<Windows::Perception::Spatial::SpatialLocatability>(this->shim().Locatability());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_LocatabilityChanged(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LocatabilityChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Perception::Spatial::SpatialLocator, Windows::Foundation::IInspectable> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().LocatabilityChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Perception::Spatial::SpatialLocator, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_LocatabilityChanged(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(LocatabilityChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().LocatabilityChanged(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_PositionalTrackingDeactivating(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PositionalTrackingDeactivating, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Perception::Spatial::SpatialLocator, Windows::Perception::Spatial::SpatialLocatorPositionalTrackingDeactivatingEventArgs> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().PositionalTrackingDeactivating(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Perception::Spatial::SpatialLocator, Windows::Perception::Spatial::SpatialLocatorPositionalTrackingDeactivatingEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PositionalTrackingDeactivating(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PositionalTrackingDeactivating, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PositionalTrackingDeactivating(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL TryLocateAtTimestamp(void* timestamp, void* coordinateSystem, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryLocateAtTimestamp, WINRT_WRAP(Windows::Perception::Spatial::SpatialLocation), Windows::Perception::PerceptionTimestamp const&, Windows::Perception::Spatial::SpatialCoordinateSystem const&);
            *value = detach_from<Windows::Perception::Spatial::SpatialLocation>(this->shim().TryLocateAtTimestamp(*reinterpret_cast<Windows::Perception::PerceptionTimestamp const*>(&timestamp), *reinterpret_cast<Windows::Perception::Spatial::SpatialCoordinateSystem const*>(&coordinateSystem)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateAttachedFrameOfReferenceAtCurrentHeading(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateAttachedFrameOfReferenceAtCurrentHeading, WINRT_WRAP(Windows::Perception::Spatial::SpatialLocatorAttachedFrameOfReference));
            *value = detach_from<Windows::Perception::Spatial::SpatialLocatorAttachedFrameOfReference>(this->shim().CreateAttachedFrameOfReferenceAtCurrentHeading());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateAttachedFrameOfReferenceAtCurrentHeadingWithPosition(Windows::Foundation::Numerics::float3 relativePosition, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateAttachedFrameOfReferenceAtCurrentHeading, WINRT_WRAP(Windows::Perception::Spatial::SpatialLocatorAttachedFrameOfReference), Windows::Foundation::Numerics::float3 const&);
            *value = detach_from<Windows::Perception::Spatial::SpatialLocatorAttachedFrameOfReference>(this->shim().CreateAttachedFrameOfReferenceAtCurrentHeading(*reinterpret_cast<Windows::Foundation::Numerics::float3 const*>(&relativePosition)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateAttachedFrameOfReferenceAtCurrentHeadingWithPositionAndOrientation(Windows::Foundation::Numerics::float3 relativePosition, Windows::Foundation::Numerics::quaternion relativeOrientation, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateAttachedFrameOfReferenceAtCurrentHeading, WINRT_WRAP(Windows::Perception::Spatial::SpatialLocatorAttachedFrameOfReference), Windows::Foundation::Numerics::float3 const&, Windows::Foundation::Numerics::quaternion const&);
            *value = detach_from<Windows::Perception::Spatial::SpatialLocatorAttachedFrameOfReference>(this->shim().CreateAttachedFrameOfReferenceAtCurrentHeading(*reinterpret_cast<Windows::Foundation::Numerics::float3 const*>(&relativePosition), *reinterpret_cast<Windows::Foundation::Numerics::quaternion const*>(&relativeOrientation)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateAttachedFrameOfReferenceAtCurrentHeadingWithPositionAndOrientationAndRelativeHeading(Windows::Foundation::Numerics::float3 relativePosition, Windows::Foundation::Numerics::quaternion relativeOrientation, double relativeHeadingInRadians, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateAttachedFrameOfReferenceAtCurrentHeading, WINRT_WRAP(Windows::Perception::Spatial::SpatialLocatorAttachedFrameOfReference), Windows::Foundation::Numerics::float3 const&, Windows::Foundation::Numerics::quaternion const&, double);
            *value = detach_from<Windows::Perception::Spatial::SpatialLocatorAttachedFrameOfReference>(this->shim().CreateAttachedFrameOfReferenceAtCurrentHeading(*reinterpret_cast<Windows::Foundation::Numerics::float3 const*>(&relativePosition), *reinterpret_cast<Windows::Foundation::Numerics::quaternion const*>(&relativeOrientation), relativeHeadingInRadians));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateStationaryFrameOfReferenceAtCurrentLocation(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateStationaryFrameOfReferenceAtCurrentLocation, WINRT_WRAP(Windows::Perception::Spatial::SpatialStationaryFrameOfReference));
            *value = detach_from<Windows::Perception::Spatial::SpatialStationaryFrameOfReference>(this->shim().CreateStationaryFrameOfReferenceAtCurrentLocation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateStationaryFrameOfReferenceAtCurrentLocationWithPosition(Windows::Foundation::Numerics::float3 relativePosition, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateStationaryFrameOfReferenceAtCurrentLocation, WINRT_WRAP(Windows::Perception::Spatial::SpatialStationaryFrameOfReference), Windows::Foundation::Numerics::float3 const&);
            *value = detach_from<Windows::Perception::Spatial::SpatialStationaryFrameOfReference>(this->shim().CreateStationaryFrameOfReferenceAtCurrentLocation(*reinterpret_cast<Windows::Foundation::Numerics::float3 const*>(&relativePosition)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateStationaryFrameOfReferenceAtCurrentLocationWithPositionAndOrientation(Windows::Foundation::Numerics::float3 relativePosition, Windows::Foundation::Numerics::quaternion relativeOrientation, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateStationaryFrameOfReferenceAtCurrentLocation, WINRT_WRAP(Windows::Perception::Spatial::SpatialStationaryFrameOfReference), Windows::Foundation::Numerics::float3 const&, Windows::Foundation::Numerics::quaternion const&);
            *value = detach_from<Windows::Perception::Spatial::SpatialStationaryFrameOfReference>(this->shim().CreateStationaryFrameOfReferenceAtCurrentLocation(*reinterpret_cast<Windows::Foundation::Numerics::float3 const*>(&relativePosition), *reinterpret_cast<Windows::Foundation::Numerics::quaternion const*>(&relativeOrientation)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateStationaryFrameOfReferenceAtCurrentLocationWithPositionAndOrientationAndRelativeHeading(Windows::Foundation::Numerics::float3 relativePosition, Windows::Foundation::Numerics::quaternion relativeOrientation, double relativeHeadingInRadians, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateStationaryFrameOfReferenceAtCurrentLocation, WINRT_WRAP(Windows::Perception::Spatial::SpatialStationaryFrameOfReference), Windows::Foundation::Numerics::float3 const&, Windows::Foundation::Numerics::quaternion const&, double);
            *value = detach_from<Windows::Perception::Spatial::SpatialStationaryFrameOfReference>(this->shim().CreateStationaryFrameOfReferenceAtCurrentLocation(*reinterpret_cast<Windows::Foundation::Numerics::float3 const*>(&relativePosition), *reinterpret_cast<Windows::Foundation::Numerics::quaternion const*>(&relativeOrientation), relativeHeadingInRadians));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Perception::Spatial::ISpatialLocatorAttachedFrameOfReference> : produce_base<D, Windows::Perception::Spatial::ISpatialLocatorAttachedFrameOfReference>
{
    int32_t WINRT_CALL get_RelativePosition(Windows::Foundation::Numerics::float3* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RelativePosition, WINRT_WRAP(Windows::Foundation::Numerics::float3));
            *value = detach_from<Windows::Foundation::Numerics::float3>(this->shim().RelativePosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RelativePosition(Windows::Foundation::Numerics::float3 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RelativePosition, WINRT_WRAP(void), Windows::Foundation::Numerics::float3 const&);
            this->shim().RelativePosition(*reinterpret_cast<Windows::Foundation::Numerics::float3 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RelativeOrientation(Windows::Foundation::Numerics::quaternion* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RelativeOrientation, WINRT_WRAP(Windows::Foundation::Numerics::quaternion));
            *value = detach_from<Windows::Foundation::Numerics::quaternion>(this->shim().RelativeOrientation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RelativeOrientation(Windows::Foundation::Numerics::quaternion value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RelativeOrientation, WINRT_WRAP(void), Windows::Foundation::Numerics::quaternion const&);
            this->shim().RelativeOrientation(*reinterpret_cast<Windows::Foundation::Numerics::quaternion const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AdjustHeading(double headingOffsetInRadians) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AdjustHeading, WINRT_WRAP(void), double);
            this->shim().AdjustHeading(headingOffsetInRadians);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetStationaryCoordinateSystemAtTimestamp(void* timestamp, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetStationaryCoordinateSystemAtTimestamp, WINRT_WRAP(Windows::Perception::Spatial::SpatialCoordinateSystem), Windows::Perception::PerceptionTimestamp const&);
            *value = detach_from<Windows::Perception::Spatial::SpatialCoordinateSystem>(this->shim().GetStationaryCoordinateSystemAtTimestamp(*reinterpret_cast<Windows::Perception::PerceptionTimestamp const*>(&timestamp)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryGetRelativeHeadingAtTimestamp(void* timestamp, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryGetRelativeHeadingAtTimestamp, WINRT_WRAP(Windows::Foundation::IReference<double>), Windows::Perception::PerceptionTimestamp const&);
            *value = detach_from<Windows::Foundation::IReference<double>>(this->shim().TryGetRelativeHeadingAtTimestamp(*reinterpret_cast<Windows::Perception::PerceptionTimestamp const*>(&timestamp)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Perception::Spatial::ISpatialLocatorPositionalTrackingDeactivatingEventArgs> : produce_base<D, Windows::Perception::Spatial::ISpatialLocatorPositionalTrackingDeactivatingEventArgs>
{
    int32_t WINRT_CALL get_Canceled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Canceled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Canceled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Canceled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Canceled, WINRT_WRAP(void), bool);
            this->shim().Canceled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Perception::Spatial::ISpatialLocatorStatics> : produce_base<D, Windows::Perception::Spatial::ISpatialLocatorStatics>
{
    int32_t WINRT_CALL GetDefault(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefault, WINRT_WRAP(Windows::Perception::Spatial::SpatialLocator));
            *value = detach_from<Windows::Perception::Spatial::SpatialLocator>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Perception::Spatial::ISpatialStageFrameOfReference> : produce_base<D, Windows::Perception::Spatial::ISpatialStageFrameOfReference>
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

    int32_t WINRT_CALL get_MovementRange(Windows::Perception::Spatial::SpatialMovementRange* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MovementRange, WINRT_WRAP(Windows::Perception::Spatial::SpatialMovementRange));
            *value = detach_from<Windows::Perception::Spatial::SpatialMovementRange>(this->shim().MovementRange());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LookDirectionRange(Windows::Perception::Spatial::SpatialLookDirectionRange* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LookDirectionRange, WINRT_WRAP(Windows::Perception::Spatial::SpatialLookDirectionRange));
            *value = detach_from<Windows::Perception::Spatial::SpatialLookDirectionRange>(this->shim().LookDirectionRange());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetCoordinateSystemAtCurrentLocation(void* locator, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCoordinateSystemAtCurrentLocation, WINRT_WRAP(Windows::Perception::Spatial::SpatialCoordinateSystem), Windows::Perception::Spatial::SpatialLocator const&);
            *result = detach_from<Windows::Perception::Spatial::SpatialCoordinateSystem>(this->shim().GetCoordinateSystemAtCurrentLocation(*reinterpret_cast<Windows::Perception::Spatial::SpatialLocator const*>(&locator)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryGetMovementBounds(void* coordinateSystem, uint32_t* __valueSize, Windows::Foundation::Numerics::float3** value) noexcept final
    {
        try
        {
            *__valueSize = 0;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryGetMovementBounds, WINRT_WRAP(com_array<Windows::Foundation::Numerics::float3>), Windows::Perception::Spatial::SpatialCoordinateSystem const&);
            std::tie(*__valueSize, *value) = detach_abi(this->shim().TryGetMovementBounds(*reinterpret_cast<Windows::Perception::Spatial::SpatialCoordinateSystem const*>(&coordinateSystem)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Perception::Spatial::ISpatialStageFrameOfReferenceStatics> : produce_base<D, Windows::Perception::Spatial::ISpatialStageFrameOfReferenceStatics>
{
    int32_t WINRT_CALL get_Current(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Current, WINRT_WRAP(Windows::Perception::Spatial::SpatialStageFrameOfReference));
            *value = detach_from<Windows::Perception::Spatial::SpatialStageFrameOfReference>(this->shim().Current());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_CurrentChanged(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CurrentChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().CurrentChanged(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_CurrentChanged(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(CurrentChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().CurrentChanged(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL RequestNewStageAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestNewStageAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Perception::Spatial::SpatialStageFrameOfReference>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Perception::Spatial::SpatialStageFrameOfReference>>(this->shim().RequestNewStageAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Perception::Spatial::ISpatialStationaryFrameOfReference> : produce_base<D, Windows::Perception::Spatial::ISpatialStationaryFrameOfReference>
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
};

}

WINRT_EXPORT namespace winrt::Windows::Perception::Spatial {

inline Windows::Perception::Spatial::SpatialAnchor SpatialAnchor::TryCreateRelativeTo(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem)
{
    return impl::call_factory<SpatialAnchor, Windows::Perception::Spatial::ISpatialAnchorStatics>([&](auto&& f) { return f.TryCreateRelativeTo(coordinateSystem); });
}

inline Windows::Perception::Spatial::SpatialAnchor SpatialAnchor::TryCreateRelativeTo(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem, Windows::Foundation::Numerics::float3 const& position)
{
    return impl::call_factory<SpatialAnchor, Windows::Perception::Spatial::ISpatialAnchorStatics>([&](auto&& f) { return f.TryCreateRelativeTo(coordinateSystem, position); });
}

inline Windows::Perception::Spatial::SpatialAnchor SpatialAnchor::TryCreateRelativeTo(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem, Windows::Foundation::Numerics::float3 const& position, Windows::Foundation::Numerics::quaternion const& orientation)
{
    return impl::call_factory<SpatialAnchor, Windows::Perception::Spatial::ISpatialAnchorStatics>([&](auto&& f) { return f.TryCreateRelativeTo(coordinateSystem, position, orientation); });
}

inline Windows::Perception::Spatial::SpatialAnchorExporter SpatialAnchorExporter::GetDefault()
{
    return impl::call_factory<SpatialAnchorExporter, Windows::Perception::Spatial::ISpatialAnchorExporterStatics>([&](auto&& f) { return f.GetDefault(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Perception::Spatial::SpatialPerceptionAccessStatus> SpatialAnchorExporter::RequestAccessAsync()
{
    return impl::call_factory<SpatialAnchorExporter, Windows::Perception::Spatial::ISpatialAnchorExporterStatics>([&](auto&& f) { return f.RequestAccessAsync(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Perception::Spatial::SpatialAnchorStore> SpatialAnchorManager::RequestStoreAsync()
{
    return impl::call_factory<SpatialAnchorManager, Windows::Perception::Spatial::ISpatialAnchorManagerStatics>([&](auto&& f) { return f.RequestStoreAsync(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IMapView<hstring, Windows::Perception::Spatial::SpatialAnchor>> SpatialAnchorTransferManager::TryImportAnchorsAsync(Windows::Storage::Streams::IInputStream const& stream)
{
    return impl::call_factory<SpatialAnchorTransferManager, Windows::Perception::Spatial::ISpatialAnchorTransferManagerStatics>([&](auto&& f) { return f.TryImportAnchorsAsync(stream); });
}

inline Windows::Foundation::IAsyncOperation<bool> SpatialAnchorTransferManager::TryExportAnchorsAsync(param::async_iterable<Windows::Foundation::Collections::IKeyValuePair<hstring, Windows::Perception::Spatial::SpatialAnchor>> const& anchors, Windows::Storage::Streams::IOutputStream const& stream)
{
    return impl::call_factory<SpatialAnchorTransferManager, Windows::Perception::Spatial::ISpatialAnchorTransferManagerStatics>([&](auto&& f) { return f.TryExportAnchorsAsync(anchors, stream); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Perception::Spatial::SpatialPerceptionAccessStatus> SpatialAnchorTransferManager::RequestAccessAsync()
{
    return impl::call_factory<SpatialAnchorTransferManager, Windows::Perception::Spatial::ISpatialAnchorTransferManagerStatics>([&](auto&& f) { return f.RequestAccessAsync(); });
}

inline Windows::Perception::Spatial::SpatialBoundingVolume SpatialBoundingVolume::FromBox(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem, Windows::Perception::Spatial::SpatialBoundingBox const& box)
{
    return impl::call_factory<SpatialBoundingVolume, Windows::Perception::Spatial::ISpatialBoundingVolumeStatics>([&](auto&& f) { return f.FromBox(coordinateSystem, box); });
}

inline Windows::Perception::Spatial::SpatialBoundingVolume SpatialBoundingVolume::FromOrientedBox(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem, Windows::Perception::Spatial::SpatialBoundingOrientedBox const& box)
{
    return impl::call_factory<SpatialBoundingVolume, Windows::Perception::Spatial::ISpatialBoundingVolumeStatics>([&](auto&& f) { return f.FromOrientedBox(coordinateSystem, box); });
}

inline Windows::Perception::Spatial::SpatialBoundingVolume SpatialBoundingVolume::FromSphere(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem, Windows::Perception::Spatial::SpatialBoundingSphere const& sphere)
{
    return impl::call_factory<SpatialBoundingVolume, Windows::Perception::Spatial::ISpatialBoundingVolumeStatics>([&](auto&& f) { return f.FromSphere(coordinateSystem, sphere); });
}

inline Windows::Perception::Spatial::SpatialBoundingVolume SpatialBoundingVolume::FromFrustum(Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem, Windows::Perception::Spatial::SpatialBoundingFrustum const& frustum)
{
    return impl::call_factory<SpatialBoundingVolume, Windows::Perception::Spatial::ISpatialBoundingVolumeStatics>([&](auto&& f) { return f.FromFrustum(coordinateSystem, frustum); });
}

inline SpatialEntity::SpatialEntity(Windows::Perception::Spatial::SpatialAnchor const& spatialAnchor) :
    SpatialEntity(impl::call_factory<SpatialEntity, Windows::Perception::Spatial::ISpatialEntityFactory>([&](auto&& f) { return f.CreateWithSpatialAnchor(spatialAnchor); }))
{}

inline SpatialEntity::SpatialEntity(Windows::Perception::Spatial::SpatialAnchor const& spatialAnchor, Windows::Foundation::Collections::ValueSet const& propertySet) :
    SpatialEntity(impl::call_factory<SpatialEntity, Windows::Perception::Spatial::ISpatialEntityFactory>([&](auto&& f) { return f.CreateWithSpatialAnchorAndProperties(spatialAnchor, propertySet); }))
{}

inline bool SpatialEntityStore::IsSupported()
{
    return impl::call_factory<SpatialEntityStore, Windows::Perception::Spatial::ISpatialEntityStoreStatics>([&](auto&& f) { return f.IsSupported(); });
}

inline Windows::Perception::Spatial::SpatialEntityStore SpatialEntityStore::TryGet(Windows::System::RemoteSystems::RemoteSystemSession const& session)
{
    return impl::call_factory<SpatialEntityStore, Windows::Perception::Spatial::ISpatialEntityStoreStatics>([&](auto&& f) { return f.TryGet(session); });
}

inline Windows::Perception::Spatial::SpatialLocator SpatialLocator::GetDefault()
{
    return impl::call_factory<SpatialLocator, Windows::Perception::Spatial::ISpatialLocatorStatics>([&](auto&& f) { return f.GetDefault(); });
}

inline Windows::Perception::Spatial::SpatialStageFrameOfReference SpatialStageFrameOfReference::Current()
{
    return impl::call_factory<SpatialStageFrameOfReference, Windows::Perception::Spatial::ISpatialStageFrameOfReferenceStatics>([&](auto&& f) { return f.Current(); });
}

inline winrt::event_token SpatialStageFrameOfReference::CurrentChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    return impl::call_factory<SpatialStageFrameOfReference, Windows::Perception::Spatial::ISpatialStageFrameOfReferenceStatics>([&](auto&& f) { return f.CurrentChanged(handler); });
}

inline SpatialStageFrameOfReference::CurrentChanged_revoker SpatialStageFrameOfReference::CurrentChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    auto f = get_activation_factory<SpatialStageFrameOfReference, Windows::Perception::Spatial::ISpatialStageFrameOfReferenceStatics>();
    return { f, f.CurrentChanged(handler) };
}

inline void SpatialStageFrameOfReference::CurrentChanged(winrt::event_token const& cookie)
{
    impl::call_factory<SpatialStageFrameOfReference, Windows::Perception::Spatial::ISpatialStageFrameOfReferenceStatics>([&](auto&& f) { return f.CurrentChanged(cookie); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Perception::Spatial::SpatialStageFrameOfReference> SpatialStageFrameOfReference::RequestNewStageAsync()
{
    return impl::call_factory<SpatialStageFrameOfReference, Windows::Perception::Spatial::ISpatialStageFrameOfReferenceStatics>([&](auto&& f) { return f.RequestNewStageAsync(); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Perception::Spatial::ISpatialAnchor> : winrt::impl::hash_base<winrt::Windows::Perception::Spatial::ISpatialAnchor> {};
template<> struct hash<winrt::Windows::Perception::Spatial::ISpatialAnchor2> : winrt::impl::hash_base<winrt::Windows::Perception::Spatial::ISpatialAnchor2> {};
template<> struct hash<winrt::Windows::Perception::Spatial::ISpatialAnchorExportSufficiency> : winrt::impl::hash_base<winrt::Windows::Perception::Spatial::ISpatialAnchorExportSufficiency> {};
template<> struct hash<winrt::Windows::Perception::Spatial::ISpatialAnchorExporter> : winrt::impl::hash_base<winrt::Windows::Perception::Spatial::ISpatialAnchorExporter> {};
template<> struct hash<winrt::Windows::Perception::Spatial::ISpatialAnchorExporterStatics> : winrt::impl::hash_base<winrt::Windows::Perception::Spatial::ISpatialAnchorExporterStatics> {};
template<> struct hash<winrt::Windows::Perception::Spatial::ISpatialAnchorManagerStatics> : winrt::impl::hash_base<winrt::Windows::Perception::Spatial::ISpatialAnchorManagerStatics> {};
template<> struct hash<winrt::Windows::Perception::Spatial::ISpatialAnchorRawCoordinateSystemAdjustedEventArgs> : winrt::impl::hash_base<winrt::Windows::Perception::Spatial::ISpatialAnchorRawCoordinateSystemAdjustedEventArgs> {};
template<> struct hash<winrt::Windows::Perception::Spatial::ISpatialAnchorStatics> : winrt::impl::hash_base<winrt::Windows::Perception::Spatial::ISpatialAnchorStatics> {};
template<> struct hash<winrt::Windows::Perception::Spatial::ISpatialAnchorStore> : winrt::impl::hash_base<winrt::Windows::Perception::Spatial::ISpatialAnchorStore> {};
template<> struct hash<winrt::Windows::Perception::Spatial::ISpatialAnchorTransferManagerStatics> : winrt::impl::hash_base<winrt::Windows::Perception::Spatial::ISpatialAnchorTransferManagerStatics> {};
template<> struct hash<winrt::Windows::Perception::Spatial::ISpatialBoundingVolume> : winrt::impl::hash_base<winrt::Windows::Perception::Spatial::ISpatialBoundingVolume> {};
template<> struct hash<winrt::Windows::Perception::Spatial::ISpatialBoundingVolumeStatics> : winrt::impl::hash_base<winrt::Windows::Perception::Spatial::ISpatialBoundingVolumeStatics> {};
template<> struct hash<winrt::Windows::Perception::Spatial::ISpatialCoordinateSystem> : winrt::impl::hash_base<winrt::Windows::Perception::Spatial::ISpatialCoordinateSystem> {};
template<> struct hash<winrt::Windows::Perception::Spatial::ISpatialEntity> : winrt::impl::hash_base<winrt::Windows::Perception::Spatial::ISpatialEntity> {};
template<> struct hash<winrt::Windows::Perception::Spatial::ISpatialEntityAddedEventArgs> : winrt::impl::hash_base<winrt::Windows::Perception::Spatial::ISpatialEntityAddedEventArgs> {};
template<> struct hash<winrt::Windows::Perception::Spatial::ISpatialEntityFactory> : winrt::impl::hash_base<winrt::Windows::Perception::Spatial::ISpatialEntityFactory> {};
template<> struct hash<winrt::Windows::Perception::Spatial::ISpatialEntityRemovedEventArgs> : winrt::impl::hash_base<winrt::Windows::Perception::Spatial::ISpatialEntityRemovedEventArgs> {};
template<> struct hash<winrt::Windows::Perception::Spatial::ISpatialEntityStore> : winrt::impl::hash_base<winrt::Windows::Perception::Spatial::ISpatialEntityStore> {};
template<> struct hash<winrt::Windows::Perception::Spatial::ISpatialEntityStoreStatics> : winrt::impl::hash_base<winrt::Windows::Perception::Spatial::ISpatialEntityStoreStatics> {};
template<> struct hash<winrt::Windows::Perception::Spatial::ISpatialEntityUpdatedEventArgs> : winrt::impl::hash_base<winrt::Windows::Perception::Spatial::ISpatialEntityUpdatedEventArgs> {};
template<> struct hash<winrt::Windows::Perception::Spatial::ISpatialEntityWatcher> : winrt::impl::hash_base<winrt::Windows::Perception::Spatial::ISpatialEntityWatcher> {};
template<> struct hash<winrt::Windows::Perception::Spatial::ISpatialLocation> : winrt::impl::hash_base<winrt::Windows::Perception::Spatial::ISpatialLocation> {};
template<> struct hash<winrt::Windows::Perception::Spatial::ISpatialLocation2> : winrt::impl::hash_base<winrt::Windows::Perception::Spatial::ISpatialLocation2> {};
template<> struct hash<winrt::Windows::Perception::Spatial::ISpatialLocator> : winrt::impl::hash_base<winrt::Windows::Perception::Spatial::ISpatialLocator> {};
template<> struct hash<winrt::Windows::Perception::Spatial::ISpatialLocatorAttachedFrameOfReference> : winrt::impl::hash_base<winrt::Windows::Perception::Spatial::ISpatialLocatorAttachedFrameOfReference> {};
template<> struct hash<winrt::Windows::Perception::Spatial::ISpatialLocatorPositionalTrackingDeactivatingEventArgs> : winrt::impl::hash_base<winrt::Windows::Perception::Spatial::ISpatialLocatorPositionalTrackingDeactivatingEventArgs> {};
template<> struct hash<winrt::Windows::Perception::Spatial::ISpatialLocatorStatics> : winrt::impl::hash_base<winrt::Windows::Perception::Spatial::ISpatialLocatorStatics> {};
template<> struct hash<winrt::Windows::Perception::Spatial::ISpatialStageFrameOfReference> : winrt::impl::hash_base<winrt::Windows::Perception::Spatial::ISpatialStageFrameOfReference> {};
template<> struct hash<winrt::Windows::Perception::Spatial::ISpatialStageFrameOfReferenceStatics> : winrt::impl::hash_base<winrt::Windows::Perception::Spatial::ISpatialStageFrameOfReferenceStatics> {};
template<> struct hash<winrt::Windows::Perception::Spatial::ISpatialStationaryFrameOfReference> : winrt::impl::hash_base<winrt::Windows::Perception::Spatial::ISpatialStationaryFrameOfReference> {};
template<> struct hash<winrt::Windows::Perception::Spatial::SpatialAnchor> : winrt::impl::hash_base<winrt::Windows::Perception::Spatial::SpatialAnchor> {};
template<> struct hash<winrt::Windows::Perception::Spatial::SpatialAnchorExportSufficiency> : winrt::impl::hash_base<winrt::Windows::Perception::Spatial::SpatialAnchorExportSufficiency> {};
template<> struct hash<winrt::Windows::Perception::Spatial::SpatialAnchorExporter> : winrt::impl::hash_base<winrt::Windows::Perception::Spatial::SpatialAnchorExporter> {};
template<> struct hash<winrt::Windows::Perception::Spatial::SpatialAnchorManager> : winrt::impl::hash_base<winrt::Windows::Perception::Spatial::SpatialAnchorManager> {};
template<> struct hash<winrt::Windows::Perception::Spatial::SpatialAnchorRawCoordinateSystemAdjustedEventArgs> : winrt::impl::hash_base<winrt::Windows::Perception::Spatial::SpatialAnchorRawCoordinateSystemAdjustedEventArgs> {};
template<> struct hash<winrt::Windows::Perception::Spatial::SpatialAnchorStore> : winrt::impl::hash_base<winrt::Windows::Perception::Spatial::SpatialAnchorStore> {};
template<> struct hash<winrt::Windows::Perception::Spatial::SpatialAnchorTransferManager> : winrt::impl::hash_base<winrt::Windows::Perception::Spatial::SpatialAnchorTransferManager> {};
template<> struct hash<winrt::Windows::Perception::Spatial::SpatialBoundingVolume> : winrt::impl::hash_base<winrt::Windows::Perception::Spatial::SpatialBoundingVolume> {};
template<> struct hash<winrt::Windows::Perception::Spatial::SpatialCoordinateSystem> : winrt::impl::hash_base<winrt::Windows::Perception::Spatial::SpatialCoordinateSystem> {};
template<> struct hash<winrt::Windows::Perception::Spatial::SpatialEntity> : winrt::impl::hash_base<winrt::Windows::Perception::Spatial::SpatialEntity> {};
template<> struct hash<winrt::Windows::Perception::Spatial::SpatialEntityAddedEventArgs> : winrt::impl::hash_base<winrt::Windows::Perception::Spatial::SpatialEntityAddedEventArgs> {};
template<> struct hash<winrt::Windows::Perception::Spatial::SpatialEntityRemovedEventArgs> : winrt::impl::hash_base<winrt::Windows::Perception::Spatial::SpatialEntityRemovedEventArgs> {};
template<> struct hash<winrt::Windows::Perception::Spatial::SpatialEntityStore> : winrt::impl::hash_base<winrt::Windows::Perception::Spatial::SpatialEntityStore> {};
template<> struct hash<winrt::Windows::Perception::Spatial::SpatialEntityUpdatedEventArgs> : winrt::impl::hash_base<winrt::Windows::Perception::Spatial::SpatialEntityUpdatedEventArgs> {};
template<> struct hash<winrt::Windows::Perception::Spatial::SpatialEntityWatcher> : winrt::impl::hash_base<winrt::Windows::Perception::Spatial::SpatialEntityWatcher> {};
template<> struct hash<winrt::Windows::Perception::Spatial::SpatialLocation> : winrt::impl::hash_base<winrt::Windows::Perception::Spatial::SpatialLocation> {};
template<> struct hash<winrt::Windows::Perception::Spatial::SpatialLocator> : winrt::impl::hash_base<winrt::Windows::Perception::Spatial::SpatialLocator> {};
template<> struct hash<winrt::Windows::Perception::Spatial::SpatialLocatorAttachedFrameOfReference> : winrt::impl::hash_base<winrt::Windows::Perception::Spatial::SpatialLocatorAttachedFrameOfReference> {};
template<> struct hash<winrt::Windows::Perception::Spatial::SpatialLocatorPositionalTrackingDeactivatingEventArgs> : winrt::impl::hash_base<winrt::Windows::Perception::Spatial::SpatialLocatorPositionalTrackingDeactivatingEventArgs> {};
template<> struct hash<winrt::Windows::Perception::Spatial::SpatialStageFrameOfReference> : winrt::impl::hash_base<winrt::Windows::Perception::Spatial::SpatialStageFrameOfReference> {};
template<> struct hash<winrt::Windows::Perception::Spatial::SpatialStationaryFrameOfReference> : winrt::impl::hash_base<winrt::Windows::Perception::Spatial::SpatialStationaryFrameOfReference> {};

}
