// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Devices.Geolocation.2.h"
#include "winrt/Windows.Devices.h"

namespace winrt::impl {

template <typename D> hstring consume_Windows_Devices_Geolocation_ICivicAddress<D>::Country() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::ICivicAddress)->get_Country(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Geolocation_ICivicAddress<D>::State() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::ICivicAddress)->get_State(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Geolocation_ICivicAddress<D>::City() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::ICivicAddress)->get_City(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Geolocation_ICivicAddress<D>::PostalCode() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::ICivicAddress)->get_PostalCode(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_Devices_Geolocation_ICivicAddress<D>::Timestamp() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::ICivicAddress)->get_Timestamp(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Geolocation::BasicGeoposition consume_Windows_Devices_Geolocation_IGeoboundingBox<D>::NorthwestCorner() const
{
    Windows::Devices::Geolocation::BasicGeoposition value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeoboundingBox)->get_NorthwestCorner(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Geolocation::BasicGeoposition consume_Windows_Devices_Geolocation_IGeoboundingBox<D>::SoutheastCorner() const
{
    Windows::Devices::Geolocation::BasicGeoposition value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeoboundingBox)->get_SoutheastCorner(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Geolocation::BasicGeoposition consume_Windows_Devices_Geolocation_IGeoboundingBox<D>::Center() const
{
    Windows::Devices::Geolocation::BasicGeoposition value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeoboundingBox)->get_Center(put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_Devices_Geolocation_IGeoboundingBox<D>::MinAltitude() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeoboundingBox)->get_MinAltitude(&value));
    return value;
}

template <typename D> double consume_Windows_Devices_Geolocation_IGeoboundingBox<D>::MaxAltitude() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeoboundingBox)->get_MaxAltitude(&value));
    return value;
}

template <typename D> Windows::Devices::Geolocation::GeoboundingBox consume_Windows_Devices_Geolocation_IGeoboundingBoxFactory<D>::Create(Windows::Devices::Geolocation::BasicGeoposition const& northwestCorner, Windows::Devices::Geolocation::BasicGeoposition const& southeastCorner) const
{
    Windows::Devices::Geolocation::GeoboundingBox value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeoboundingBoxFactory)->Create(get_abi(northwestCorner), get_abi(southeastCorner), put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Geolocation::GeoboundingBox consume_Windows_Devices_Geolocation_IGeoboundingBoxFactory<D>::CreateWithAltitudeReference(Windows::Devices::Geolocation::BasicGeoposition const& northwestCorner, Windows::Devices::Geolocation::BasicGeoposition const& southeastCorner, Windows::Devices::Geolocation::AltitudeReferenceSystem const& altitudeReferenceSystem) const
{
    Windows::Devices::Geolocation::GeoboundingBox value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeoboundingBoxFactory)->CreateWithAltitudeReference(get_abi(northwestCorner), get_abi(southeastCorner), get_abi(altitudeReferenceSystem), put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Geolocation::GeoboundingBox consume_Windows_Devices_Geolocation_IGeoboundingBoxFactory<D>::CreateWithAltitudeReferenceAndSpatialReference(Windows::Devices::Geolocation::BasicGeoposition const& northwestCorner, Windows::Devices::Geolocation::BasicGeoposition const& southeastCorner, Windows::Devices::Geolocation::AltitudeReferenceSystem const& altitudeReferenceSystem, uint32_t spatialReferenceId) const
{
    Windows::Devices::Geolocation::GeoboundingBox value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeoboundingBoxFactory)->CreateWithAltitudeReferenceAndSpatialReference(get_abi(northwestCorner), get_abi(southeastCorner), get_abi(altitudeReferenceSystem), spatialReferenceId, put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Geolocation::GeoboundingBox consume_Windows_Devices_Geolocation_IGeoboundingBoxStatics<D>::TryCompute(param::iterable<Windows::Devices::Geolocation::BasicGeoposition> const& positions) const
{
    Windows::Devices::Geolocation::GeoboundingBox value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeoboundingBoxStatics)->TryCompute(get_abi(positions), put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Geolocation::GeoboundingBox consume_Windows_Devices_Geolocation_IGeoboundingBoxStatics<D>::TryCompute(param::iterable<Windows::Devices::Geolocation::BasicGeoposition> const& positions, Windows::Devices::Geolocation::AltitudeReferenceSystem const& altitudeRefSystem) const
{
    Windows::Devices::Geolocation::GeoboundingBox value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeoboundingBoxStatics)->TryComputeWithAltitudeReference(get_abi(positions), get_abi(altitudeRefSystem), put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Geolocation::GeoboundingBox consume_Windows_Devices_Geolocation_IGeoboundingBoxStatics<D>::TryCompute(param::iterable<Windows::Devices::Geolocation::BasicGeoposition> const& positions, Windows::Devices::Geolocation::AltitudeReferenceSystem const& altitudeRefSystem, uint32_t spatialReferenceId) const
{
    Windows::Devices::Geolocation::GeoboundingBox value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeoboundingBoxStatics)->TryComputeWithAltitudeReferenceAndSpatialReference(get_abi(positions), get_abi(altitudeRefSystem), spatialReferenceId, put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Geolocation::BasicGeoposition consume_Windows_Devices_Geolocation_IGeocircle<D>::Center() const
{
    Windows::Devices::Geolocation::BasicGeoposition value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeocircle)->get_Center(put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_Devices_Geolocation_IGeocircle<D>::Radius() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeocircle)->get_Radius(&value));
    return value;
}

template <typename D> Windows::Devices::Geolocation::Geocircle consume_Windows_Devices_Geolocation_IGeocircleFactory<D>::Create(Windows::Devices::Geolocation::BasicGeoposition const& position, double radius) const
{
    Windows::Devices::Geolocation::Geocircle value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeocircleFactory)->Create(get_abi(position), radius, put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Geolocation::Geocircle consume_Windows_Devices_Geolocation_IGeocircleFactory<D>::CreateWithAltitudeReferenceSystem(Windows::Devices::Geolocation::BasicGeoposition const& position, double radius, Windows::Devices::Geolocation::AltitudeReferenceSystem const& altitudeReferenceSystem) const
{
    Windows::Devices::Geolocation::Geocircle value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeocircleFactory)->CreateWithAltitudeReferenceSystem(get_abi(position), radius, get_abi(altitudeReferenceSystem), put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Geolocation::Geocircle consume_Windows_Devices_Geolocation_IGeocircleFactory<D>::CreateWithAltitudeReferenceSystemAndSpatialReferenceId(Windows::Devices::Geolocation::BasicGeoposition const& position, double radius, Windows::Devices::Geolocation::AltitudeReferenceSystem const& altitudeReferenceSystem, uint32_t spatialReferenceId) const
{
    Windows::Devices::Geolocation::Geocircle value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeocircleFactory)->CreateWithAltitudeReferenceSystemAndSpatialReferenceId(get_abi(position), radius, get_abi(altitudeReferenceSystem), spatialReferenceId, put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_Devices_Geolocation_IGeocoordinate<D>::Latitude() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeocoordinate)->get_Latitude(&value));
    return value;
}

template <typename D> double consume_Windows_Devices_Geolocation_IGeocoordinate<D>::Longitude() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeocoordinate)->get_Longitude(&value));
    return value;
}

template <typename D> Windows::Foundation::IReference<double> consume_Windows_Devices_Geolocation_IGeocoordinate<D>::Altitude() const
{
    Windows::Foundation::IReference<double> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeocoordinate)->get_Altitude(put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_Devices_Geolocation_IGeocoordinate<D>::Accuracy() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeocoordinate)->get_Accuracy(&value));
    return value;
}

template <typename D> Windows::Foundation::IReference<double> consume_Windows_Devices_Geolocation_IGeocoordinate<D>::AltitudeAccuracy() const
{
    Windows::Foundation::IReference<double> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeocoordinate)->get_AltitudeAccuracy(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<double> consume_Windows_Devices_Geolocation_IGeocoordinate<D>::Heading() const
{
    Windows::Foundation::IReference<double> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeocoordinate)->get_Heading(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<double> consume_Windows_Devices_Geolocation_IGeocoordinate<D>::Speed() const
{
    Windows::Foundation::IReference<double> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeocoordinate)->get_Speed(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_Devices_Geolocation_IGeocoordinate<D>::Timestamp() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeocoordinate)->get_Timestamp(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<double> consume_Windows_Devices_Geolocation_IGeocoordinateSatelliteData<D>::PositionDilutionOfPrecision() const
{
    Windows::Foundation::IReference<double> ppValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeocoordinateSatelliteData)->get_PositionDilutionOfPrecision(put_abi(ppValue)));
    return ppValue;
}

template <typename D> Windows::Foundation::IReference<double> consume_Windows_Devices_Geolocation_IGeocoordinateSatelliteData<D>::HorizontalDilutionOfPrecision() const
{
    Windows::Foundation::IReference<double> ppValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeocoordinateSatelliteData)->get_HorizontalDilutionOfPrecision(put_abi(ppValue)));
    return ppValue;
}

template <typename D> Windows::Foundation::IReference<double> consume_Windows_Devices_Geolocation_IGeocoordinateSatelliteData<D>::VerticalDilutionOfPrecision() const
{
    Windows::Foundation::IReference<double> ppValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeocoordinateSatelliteData)->get_VerticalDilutionOfPrecision(put_abi(ppValue)));
    return ppValue;
}

template <typename D> Windows::Devices::Geolocation::Geopoint consume_Windows_Devices_Geolocation_IGeocoordinateWithPoint<D>::Point() const
{
    Windows::Devices::Geolocation::Geopoint value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeocoordinateWithPoint)->get_Point(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Geolocation::PositionSource consume_Windows_Devices_Geolocation_IGeocoordinateWithPositionData<D>::PositionSource() const
{
    Windows::Devices::Geolocation::PositionSource pValue{};
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeocoordinateWithPositionData)->get_PositionSource(put_abi(pValue)));
    return pValue;
}

template <typename D> Windows::Devices::Geolocation::GeocoordinateSatelliteData consume_Windows_Devices_Geolocation_IGeocoordinateWithPositionData<D>::SatelliteData() const
{
    Windows::Devices::Geolocation::GeocoordinateSatelliteData ppValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeocoordinateWithPositionData)->get_SatelliteData(put_abi(ppValue)));
    return ppValue;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::DateTime> consume_Windows_Devices_Geolocation_IGeocoordinateWithPositionSourceTimestamp<D>::PositionSourceTimestamp() const
{
    Windows::Foundation::IReference<Windows::Foundation::DateTime> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeocoordinateWithPositionSourceTimestamp)->get_PositionSourceTimestamp(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Geolocation::PositionAccuracy consume_Windows_Devices_Geolocation_IGeolocator<D>::DesiredAccuracy() const
{
    Windows::Devices::Geolocation::PositionAccuracy value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeolocator)->get_DesiredAccuracy(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Geolocation_IGeolocator<D>::DesiredAccuracy(Windows::Devices::Geolocation::PositionAccuracy const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeolocator)->put_DesiredAccuracy(get_abi(value)));
}

template <typename D> double consume_Windows_Devices_Geolocation_IGeolocator<D>::MovementThreshold() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeolocator)->get_MovementThreshold(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_Geolocation_IGeolocator<D>::MovementThreshold(double value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeolocator)->put_MovementThreshold(value));
}

template <typename D> uint32_t consume_Windows_Devices_Geolocation_IGeolocator<D>::ReportInterval() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeolocator)->get_ReportInterval(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_Geolocation_IGeolocator<D>::ReportInterval(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeolocator)->put_ReportInterval(value));
}

template <typename D> Windows::Devices::Geolocation::PositionStatus consume_Windows_Devices_Geolocation_IGeolocator<D>::LocationStatus() const
{
    Windows::Devices::Geolocation::PositionStatus value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeolocator)->get_LocationStatus(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Geolocation::Geoposition> consume_Windows_Devices_Geolocation_IGeolocator<D>::GetGeopositionAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Geolocation::Geoposition> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeolocator)->GetGeopositionAsync(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Geolocation::Geoposition> consume_Windows_Devices_Geolocation_IGeolocator<D>::GetGeopositionAsync(Windows::Foundation::TimeSpan const& maximumAge, Windows::Foundation::TimeSpan const& timeout) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Geolocation::Geoposition> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeolocator)->GetGeopositionAsyncWithAgeAndTimeout(get_abi(maximumAge), get_abi(timeout), put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Devices_Geolocation_IGeolocator<D>::PositionChanged(Windows::Foundation::TypedEventHandler<Windows::Devices::Geolocation::Geolocator, Windows::Devices::Geolocation::PositionChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeolocator)->add_PositionChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Geolocation_IGeolocator<D>::PositionChanged_revoker consume_Windows_Devices_Geolocation_IGeolocator<D>::PositionChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Geolocation::Geolocator, Windows::Devices::Geolocation::PositionChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, PositionChanged_revoker>(this, PositionChanged(handler));
}

template <typename D> void consume_Windows_Devices_Geolocation_IGeolocator<D>::PositionChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Geolocation::IGeolocator)->remove_PositionChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Devices_Geolocation_IGeolocator<D>::StatusChanged(Windows::Foundation::TypedEventHandler<Windows::Devices::Geolocation::Geolocator, Windows::Devices::Geolocation::StatusChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeolocator)->add_StatusChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Geolocation_IGeolocator<D>::StatusChanged_revoker consume_Windows_Devices_Geolocation_IGeolocator<D>::StatusChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Geolocation::Geolocator, Windows::Devices::Geolocation::StatusChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, StatusChanged_revoker>(this, StatusChanged(handler));
}

template <typename D> void consume_Windows_Devices_Geolocation_IGeolocator<D>::StatusChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Geolocation::IGeolocator)->remove_StatusChanged(get_abi(token)));
}

template <typename D> void consume_Windows_Devices_Geolocation_IGeolocator2<D>::AllowFallbackToConsentlessPositions() const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeolocator2)->AllowFallbackToConsentlessPositions());
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Geolocation::GeolocationAccessStatus> consume_Windows_Devices_Geolocation_IGeolocatorStatics<D>::RequestAccessAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Geolocation::GeolocationAccessStatus> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeolocatorStatics)->RequestAccessAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Geolocation::Geoposition>> consume_Windows_Devices_Geolocation_IGeolocatorStatics<D>::GetGeopositionHistoryAsync(Windows::Foundation::DateTime const& startTime) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Geolocation::Geoposition>> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeolocatorStatics)->GetGeopositionHistoryAsync(get_abi(startTime), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Geolocation::Geoposition>> consume_Windows_Devices_Geolocation_IGeolocatorStatics<D>::GetGeopositionHistoryAsync(Windows::Foundation::DateTime const& startTime, Windows::Foundation::TimeSpan const& duration) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Geolocation::Geoposition>> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeolocatorStatics)->GetGeopositionHistoryWithDurationAsync(get_abi(startTime), get_abi(duration), put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_Devices_Geolocation_IGeolocatorStatics2<D>::IsDefaultGeopositionRecommended() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeolocatorStatics2)->get_IsDefaultGeopositionRecommended(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_Geolocation_IGeolocatorStatics2<D>::DefaultGeoposition(optional<Windows::Devices::Geolocation::BasicGeoposition> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeolocatorStatics2)->put_DefaultGeoposition(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::Devices::Geolocation::BasicGeoposition> consume_Windows_Devices_Geolocation_IGeolocatorStatics2<D>::DefaultGeoposition() const
{
    Windows::Foundation::IReference<Windows::Devices::Geolocation::BasicGeoposition> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeolocatorStatics2)->get_DefaultGeoposition(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<uint32_t> consume_Windows_Devices_Geolocation_IGeolocatorWithScalarAccuracy<D>::DesiredAccuracyInMeters() const
{
    Windows::Foundation::IReference<uint32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeolocatorWithScalarAccuracy)->get_DesiredAccuracyInMeters(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Geolocation_IGeolocatorWithScalarAccuracy<D>::DesiredAccuracyInMeters(optional<uint32_t> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeolocatorWithScalarAccuracy)->put_DesiredAccuracyInMeters(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::Geolocation::BasicGeoposition> consume_Windows_Devices_Geolocation_IGeopath<D>::Positions() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Geolocation::BasicGeoposition> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeopath)->get_Positions(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Geolocation::Geopath consume_Windows_Devices_Geolocation_IGeopathFactory<D>::Create(param::iterable<Windows::Devices::Geolocation::BasicGeoposition> const& positions) const
{
    Windows::Devices::Geolocation::Geopath value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeopathFactory)->Create(get_abi(positions), put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Geolocation::Geopath consume_Windows_Devices_Geolocation_IGeopathFactory<D>::CreateWithAltitudeReference(param::iterable<Windows::Devices::Geolocation::BasicGeoposition> const& positions, Windows::Devices::Geolocation::AltitudeReferenceSystem const& altitudeReferenceSystem) const
{
    Windows::Devices::Geolocation::Geopath value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeopathFactory)->CreateWithAltitudeReference(get_abi(positions), get_abi(altitudeReferenceSystem), put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Geolocation::Geopath consume_Windows_Devices_Geolocation_IGeopathFactory<D>::CreateWithAltitudeReferenceAndSpatialReference(param::iterable<Windows::Devices::Geolocation::BasicGeoposition> const& positions, Windows::Devices::Geolocation::AltitudeReferenceSystem const& altitudeReferenceSystem, uint32_t spatialReferenceId) const
{
    Windows::Devices::Geolocation::Geopath value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeopathFactory)->CreateWithAltitudeReferenceAndSpatialReference(get_abi(positions), get_abi(altitudeReferenceSystem), spatialReferenceId, put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Geolocation::BasicGeoposition consume_Windows_Devices_Geolocation_IGeopoint<D>::Position() const
{
    Windows::Devices::Geolocation::BasicGeoposition value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeopoint)->get_Position(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Geolocation::Geopoint consume_Windows_Devices_Geolocation_IGeopointFactory<D>::Create(Windows::Devices::Geolocation::BasicGeoposition const& position) const
{
    Windows::Devices::Geolocation::Geopoint value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeopointFactory)->Create(get_abi(position), put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Geolocation::Geopoint consume_Windows_Devices_Geolocation_IGeopointFactory<D>::CreateWithAltitudeReferenceSystem(Windows::Devices::Geolocation::BasicGeoposition const& position, Windows::Devices::Geolocation::AltitudeReferenceSystem const& altitudeReferenceSystem) const
{
    Windows::Devices::Geolocation::Geopoint value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeopointFactory)->CreateWithAltitudeReferenceSystem(get_abi(position), get_abi(altitudeReferenceSystem), put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Geolocation::Geopoint consume_Windows_Devices_Geolocation_IGeopointFactory<D>::CreateWithAltitudeReferenceSystemAndSpatialReferenceId(Windows::Devices::Geolocation::BasicGeoposition const& position, Windows::Devices::Geolocation::AltitudeReferenceSystem const& altitudeReferenceSystem, uint32_t spatialReferenceId) const
{
    Windows::Devices::Geolocation::Geopoint value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeopointFactory)->CreateWithAltitudeReferenceSystemAndSpatialReferenceId(get_abi(position), get_abi(altitudeReferenceSystem), spatialReferenceId, put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Geolocation::Geocoordinate consume_Windows_Devices_Geolocation_IGeoposition<D>::Coordinate() const
{
    Windows::Devices::Geolocation::Geocoordinate value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeoposition)->get_Coordinate(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Geolocation::CivicAddress consume_Windows_Devices_Geolocation_IGeoposition<D>::CivicAddress() const
{
    Windows::Devices::Geolocation::CivicAddress value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeoposition)->get_CivicAddress(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Geolocation::VenueData consume_Windows_Devices_Geolocation_IGeoposition2<D>::VenueData() const
{
    Windows::Devices::Geolocation::VenueData value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeoposition2)->get_VenueData(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Geolocation::GeoshapeType consume_Windows_Devices_Geolocation_IGeoshape<D>::GeoshapeType() const
{
    Windows::Devices::Geolocation::GeoshapeType value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeoshape)->get_GeoshapeType(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_Geolocation_IGeoshape<D>::SpatialReferenceId() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeoshape)->get_SpatialReferenceId(&value));
    return value;
}

template <typename D> Windows::Devices::Geolocation::AltitudeReferenceSystem consume_Windows_Devices_Geolocation_IGeoshape<D>::AltitudeReferenceSystem() const
{
    Windows::Devices::Geolocation::AltitudeReferenceSystem value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeoshape)->get_AltitudeReferenceSystem(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Geolocation::Geoposition consume_Windows_Devices_Geolocation_IGeovisit<D>::Position() const
{
    Windows::Devices::Geolocation::Geoposition value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeovisit)->get_Position(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Geolocation::VisitStateChange consume_Windows_Devices_Geolocation_IGeovisit<D>::StateChange() const
{
    Windows::Devices::Geolocation::VisitStateChange value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeovisit)->get_StateChange(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_Devices_Geolocation_IGeovisit<D>::Timestamp() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeovisit)->get_Timestamp(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Geolocation::VisitMonitoringScope consume_Windows_Devices_Geolocation_IGeovisitMonitor<D>::MonitoringScope() const
{
    Windows::Devices::Geolocation::VisitMonitoringScope value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeovisitMonitor)->get_MonitoringScope(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Geolocation_IGeovisitMonitor<D>::Start(Windows::Devices::Geolocation::VisitMonitoringScope const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeovisitMonitor)->Start(get_abi(value)));
}

template <typename D> void consume_Windows_Devices_Geolocation_IGeovisitMonitor<D>::Stop() const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeovisitMonitor)->Stop());
}

template <typename D> winrt::event_token consume_Windows_Devices_Geolocation_IGeovisitMonitor<D>::VisitStateChanged(Windows::Foundation::TypedEventHandler<Windows::Devices::Geolocation::GeovisitMonitor, Windows::Devices::Geolocation::GeovisitStateChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeovisitMonitor)->add_VisitStateChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Geolocation_IGeovisitMonitor<D>::VisitStateChanged_revoker consume_Windows_Devices_Geolocation_IGeovisitMonitor<D>::VisitStateChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Geolocation::GeovisitMonitor, Windows::Devices::Geolocation::GeovisitStateChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, VisitStateChanged_revoker>(this, VisitStateChanged(handler));
}

template <typename D> void consume_Windows_Devices_Geolocation_IGeovisitMonitor<D>::VisitStateChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Geolocation::IGeovisitMonitor)->remove_VisitStateChanged(get_abi(token)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Geolocation::Geovisit> consume_Windows_Devices_Geolocation_IGeovisitMonitorStatics<D>::GetLastReportAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Geolocation::Geovisit> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeovisitMonitorStatics)->GetLastReportAsync(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Geolocation::Geovisit consume_Windows_Devices_Geolocation_IGeovisitStateChangedEventArgs<D>::Visit() const
{
    Windows::Devices::Geolocation::Geovisit value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeovisitStateChangedEventArgs)->get_Visit(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::Geolocation::Geovisit> consume_Windows_Devices_Geolocation_IGeovisitTriggerDetails<D>::ReadReports() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Geolocation::Geovisit> values{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IGeovisitTriggerDetails)->ReadReports(put_abi(values)));
    return values;
}

template <typename D> Windows::Devices::Geolocation::Geoposition consume_Windows_Devices_Geolocation_IPositionChangedEventArgs<D>::Position() const
{
    Windows::Devices::Geolocation::Geoposition value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IPositionChangedEventArgs)->get_Position(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Geolocation::PositionStatus consume_Windows_Devices_Geolocation_IStatusChangedEventArgs<D>::Status() const
{
    Windows::Devices::Geolocation::PositionStatus value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IStatusChangedEventArgs)->get_Status(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Geolocation_IVenueData<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IVenueData)->get_Id(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Geolocation_IVenueData<D>::Level() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::IVenueData)->get_Level(put_abi(value)));
    return value;
}

template <typename D>
struct produce<D, Windows::Devices::Geolocation::ICivicAddress> : produce_base<D, Windows::Devices::Geolocation::ICivicAddress>
{
    int32_t WINRT_CALL get_Country(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Country, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Country());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_State(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(State, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_City(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(City, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().City());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PostalCode(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PostalCode, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().PostalCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Timestamp(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Timestamp, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().Timestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Geolocation::IGeoboundingBox> : produce_base<D, Windows::Devices::Geolocation::IGeoboundingBox>
{
    int32_t WINRT_CALL get_NorthwestCorner(struct struct_Windows_Devices_Geolocation_BasicGeoposition* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NorthwestCorner, WINRT_WRAP(Windows::Devices::Geolocation::BasicGeoposition));
            *value = detach_from<Windows::Devices::Geolocation::BasicGeoposition>(this->shim().NorthwestCorner());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SoutheastCorner(struct struct_Windows_Devices_Geolocation_BasicGeoposition* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SoutheastCorner, WINRT_WRAP(Windows::Devices::Geolocation::BasicGeoposition));
            *value = detach_from<Windows::Devices::Geolocation::BasicGeoposition>(this->shim().SoutheastCorner());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Center(struct struct_Windows_Devices_Geolocation_BasicGeoposition* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Center, WINRT_WRAP(Windows::Devices::Geolocation::BasicGeoposition));
            *value = detach_from<Windows::Devices::Geolocation::BasicGeoposition>(this->shim().Center());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MinAltitude(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinAltitude, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().MinAltitude());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxAltitude(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxAltitude, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().MaxAltitude());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Geolocation::IGeoboundingBoxFactory> : produce_base<D, Windows::Devices::Geolocation::IGeoboundingBoxFactory>
{
    int32_t WINRT_CALL Create(struct struct_Windows_Devices_Geolocation_BasicGeoposition northwestCorner, struct struct_Windows_Devices_Geolocation_BasicGeoposition southeastCorner, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Devices::Geolocation::GeoboundingBox), Windows::Devices::Geolocation::BasicGeoposition const&, Windows::Devices::Geolocation::BasicGeoposition const&);
            *value = detach_from<Windows::Devices::Geolocation::GeoboundingBox>(this->shim().Create(*reinterpret_cast<Windows::Devices::Geolocation::BasicGeoposition const*>(&northwestCorner), *reinterpret_cast<Windows::Devices::Geolocation::BasicGeoposition const*>(&southeastCorner)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithAltitudeReference(struct struct_Windows_Devices_Geolocation_BasicGeoposition northwestCorner, struct struct_Windows_Devices_Geolocation_BasicGeoposition southeastCorner, Windows::Devices::Geolocation::AltitudeReferenceSystem altitudeReferenceSystem, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithAltitudeReference, WINRT_WRAP(Windows::Devices::Geolocation::GeoboundingBox), Windows::Devices::Geolocation::BasicGeoposition const&, Windows::Devices::Geolocation::BasicGeoposition const&, Windows::Devices::Geolocation::AltitudeReferenceSystem const&);
            *value = detach_from<Windows::Devices::Geolocation::GeoboundingBox>(this->shim().CreateWithAltitudeReference(*reinterpret_cast<Windows::Devices::Geolocation::BasicGeoposition const*>(&northwestCorner), *reinterpret_cast<Windows::Devices::Geolocation::BasicGeoposition const*>(&southeastCorner), *reinterpret_cast<Windows::Devices::Geolocation::AltitudeReferenceSystem const*>(&altitudeReferenceSystem)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithAltitudeReferenceAndSpatialReference(struct struct_Windows_Devices_Geolocation_BasicGeoposition northwestCorner, struct struct_Windows_Devices_Geolocation_BasicGeoposition southeastCorner, Windows::Devices::Geolocation::AltitudeReferenceSystem altitudeReferenceSystem, uint32_t spatialReferenceId, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithAltitudeReferenceAndSpatialReference, WINRT_WRAP(Windows::Devices::Geolocation::GeoboundingBox), Windows::Devices::Geolocation::BasicGeoposition const&, Windows::Devices::Geolocation::BasicGeoposition const&, Windows::Devices::Geolocation::AltitudeReferenceSystem const&, uint32_t);
            *value = detach_from<Windows::Devices::Geolocation::GeoboundingBox>(this->shim().CreateWithAltitudeReferenceAndSpatialReference(*reinterpret_cast<Windows::Devices::Geolocation::BasicGeoposition const*>(&northwestCorner), *reinterpret_cast<Windows::Devices::Geolocation::BasicGeoposition const*>(&southeastCorner), *reinterpret_cast<Windows::Devices::Geolocation::AltitudeReferenceSystem const*>(&altitudeReferenceSystem), spatialReferenceId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Geolocation::IGeoboundingBoxStatics> : produce_base<D, Windows::Devices::Geolocation::IGeoboundingBoxStatics>
{
    int32_t WINRT_CALL TryCompute(void* positions, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryCompute, WINRT_WRAP(Windows::Devices::Geolocation::GeoboundingBox), Windows::Foundation::Collections::IIterable<Windows::Devices::Geolocation::BasicGeoposition> const&);
            *value = detach_from<Windows::Devices::Geolocation::GeoboundingBox>(this->shim().TryCompute(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Devices::Geolocation::BasicGeoposition> const*>(&positions)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryComputeWithAltitudeReference(void* positions, Windows::Devices::Geolocation::AltitudeReferenceSystem altitudeRefSystem, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryCompute, WINRT_WRAP(Windows::Devices::Geolocation::GeoboundingBox), Windows::Foundation::Collections::IIterable<Windows::Devices::Geolocation::BasicGeoposition> const&, Windows::Devices::Geolocation::AltitudeReferenceSystem const&);
            *value = detach_from<Windows::Devices::Geolocation::GeoboundingBox>(this->shim().TryCompute(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Devices::Geolocation::BasicGeoposition> const*>(&positions), *reinterpret_cast<Windows::Devices::Geolocation::AltitudeReferenceSystem const*>(&altitudeRefSystem)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryComputeWithAltitudeReferenceAndSpatialReference(void* positions, Windows::Devices::Geolocation::AltitudeReferenceSystem altitudeRefSystem, uint32_t spatialReferenceId, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryCompute, WINRT_WRAP(Windows::Devices::Geolocation::GeoboundingBox), Windows::Foundation::Collections::IIterable<Windows::Devices::Geolocation::BasicGeoposition> const&, Windows::Devices::Geolocation::AltitudeReferenceSystem const&, uint32_t);
            *value = detach_from<Windows::Devices::Geolocation::GeoboundingBox>(this->shim().TryCompute(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Devices::Geolocation::BasicGeoposition> const*>(&positions), *reinterpret_cast<Windows::Devices::Geolocation::AltitudeReferenceSystem const*>(&altitudeRefSystem), spatialReferenceId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Geolocation::IGeocircle> : produce_base<D, Windows::Devices::Geolocation::IGeocircle>
{
    int32_t WINRT_CALL get_Center(struct struct_Windows_Devices_Geolocation_BasicGeoposition* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Center, WINRT_WRAP(Windows::Devices::Geolocation::BasicGeoposition));
            *value = detach_from<Windows::Devices::Geolocation::BasicGeoposition>(this->shim().Center());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Radius(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Radius, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().Radius());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Geolocation::IGeocircleFactory> : produce_base<D, Windows::Devices::Geolocation::IGeocircleFactory>
{
    int32_t WINRT_CALL Create(struct struct_Windows_Devices_Geolocation_BasicGeoposition position, double radius, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Devices::Geolocation::Geocircle), Windows::Devices::Geolocation::BasicGeoposition const&, double);
            *value = detach_from<Windows::Devices::Geolocation::Geocircle>(this->shim().Create(*reinterpret_cast<Windows::Devices::Geolocation::BasicGeoposition const*>(&position), radius));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithAltitudeReferenceSystem(struct struct_Windows_Devices_Geolocation_BasicGeoposition position, double radius, Windows::Devices::Geolocation::AltitudeReferenceSystem altitudeReferenceSystem, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithAltitudeReferenceSystem, WINRT_WRAP(Windows::Devices::Geolocation::Geocircle), Windows::Devices::Geolocation::BasicGeoposition const&, double, Windows::Devices::Geolocation::AltitudeReferenceSystem const&);
            *value = detach_from<Windows::Devices::Geolocation::Geocircle>(this->shim().CreateWithAltitudeReferenceSystem(*reinterpret_cast<Windows::Devices::Geolocation::BasicGeoposition const*>(&position), radius, *reinterpret_cast<Windows::Devices::Geolocation::AltitudeReferenceSystem const*>(&altitudeReferenceSystem)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithAltitudeReferenceSystemAndSpatialReferenceId(struct struct_Windows_Devices_Geolocation_BasicGeoposition position, double radius, Windows::Devices::Geolocation::AltitudeReferenceSystem altitudeReferenceSystem, uint32_t spatialReferenceId, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithAltitudeReferenceSystemAndSpatialReferenceId, WINRT_WRAP(Windows::Devices::Geolocation::Geocircle), Windows::Devices::Geolocation::BasicGeoposition const&, double, Windows::Devices::Geolocation::AltitudeReferenceSystem const&, uint32_t);
            *value = detach_from<Windows::Devices::Geolocation::Geocircle>(this->shim().CreateWithAltitudeReferenceSystemAndSpatialReferenceId(*reinterpret_cast<Windows::Devices::Geolocation::BasicGeoposition const*>(&position), radius, *reinterpret_cast<Windows::Devices::Geolocation::AltitudeReferenceSystem const*>(&altitudeReferenceSystem), spatialReferenceId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Geolocation::IGeocoordinate> : produce_base<D, Windows::Devices::Geolocation::IGeocoordinate>
{
    int32_t WINRT_CALL get_Latitude(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Latitude, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().Latitude());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Longitude(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Longitude, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().Longitude());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Altitude(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Altitude, WINRT_WRAP(Windows::Foundation::IReference<double>));
            *value = detach_from<Windows::Foundation::IReference<double>>(this->shim().Altitude());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Accuracy(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Accuracy, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().Accuracy());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AltitudeAccuracy(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AltitudeAccuracy, WINRT_WRAP(Windows::Foundation::IReference<double>));
            *value = detach_from<Windows::Foundation::IReference<double>>(this->shim().AltitudeAccuracy());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Heading(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Heading, WINRT_WRAP(Windows::Foundation::IReference<double>));
            *value = detach_from<Windows::Foundation::IReference<double>>(this->shim().Heading());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Speed(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Speed, WINRT_WRAP(Windows::Foundation::IReference<double>));
            *value = detach_from<Windows::Foundation::IReference<double>>(this->shim().Speed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Timestamp(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Timestamp, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().Timestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Geolocation::IGeocoordinateSatelliteData> : produce_base<D, Windows::Devices::Geolocation::IGeocoordinateSatelliteData>
{
    int32_t WINRT_CALL get_PositionDilutionOfPrecision(void** ppValue) noexcept final
    {
        try
        {
            *ppValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PositionDilutionOfPrecision, WINRT_WRAP(Windows::Foundation::IReference<double>));
            *ppValue = detach_from<Windows::Foundation::IReference<double>>(this->shim().PositionDilutionOfPrecision());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HorizontalDilutionOfPrecision(void** ppValue) noexcept final
    {
        try
        {
            *ppValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HorizontalDilutionOfPrecision, WINRT_WRAP(Windows::Foundation::IReference<double>));
            *ppValue = detach_from<Windows::Foundation::IReference<double>>(this->shim().HorizontalDilutionOfPrecision());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VerticalDilutionOfPrecision(void** ppValue) noexcept final
    {
        try
        {
            *ppValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VerticalDilutionOfPrecision, WINRT_WRAP(Windows::Foundation::IReference<double>));
            *ppValue = detach_from<Windows::Foundation::IReference<double>>(this->shim().VerticalDilutionOfPrecision());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Geolocation::IGeocoordinateWithPoint> : produce_base<D, Windows::Devices::Geolocation::IGeocoordinateWithPoint>
{
    int32_t WINRT_CALL get_Point(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Point, WINRT_WRAP(Windows::Devices::Geolocation::Geopoint));
            *value = detach_from<Windows::Devices::Geolocation::Geopoint>(this->shim().Point());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Geolocation::IGeocoordinateWithPositionData> : produce_base<D, Windows::Devices::Geolocation::IGeocoordinateWithPositionData>
{
    int32_t WINRT_CALL get_PositionSource(Windows::Devices::Geolocation::PositionSource* pValue) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PositionSource, WINRT_WRAP(Windows::Devices::Geolocation::PositionSource));
            *pValue = detach_from<Windows::Devices::Geolocation::PositionSource>(this->shim().PositionSource());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SatelliteData(void** ppValue) noexcept final
    {
        try
        {
            *ppValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SatelliteData, WINRT_WRAP(Windows::Devices::Geolocation::GeocoordinateSatelliteData));
            *ppValue = detach_from<Windows::Devices::Geolocation::GeocoordinateSatelliteData>(this->shim().SatelliteData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Geolocation::IGeocoordinateWithPositionSourceTimestamp> : produce_base<D, Windows::Devices::Geolocation::IGeocoordinateWithPositionSourceTimestamp>
{
    int32_t WINRT_CALL get_PositionSourceTimestamp(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PositionSourceTimestamp, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::DateTime>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::DateTime>>(this->shim().PositionSourceTimestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Geolocation::IGeolocator> : produce_base<D, Windows::Devices::Geolocation::IGeolocator>
{
    int32_t WINRT_CALL get_DesiredAccuracy(Windows::Devices::Geolocation::PositionAccuracy* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesiredAccuracy, WINRT_WRAP(Windows::Devices::Geolocation::PositionAccuracy));
            *value = detach_from<Windows::Devices::Geolocation::PositionAccuracy>(this->shim().DesiredAccuracy());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DesiredAccuracy(Windows::Devices::Geolocation::PositionAccuracy value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesiredAccuracy, WINRT_WRAP(void), Windows::Devices::Geolocation::PositionAccuracy const&);
            this->shim().DesiredAccuracy(*reinterpret_cast<Windows::Devices::Geolocation::PositionAccuracy const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MovementThreshold(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MovementThreshold, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().MovementThreshold());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MovementThreshold(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MovementThreshold, WINRT_WRAP(void), double);
            this->shim().MovementThreshold(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ReportInterval(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportInterval, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().ReportInterval());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ReportInterval(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportInterval, WINRT_WRAP(void), uint32_t);
            this->shim().ReportInterval(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LocationStatus(Windows::Devices::Geolocation::PositionStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LocationStatus, WINRT_WRAP(Windows::Devices::Geolocation::PositionStatus));
            *value = detach_from<Windows::Devices::Geolocation::PositionStatus>(this->shim().LocationStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetGeopositionAsync(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetGeopositionAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Geolocation::Geoposition>));
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Geolocation::Geoposition>>(this->shim().GetGeopositionAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetGeopositionAsyncWithAgeAndTimeout(Windows::Foundation::TimeSpan maximumAge, Windows::Foundation::TimeSpan timeout, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetGeopositionAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Geolocation::Geoposition>), Windows::Foundation::TimeSpan const, Windows::Foundation::TimeSpan const);
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Geolocation::Geoposition>>(this->shim().GetGeopositionAsync(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&maximumAge), *reinterpret_cast<Windows::Foundation::TimeSpan const*>(&timeout)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_PositionChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PositionChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Geolocation::Geolocator, Windows::Devices::Geolocation::PositionChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().PositionChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Geolocation::Geolocator, Windows::Devices::Geolocation::PositionChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PositionChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PositionChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PositionChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_StatusChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StatusChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Geolocation::Geolocator, Windows::Devices::Geolocation::StatusChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().StatusChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Geolocation::Geolocator, Windows::Devices::Geolocation::StatusChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_StatusChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(StatusChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().StatusChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Devices::Geolocation::IGeolocator2> : produce_base<D, Windows::Devices::Geolocation::IGeolocator2>
{
    int32_t WINRT_CALL AllowFallbackToConsentlessPositions() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllowFallbackToConsentlessPositions, WINRT_WRAP(void));
            this->shim().AllowFallbackToConsentlessPositions();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Geolocation::IGeolocatorStatics> : produce_base<D, Windows::Devices::Geolocation::IGeolocatorStatics>
{
    int32_t WINRT_CALL RequestAccessAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestAccessAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Geolocation::GeolocationAccessStatus>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Geolocation::GeolocationAccessStatus>>(this->shim().RequestAccessAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetGeopositionHistoryAsync(Windows::Foundation::DateTime startTime, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetGeopositionHistoryAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Geolocation::Geoposition>>), Windows::Foundation::DateTime const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Geolocation::Geoposition>>>(this->shim().GetGeopositionHistoryAsync(*reinterpret_cast<Windows::Foundation::DateTime const*>(&startTime)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetGeopositionHistoryWithDurationAsync(Windows::Foundation::DateTime startTime, Windows::Foundation::TimeSpan duration, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetGeopositionHistoryAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Geolocation::Geoposition>>), Windows::Foundation::DateTime const, Windows::Foundation::TimeSpan const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Geolocation::Geoposition>>>(this->shim().GetGeopositionHistoryAsync(*reinterpret_cast<Windows::Foundation::DateTime const*>(&startTime), *reinterpret_cast<Windows::Foundation::TimeSpan const*>(&duration)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Geolocation::IGeolocatorStatics2> : produce_base<D, Windows::Devices::Geolocation::IGeolocatorStatics2>
{
    int32_t WINRT_CALL get_IsDefaultGeopositionRecommended(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDefaultGeopositionRecommended, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsDefaultGeopositionRecommended());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DefaultGeoposition(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DefaultGeoposition, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Devices::Geolocation::BasicGeoposition> const&);
            this->shim().DefaultGeoposition(*reinterpret_cast<Windows::Foundation::IReference<Windows::Devices::Geolocation::BasicGeoposition> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DefaultGeoposition(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DefaultGeoposition, WINRT_WRAP(Windows::Foundation::IReference<Windows::Devices::Geolocation::BasicGeoposition>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Devices::Geolocation::BasicGeoposition>>(this->shim().DefaultGeoposition());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Geolocation::IGeolocatorWithScalarAccuracy> : produce_base<D, Windows::Devices::Geolocation::IGeolocatorWithScalarAccuracy>
{
    int32_t WINRT_CALL get_DesiredAccuracyInMeters(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesiredAccuracyInMeters, WINRT_WRAP(Windows::Foundation::IReference<uint32_t>));
            *value = detach_from<Windows::Foundation::IReference<uint32_t>>(this->shim().DesiredAccuracyInMeters());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DesiredAccuracyInMeters(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesiredAccuracyInMeters, WINRT_WRAP(void), Windows::Foundation::IReference<uint32_t> const&);
            this->shim().DesiredAccuracyInMeters(*reinterpret_cast<Windows::Foundation::IReference<uint32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Geolocation::IGeopath> : produce_base<D, Windows::Devices::Geolocation::IGeopath>
{
    int32_t WINRT_CALL get_Positions(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Positions, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::Geolocation::BasicGeoposition>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::Geolocation::BasicGeoposition>>(this->shim().Positions());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Geolocation::IGeopathFactory> : produce_base<D, Windows::Devices::Geolocation::IGeopathFactory>
{
    int32_t WINRT_CALL Create(void* positions, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Devices::Geolocation::Geopath), Windows::Foundation::Collections::IIterable<Windows::Devices::Geolocation::BasicGeoposition> const&);
            *value = detach_from<Windows::Devices::Geolocation::Geopath>(this->shim().Create(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Devices::Geolocation::BasicGeoposition> const*>(&positions)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithAltitudeReference(void* positions, Windows::Devices::Geolocation::AltitudeReferenceSystem altitudeReferenceSystem, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithAltitudeReference, WINRT_WRAP(Windows::Devices::Geolocation::Geopath), Windows::Foundation::Collections::IIterable<Windows::Devices::Geolocation::BasicGeoposition> const&, Windows::Devices::Geolocation::AltitudeReferenceSystem const&);
            *value = detach_from<Windows::Devices::Geolocation::Geopath>(this->shim().CreateWithAltitudeReference(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Devices::Geolocation::BasicGeoposition> const*>(&positions), *reinterpret_cast<Windows::Devices::Geolocation::AltitudeReferenceSystem const*>(&altitudeReferenceSystem)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithAltitudeReferenceAndSpatialReference(void* positions, Windows::Devices::Geolocation::AltitudeReferenceSystem altitudeReferenceSystem, uint32_t spatialReferenceId, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithAltitudeReferenceAndSpatialReference, WINRT_WRAP(Windows::Devices::Geolocation::Geopath), Windows::Foundation::Collections::IIterable<Windows::Devices::Geolocation::BasicGeoposition> const&, Windows::Devices::Geolocation::AltitudeReferenceSystem const&, uint32_t);
            *value = detach_from<Windows::Devices::Geolocation::Geopath>(this->shim().CreateWithAltitudeReferenceAndSpatialReference(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Devices::Geolocation::BasicGeoposition> const*>(&positions), *reinterpret_cast<Windows::Devices::Geolocation::AltitudeReferenceSystem const*>(&altitudeReferenceSystem), spatialReferenceId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Geolocation::IGeopoint> : produce_base<D, Windows::Devices::Geolocation::IGeopoint>
{
    int32_t WINRT_CALL get_Position(struct struct_Windows_Devices_Geolocation_BasicGeoposition* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Position, WINRT_WRAP(Windows::Devices::Geolocation::BasicGeoposition));
            *value = detach_from<Windows::Devices::Geolocation::BasicGeoposition>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Geolocation::IGeopointFactory> : produce_base<D, Windows::Devices::Geolocation::IGeopointFactory>
{
    int32_t WINRT_CALL Create(struct struct_Windows_Devices_Geolocation_BasicGeoposition position, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Devices::Geolocation::Geopoint), Windows::Devices::Geolocation::BasicGeoposition const&);
            *value = detach_from<Windows::Devices::Geolocation::Geopoint>(this->shim().Create(*reinterpret_cast<Windows::Devices::Geolocation::BasicGeoposition const*>(&position)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithAltitudeReferenceSystem(struct struct_Windows_Devices_Geolocation_BasicGeoposition position, Windows::Devices::Geolocation::AltitudeReferenceSystem altitudeReferenceSystem, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithAltitudeReferenceSystem, WINRT_WRAP(Windows::Devices::Geolocation::Geopoint), Windows::Devices::Geolocation::BasicGeoposition const&, Windows::Devices::Geolocation::AltitudeReferenceSystem const&);
            *value = detach_from<Windows::Devices::Geolocation::Geopoint>(this->shim().CreateWithAltitudeReferenceSystem(*reinterpret_cast<Windows::Devices::Geolocation::BasicGeoposition const*>(&position), *reinterpret_cast<Windows::Devices::Geolocation::AltitudeReferenceSystem const*>(&altitudeReferenceSystem)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithAltitudeReferenceSystemAndSpatialReferenceId(struct struct_Windows_Devices_Geolocation_BasicGeoposition position, Windows::Devices::Geolocation::AltitudeReferenceSystem altitudeReferenceSystem, uint32_t spatialReferenceId, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithAltitudeReferenceSystemAndSpatialReferenceId, WINRT_WRAP(Windows::Devices::Geolocation::Geopoint), Windows::Devices::Geolocation::BasicGeoposition const&, Windows::Devices::Geolocation::AltitudeReferenceSystem const&, uint32_t);
            *value = detach_from<Windows::Devices::Geolocation::Geopoint>(this->shim().CreateWithAltitudeReferenceSystemAndSpatialReferenceId(*reinterpret_cast<Windows::Devices::Geolocation::BasicGeoposition const*>(&position), *reinterpret_cast<Windows::Devices::Geolocation::AltitudeReferenceSystem const*>(&altitudeReferenceSystem), spatialReferenceId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Geolocation::IGeoposition> : produce_base<D, Windows::Devices::Geolocation::IGeoposition>
{
    int32_t WINRT_CALL get_Coordinate(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Coordinate, WINRT_WRAP(Windows::Devices::Geolocation::Geocoordinate));
            *value = detach_from<Windows::Devices::Geolocation::Geocoordinate>(this->shim().Coordinate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CivicAddress(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CivicAddress, WINRT_WRAP(Windows::Devices::Geolocation::CivicAddress));
            *value = detach_from<Windows::Devices::Geolocation::CivicAddress>(this->shim().CivicAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Geolocation::IGeoposition2> : produce_base<D, Windows::Devices::Geolocation::IGeoposition2>
{
    int32_t WINRT_CALL get_VenueData(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VenueData, WINRT_WRAP(Windows::Devices::Geolocation::VenueData));
            *value = detach_from<Windows::Devices::Geolocation::VenueData>(this->shim().VenueData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Geolocation::IGeoshape> : produce_base<D, Windows::Devices::Geolocation::IGeoshape>
{
    int32_t WINRT_CALL get_GeoshapeType(Windows::Devices::Geolocation::GeoshapeType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GeoshapeType, WINRT_WRAP(Windows::Devices::Geolocation::GeoshapeType));
            *value = detach_from<Windows::Devices::Geolocation::GeoshapeType>(this->shim().GeoshapeType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SpatialReferenceId(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SpatialReferenceId, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().SpatialReferenceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AltitudeReferenceSystem(Windows::Devices::Geolocation::AltitudeReferenceSystem* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AltitudeReferenceSystem, WINRT_WRAP(Windows::Devices::Geolocation::AltitudeReferenceSystem));
            *value = detach_from<Windows::Devices::Geolocation::AltitudeReferenceSystem>(this->shim().AltitudeReferenceSystem());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Geolocation::IGeovisit> : produce_base<D, Windows::Devices::Geolocation::IGeovisit>
{
    int32_t WINRT_CALL get_Position(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Position, WINRT_WRAP(Windows::Devices::Geolocation::Geoposition));
            *value = detach_from<Windows::Devices::Geolocation::Geoposition>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StateChange(Windows::Devices::Geolocation::VisitStateChange* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StateChange, WINRT_WRAP(Windows::Devices::Geolocation::VisitStateChange));
            *value = detach_from<Windows::Devices::Geolocation::VisitStateChange>(this->shim().StateChange());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Timestamp(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Timestamp, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().Timestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Geolocation::IGeovisitMonitor> : produce_base<D, Windows::Devices::Geolocation::IGeovisitMonitor>
{
    int32_t WINRT_CALL get_MonitoringScope(Windows::Devices::Geolocation::VisitMonitoringScope* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MonitoringScope, WINRT_WRAP(Windows::Devices::Geolocation::VisitMonitoringScope));
            *value = detach_from<Windows::Devices::Geolocation::VisitMonitoringScope>(this->shim().MonitoringScope());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Start(Windows::Devices::Geolocation::VisitMonitoringScope value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Start, WINRT_WRAP(void), Windows::Devices::Geolocation::VisitMonitoringScope const&);
            this->shim().Start(*reinterpret_cast<Windows::Devices::Geolocation::VisitMonitoringScope const*>(&value));
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

    int32_t WINRT_CALL add_VisitStateChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VisitStateChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Geolocation::GeovisitMonitor, Windows::Devices::Geolocation::GeovisitStateChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().VisitStateChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Geolocation::GeovisitMonitor, Windows::Devices::Geolocation::GeovisitStateChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_VisitStateChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(VisitStateChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().VisitStateChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Devices::Geolocation::IGeovisitMonitorStatics> : produce_base<D, Windows::Devices::Geolocation::IGeovisitMonitorStatics>
{
    int32_t WINRT_CALL GetLastReportAsync(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetLastReportAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Geolocation::Geovisit>));
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Geolocation::Geovisit>>(this->shim().GetLastReportAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Geolocation::IGeovisitStateChangedEventArgs> : produce_base<D, Windows::Devices::Geolocation::IGeovisitStateChangedEventArgs>
{
    int32_t WINRT_CALL get_Visit(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Visit, WINRT_WRAP(Windows::Devices::Geolocation::Geovisit));
            *value = detach_from<Windows::Devices::Geolocation::Geovisit>(this->shim().Visit());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Geolocation::IGeovisitTriggerDetails> : produce_base<D, Windows::Devices::Geolocation::IGeovisitTriggerDetails>
{
    int32_t WINRT_CALL ReadReports(void** values) noexcept final
    {
        try
        {
            *values = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadReports, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::Geolocation::Geovisit>));
            *values = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::Geolocation::Geovisit>>(this->shim().ReadReports());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Geolocation::IPositionChangedEventArgs> : produce_base<D, Windows::Devices::Geolocation::IPositionChangedEventArgs>
{
    int32_t WINRT_CALL get_Position(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Position, WINRT_WRAP(Windows::Devices::Geolocation::Geoposition));
            *value = detach_from<Windows::Devices::Geolocation::Geoposition>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Geolocation::IStatusChangedEventArgs> : produce_base<D, Windows::Devices::Geolocation::IStatusChangedEventArgs>
{
    int32_t WINRT_CALL get_Status(Windows::Devices::Geolocation::PositionStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Devices::Geolocation::PositionStatus));
            *value = detach_from<Windows::Devices::Geolocation::PositionStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Geolocation::IVenueData> : produce_base<D, Windows::Devices::Geolocation::IVenueData>
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

    int32_t WINRT_CALL get_Level(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Level, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Level());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Devices::Geolocation {

inline GeoboundingBox::GeoboundingBox(Windows::Devices::Geolocation::BasicGeoposition const& northwestCorner, Windows::Devices::Geolocation::BasicGeoposition const& southeastCorner) :
    GeoboundingBox(impl::call_factory<GeoboundingBox, Windows::Devices::Geolocation::IGeoboundingBoxFactory>([&](auto&& f) { return f.Create(northwestCorner, southeastCorner); }))
{}

inline GeoboundingBox::GeoboundingBox(Windows::Devices::Geolocation::BasicGeoposition const& northwestCorner, Windows::Devices::Geolocation::BasicGeoposition const& southeastCorner, Windows::Devices::Geolocation::AltitudeReferenceSystem const& altitudeReferenceSystem) :
    GeoboundingBox(impl::call_factory<GeoboundingBox, Windows::Devices::Geolocation::IGeoboundingBoxFactory>([&](auto&& f) { return f.CreateWithAltitudeReference(northwestCorner, southeastCorner, altitudeReferenceSystem); }))
{}

inline GeoboundingBox::GeoboundingBox(Windows::Devices::Geolocation::BasicGeoposition const& northwestCorner, Windows::Devices::Geolocation::BasicGeoposition const& southeastCorner, Windows::Devices::Geolocation::AltitudeReferenceSystem const& altitudeReferenceSystem, uint32_t spatialReferenceId) :
    GeoboundingBox(impl::call_factory<GeoboundingBox, Windows::Devices::Geolocation::IGeoboundingBoxFactory>([&](auto&& f) { return f.CreateWithAltitudeReferenceAndSpatialReference(northwestCorner, southeastCorner, altitudeReferenceSystem, spatialReferenceId); }))
{}

inline Windows::Devices::Geolocation::GeoboundingBox GeoboundingBox::TryCompute(param::iterable<Windows::Devices::Geolocation::BasicGeoposition> const& positions)
{
    return impl::call_factory<GeoboundingBox, Windows::Devices::Geolocation::IGeoboundingBoxStatics>([&](auto&& f) { return f.TryCompute(positions); });
}

inline Windows::Devices::Geolocation::GeoboundingBox GeoboundingBox::TryCompute(param::iterable<Windows::Devices::Geolocation::BasicGeoposition> const& positions, Windows::Devices::Geolocation::AltitudeReferenceSystem const& altitudeRefSystem)
{
    return impl::call_factory<GeoboundingBox, Windows::Devices::Geolocation::IGeoboundingBoxStatics>([&](auto&& f) { return f.TryCompute(positions, altitudeRefSystem); });
}

inline Windows::Devices::Geolocation::GeoboundingBox GeoboundingBox::TryCompute(param::iterable<Windows::Devices::Geolocation::BasicGeoposition> const& positions, Windows::Devices::Geolocation::AltitudeReferenceSystem const& altitudeRefSystem, uint32_t spatialReferenceId)
{
    return impl::call_factory<GeoboundingBox, Windows::Devices::Geolocation::IGeoboundingBoxStatics>([&](auto&& f) { return f.TryCompute(positions, altitudeRefSystem, spatialReferenceId); });
}

inline Geocircle::Geocircle(Windows::Devices::Geolocation::BasicGeoposition const& position, double radius) :
    Geocircle(impl::call_factory<Geocircle, Windows::Devices::Geolocation::IGeocircleFactory>([&](auto&& f) { return f.Create(position, radius); }))
{}

inline Geocircle::Geocircle(Windows::Devices::Geolocation::BasicGeoposition const& position, double radius, Windows::Devices::Geolocation::AltitudeReferenceSystem const& altitudeReferenceSystem) :
    Geocircle(impl::call_factory<Geocircle, Windows::Devices::Geolocation::IGeocircleFactory>([&](auto&& f) { return f.CreateWithAltitudeReferenceSystem(position, radius, altitudeReferenceSystem); }))
{}

inline Geocircle::Geocircle(Windows::Devices::Geolocation::BasicGeoposition const& position, double radius, Windows::Devices::Geolocation::AltitudeReferenceSystem const& altitudeReferenceSystem, uint32_t spatialReferenceId) :
    Geocircle(impl::call_factory<Geocircle, Windows::Devices::Geolocation::IGeocircleFactory>([&](auto&& f) { return f.CreateWithAltitudeReferenceSystemAndSpatialReferenceId(position, radius, altitudeReferenceSystem, spatialReferenceId); }))
{}

inline Geolocator::Geolocator() :
    Geolocator(impl::call_factory<Geolocator>([](auto&& f) { return f.template ActivateInstance<Geolocator>(); }))
{}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::Geolocation::GeolocationAccessStatus> Geolocator::RequestAccessAsync()
{
    return impl::call_factory<Geolocator, Windows::Devices::Geolocation::IGeolocatorStatics>([&](auto&& f) { return f.RequestAccessAsync(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Geolocation::Geoposition>> Geolocator::GetGeopositionHistoryAsync(Windows::Foundation::DateTime const& startTime)
{
    return impl::call_factory<Geolocator, Windows::Devices::Geolocation::IGeolocatorStatics>([&](auto&& f) { return f.GetGeopositionHistoryAsync(startTime); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Geolocation::Geoposition>> Geolocator::GetGeopositionHistoryAsync(Windows::Foundation::DateTime const& startTime, Windows::Foundation::TimeSpan const& duration)
{
    return impl::call_factory<Geolocator, Windows::Devices::Geolocation::IGeolocatorStatics>([&](auto&& f) { return f.GetGeopositionHistoryAsync(startTime, duration); });
}

inline bool Geolocator::IsDefaultGeopositionRecommended()
{
    return impl::call_factory<Geolocator, Windows::Devices::Geolocation::IGeolocatorStatics2>([&](auto&& f) { return f.IsDefaultGeopositionRecommended(); });
}

inline void Geolocator::DefaultGeoposition(optional<Windows::Devices::Geolocation::BasicGeoposition> const& value)
{
    impl::call_factory<Geolocator, Windows::Devices::Geolocation::IGeolocatorStatics2>([&](auto&& f) { return f.DefaultGeoposition(value); });
}

inline Windows::Foundation::IReference<Windows::Devices::Geolocation::BasicGeoposition> Geolocator::DefaultGeoposition()
{
    return impl::call_factory<Geolocator, Windows::Devices::Geolocation::IGeolocatorStatics2>([&](auto&& f) { return f.DefaultGeoposition(); });
}

inline Geopath::Geopath(param::iterable<Windows::Devices::Geolocation::BasicGeoposition> const& positions) :
    Geopath(impl::call_factory<Geopath, Windows::Devices::Geolocation::IGeopathFactory>([&](auto&& f) { return f.Create(positions); }))
{}

inline Geopath::Geopath(param::iterable<Windows::Devices::Geolocation::BasicGeoposition> const& positions, Windows::Devices::Geolocation::AltitudeReferenceSystem const& altitudeReferenceSystem) :
    Geopath(impl::call_factory<Geopath, Windows::Devices::Geolocation::IGeopathFactory>([&](auto&& f) { return f.CreateWithAltitudeReference(positions, altitudeReferenceSystem); }))
{}

inline Geopath::Geopath(param::iterable<Windows::Devices::Geolocation::BasicGeoposition> const& positions, Windows::Devices::Geolocation::AltitudeReferenceSystem const& altitudeReferenceSystem, uint32_t spatialReferenceId) :
    Geopath(impl::call_factory<Geopath, Windows::Devices::Geolocation::IGeopathFactory>([&](auto&& f) { return f.CreateWithAltitudeReferenceAndSpatialReference(positions, altitudeReferenceSystem, spatialReferenceId); }))
{}

inline Geopoint::Geopoint(Windows::Devices::Geolocation::BasicGeoposition const& position) :
    Geopoint(impl::call_factory<Geopoint, Windows::Devices::Geolocation::IGeopointFactory>([&](auto&& f) { return f.Create(position); }))
{}

inline Geopoint::Geopoint(Windows::Devices::Geolocation::BasicGeoposition const& position, Windows::Devices::Geolocation::AltitudeReferenceSystem const& altitudeReferenceSystem) :
    Geopoint(impl::call_factory<Geopoint, Windows::Devices::Geolocation::IGeopointFactory>([&](auto&& f) { return f.CreateWithAltitudeReferenceSystem(position, altitudeReferenceSystem); }))
{}

inline Geopoint::Geopoint(Windows::Devices::Geolocation::BasicGeoposition const& position, Windows::Devices::Geolocation::AltitudeReferenceSystem const& altitudeReferenceSystem, uint32_t spatialReferenceId) :
    Geopoint(impl::call_factory<Geopoint, Windows::Devices::Geolocation::IGeopointFactory>([&](auto&& f) { return f.CreateWithAltitudeReferenceSystemAndSpatialReferenceId(position, altitudeReferenceSystem, spatialReferenceId); }))
{}

inline GeovisitMonitor::GeovisitMonitor() :
    GeovisitMonitor(impl::call_factory<GeovisitMonitor>([](auto&& f) { return f.template ActivateInstance<GeovisitMonitor>(); }))
{}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::Geolocation::Geovisit> GeovisitMonitor::GetLastReportAsync()
{
    return impl::call_factory<GeovisitMonitor, Windows::Devices::Geolocation::IGeovisitMonitorStatics>([&](auto&& f) { return f.GetLastReportAsync(); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Devices::Geolocation::ICivicAddress> : winrt::impl::hash_base<winrt::Windows::Devices::Geolocation::ICivicAddress> {};
template<> struct hash<winrt::Windows::Devices::Geolocation::IGeoboundingBox> : winrt::impl::hash_base<winrt::Windows::Devices::Geolocation::IGeoboundingBox> {};
template<> struct hash<winrt::Windows::Devices::Geolocation::IGeoboundingBoxFactory> : winrt::impl::hash_base<winrt::Windows::Devices::Geolocation::IGeoboundingBoxFactory> {};
template<> struct hash<winrt::Windows::Devices::Geolocation::IGeoboundingBoxStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Geolocation::IGeoboundingBoxStatics> {};
template<> struct hash<winrt::Windows::Devices::Geolocation::IGeocircle> : winrt::impl::hash_base<winrt::Windows::Devices::Geolocation::IGeocircle> {};
template<> struct hash<winrt::Windows::Devices::Geolocation::IGeocircleFactory> : winrt::impl::hash_base<winrt::Windows::Devices::Geolocation::IGeocircleFactory> {};
template<> struct hash<winrt::Windows::Devices::Geolocation::IGeocoordinate> : winrt::impl::hash_base<winrt::Windows::Devices::Geolocation::IGeocoordinate> {};
template<> struct hash<winrt::Windows::Devices::Geolocation::IGeocoordinateSatelliteData> : winrt::impl::hash_base<winrt::Windows::Devices::Geolocation::IGeocoordinateSatelliteData> {};
template<> struct hash<winrt::Windows::Devices::Geolocation::IGeocoordinateWithPoint> : winrt::impl::hash_base<winrt::Windows::Devices::Geolocation::IGeocoordinateWithPoint> {};
template<> struct hash<winrt::Windows::Devices::Geolocation::IGeocoordinateWithPositionData> : winrt::impl::hash_base<winrt::Windows::Devices::Geolocation::IGeocoordinateWithPositionData> {};
template<> struct hash<winrt::Windows::Devices::Geolocation::IGeocoordinateWithPositionSourceTimestamp> : winrt::impl::hash_base<winrt::Windows::Devices::Geolocation::IGeocoordinateWithPositionSourceTimestamp> {};
template<> struct hash<winrt::Windows::Devices::Geolocation::IGeolocator> : winrt::impl::hash_base<winrt::Windows::Devices::Geolocation::IGeolocator> {};
template<> struct hash<winrt::Windows::Devices::Geolocation::IGeolocator2> : winrt::impl::hash_base<winrt::Windows::Devices::Geolocation::IGeolocator2> {};
template<> struct hash<winrt::Windows::Devices::Geolocation::IGeolocatorStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Geolocation::IGeolocatorStatics> {};
template<> struct hash<winrt::Windows::Devices::Geolocation::IGeolocatorStatics2> : winrt::impl::hash_base<winrt::Windows::Devices::Geolocation::IGeolocatorStatics2> {};
template<> struct hash<winrt::Windows::Devices::Geolocation::IGeolocatorWithScalarAccuracy> : winrt::impl::hash_base<winrt::Windows::Devices::Geolocation::IGeolocatorWithScalarAccuracy> {};
template<> struct hash<winrt::Windows::Devices::Geolocation::IGeopath> : winrt::impl::hash_base<winrt::Windows::Devices::Geolocation::IGeopath> {};
template<> struct hash<winrt::Windows::Devices::Geolocation::IGeopathFactory> : winrt::impl::hash_base<winrt::Windows::Devices::Geolocation::IGeopathFactory> {};
template<> struct hash<winrt::Windows::Devices::Geolocation::IGeopoint> : winrt::impl::hash_base<winrt::Windows::Devices::Geolocation::IGeopoint> {};
template<> struct hash<winrt::Windows::Devices::Geolocation::IGeopointFactory> : winrt::impl::hash_base<winrt::Windows::Devices::Geolocation::IGeopointFactory> {};
template<> struct hash<winrt::Windows::Devices::Geolocation::IGeoposition> : winrt::impl::hash_base<winrt::Windows::Devices::Geolocation::IGeoposition> {};
template<> struct hash<winrt::Windows::Devices::Geolocation::IGeoposition2> : winrt::impl::hash_base<winrt::Windows::Devices::Geolocation::IGeoposition2> {};
template<> struct hash<winrt::Windows::Devices::Geolocation::IGeoshape> : winrt::impl::hash_base<winrt::Windows::Devices::Geolocation::IGeoshape> {};
template<> struct hash<winrt::Windows::Devices::Geolocation::IGeovisit> : winrt::impl::hash_base<winrt::Windows::Devices::Geolocation::IGeovisit> {};
template<> struct hash<winrt::Windows::Devices::Geolocation::IGeovisitMonitor> : winrt::impl::hash_base<winrt::Windows::Devices::Geolocation::IGeovisitMonitor> {};
template<> struct hash<winrt::Windows::Devices::Geolocation::IGeovisitMonitorStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Geolocation::IGeovisitMonitorStatics> {};
template<> struct hash<winrt::Windows::Devices::Geolocation::IGeovisitStateChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Geolocation::IGeovisitStateChangedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Geolocation::IGeovisitTriggerDetails> : winrt::impl::hash_base<winrt::Windows::Devices::Geolocation::IGeovisitTriggerDetails> {};
template<> struct hash<winrt::Windows::Devices::Geolocation::IPositionChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Geolocation::IPositionChangedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Geolocation::IStatusChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Geolocation::IStatusChangedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Geolocation::IVenueData> : winrt::impl::hash_base<winrt::Windows::Devices::Geolocation::IVenueData> {};
template<> struct hash<winrt::Windows::Devices::Geolocation::CivicAddress> : winrt::impl::hash_base<winrt::Windows::Devices::Geolocation::CivicAddress> {};
template<> struct hash<winrt::Windows::Devices::Geolocation::GeoboundingBox> : winrt::impl::hash_base<winrt::Windows::Devices::Geolocation::GeoboundingBox> {};
template<> struct hash<winrt::Windows::Devices::Geolocation::Geocircle> : winrt::impl::hash_base<winrt::Windows::Devices::Geolocation::Geocircle> {};
template<> struct hash<winrt::Windows::Devices::Geolocation::Geocoordinate> : winrt::impl::hash_base<winrt::Windows::Devices::Geolocation::Geocoordinate> {};
template<> struct hash<winrt::Windows::Devices::Geolocation::GeocoordinateSatelliteData> : winrt::impl::hash_base<winrt::Windows::Devices::Geolocation::GeocoordinateSatelliteData> {};
template<> struct hash<winrt::Windows::Devices::Geolocation::Geolocator> : winrt::impl::hash_base<winrt::Windows::Devices::Geolocation::Geolocator> {};
template<> struct hash<winrt::Windows::Devices::Geolocation::Geopath> : winrt::impl::hash_base<winrt::Windows::Devices::Geolocation::Geopath> {};
template<> struct hash<winrt::Windows::Devices::Geolocation::Geopoint> : winrt::impl::hash_base<winrt::Windows::Devices::Geolocation::Geopoint> {};
template<> struct hash<winrt::Windows::Devices::Geolocation::Geoposition> : winrt::impl::hash_base<winrt::Windows::Devices::Geolocation::Geoposition> {};
template<> struct hash<winrt::Windows::Devices::Geolocation::Geovisit> : winrt::impl::hash_base<winrt::Windows::Devices::Geolocation::Geovisit> {};
template<> struct hash<winrt::Windows::Devices::Geolocation::GeovisitMonitor> : winrt::impl::hash_base<winrt::Windows::Devices::Geolocation::GeovisitMonitor> {};
template<> struct hash<winrt::Windows::Devices::Geolocation::GeovisitStateChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Geolocation::GeovisitStateChangedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Geolocation::GeovisitTriggerDetails> : winrt::impl::hash_base<winrt::Windows::Devices::Geolocation::GeovisitTriggerDetails> {};
template<> struct hash<winrt::Windows::Devices::Geolocation::PositionChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Geolocation::PositionChangedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Geolocation::StatusChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Geolocation::StatusChangedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Geolocation::VenueData> : winrt::impl::hash_base<winrt::Windows::Devices::Geolocation::VenueData> {};

}
