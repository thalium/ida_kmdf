// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Devices.Geolocation.2.h"
#include "winrt/impl/Windows.UI.Popups.2.h"
#include "winrt/impl/Windows.Services.Maps.2.h"

namespace winrt::impl {

template <typename D> Windows::Devices::Geolocation::Geopoint consume_Windows_Services_Maps_IEnhancedWaypoint<D>::Point() const
{
    Windows::Devices::Geolocation::Geopoint value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IEnhancedWaypoint)->get_Point(put_abi(value)));
    return value;
}

template <typename D> Windows::Services::Maps::WaypointKind consume_Windows_Services_Maps_IEnhancedWaypoint<D>::Kind() const
{
    Windows::Services::Maps::WaypointKind value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IEnhancedWaypoint)->get_Kind(put_abi(value)));
    return value;
}

template <typename D> Windows::Services::Maps::EnhancedWaypoint consume_Windows_Services_Maps_IEnhancedWaypointFactory<D>::Create(Windows::Devices::Geolocation::Geopoint const& point, Windows::Services::Maps::WaypointKind const& kind) const
{
    Windows::Services::Maps::EnhancedWaypoint value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IEnhancedWaypointFactory)->Create(get_abi(point), get_abi(kind), put_abi(value)));
    return value;
}

template <typename D> Windows::Services::Maps::ManeuverWarningKind consume_Windows_Services_Maps_IManeuverWarning<D>::Kind() const
{
    Windows::Services::Maps::ManeuverWarningKind value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IManeuverWarning)->get_Kind(put_abi(value)));
    return value;
}

template <typename D> Windows::Services::Maps::ManeuverWarningSeverity consume_Windows_Services_Maps_IManeuverWarning<D>::Severity() const
{
    Windows::Services::Maps::ManeuverWarningSeverity value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IManeuverWarning)->get_Severity(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Maps_IMapAddress<D>::BuildingName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapAddress)->get_BuildingName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Maps_IMapAddress<D>::BuildingFloor() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapAddress)->get_BuildingFloor(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Maps_IMapAddress<D>::BuildingRoom() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapAddress)->get_BuildingRoom(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Maps_IMapAddress<D>::BuildingWing() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapAddress)->get_BuildingWing(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Maps_IMapAddress<D>::StreetNumber() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapAddress)->get_StreetNumber(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Maps_IMapAddress<D>::Street() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapAddress)->get_Street(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Maps_IMapAddress<D>::Neighborhood() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapAddress)->get_Neighborhood(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Maps_IMapAddress<D>::District() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapAddress)->get_District(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Maps_IMapAddress<D>::Town() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapAddress)->get_Town(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Maps_IMapAddress<D>::Region() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapAddress)->get_Region(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Maps_IMapAddress<D>::RegionCode() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapAddress)->get_RegionCode(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Maps_IMapAddress<D>::Country() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapAddress)->get_Country(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Maps_IMapAddress<D>::CountryCode() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapAddress)->get_CountryCode(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Maps_IMapAddress<D>::PostCode() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapAddress)->get_PostCode(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Maps_IMapAddress<D>::Continent() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapAddress)->get_Continent(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Maps_IMapAddress2<D>::FormattedAddress() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapAddress2)->get_FormattedAddress(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Geolocation::Geopoint consume_Windows_Services_Maps_IMapLocation<D>::Point() const
{
    Windows::Devices::Geolocation::Geopoint value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapLocation)->get_Point(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Maps_IMapLocation<D>::DisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapLocation)->get_DisplayName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Maps_IMapLocation<D>::Description() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapLocation)->get_Description(put_abi(value)));
    return value;
}

template <typename D> Windows::Services::Maps::MapAddress consume_Windows_Services_Maps_IMapLocation<D>::Address() const
{
    Windows::Services::Maps::MapAddress value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapLocation)->get_Address(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Services::Maps::MapLocation> consume_Windows_Services_Maps_IMapLocationFinderResult<D>::Locations() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Services::Maps::MapLocation> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapLocationFinderResult)->get_Locations(put_abi(value)));
    return value;
}

template <typename D> Windows::Services::Maps::MapLocationFinderStatus consume_Windows_Services_Maps_IMapLocationFinderResult<D>::Status() const
{
    Windows::Services::Maps::MapLocationFinderStatus value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapLocationFinderResult)->get_Status(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapLocationFinderResult> consume_Windows_Services_Maps_IMapLocationFinderStatics<D>::FindLocationsAtAsync(Windows::Devices::Geolocation::Geopoint const& queryPoint) const
{
    Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapLocationFinderResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapLocationFinderStatics)->FindLocationsAtAsync(get_abi(queryPoint), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapLocationFinderResult> consume_Windows_Services_Maps_IMapLocationFinderStatics<D>::FindLocationsAsync(param::hstring const& searchText, Windows::Devices::Geolocation::Geopoint const& referencePoint) const
{
    Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapLocationFinderResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapLocationFinderStatics)->FindLocationsAsync(get_abi(searchText), get_abi(referencePoint), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapLocationFinderResult> consume_Windows_Services_Maps_IMapLocationFinderStatics<D>::FindLocationsAsync(param::hstring const& searchText, Windows::Devices::Geolocation::Geopoint const& referencePoint, uint32_t maxCount) const
{
    Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapLocationFinderResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapLocationFinderStatics)->FindLocationsWithMaxCountAsync(get_abi(searchText), get_abi(referencePoint), maxCount, put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapLocationFinderResult> consume_Windows_Services_Maps_IMapLocationFinderStatics2<D>::FindLocationsAtAsync(Windows::Devices::Geolocation::Geopoint const& queryPoint, Windows::Services::Maps::MapLocationDesiredAccuracy const& accuracy) const
{
    Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapLocationFinderResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapLocationFinderStatics2)->FindLocationsAtWithAccuracyAsync(get_abi(queryPoint), get_abi(accuracy), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_Services_Maps_IMapManagerStatics<D>::ShowDownloadedMapsUI() const
{
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapManagerStatics)->ShowDownloadedMapsUI());
}

template <typename D> void consume_Windows_Services_Maps_IMapManagerStatics<D>::ShowMapsUpdateUI() const
{
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapManagerStatics)->ShowMapsUpdateUI());
}

template <typename D> Windows::Devices::Geolocation::GeoboundingBox consume_Windows_Services_Maps_IMapRoute<D>::BoundingBox() const
{
    Windows::Devices::Geolocation::GeoboundingBox value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapRoute)->get_BoundingBox(put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_Services_Maps_IMapRoute<D>::LengthInMeters() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapRoute)->get_LengthInMeters(&value));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Services_Maps_IMapRoute<D>::EstimatedDuration() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapRoute)->get_EstimatedDuration(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Geolocation::Geopath consume_Windows_Services_Maps_IMapRoute<D>::Path() const
{
    Windows::Devices::Geolocation::Geopath value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapRoute)->get_Path(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Services::Maps::MapRouteLeg> consume_Windows_Services_Maps_IMapRoute<D>::Legs() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Services::Maps::MapRouteLeg> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapRoute)->get_Legs(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Services_Maps_IMapRoute<D>::IsTrafficBased() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapRoute)->get_IsTrafficBased(&value));
    return value;
}

template <typename D> Windows::Services::Maps::MapRouteRestrictions consume_Windows_Services_Maps_IMapRoute2<D>::ViolatedRestrictions() const
{
    Windows::Services::Maps::MapRouteRestrictions value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapRoute2)->get_ViolatedRestrictions(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Services_Maps_IMapRoute2<D>::HasBlockedRoads() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapRoute2)->get_HasBlockedRoads(&value));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Services_Maps_IMapRoute3<D>::DurationWithoutTraffic() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapRoute3)->get_DurationWithoutTraffic(put_abi(value)));
    return value;
}

template <typename D> Windows::Services::Maps::TrafficCongestion consume_Windows_Services_Maps_IMapRoute3<D>::TrafficCongestion() const
{
    Windows::Services::Maps::TrafficCongestion value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapRoute3)->get_TrafficCongestion(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Services_Maps_IMapRoute4<D>::IsScenic() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapRoute4)->get_IsScenic(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Services_Maps_IMapRouteDrivingOptions<D>::MaxAlternateRouteCount() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapRouteDrivingOptions)->get_MaxAlternateRouteCount(&value));
    return value;
}

template <typename D> void consume_Windows_Services_Maps_IMapRouteDrivingOptions<D>::MaxAlternateRouteCount(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapRouteDrivingOptions)->put_MaxAlternateRouteCount(value));
}

template <typename D> Windows::Foundation::IReference<double> consume_Windows_Services_Maps_IMapRouteDrivingOptions<D>::InitialHeading() const
{
    Windows::Foundation::IReference<double> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapRouteDrivingOptions)->get_InitialHeading(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Services_Maps_IMapRouteDrivingOptions<D>::InitialHeading(optional<double> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapRouteDrivingOptions)->put_InitialHeading(get_abi(value)));
}

template <typename D> Windows::Services::Maps::MapRouteOptimization consume_Windows_Services_Maps_IMapRouteDrivingOptions<D>::RouteOptimization() const
{
    Windows::Services::Maps::MapRouteOptimization value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapRouteDrivingOptions)->get_RouteOptimization(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Services_Maps_IMapRouteDrivingOptions<D>::RouteOptimization(Windows::Services::Maps::MapRouteOptimization const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapRouteDrivingOptions)->put_RouteOptimization(get_abi(value)));
}

template <typename D> Windows::Services::Maps::MapRouteRestrictions consume_Windows_Services_Maps_IMapRouteDrivingOptions<D>::RouteRestrictions() const
{
    Windows::Services::Maps::MapRouteRestrictions value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapRouteDrivingOptions)->get_RouteRestrictions(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Services_Maps_IMapRouteDrivingOptions<D>::RouteRestrictions(Windows::Services::Maps::MapRouteRestrictions const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapRouteDrivingOptions)->put_RouteRestrictions(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::DateTime> consume_Windows_Services_Maps_IMapRouteDrivingOptions2<D>::DepartureTime() const
{
    Windows::Foundation::IReference<Windows::Foundation::DateTime> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapRouteDrivingOptions2)->get_DepartureTime(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Services_Maps_IMapRouteDrivingOptions2<D>::DepartureTime(optional<Windows::Foundation::DateTime> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapRouteDrivingOptions2)->put_DepartureTime(get_abi(value)));
}

template <typename D> Windows::Services::Maps::MapRoute consume_Windows_Services_Maps_IMapRouteFinderResult<D>::Route() const
{
    Windows::Services::Maps::MapRoute value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapRouteFinderResult)->get_Route(put_abi(value)));
    return value;
}

template <typename D> Windows::Services::Maps::MapRouteFinderStatus consume_Windows_Services_Maps_IMapRouteFinderResult<D>::Status() const
{
    Windows::Services::Maps::MapRouteFinderStatus value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapRouteFinderResult)->get_Status(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Services::Maps::MapRoute> consume_Windows_Services_Maps_IMapRouteFinderResult2<D>::AlternateRoutes() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Services::Maps::MapRoute> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapRouteFinderResult2)->get_AlternateRoutes(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapRouteFinderResult> consume_Windows_Services_Maps_IMapRouteFinderStatics<D>::GetDrivingRouteAsync(Windows::Devices::Geolocation::Geopoint const& startPoint, Windows::Devices::Geolocation::Geopoint const& endPoint) const
{
    Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapRouteFinderResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapRouteFinderStatics)->GetDrivingRouteAsync(get_abi(startPoint), get_abi(endPoint), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapRouteFinderResult> consume_Windows_Services_Maps_IMapRouteFinderStatics<D>::GetDrivingRouteAsync(Windows::Devices::Geolocation::Geopoint const& startPoint, Windows::Devices::Geolocation::Geopoint const& endPoint, Windows::Services::Maps::MapRouteOptimization const& optimization) const
{
    Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapRouteFinderResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapRouteFinderStatics)->GetDrivingRouteWithOptimizationAsync(get_abi(startPoint), get_abi(endPoint), get_abi(optimization), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapRouteFinderResult> consume_Windows_Services_Maps_IMapRouteFinderStatics<D>::GetDrivingRouteAsync(Windows::Devices::Geolocation::Geopoint const& startPoint, Windows::Devices::Geolocation::Geopoint const& endPoint, Windows::Services::Maps::MapRouteOptimization const& optimization, Windows::Services::Maps::MapRouteRestrictions const& restrictions) const
{
    Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapRouteFinderResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapRouteFinderStatics)->GetDrivingRouteWithOptimizationAndRestrictionsAsync(get_abi(startPoint), get_abi(endPoint), get_abi(optimization), get_abi(restrictions), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapRouteFinderResult> consume_Windows_Services_Maps_IMapRouteFinderStatics<D>::GetDrivingRouteAsync(Windows::Devices::Geolocation::Geopoint const& startPoint, Windows::Devices::Geolocation::Geopoint const& endPoint, Windows::Services::Maps::MapRouteOptimization const& optimization, Windows::Services::Maps::MapRouteRestrictions const& restrictions, double headingInDegrees) const
{
    Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapRouteFinderResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapRouteFinderStatics)->GetDrivingRouteWithOptimizationRestrictionsAndHeadingAsync(get_abi(startPoint), get_abi(endPoint), get_abi(optimization), get_abi(restrictions), headingInDegrees, put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapRouteFinderResult> consume_Windows_Services_Maps_IMapRouteFinderStatics<D>::GetDrivingRouteFromWaypointsAsync(param::async_iterable<Windows::Devices::Geolocation::Geopoint> const& wayPoints) const
{
    Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapRouteFinderResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapRouteFinderStatics)->GetDrivingRouteFromWaypointsAsync(get_abi(wayPoints), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapRouteFinderResult> consume_Windows_Services_Maps_IMapRouteFinderStatics<D>::GetDrivingRouteFromWaypointsAsync(param::async_iterable<Windows::Devices::Geolocation::Geopoint> const& wayPoints, Windows::Services::Maps::MapRouteOptimization const& optimization) const
{
    Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapRouteFinderResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapRouteFinderStatics)->GetDrivingRouteFromWaypointsAndOptimizationAsync(get_abi(wayPoints), get_abi(optimization), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapRouteFinderResult> consume_Windows_Services_Maps_IMapRouteFinderStatics<D>::GetDrivingRouteFromWaypointsAsync(param::async_iterable<Windows::Devices::Geolocation::Geopoint> const& wayPoints, Windows::Services::Maps::MapRouteOptimization const& optimization, Windows::Services::Maps::MapRouteRestrictions const& restrictions) const
{
    Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapRouteFinderResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapRouteFinderStatics)->GetDrivingRouteFromWaypointsOptimizationAndRestrictionsAsync(get_abi(wayPoints), get_abi(optimization), get_abi(restrictions), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapRouteFinderResult> consume_Windows_Services_Maps_IMapRouteFinderStatics<D>::GetDrivingRouteFromWaypointsAsync(param::async_iterable<Windows::Devices::Geolocation::Geopoint> const& wayPoints, Windows::Services::Maps::MapRouteOptimization const& optimization, Windows::Services::Maps::MapRouteRestrictions const& restrictions, double headingInDegrees) const
{
    Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapRouteFinderResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapRouteFinderStatics)->GetDrivingRouteFromWaypointsOptimizationRestrictionsAndHeadingAsync(get_abi(wayPoints), get_abi(optimization), get_abi(restrictions), headingInDegrees, put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapRouteFinderResult> consume_Windows_Services_Maps_IMapRouteFinderStatics<D>::GetWalkingRouteAsync(Windows::Devices::Geolocation::Geopoint const& startPoint, Windows::Devices::Geolocation::Geopoint const& endPoint) const
{
    Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapRouteFinderResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapRouteFinderStatics)->GetWalkingRouteAsync(get_abi(startPoint), get_abi(endPoint), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapRouteFinderResult> consume_Windows_Services_Maps_IMapRouteFinderStatics<D>::GetWalkingRouteFromWaypointsAsync(param::async_iterable<Windows::Devices::Geolocation::Geopoint> const& wayPoints) const
{
    Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapRouteFinderResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapRouteFinderStatics)->GetWalkingRouteFromWaypointsAsync(get_abi(wayPoints), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapRouteFinderResult> consume_Windows_Services_Maps_IMapRouteFinderStatics2<D>::GetDrivingRouteAsync(Windows::Devices::Geolocation::Geopoint const& startPoint, Windows::Devices::Geolocation::Geopoint const& endPoint, Windows::Services::Maps::MapRouteDrivingOptions const& options) const
{
    Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapRouteFinderResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapRouteFinderStatics2)->GetDrivingRouteWithOptionsAsync(get_abi(startPoint), get_abi(endPoint), get_abi(options), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapRouteFinderResult> consume_Windows_Services_Maps_IMapRouteFinderStatics3<D>::GetDrivingRouteFromEnhancedWaypointsAsync(param::async_iterable<Windows::Services::Maps::EnhancedWaypoint> const& waypoints) const
{
    Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapRouteFinderResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapRouteFinderStatics3)->GetDrivingRouteFromEnhancedWaypointsAsync(get_abi(waypoints), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapRouteFinderResult> consume_Windows_Services_Maps_IMapRouteFinderStatics3<D>::GetDrivingRouteFromEnhancedWaypointsAsync(param::async_iterable<Windows::Services::Maps::EnhancedWaypoint> const& waypoints, Windows::Services::Maps::MapRouteDrivingOptions const& options) const
{
    Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapRouteFinderResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapRouteFinderStatics3)->GetDrivingRouteFromEnhancedWaypointsWithOptionsAsync(get_abi(waypoints), get_abi(options), put_abi(result)));
    return result;
}

template <typename D> Windows::Devices::Geolocation::GeoboundingBox consume_Windows_Services_Maps_IMapRouteLeg<D>::BoundingBox() const
{
    Windows::Devices::Geolocation::GeoboundingBox value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapRouteLeg)->get_BoundingBox(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Geolocation::Geopath consume_Windows_Services_Maps_IMapRouteLeg<D>::Path() const
{
    Windows::Devices::Geolocation::Geopath value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapRouteLeg)->get_Path(put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_Services_Maps_IMapRouteLeg<D>::LengthInMeters() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapRouteLeg)->get_LengthInMeters(&value));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Services_Maps_IMapRouteLeg<D>::EstimatedDuration() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapRouteLeg)->get_EstimatedDuration(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Services::Maps::MapRouteManeuver> consume_Windows_Services_Maps_IMapRouteLeg<D>::Maneuvers() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Services::Maps::MapRouteManeuver> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapRouteLeg)->get_Maneuvers(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Services_Maps_IMapRouteLeg2<D>::DurationWithoutTraffic() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapRouteLeg2)->get_DurationWithoutTraffic(put_abi(value)));
    return value;
}

template <typename D> Windows::Services::Maps::TrafficCongestion consume_Windows_Services_Maps_IMapRouteLeg2<D>::TrafficCongestion() const
{
    Windows::Services::Maps::TrafficCongestion value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapRouteLeg2)->get_TrafficCongestion(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Geolocation::Geopoint consume_Windows_Services_Maps_IMapRouteManeuver<D>::StartingPoint() const
{
    Windows::Devices::Geolocation::Geopoint value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapRouteManeuver)->get_StartingPoint(put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_Services_Maps_IMapRouteManeuver<D>::LengthInMeters() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapRouteManeuver)->get_LengthInMeters(&value));
    return value;
}

template <typename D> hstring consume_Windows_Services_Maps_IMapRouteManeuver<D>::InstructionText() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapRouteManeuver)->get_InstructionText(put_abi(value)));
    return value;
}

template <typename D> Windows::Services::Maps::MapRouteManeuverKind consume_Windows_Services_Maps_IMapRouteManeuver<D>::Kind() const
{
    Windows::Services::Maps::MapRouteManeuverKind value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapRouteManeuver)->get_Kind(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Maps_IMapRouteManeuver<D>::ExitNumber() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapRouteManeuver)->get_ExitNumber(put_abi(value)));
    return value;
}

template <typename D> Windows::Services::Maps::MapManeuverNotices consume_Windows_Services_Maps_IMapRouteManeuver<D>::ManeuverNotices() const
{
    Windows::Services::Maps::MapManeuverNotices value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapRouteManeuver)->get_ManeuverNotices(put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_Services_Maps_IMapRouteManeuver2<D>::StartHeading() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapRouteManeuver2)->get_StartHeading(&value));
    return value;
}

template <typename D> double consume_Windows_Services_Maps_IMapRouteManeuver2<D>::EndHeading() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapRouteManeuver2)->get_EndHeading(&value));
    return value;
}

template <typename D> hstring consume_Windows_Services_Maps_IMapRouteManeuver2<D>::StreetName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapRouteManeuver2)->get_StreetName(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Services::Maps::ManeuverWarning> consume_Windows_Services_Maps_IMapRouteManeuver3<D>::Warnings() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Services::Maps::ManeuverWarning> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapRouteManeuver3)->get_Warnings(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Services_Maps_IMapServiceStatics<D>::ServiceToken(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapServiceStatics)->put_ServiceToken(get_abi(value)));
}

template <typename D> hstring consume_Windows_Services_Maps_IMapServiceStatics<D>::ServiceToken() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapServiceStatics)->get_ServiceToken(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Maps_IMapServiceStatics2<D>::WorldViewRegionCode() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapServiceStatics2)->get_WorldViewRegionCode(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Maps_IMapServiceStatics3<D>::DataAttributions() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapServiceStatics3)->get_DataAttributions(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Services_Maps_IMapServiceStatics4<D>::DataUsagePreference(Windows::Services::Maps::MapServiceDataUsagePreference const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapServiceStatics4)->put_DataUsagePreference(get_abi(value)));
}

template <typename D> Windows::Services::Maps::MapServiceDataUsagePreference consume_Windows_Services_Maps_IMapServiceStatics4<D>::DataUsagePreference() const
{
    Windows::Services::Maps::MapServiceDataUsagePreference value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IMapServiceStatics4)->get_DataUsagePreference(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Services_Maps_IPlaceInfo<D>::Show(Windows::Foundation::Rect const& selection) const
{
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IPlaceInfo)->Show(get_abi(selection)));
}

template <typename D> void consume_Windows_Services_Maps_IPlaceInfo<D>::Show(Windows::Foundation::Rect const& selection, Windows::UI::Popups::Placement const& preferredPlacement) const
{
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IPlaceInfo)->ShowWithPreferredPlacement(get_abi(selection), get_abi(preferredPlacement)));
}

template <typename D> hstring consume_Windows_Services_Maps_IPlaceInfo<D>::Identifier() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IPlaceInfo)->get_Identifier(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Maps_IPlaceInfo<D>::DisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IPlaceInfo)->get_DisplayName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Maps_IPlaceInfo<D>::DisplayAddress() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IPlaceInfo)->get_DisplayAddress(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Geolocation::IGeoshape consume_Windows_Services_Maps_IPlaceInfo<D>::Geoshape() const
{
    Windows::Devices::Geolocation::IGeoshape value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IPlaceInfo)->get_Geoshape(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Services_Maps_IPlaceInfoCreateOptions<D>::DisplayName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IPlaceInfoCreateOptions)->put_DisplayName(get_abi(value)));
}

template <typename D> hstring consume_Windows_Services_Maps_IPlaceInfoCreateOptions<D>::DisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IPlaceInfoCreateOptions)->get_DisplayName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Services_Maps_IPlaceInfoCreateOptions<D>::DisplayAddress(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IPlaceInfoCreateOptions)->put_DisplayAddress(get_abi(value)));
}

template <typename D> hstring consume_Windows_Services_Maps_IPlaceInfoCreateOptions<D>::DisplayAddress() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IPlaceInfoCreateOptions)->get_DisplayAddress(put_abi(value)));
    return value;
}

template <typename D> Windows::Services::Maps::PlaceInfo consume_Windows_Services_Maps_IPlaceInfoStatics<D>::Create(Windows::Devices::Geolocation::Geopoint const& referencePoint) const
{
    Windows::Services::Maps::PlaceInfo resultValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IPlaceInfoStatics)->Create(get_abi(referencePoint), put_abi(resultValue)));
    return resultValue;
}

template <typename D> Windows::Services::Maps::PlaceInfo consume_Windows_Services_Maps_IPlaceInfoStatics<D>::Create(Windows::Devices::Geolocation::Geopoint const& referencePoint, Windows::Services::Maps::PlaceInfoCreateOptions const& options) const
{
    Windows::Services::Maps::PlaceInfo resultValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IPlaceInfoStatics)->CreateWithGeopointAndOptions(get_abi(referencePoint), get_abi(options), put_abi(resultValue)));
    return resultValue;
}

template <typename D> Windows::Services::Maps::PlaceInfo consume_Windows_Services_Maps_IPlaceInfoStatics<D>::CreateFromIdentifier(param::hstring const& identifier) const
{
    Windows::Services::Maps::PlaceInfo resultValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IPlaceInfoStatics)->CreateFromIdentifier(get_abi(identifier), put_abi(resultValue)));
    return resultValue;
}

template <typename D> Windows::Services::Maps::PlaceInfo consume_Windows_Services_Maps_IPlaceInfoStatics<D>::CreateFromIdentifier(param::hstring const& identifier, Windows::Devices::Geolocation::Geopoint const& defaultPoint, Windows::Services::Maps::PlaceInfoCreateOptions const& options) const
{
    Windows::Services::Maps::PlaceInfo resultValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IPlaceInfoStatics)->CreateFromIdentifierWithOptions(get_abi(identifier), get_abi(defaultPoint), get_abi(options), put_abi(resultValue)));
    return resultValue;
}

template <typename D> Windows::Services::Maps::PlaceInfo consume_Windows_Services_Maps_IPlaceInfoStatics<D>::CreateFromMapLocation(Windows::Services::Maps::MapLocation const& location) const
{
    Windows::Services::Maps::PlaceInfo resultValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IPlaceInfoStatics)->CreateFromMapLocation(get_abi(location), put_abi(resultValue)));
    return resultValue;
}

template <typename D> bool consume_Windows_Services_Maps_IPlaceInfoStatics<D>::IsShowSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IPlaceInfoStatics)->get_IsShowSupported(&value));
    return value;
}

template <typename D> Windows::Services::Maps::PlaceInfo consume_Windows_Services_Maps_IPlaceInfoStatics2<D>::CreateFromAddress(param::hstring const& displayAddress) const
{
    Windows::Services::Maps::PlaceInfo resultValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IPlaceInfoStatics2)->CreateFromAddress(get_abi(displayAddress), put_abi(resultValue)));
    return resultValue;
}

template <typename D> Windows::Services::Maps::PlaceInfo consume_Windows_Services_Maps_IPlaceInfoStatics2<D>::CreateFromAddress(param::hstring const& displayAddress, param::hstring const& displayName) const
{
    Windows::Services::Maps::PlaceInfo resultValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::IPlaceInfoStatics2)->CreateFromAddressWithName(get_abi(displayAddress), get_abi(displayName), put_abi(resultValue)));
    return resultValue;
}

template <typename D>
struct produce<D, Windows::Services::Maps::IEnhancedWaypoint> : produce_base<D, Windows::Services::Maps::IEnhancedWaypoint>
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

    int32_t WINRT_CALL get_Kind(Windows::Services::Maps::WaypointKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Kind, WINRT_WRAP(Windows::Services::Maps::WaypointKind));
            *value = detach_from<Windows::Services::Maps::WaypointKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Maps::IEnhancedWaypointFactory> : produce_base<D, Windows::Services::Maps::IEnhancedWaypointFactory>
{
    int32_t WINRT_CALL Create(void* point, Windows::Services::Maps::WaypointKind kind, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Services::Maps::EnhancedWaypoint), Windows::Devices::Geolocation::Geopoint const&, Windows::Services::Maps::WaypointKind const&);
            *value = detach_from<Windows::Services::Maps::EnhancedWaypoint>(this->shim().Create(*reinterpret_cast<Windows::Devices::Geolocation::Geopoint const*>(&point), *reinterpret_cast<Windows::Services::Maps::WaypointKind const*>(&kind)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Maps::IManeuverWarning> : produce_base<D, Windows::Services::Maps::IManeuverWarning>
{
    int32_t WINRT_CALL get_Kind(Windows::Services::Maps::ManeuverWarningKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Kind, WINRT_WRAP(Windows::Services::Maps::ManeuverWarningKind));
            *value = detach_from<Windows::Services::Maps::ManeuverWarningKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Severity(Windows::Services::Maps::ManeuverWarningSeverity* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Severity, WINRT_WRAP(Windows::Services::Maps::ManeuverWarningSeverity));
            *value = detach_from<Windows::Services::Maps::ManeuverWarningSeverity>(this->shim().Severity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Maps::IMapAddress> : produce_base<D, Windows::Services::Maps::IMapAddress>
{
    int32_t WINRT_CALL get_BuildingName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BuildingName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().BuildingName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BuildingFloor(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BuildingFloor, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().BuildingFloor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BuildingRoom(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BuildingRoom, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().BuildingRoom());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BuildingWing(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BuildingWing, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().BuildingWing());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StreetNumber(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StreetNumber, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().StreetNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Street(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Street, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Street());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Neighborhood(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Neighborhood, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Neighborhood());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_District(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(District, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().District());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Town(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Town, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Town());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Region(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Region, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Region());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RegionCode(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RegionCode, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().RegionCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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

    int32_t WINRT_CALL get_CountryCode(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CountryCode, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().CountryCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PostCode(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PostCode, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().PostCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Continent(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Continent, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Continent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Maps::IMapAddress2> : produce_base<D, Windows::Services::Maps::IMapAddress2>
{
    int32_t WINRT_CALL get_FormattedAddress(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FormattedAddress, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().FormattedAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Maps::IMapLocation> : produce_base<D, Windows::Services::Maps::IMapLocation>
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

    int32_t WINRT_CALL get_DisplayName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DisplayName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Description(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Description, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Description());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Address(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Address, WINRT_WRAP(Windows::Services::Maps::MapAddress));
            *value = detach_from<Windows::Services::Maps::MapAddress>(this->shim().Address());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Maps::IMapLocationFinderResult> : produce_base<D, Windows::Services::Maps::IMapLocationFinderResult>
{
    int32_t WINRT_CALL get_Locations(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Locations, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Services::Maps::MapLocation>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Services::Maps::MapLocation>>(this->shim().Locations());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Status(Windows::Services::Maps::MapLocationFinderStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Services::Maps::MapLocationFinderStatus));
            *value = detach_from<Windows::Services::Maps::MapLocationFinderStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Maps::IMapLocationFinderStatics> : produce_base<D, Windows::Services::Maps::IMapLocationFinderStatics>
{
    int32_t WINRT_CALL FindLocationsAtAsync(void* queryPoint, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindLocationsAtAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapLocationFinderResult>), Windows::Devices::Geolocation::Geopoint const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapLocationFinderResult>>(this->shim().FindLocationsAtAsync(*reinterpret_cast<Windows::Devices::Geolocation::Geopoint const*>(&queryPoint)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindLocationsAsync(void* searchText, void* referencePoint, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindLocationsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapLocationFinderResult>), hstring const, Windows::Devices::Geolocation::Geopoint const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapLocationFinderResult>>(this->shim().FindLocationsAsync(*reinterpret_cast<hstring const*>(&searchText), *reinterpret_cast<Windows::Devices::Geolocation::Geopoint const*>(&referencePoint)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindLocationsWithMaxCountAsync(void* searchText, void* referencePoint, uint32_t maxCount, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindLocationsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapLocationFinderResult>), hstring const, Windows::Devices::Geolocation::Geopoint const, uint32_t);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapLocationFinderResult>>(this->shim().FindLocationsAsync(*reinterpret_cast<hstring const*>(&searchText), *reinterpret_cast<Windows::Devices::Geolocation::Geopoint const*>(&referencePoint), maxCount));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Maps::IMapLocationFinderStatics2> : produce_base<D, Windows::Services::Maps::IMapLocationFinderStatics2>
{
    int32_t WINRT_CALL FindLocationsAtWithAccuracyAsync(void* queryPoint, Windows::Services::Maps::MapLocationDesiredAccuracy accuracy, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindLocationsAtAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapLocationFinderResult>), Windows::Devices::Geolocation::Geopoint const, Windows::Services::Maps::MapLocationDesiredAccuracy const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapLocationFinderResult>>(this->shim().FindLocationsAtAsync(*reinterpret_cast<Windows::Devices::Geolocation::Geopoint const*>(&queryPoint), *reinterpret_cast<Windows::Services::Maps::MapLocationDesiredAccuracy const*>(&accuracy)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Maps::IMapManagerStatics> : produce_base<D, Windows::Services::Maps::IMapManagerStatics>
{
    int32_t WINRT_CALL ShowDownloadedMapsUI() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowDownloadedMapsUI, WINRT_WRAP(void));
            this->shim().ShowDownloadedMapsUI();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ShowMapsUpdateUI() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowMapsUpdateUI, WINRT_WRAP(void));
            this->shim().ShowMapsUpdateUI();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Maps::IMapRoute> : produce_base<D, Windows::Services::Maps::IMapRoute>
{
    int32_t WINRT_CALL get_BoundingBox(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BoundingBox, WINRT_WRAP(Windows::Devices::Geolocation::GeoboundingBox));
            *value = detach_from<Windows::Devices::Geolocation::GeoboundingBox>(this->shim().BoundingBox());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LengthInMeters(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LengthInMeters, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().LengthInMeters());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EstimatedDuration(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EstimatedDuration, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().EstimatedDuration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Path(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Path, WINRT_WRAP(Windows::Devices::Geolocation::Geopath));
            *value = detach_from<Windows::Devices::Geolocation::Geopath>(this->shim().Path());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Legs(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Legs, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Services::Maps::MapRouteLeg>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Services::Maps::MapRouteLeg>>(this->shim().Legs());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsTrafficBased(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsTrafficBased, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsTrafficBased());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Maps::IMapRoute2> : produce_base<D, Windows::Services::Maps::IMapRoute2>
{
    int32_t WINRT_CALL get_ViolatedRestrictions(Windows::Services::Maps::MapRouteRestrictions* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ViolatedRestrictions, WINRT_WRAP(Windows::Services::Maps::MapRouteRestrictions));
            *value = detach_from<Windows::Services::Maps::MapRouteRestrictions>(this->shim().ViolatedRestrictions());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HasBlockedRoads(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HasBlockedRoads, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().HasBlockedRoads());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Maps::IMapRoute3> : produce_base<D, Windows::Services::Maps::IMapRoute3>
{
    int32_t WINRT_CALL get_DurationWithoutTraffic(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DurationWithoutTraffic, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().DurationWithoutTraffic());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TrafficCongestion(Windows::Services::Maps::TrafficCongestion* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrafficCongestion, WINRT_WRAP(Windows::Services::Maps::TrafficCongestion));
            *value = detach_from<Windows::Services::Maps::TrafficCongestion>(this->shim().TrafficCongestion());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Maps::IMapRoute4> : produce_base<D, Windows::Services::Maps::IMapRoute4>
{
    int32_t WINRT_CALL get_IsScenic(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsScenic, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsScenic());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Maps::IMapRouteDrivingOptions> : produce_base<D, Windows::Services::Maps::IMapRouteDrivingOptions>
{
    int32_t WINRT_CALL get_MaxAlternateRouteCount(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxAlternateRouteCount, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().MaxAlternateRouteCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MaxAlternateRouteCount(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxAlternateRouteCount, WINRT_WRAP(void), uint32_t);
            this->shim().MaxAlternateRouteCount(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InitialHeading(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InitialHeading, WINRT_WRAP(Windows::Foundation::IReference<double>));
            *value = detach_from<Windows::Foundation::IReference<double>>(this->shim().InitialHeading());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_InitialHeading(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InitialHeading, WINRT_WRAP(void), Windows::Foundation::IReference<double> const&);
            this->shim().InitialHeading(*reinterpret_cast<Windows::Foundation::IReference<double> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RouteOptimization(Windows::Services::Maps::MapRouteOptimization* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RouteOptimization, WINRT_WRAP(Windows::Services::Maps::MapRouteOptimization));
            *value = detach_from<Windows::Services::Maps::MapRouteOptimization>(this->shim().RouteOptimization());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RouteOptimization(Windows::Services::Maps::MapRouteOptimization value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RouteOptimization, WINRT_WRAP(void), Windows::Services::Maps::MapRouteOptimization const&);
            this->shim().RouteOptimization(*reinterpret_cast<Windows::Services::Maps::MapRouteOptimization const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RouteRestrictions(Windows::Services::Maps::MapRouteRestrictions* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RouteRestrictions, WINRT_WRAP(Windows::Services::Maps::MapRouteRestrictions));
            *value = detach_from<Windows::Services::Maps::MapRouteRestrictions>(this->shim().RouteRestrictions());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RouteRestrictions(Windows::Services::Maps::MapRouteRestrictions value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RouteRestrictions, WINRT_WRAP(void), Windows::Services::Maps::MapRouteRestrictions const&);
            this->shim().RouteRestrictions(*reinterpret_cast<Windows::Services::Maps::MapRouteRestrictions const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Maps::IMapRouteDrivingOptions2> : produce_base<D, Windows::Services::Maps::IMapRouteDrivingOptions2>
{
    int32_t WINRT_CALL get_DepartureTime(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DepartureTime, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::DateTime>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::DateTime>>(this->shim().DepartureTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DepartureTime(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DepartureTime, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Foundation::DateTime> const&);
            this->shim().DepartureTime(*reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::DateTime> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Maps::IMapRouteFinderResult> : produce_base<D, Windows::Services::Maps::IMapRouteFinderResult>
{
    int32_t WINRT_CALL get_Route(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Route, WINRT_WRAP(Windows::Services::Maps::MapRoute));
            *value = detach_from<Windows::Services::Maps::MapRoute>(this->shim().Route());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Status(Windows::Services::Maps::MapRouteFinderStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Services::Maps::MapRouteFinderStatus));
            *value = detach_from<Windows::Services::Maps::MapRouteFinderStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Maps::IMapRouteFinderResult2> : produce_base<D, Windows::Services::Maps::IMapRouteFinderResult2>
{
    int32_t WINRT_CALL get_AlternateRoutes(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AlternateRoutes, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Services::Maps::MapRoute>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Services::Maps::MapRoute>>(this->shim().AlternateRoutes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Maps::IMapRouteFinderStatics> : produce_base<D, Windows::Services::Maps::IMapRouteFinderStatics>
{
    int32_t WINRT_CALL GetDrivingRouteAsync(void* startPoint, void* endPoint, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDrivingRouteAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapRouteFinderResult>), Windows::Devices::Geolocation::Geopoint const, Windows::Devices::Geolocation::Geopoint const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapRouteFinderResult>>(this->shim().GetDrivingRouteAsync(*reinterpret_cast<Windows::Devices::Geolocation::Geopoint const*>(&startPoint), *reinterpret_cast<Windows::Devices::Geolocation::Geopoint const*>(&endPoint)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDrivingRouteWithOptimizationAsync(void* startPoint, void* endPoint, Windows::Services::Maps::MapRouteOptimization optimization, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDrivingRouteAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapRouteFinderResult>), Windows::Devices::Geolocation::Geopoint const, Windows::Devices::Geolocation::Geopoint const, Windows::Services::Maps::MapRouteOptimization const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapRouteFinderResult>>(this->shim().GetDrivingRouteAsync(*reinterpret_cast<Windows::Devices::Geolocation::Geopoint const*>(&startPoint), *reinterpret_cast<Windows::Devices::Geolocation::Geopoint const*>(&endPoint), *reinterpret_cast<Windows::Services::Maps::MapRouteOptimization const*>(&optimization)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDrivingRouteWithOptimizationAndRestrictionsAsync(void* startPoint, void* endPoint, Windows::Services::Maps::MapRouteOptimization optimization, Windows::Services::Maps::MapRouteRestrictions restrictions, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDrivingRouteAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapRouteFinderResult>), Windows::Devices::Geolocation::Geopoint const, Windows::Devices::Geolocation::Geopoint const, Windows::Services::Maps::MapRouteOptimization const, Windows::Services::Maps::MapRouteRestrictions const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapRouteFinderResult>>(this->shim().GetDrivingRouteAsync(*reinterpret_cast<Windows::Devices::Geolocation::Geopoint const*>(&startPoint), *reinterpret_cast<Windows::Devices::Geolocation::Geopoint const*>(&endPoint), *reinterpret_cast<Windows::Services::Maps::MapRouteOptimization const*>(&optimization), *reinterpret_cast<Windows::Services::Maps::MapRouteRestrictions const*>(&restrictions)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDrivingRouteWithOptimizationRestrictionsAndHeadingAsync(void* startPoint, void* endPoint, Windows::Services::Maps::MapRouteOptimization optimization, Windows::Services::Maps::MapRouteRestrictions restrictions, double headingInDegrees, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDrivingRouteAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapRouteFinderResult>), Windows::Devices::Geolocation::Geopoint const, Windows::Devices::Geolocation::Geopoint const, Windows::Services::Maps::MapRouteOptimization const, Windows::Services::Maps::MapRouteRestrictions const, double);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapRouteFinderResult>>(this->shim().GetDrivingRouteAsync(*reinterpret_cast<Windows::Devices::Geolocation::Geopoint const*>(&startPoint), *reinterpret_cast<Windows::Devices::Geolocation::Geopoint const*>(&endPoint), *reinterpret_cast<Windows::Services::Maps::MapRouteOptimization const*>(&optimization), *reinterpret_cast<Windows::Services::Maps::MapRouteRestrictions const*>(&restrictions), headingInDegrees));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDrivingRouteFromWaypointsAsync(void* wayPoints, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDrivingRouteFromWaypointsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapRouteFinderResult>), Windows::Foundation::Collections::IIterable<Windows::Devices::Geolocation::Geopoint> const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapRouteFinderResult>>(this->shim().GetDrivingRouteFromWaypointsAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Devices::Geolocation::Geopoint> const*>(&wayPoints)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDrivingRouteFromWaypointsAndOptimizationAsync(void* wayPoints, Windows::Services::Maps::MapRouteOptimization optimization, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDrivingRouteFromWaypointsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapRouteFinderResult>), Windows::Foundation::Collections::IIterable<Windows::Devices::Geolocation::Geopoint> const, Windows::Services::Maps::MapRouteOptimization const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapRouteFinderResult>>(this->shim().GetDrivingRouteFromWaypointsAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Devices::Geolocation::Geopoint> const*>(&wayPoints), *reinterpret_cast<Windows::Services::Maps::MapRouteOptimization const*>(&optimization)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDrivingRouteFromWaypointsOptimizationAndRestrictionsAsync(void* wayPoints, Windows::Services::Maps::MapRouteOptimization optimization, Windows::Services::Maps::MapRouteRestrictions restrictions, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDrivingRouteFromWaypointsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapRouteFinderResult>), Windows::Foundation::Collections::IIterable<Windows::Devices::Geolocation::Geopoint> const, Windows::Services::Maps::MapRouteOptimization const, Windows::Services::Maps::MapRouteRestrictions const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapRouteFinderResult>>(this->shim().GetDrivingRouteFromWaypointsAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Devices::Geolocation::Geopoint> const*>(&wayPoints), *reinterpret_cast<Windows::Services::Maps::MapRouteOptimization const*>(&optimization), *reinterpret_cast<Windows::Services::Maps::MapRouteRestrictions const*>(&restrictions)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDrivingRouteFromWaypointsOptimizationRestrictionsAndHeadingAsync(void* wayPoints, Windows::Services::Maps::MapRouteOptimization optimization, Windows::Services::Maps::MapRouteRestrictions restrictions, double headingInDegrees, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDrivingRouteFromWaypointsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapRouteFinderResult>), Windows::Foundation::Collections::IIterable<Windows::Devices::Geolocation::Geopoint> const, Windows::Services::Maps::MapRouteOptimization const, Windows::Services::Maps::MapRouteRestrictions const, double);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapRouteFinderResult>>(this->shim().GetDrivingRouteFromWaypointsAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Devices::Geolocation::Geopoint> const*>(&wayPoints), *reinterpret_cast<Windows::Services::Maps::MapRouteOptimization const*>(&optimization), *reinterpret_cast<Windows::Services::Maps::MapRouteRestrictions const*>(&restrictions), headingInDegrees));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetWalkingRouteAsync(void* startPoint, void* endPoint, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetWalkingRouteAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapRouteFinderResult>), Windows::Devices::Geolocation::Geopoint const, Windows::Devices::Geolocation::Geopoint const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapRouteFinderResult>>(this->shim().GetWalkingRouteAsync(*reinterpret_cast<Windows::Devices::Geolocation::Geopoint const*>(&startPoint), *reinterpret_cast<Windows::Devices::Geolocation::Geopoint const*>(&endPoint)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetWalkingRouteFromWaypointsAsync(void* wayPoints, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetWalkingRouteFromWaypointsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapRouteFinderResult>), Windows::Foundation::Collections::IIterable<Windows::Devices::Geolocation::Geopoint> const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapRouteFinderResult>>(this->shim().GetWalkingRouteFromWaypointsAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Devices::Geolocation::Geopoint> const*>(&wayPoints)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Maps::IMapRouteFinderStatics2> : produce_base<D, Windows::Services::Maps::IMapRouteFinderStatics2>
{
    int32_t WINRT_CALL GetDrivingRouteWithOptionsAsync(void* startPoint, void* endPoint, void* options, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDrivingRouteAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapRouteFinderResult>), Windows::Devices::Geolocation::Geopoint const, Windows::Devices::Geolocation::Geopoint const, Windows::Services::Maps::MapRouteDrivingOptions const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapRouteFinderResult>>(this->shim().GetDrivingRouteAsync(*reinterpret_cast<Windows::Devices::Geolocation::Geopoint const*>(&startPoint), *reinterpret_cast<Windows::Devices::Geolocation::Geopoint const*>(&endPoint), *reinterpret_cast<Windows::Services::Maps::MapRouteDrivingOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Maps::IMapRouteFinderStatics3> : produce_base<D, Windows::Services::Maps::IMapRouteFinderStatics3>
{
    int32_t WINRT_CALL GetDrivingRouteFromEnhancedWaypointsAsync(void* waypoints, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDrivingRouteFromEnhancedWaypointsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapRouteFinderResult>), Windows::Foundation::Collections::IIterable<Windows::Services::Maps::EnhancedWaypoint> const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapRouteFinderResult>>(this->shim().GetDrivingRouteFromEnhancedWaypointsAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Services::Maps::EnhancedWaypoint> const*>(&waypoints)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDrivingRouteFromEnhancedWaypointsWithOptionsAsync(void* waypoints, void* options, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDrivingRouteFromEnhancedWaypointsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapRouteFinderResult>), Windows::Foundation::Collections::IIterable<Windows::Services::Maps::EnhancedWaypoint> const, Windows::Services::Maps::MapRouteDrivingOptions const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapRouteFinderResult>>(this->shim().GetDrivingRouteFromEnhancedWaypointsAsync(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Services::Maps::EnhancedWaypoint> const*>(&waypoints), *reinterpret_cast<Windows::Services::Maps::MapRouteDrivingOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Maps::IMapRouteLeg> : produce_base<D, Windows::Services::Maps::IMapRouteLeg>
{
    int32_t WINRT_CALL get_BoundingBox(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BoundingBox, WINRT_WRAP(Windows::Devices::Geolocation::GeoboundingBox));
            *value = detach_from<Windows::Devices::Geolocation::GeoboundingBox>(this->shim().BoundingBox());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Path(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Path, WINRT_WRAP(Windows::Devices::Geolocation::Geopath));
            *value = detach_from<Windows::Devices::Geolocation::Geopath>(this->shim().Path());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LengthInMeters(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LengthInMeters, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().LengthInMeters());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EstimatedDuration(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EstimatedDuration, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().EstimatedDuration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Maneuvers(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Maneuvers, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Services::Maps::MapRouteManeuver>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Services::Maps::MapRouteManeuver>>(this->shim().Maneuvers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Maps::IMapRouteLeg2> : produce_base<D, Windows::Services::Maps::IMapRouteLeg2>
{
    int32_t WINRT_CALL get_DurationWithoutTraffic(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DurationWithoutTraffic, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().DurationWithoutTraffic());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TrafficCongestion(Windows::Services::Maps::TrafficCongestion* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrafficCongestion, WINRT_WRAP(Windows::Services::Maps::TrafficCongestion));
            *value = detach_from<Windows::Services::Maps::TrafficCongestion>(this->shim().TrafficCongestion());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Maps::IMapRouteManeuver> : produce_base<D, Windows::Services::Maps::IMapRouteManeuver>
{
    int32_t WINRT_CALL get_StartingPoint(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartingPoint, WINRT_WRAP(Windows::Devices::Geolocation::Geopoint));
            *value = detach_from<Windows::Devices::Geolocation::Geopoint>(this->shim().StartingPoint());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LengthInMeters(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LengthInMeters, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().LengthInMeters());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InstructionText(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InstructionText, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().InstructionText());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Kind(Windows::Services::Maps::MapRouteManeuverKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Kind, WINRT_WRAP(Windows::Services::Maps::MapRouteManeuverKind));
            *value = detach_from<Windows::Services::Maps::MapRouteManeuverKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExitNumber(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExitNumber, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ExitNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ManeuverNotices(Windows::Services::Maps::MapManeuverNotices* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ManeuverNotices, WINRT_WRAP(Windows::Services::Maps::MapManeuverNotices));
            *value = detach_from<Windows::Services::Maps::MapManeuverNotices>(this->shim().ManeuverNotices());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Maps::IMapRouteManeuver2> : produce_base<D, Windows::Services::Maps::IMapRouteManeuver2>
{
    int32_t WINRT_CALL get_StartHeading(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartHeading, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().StartHeading());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EndHeading(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EndHeading, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().EndHeading());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StreetName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StreetName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().StreetName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Maps::IMapRouteManeuver3> : produce_base<D, Windows::Services::Maps::IMapRouteManeuver3>
{
    int32_t WINRT_CALL get_Warnings(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Warnings, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Services::Maps::ManeuverWarning>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Services::Maps::ManeuverWarning>>(this->shim().Warnings());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Maps::IMapServiceStatics> : produce_base<D, Windows::Services::Maps::IMapServiceStatics>
{
    int32_t WINRT_CALL put_ServiceToken(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServiceToken, WINRT_WRAP(void), hstring const&);
            this->shim().ServiceToken(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ServiceToken(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServiceToken, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ServiceToken());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Maps::IMapServiceStatics2> : produce_base<D, Windows::Services::Maps::IMapServiceStatics2>
{
    int32_t WINRT_CALL get_WorldViewRegionCode(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WorldViewRegionCode, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().WorldViewRegionCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Maps::IMapServiceStatics3> : produce_base<D, Windows::Services::Maps::IMapServiceStatics3>
{
    int32_t WINRT_CALL get_DataAttributions(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DataAttributions, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DataAttributions());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Maps::IMapServiceStatics4> : produce_base<D, Windows::Services::Maps::IMapServiceStatics4>
{
    int32_t WINRT_CALL put_DataUsagePreference(Windows::Services::Maps::MapServiceDataUsagePreference value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DataUsagePreference, WINRT_WRAP(void), Windows::Services::Maps::MapServiceDataUsagePreference const&);
            this->shim().DataUsagePreference(*reinterpret_cast<Windows::Services::Maps::MapServiceDataUsagePreference const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DataUsagePreference(Windows::Services::Maps::MapServiceDataUsagePreference* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DataUsagePreference, WINRT_WRAP(Windows::Services::Maps::MapServiceDataUsagePreference));
            *value = detach_from<Windows::Services::Maps::MapServiceDataUsagePreference>(this->shim().DataUsagePreference());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Maps::IPlaceInfo> : produce_base<D, Windows::Services::Maps::IPlaceInfo>
{
    int32_t WINRT_CALL Show(Windows::Foundation::Rect selection) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Show, WINRT_WRAP(void), Windows::Foundation::Rect const&);
            this->shim().Show(*reinterpret_cast<Windows::Foundation::Rect const*>(&selection));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ShowWithPreferredPlacement(Windows::Foundation::Rect selection, Windows::UI::Popups::Placement preferredPlacement) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Show, WINRT_WRAP(void), Windows::Foundation::Rect const&, Windows::UI::Popups::Placement const&);
            this->shim().Show(*reinterpret_cast<Windows::Foundation::Rect const*>(&selection), *reinterpret_cast<Windows::UI::Popups::Placement const*>(&preferredPlacement));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Identifier(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Identifier, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Identifier());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DisplayName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DisplayName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DisplayAddress(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayAddress, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DisplayAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Geoshape(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Geoshape, WINRT_WRAP(Windows::Devices::Geolocation::IGeoshape));
            *value = detach_from<Windows::Devices::Geolocation::IGeoshape>(this->shim().Geoshape());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Maps::IPlaceInfoCreateOptions> : produce_base<D, Windows::Services::Maps::IPlaceInfoCreateOptions>
{
    int32_t WINRT_CALL put_DisplayName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayName, WINRT_WRAP(void), hstring const&);
            this->shim().DisplayName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DisplayName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DisplayName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DisplayAddress(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayAddress, WINRT_WRAP(void), hstring const&);
            this->shim().DisplayAddress(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DisplayAddress(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayAddress, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DisplayAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Maps::IPlaceInfoStatics> : produce_base<D, Windows::Services::Maps::IPlaceInfoStatics>
{
    int32_t WINRT_CALL Create(void* referencePoint, void** resultValue) noexcept final
    {
        try
        {
            *resultValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Services::Maps::PlaceInfo), Windows::Devices::Geolocation::Geopoint const&);
            *resultValue = detach_from<Windows::Services::Maps::PlaceInfo>(this->shim().Create(*reinterpret_cast<Windows::Devices::Geolocation::Geopoint const*>(&referencePoint)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithGeopointAndOptions(void* referencePoint, void* options, void** resultValue) noexcept final
    {
        try
        {
            *resultValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Services::Maps::PlaceInfo), Windows::Devices::Geolocation::Geopoint const&, Windows::Services::Maps::PlaceInfoCreateOptions const&);
            *resultValue = detach_from<Windows::Services::Maps::PlaceInfo>(this->shim().Create(*reinterpret_cast<Windows::Devices::Geolocation::Geopoint const*>(&referencePoint), *reinterpret_cast<Windows::Services::Maps::PlaceInfoCreateOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromIdentifier(void* identifier, void** resultValue) noexcept final
    {
        try
        {
            *resultValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromIdentifier, WINRT_WRAP(Windows::Services::Maps::PlaceInfo), hstring const&);
            *resultValue = detach_from<Windows::Services::Maps::PlaceInfo>(this->shim().CreateFromIdentifier(*reinterpret_cast<hstring const*>(&identifier)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromIdentifierWithOptions(void* identifier, void* defaultPoint, void* options, void** resultValue) noexcept final
    {
        try
        {
            *resultValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromIdentifier, WINRT_WRAP(Windows::Services::Maps::PlaceInfo), hstring const&, Windows::Devices::Geolocation::Geopoint const&, Windows::Services::Maps::PlaceInfoCreateOptions const&);
            *resultValue = detach_from<Windows::Services::Maps::PlaceInfo>(this->shim().CreateFromIdentifier(*reinterpret_cast<hstring const*>(&identifier), *reinterpret_cast<Windows::Devices::Geolocation::Geopoint const*>(&defaultPoint), *reinterpret_cast<Windows::Services::Maps::PlaceInfoCreateOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromMapLocation(void* location, void** resultValue) noexcept final
    {
        try
        {
            *resultValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromMapLocation, WINRT_WRAP(Windows::Services::Maps::PlaceInfo), Windows::Services::Maps::MapLocation const&);
            *resultValue = detach_from<Windows::Services::Maps::PlaceInfo>(this->shim().CreateFromMapLocation(*reinterpret_cast<Windows::Services::Maps::MapLocation const*>(&location)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsShowSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsShowSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsShowSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Maps::IPlaceInfoStatics2> : produce_base<D, Windows::Services::Maps::IPlaceInfoStatics2>
{
    int32_t WINRT_CALL CreateFromAddress(void* displayAddress, void** resultValue) noexcept final
    {
        try
        {
            *resultValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromAddress, WINRT_WRAP(Windows::Services::Maps::PlaceInfo), hstring const&);
            *resultValue = detach_from<Windows::Services::Maps::PlaceInfo>(this->shim().CreateFromAddress(*reinterpret_cast<hstring const*>(&displayAddress)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromAddressWithName(void* displayAddress, void* displayName, void** resultValue) noexcept final
    {
        try
        {
            *resultValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromAddress, WINRT_WRAP(Windows::Services::Maps::PlaceInfo), hstring const&, hstring const&);
            *resultValue = detach_from<Windows::Services::Maps::PlaceInfo>(this->shim().CreateFromAddress(*reinterpret_cast<hstring const*>(&displayAddress), *reinterpret_cast<hstring const*>(&displayName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Services::Maps {

inline EnhancedWaypoint::EnhancedWaypoint(Windows::Devices::Geolocation::Geopoint const& point, Windows::Services::Maps::WaypointKind const& kind) :
    EnhancedWaypoint(impl::call_factory<EnhancedWaypoint, Windows::Services::Maps::IEnhancedWaypointFactory>([&](auto&& f) { return f.Create(point, kind); }))
{}

inline Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapLocationFinderResult> MapLocationFinder::FindLocationsAtAsync(Windows::Devices::Geolocation::Geopoint const& queryPoint)
{
    return impl::call_factory<MapLocationFinder, Windows::Services::Maps::IMapLocationFinderStatics>([&](auto&& f) { return f.FindLocationsAtAsync(queryPoint); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapLocationFinderResult> MapLocationFinder::FindLocationsAsync(param::hstring const& searchText, Windows::Devices::Geolocation::Geopoint const& referencePoint)
{
    return impl::call_factory<MapLocationFinder, Windows::Services::Maps::IMapLocationFinderStatics>([&](auto&& f) { return f.FindLocationsAsync(searchText, referencePoint); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapLocationFinderResult> MapLocationFinder::FindLocationsAsync(param::hstring const& searchText, Windows::Devices::Geolocation::Geopoint const& referencePoint, uint32_t maxCount)
{
    return impl::call_factory<MapLocationFinder, Windows::Services::Maps::IMapLocationFinderStatics>([&](auto&& f) { return f.FindLocationsAsync(searchText, referencePoint, maxCount); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapLocationFinderResult> MapLocationFinder::FindLocationsAtAsync(Windows::Devices::Geolocation::Geopoint const& queryPoint, Windows::Services::Maps::MapLocationDesiredAccuracy const& accuracy)
{
    return impl::call_factory<MapLocationFinder, Windows::Services::Maps::IMapLocationFinderStatics2>([&](auto&& f) { return f.FindLocationsAtAsync(queryPoint, accuracy); });
}

inline void MapManager::ShowDownloadedMapsUI()
{
    impl::call_factory<MapManager, Windows::Services::Maps::IMapManagerStatics>([&](auto&& f) { return f.ShowDownloadedMapsUI(); });
}

inline void MapManager::ShowMapsUpdateUI()
{
    impl::call_factory<MapManager, Windows::Services::Maps::IMapManagerStatics>([&](auto&& f) { return f.ShowMapsUpdateUI(); });
}

inline MapRouteDrivingOptions::MapRouteDrivingOptions() :
    MapRouteDrivingOptions(impl::call_factory<MapRouteDrivingOptions>([](auto&& f) { return f.template ActivateInstance<MapRouteDrivingOptions>(); }))
{}

inline Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapRouteFinderResult> MapRouteFinder::GetDrivingRouteAsync(Windows::Devices::Geolocation::Geopoint const& startPoint, Windows::Devices::Geolocation::Geopoint const& endPoint)
{
    return impl::call_factory<MapRouteFinder, Windows::Services::Maps::IMapRouteFinderStatics>([&](auto&& f) { return f.GetDrivingRouteAsync(startPoint, endPoint); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapRouteFinderResult> MapRouteFinder::GetDrivingRouteAsync(Windows::Devices::Geolocation::Geopoint const& startPoint, Windows::Devices::Geolocation::Geopoint const& endPoint, Windows::Services::Maps::MapRouteOptimization const& optimization)
{
    return impl::call_factory<MapRouteFinder, Windows::Services::Maps::IMapRouteFinderStatics>([&](auto&& f) { return f.GetDrivingRouteAsync(startPoint, endPoint, optimization); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapRouteFinderResult> MapRouteFinder::GetDrivingRouteAsync(Windows::Devices::Geolocation::Geopoint const& startPoint, Windows::Devices::Geolocation::Geopoint const& endPoint, Windows::Services::Maps::MapRouteOptimization const& optimization, Windows::Services::Maps::MapRouteRestrictions const& restrictions)
{
    return impl::call_factory<MapRouteFinder, Windows::Services::Maps::IMapRouteFinderStatics>([&](auto&& f) { return f.GetDrivingRouteAsync(startPoint, endPoint, optimization, restrictions); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapRouteFinderResult> MapRouteFinder::GetDrivingRouteAsync(Windows::Devices::Geolocation::Geopoint const& startPoint, Windows::Devices::Geolocation::Geopoint const& endPoint, Windows::Services::Maps::MapRouteOptimization const& optimization, Windows::Services::Maps::MapRouteRestrictions const& restrictions, double headingInDegrees)
{
    return impl::call_factory<MapRouteFinder, Windows::Services::Maps::IMapRouteFinderStatics>([&](auto&& f) { return f.GetDrivingRouteAsync(startPoint, endPoint, optimization, restrictions, headingInDegrees); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapRouteFinderResult> MapRouteFinder::GetDrivingRouteFromWaypointsAsync(param::async_iterable<Windows::Devices::Geolocation::Geopoint> const& wayPoints)
{
    return impl::call_factory<MapRouteFinder, Windows::Services::Maps::IMapRouteFinderStatics>([&](auto&& f) { return f.GetDrivingRouteFromWaypointsAsync(wayPoints); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapRouteFinderResult> MapRouteFinder::GetDrivingRouteFromWaypointsAsync(param::async_iterable<Windows::Devices::Geolocation::Geopoint> const& wayPoints, Windows::Services::Maps::MapRouteOptimization const& optimization)
{
    return impl::call_factory<MapRouteFinder, Windows::Services::Maps::IMapRouteFinderStatics>([&](auto&& f) { return f.GetDrivingRouteFromWaypointsAsync(wayPoints, optimization); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapRouteFinderResult> MapRouteFinder::GetDrivingRouteFromWaypointsAsync(param::async_iterable<Windows::Devices::Geolocation::Geopoint> const& wayPoints, Windows::Services::Maps::MapRouteOptimization const& optimization, Windows::Services::Maps::MapRouteRestrictions const& restrictions)
{
    return impl::call_factory<MapRouteFinder, Windows::Services::Maps::IMapRouteFinderStatics>([&](auto&& f) { return f.GetDrivingRouteFromWaypointsAsync(wayPoints, optimization, restrictions); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapRouteFinderResult> MapRouteFinder::GetDrivingRouteFromWaypointsAsync(param::async_iterable<Windows::Devices::Geolocation::Geopoint> const& wayPoints, Windows::Services::Maps::MapRouteOptimization const& optimization, Windows::Services::Maps::MapRouteRestrictions const& restrictions, double headingInDegrees)
{
    return impl::call_factory<MapRouteFinder, Windows::Services::Maps::IMapRouteFinderStatics>([&](auto&& f) { return f.GetDrivingRouteFromWaypointsAsync(wayPoints, optimization, restrictions, headingInDegrees); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapRouteFinderResult> MapRouteFinder::GetWalkingRouteAsync(Windows::Devices::Geolocation::Geopoint const& startPoint, Windows::Devices::Geolocation::Geopoint const& endPoint)
{
    return impl::call_factory<MapRouteFinder, Windows::Services::Maps::IMapRouteFinderStatics>([&](auto&& f) { return f.GetWalkingRouteAsync(startPoint, endPoint); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapRouteFinderResult> MapRouteFinder::GetWalkingRouteFromWaypointsAsync(param::async_iterable<Windows::Devices::Geolocation::Geopoint> const& wayPoints)
{
    return impl::call_factory<MapRouteFinder, Windows::Services::Maps::IMapRouteFinderStatics>([&](auto&& f) { return f.GetWalkingRouteFromWaypointsAsync(wayPoints); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapRouteFinderResult> MapRouteFinder::GetDrivingRouteAsync(Windows::Devices::Geolocation::Geopoint const& startPoint, Windows::Devices::Geolocation::Geopoint const& endPoint, Windows::Services::Maps::MapRouteDrivingOptions const& options)
{
    return impl::call_factory<MapRouteFinder, Windows::Services::Maps::IMapRouteFinderStatics2>([&](auto&& f) { return f.GetDrivingRouteAsync(startPoint, endPoint, options); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapRouteFinderResult> MapRouteFinder::GetDrivingRouteFromEnhancedWaypointsAsync(param::async_iterable<Windows::Services::Maps::EnhancedWaypoint> const& waypoints)
{
    return impl::call_factory<MapRouteFinder, Windows::Services::Maps::IMapRouteFinderStatics3>([&](auto&& f) { return f.GetDrivingRouteFromEnhancedWaypointsAsync(waypoints); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Services::Maps::MapRouteFinderResult> MapRouteFinder::GetDrivingRouteFromEnhancedWaypointsAsync(param::async_iterable<Windows::Services::Maps::EnhancedWaypoint> const& waypoints, Windows::Services::Maps::MapRouteDrivingOptions const& options)
{
    return impl::call_factory<MapRouteFinder, Windows::Services::Maps::IMapRouteFinderStatics3>([&](auto&& f) { return f.GetDrivingRouteFromEnhancedWaypointsAsync(waypoints, options); });
}

inline void MapService::ServiceToken(param::hstring const& value)
{
    impl::call_factory<MapService, Windows::Services::Maps::IMapServiceStatics>([&](auto&& f) { return f.ServiceToken(value); });
}

inline hstring MapService::ServiceToken()
{
    return impl::call_factory<MapService, Windows::Services::Maps::IMapServiceStatics>([&](auto&& f) { return f.ServiceToken(); });
}

inline hstring MapService::WorldViewRegionCode()
{
    return impl::call_factory<MapService, Windows::Services::Maps::IMapServiceStatics2>([&](auto&& f) { return f.WorldViewRegionCode(); });
}

inline hstring MapService::DataAttributions()
{
    return impl::call_factory<MapService, Windows::Services::Maps::IMapServiceStatics3>([&](auto&& f) { return f.DataAttributions(); });
}

inline void MapService::DataUsagePreference(Windows::Services::Maps::MapServiceDataUsagePreference const& value)
{
    impl::call_factory<MapService, Windows::Services::Maps::IMapServiceStatics4>([&](auto&& f) { return f.DataUsagePreference(value); });
}

inline Windows::Services::Maps::MapServiceDataUsagePreference MapService::DataUsagePreference()
{
    return impl::call_factory<MapService, Windows::Services::Maps::IMapServiceStatics4>([&](auto&& f) { return f.DataUsagePreference(); });
}

inline Windows::Services::Maps::PlaceInfo PlaceInfo::Create(Windows::Devices::Geolocation::Geopoint const& referencePoint)
{
    return impl::call_factory<PlaceInfo, Windows::Services::Maps::IPlaceInfoStatics>([&](auto&& f) { return f.Create(referencePoint); });
}

inline Windows::Services::Maps::PlaceInfo PlaceInfo::Create(Windows::Devices::Geolocation::Geopoint const& referencePoint, Windows::Services::Maps::PlaceInfoCreateOptions const& options)
{
    return impl::call_factory<PlaceInfo, Windows::Services::Maps::IPlaceInfoStatics>([&](auto&& f) { return f.Create(referencePoint, options); });
}

inline Windows::Services::Maps::PlaceInfo PlaceInfo::CreateFromIdentifier(param::hstring const& identifier)
{
    return impl::call_factory<PlaceInfo, Windows::Services::Maps::IPlaceInfoStatics>([&](auto&& f) { return f.CreateFromIdentifier(identifier); });
}

inline Windows::Services::Maps::PlaceInfo PlaceInfo::CreateFromIdentifier(param::hstring const& identifier, Windows::Devices::Geolocation::Geopoint const& defaultPoint, Windows::Services::Maps::PlaceInfoCreateOptions const& options)
{
    return impl::call_factory<PlaceInfo, Windows::Services::Maps::IPlaceInfoStatics>([&](auto&& f) { return f.CreateFromIdentifier(identifier, defaultPoint, options); });
}

inline Windows::Services::Maps::PlaceInfo PlaceInfo::CreateFromMapLocation(Windows::Services::Maps::MapLocation const& location)
{
    return impl::call_factory<PlaceInfo, Windows::Services::Maps::IPlaceInfoStatics>([&](auto&& f) { return f.CreateFromMapLocation(location); });
}

inline bool PlaceInfo::IsShowSupported()
{
    return impl::call_factory<PlaceInfo, Windows::Services::Maps::IPlaceInfoStatics>([&](auto&& f) { return f.IsShowSupported(); });
}

inline Windows::Services::Maps::PlaceInfo PlaceInfo::CreateFromAddress(param::hstring const& displayAddress)
{
    return impl::call_factory<PlaceInfo, Windows::Services::Maps::IPlaceInfoStatics2>([&](auto&& f) { return f.CreateFromAddress(displayAddress); });
}

inline Windows::Services::Maps::PlaceInfo PlaceInfo::CreateFromAddress(param::hstring const& displayAddress, param::hstring const& displayName)
{
    return impl::call_factory<PlaceInfo, Windows::Services::Maps::IPlaceInfoStatics2>([&](auto&& f) { return f.CreateFromAddress(displayAddress, displayName); });
}

inline PlaceInfoCreateOptions::PlaceInfoCreateOptions() :
    PlaceInfoCreateOptions(impl::call_factory<PlaceInfoCreateOptions>([](auto&& f) { return f.template ActivateInstance<PlaceInfoCreateOptions>(); }))
{}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Services::Maps::IEnhancedWaypoint> : winrt::impl::hash_base<winrt::Windows::Services::Maps::IEnhancedWaypoint> {};
template<> struct hash<winrt::Windows::Services::Maps::IEnhancedWaypointFactory> : winrt::impl::hash_base<winrt::Windows::Services::Maps::IEnhancedWaypointFactory> {};
template<> struct hash<winrt::Windows::Services::Maps::IManeuverWarning> : winrt::impl::hash_base<winrt::Windows::Services::Maps::IManeuverWarning> {};
template<> struct hash<winrt::Windows::Services::Maps::IMapAddress> : winrt::impl::hash_base<winrt::Windows::Services::Maps::IMapAddress> {};
template<> struct hash<winrt::Windows::Services::Maps::IMapAddress2> : winrt::impl::hash_base<winrt::Windows::Services::Maps::IMapAddress2> {};
template<> struct hash<winrt::Windows::Services::Maps::IMapLocation> : winrt::impl::hash_base<winrt::Windows::Services::Maps::IMapLocation> {};
template<> struct hash<winrt::Windows::Services::Maps::IMapLocationFinderResult> : winrt::impl::hash_base<winrt::Windows::Services::Maps::IMapLocationFinderResult> {};
template<> struct hash<winrt::Windows::Services::Maps::IMapLocationFinderStatics> : winrt::impl::hash_base<winrt::Windows::Services::Maps::IMapLocationFinderStatics> {};
template<> struct hash<winrt::Windows::Services::Maps::IMapLocationFinderStatics2> : winrt::impl::hash_base<winrt::Windows::Services::Maps::IMapLocationFinderStatics2> {};
template<> struct hash<winrt::Windows::Services::Maps::IMapManagerStatics> : winrt::impl::hash_base<winrt::Windows::Services::Maps::IMapManagerStatics> {};
template<> struct hash<winrt::Windows::Services::Maps::IMapRoute> : winrt::impl::hash_base<winrt::Windows::Services::Maps::IMapRoute> {};
template<> struct hash<winrt::Windows::Services::Maps::IMapRoute2> : winrt::impl::hash_base<winrt::Windows::Services::Maps::IMapRoute2> {};
template<> struct hash<winrt::Windows::Services::Maps::IMapRoute3> : winrt::impl::hash_base<winrt::Windows::Services::Maps::IMapRoute3> {};
template<> struct hash<winrt::Windows::Services::Maps::IMapRoute4> : winrt::impl::hash_base<winrt::Windows::Services::Maps::IMapRoute4> {};
template<> struct hash<winrt::Windows::Services::Maps::IMapRouteDrivingOptions> : winrt::impl::hash_base<winrt::Windows::Services::Maps::IMapRouteDrivingOptions> {};
template<> struct hash<winrt::Windows::Services::Maps::IMapRouteDrivingOptions2> : winrt::impl::hash_base<winrt::Windows::Services::Maps::IMapRouteDrivingOptions2> {};
template<> struct hash<winrt::Windows::Services::Maps::IMapRouteFinderResult> : winrt::impl::hash_base<winrt::Windows::Services::Maps::IMapRouteFinderResult> {};
template<> struct hash<winrt::Windows::Services::Maps::IMapRouteFinderResult2> : winrt::impl::hash_base<winrt::Windows::Services::Maps::IMapRouteFinderResult2> {};
template<> struct hash<winrt::Windows::Services::Maps::IMapRouteFinderStatics> : winrt::impl::hash_base<winrt::Windows::Services::Maps::IMapRouteFinderStatics> {};
template<> struct hash<winrt::Windows::Services::Maps::IMapRouteFinderStatics2> : winrt::impl::hash_base<winrt::Windows::Services::Maps::IMapRouteFinderStatics2> {};
template<> struct hash<winrt::Windows::Services::Maps::IMapRouteFinderStatics3> : winrt::impl::hash_base<winrt::Windows::Services::Maps::IMapRouteFinderStatics3> {};
template<> struct hash<winrt::Windows::Services::Maps::IMapRouteLeg> : winrt::impl::hash_base<winrt::Windows::Services::Maps::IMapRouteLeg> {};
template<> struct hash<winrt::Windows::Services::Maps::IMapRouteLeg2> : winrt::impl::hash_base<winrt::Windows::Services::Maps::IMapRouteLeg2> {};
template<> struct hash<winrt::Windows::Services::Maps::IMapRouteManeuver> : winrt::impl::hash_base<winrt::Windows::Services::Maps::IMapRouteManeuver> {};
template<> struct hash<winrt::Windows::Services::Maps::IMapRouteManeuver2> : winrt::impl::hash_base<winrt::Windows::Services::Maps::IMapRouteManeuver2> {};
template<> struct hash<winrt::Windows::Services::Maps::IMapRouteManeuver3> : winrt::impl::hash_base<winrt::Windows::Services::Maps::IMapRouteManeuver3> {};
template<> struct hash<winrt::Windows::Services::Maps::IMapServiceStatics> : winrt::impl::hash_base<winrt::Windows::Services::Maps::IMapServiceStatics> {};
template<> struct hash<winrt::Windows::Services::Maps::IMapServiceStatics2> : winrt::impl::hash_base<winrt::Windows::Services::Maps::IMapServiceStatics2> {};
template<> struct hash<winrt::Windows::Services::Maps::IMapServiceStatics3> : winrt::impl::hash_base<winrt::Windows::Services::Maps::IMapServiceStatics3> {};
template<> struct hash<winrt::Windows::Services::Maps::IMapServiceStatics4> : winrt::impl::hash_base<winrt::Windows::Services::Maps::IMapServiceStatics4> {};
template<> struct hash<winrt::Windows::Services::Maps::IPlaceInfo> : winrt::impl::hash_base<winrt::Windows::Services::Maps::IPlaceInfo> {};
template<> struct hash<winrt::Windows::Services::Maps::IPlaceInfoCreateOptions> : winrt::impl::hash_base<winrt::Windows::Services::Maps::IPlaceInfoCreateOptions> {};
template<> struct hash<winrt::Windows::Services::Maps::IPlaceInfoStatics> : winrt::impl::hash_base<winrt::Windows::Services::Maps::IPlaceInfoStatics> {};
template<> struct hash<winrt::Windows::Services::Maps::IPlaceInfoStatics2> : winrt::impl::hash_base<winrt::Windows::Services::Maps::IPlaceInfoStatics2> {};
template<> struct hash<winrt::Windows::Services::Maps::EnhancedWaypoint> : winrt::impl::hash_base<winrt::Windows::Services::Maps::EnhancedWaypoint> {};
template<> struct hash<winrt::Windows::Services::Maps::ManeuverWarning> : winrt::impl::hash_base<winrt::Windows::Services::Maps::ManeuverWarning> {};
template<> struct hash<winrt::Windows::Services::Maps::MapAddress> : winrt::impl::hash_base<winrt::Windows::Services::Maps::MapAddress> {};
template<> struct hash<winrt::Windows::Services::Maps::MapLocation> : winrt::impl::hash_base<winrt::Windows::Services::Maps::MapLocation> {};
template<> struct hash<winrt::Windows::Services::Maps::MapLocationFinder> : winrt::impl::hash_base<winrt::Windows::Services::Maps::MapLocationFinder> {};
template<> struct hash<winrt::Windows::Services::Maps::MapLocationFinderResult> : winrt::impl::hash_base<winrt::Windows::Services::Maps::MapLocationFinderResult> {};
template<> struct hash<winrt::Windows::Services::Maps::MapManager> : winrt::impl::hash_base<winrt::Windows::Services::Maps::MapManager> {};
template<> struct hash<winrt::Windows::Services::Maps::MapRoute> : winrt::impl::hash_base<winrt::Windows::Services::Maps::MapRoute> {};
template<> struct hash<winrt::Windows::Services::Maps::MapRouteDrivingOptions> : winrt::impl::hash_base<winrt::Windows::Services::Maps::MapRouteDrivingOptions> {};
template<> struct hash<winrt::Windows::Services::Maps::MapRouteFinder> : winrt::impl::hash_base<winrt::Windows::Services::Maps::MapRouteFinder> {};
template<> struct hash<winrt::Windows::Services::Maps::MapRouteFinderResult> : winrt::impl::hash_base<winrt::Windows::Services::Maps::MapRouteFinderResult> {};
template<> struct hash<winrt::Windows::Services::Maps::MapRouteLeg> : winrt::impl::hash_base<winrt::Windows::Services::Maps::MapRouteLeg> {};
template<> struct hash<winrt::Windows::Services::Maps::MapRouteManeuver> : winrt::impl::hash_base<winrt::Windows::Services::Maps::MapRouteManeuver> {};
template<> struct hash<winrt::Windows::Services::Maps::MapService> : winrt::impl::hash_base<winrt::Windows::Services::Maps::MapService> {};
template<> struct hash<winrt::Windows::Services::Maps::PlaceInfo> : winrt::impl::hash_base<winrt::Windows::Services::Maps::PlaceInfo> {};
template<> struct hash<winrt::Windows::Services::Maps::PlaceInfoCreateOptions> : winrt::impl::hash_base<winrt::Windows::Services::Maps::PlaceInfoCreateOptions> {};

}
