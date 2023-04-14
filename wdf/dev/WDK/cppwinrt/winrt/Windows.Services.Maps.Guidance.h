// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Devices.Geolocation.2.h"
#include "winrt/impl/Windows.Services.Maps.2.h"
#include "winrt/impl/Windows.UI.2.h"
#include "winrt/impl/Windows.Services.Maps.Guidance.2.h"
#include "winrt/Windows.Services.Maps.h"

namespace winrt::impl {

template <typename D> Windows::Services::Maps::Guidance::GuidanceAudioNotificationKind consume_Windows_Services_Maps_Guidance_IGuidanceAudioNotificationRequestedEventArgs<D>::AudioNotification() const
{
    Windows::Services::Maps::Guidance::GuidanceAudioNotificationKind value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceAudioNotificationRequestedEventArgs)->get_AudioNotification(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<hstring> consume_Windows_Services_Maps_Guidance_IGuidanceAudioNotificationRequestedEventArgs<D>::AudioFilePaths() const
{
    Windows::Foundation::Collections::IVectorView<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceAudioNotificationRequestedEventArgs)->get_AudioFilePaths(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Maps_Guidance_IGuidanceAudioNotificationRequestedEventArgs<D>::AudioText() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceAudioNotificationRequestedEventArgs)->get_AudioText(put_abi(value)));
    return value;
}

template <typename D> Windows::Services::Maps::Guidance::GuidanceLaneMarkers consume_Windows_Services_Maps_Guidance_IGuidanceLaneInfo<D>::LaneMarkers() const
{
    Windows::Services::Maps::Guidance::GuidanceLaneMarkers value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceLaneInfo)->get_LaneMarkers(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Services_Maps_Guidance_IGuidanceLaneInfo<D>::IsOnRoute() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceLaneInfo)->get_IsOnRoute(&value));
    return value;
}

template <typename D> Windows::Devices::Geolocation::Geopoint consume_Windows_Services_Maps_Guidance_IGuidanceManeuver<D>::StartLocation() const
{
    Windows::Devices::Geolocation::Geopoint value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceManeuver)->get_StartLocation(put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_Services_Maps_Guidance_IGuidanceManeuver<D>::DistanceFromRouteStart() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceManeuver)->get_DistanceFromRouteStart(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Services_Maps_Guidance_IGuidanceManeuver<D>::DistanceFromPreviousManeuver() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceManeuver)->get_DistanceFromPreviousManeuver(&value));
    return value;
}

template <typename D> hstring consume_Windows_Services_Maps_Guidance_IGuidanceManeuver<D>::DepartureRoadName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceManeuver)->get_DepartureRoadName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Maps_Guidance_IGuidanceManeuver<D>::NextRoadName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceManeuver)->get_NextRoadName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Maps_Guidance_IGuidanceManeuver<D>::DepartureShortRoadName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceManeuver)->get_DepartureShortRoadName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Maps_Guidance_IGuidanceManeuver<D>::NextShortRoadName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceManeuver)->get_NextShortRoadName(put_abi(value)));
    return value;
}

template <typename D> Windows::Services::Maps::Guidance::GuidanceManeuverKind consume_Windows_Services_Maps_Guidance_IGuidanceManeuver<D>::Kind() const
{
    Windows::Services::Maps::Guidance::GuidanceManeuverKind value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceManeuver)->get_Kind(put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_Services_Maps_Guidance_IGuidanceManeuver<D>::StartAngle() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceManeuver)->get_StartAngle(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Services_Maps_Guidance_IGuidanceManeuver<D>::EndAngle() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceManeuver)->get_EndAngle(&value));
    return value;
}

template <typename D> Windows::Services::Maps::Guidance::GuidanceRoadSignpost consume_Windows_Services_Maps_Guidance_IGuidanceManeuver<D>::RoadSignpost() const
{
    Windows::Services::Maps::Guidance::GuidanceRoadSignpost value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceManeuver)->get_RoadSignpost(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Maps_Guidance_IGuidanceManeuver<D>::InstructionText() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceManeuver)->get_InstructionText(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Geolocation::Geopoint consume_Windows_Services_Maps_Guidance_IGuidanceMapMatchedCoordinate<D>::Location() const
{
    Windows::Devices::Geolocation::Geopoint value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceMapMatchedCoordinate)->get_Location(put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_Services_Maps_Guidance_IGuidanceMapMatchedCoordinate<D>::CurrentHeading() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceMapMatchedCoordinate)->get_CurrentHeading(&value));
    return value;
}

template <typename D> double consume_Windows_Services_Maps_Guidance_IGuidanceMapMatchedCoordinate<D>::CurrentSpeed() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceMapMatchedCoordinate)->get_CurrentSpeed(&value));
    return value;
}

template <typename D> bool consume_Windows_Services_Maps_Guidance_IGuidanceMapMatchedCoordinate<D>::IsOnStreet() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceMapMatchedCoordinate)->get_IsOnStreet(&value));
    return value;
}

template <typename D> Windows::Services::Maps::Guidance::GuidanceRoadSegment consume_Windows_Services_Maps_Guidance_IGuidanceMapMatchedCoordinate<D>::Road() const
{
    Windows::Services::Maps::Guidance::GuidanceRoadSegment value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceMapMatchedCoordinate)->get_Road(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::StartNavigating(Windows::Services::Maps::Guidance::GuidanceRoute const& route) const
{
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceNavigator)->StartNavigating(get_abi(route)));
}

template <typename D> void consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::StartSimulating(Windows::Services::Maps::Guidance::GuidanceRoute const& route, int32_t speedInMetersPerSecond) const
{
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceNavigator)->StartSimulating(get_abi(route), speedInMetersPerSecond));
}

template <typename D> void consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::StartTracking() const
{
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceNavigator)->StartTracking());
}

template <typename D> void consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::Pause() const
{
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceNavigator)->Pause());
}

template <typename D> void consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::Resume() const
{
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceNavigator)->Resume());
}

template <typename D> void consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::Stop() const
{
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceNavigator)->Stop());
}

template <typename D> void consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::RepeatLastAudioNotification() const
{
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceNavigator)->RepeatLastAudioNotification());
}

template <typename D> Windows::Services::Maps::Guidance::GuidanceAudioMeasurementSystem consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::AudioMeasurementSystem() const
{
    Windows::Services::Maps::Guidance::GuidanceAudioMeasurementSystem value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceNavigator)->get_AudioMeasurementSystem(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::AudioMeasurementSystem(Windows::Services::Maps::Guidance::GuidanceAudioMeasurementSystem const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceNavigator)->put_AudioMeasurementSystem(get_abi(value)));
}

template <typename D> Windows::Services::Maps::Guidance::GuidanceAudioNotifications consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::AudioNotifications() const
{
    Windows::Services::Maps::Guidance::GuidanceAudioNotifications value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceNavigator)->get_AudioNotifications(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::AudioNotifications(Windows::Services::Maps::Guidance::GuidanceAudioNotifications const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceNavigator)->put_AudioNotifications(get_abi(value)));
}

template <typename D> winrt::event_token consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::GuidanceUpdated(Windows::Foundation::TypedEventHandler<Windows::Services::Maps::Guidance::GuidanceNavigator, Windows::Services::Maps::Guidance::GuidanceUpdatedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceNavigator)->add_GuidanceUpdated(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::GuidanceUpdated_revoker consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::GuidanceUpdated(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Services::Maps::Guidance::GuidanceNavigator, Windows::Services::Maps::Guidance::GuidanceUpdatedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, GuidanceUpdated_revoker>(this, GuidanceUpdated(handler));
}

template <typename D> void consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::GuidanceUpdated(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceNavigator)->remove_GuidanceUpdated(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::DestinationReached(Windows::Foundation::TypedEventHandler<Windows::Services::Maps::Guidance::GuidanceNavigator, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceNavigator)->add_DestinationReached(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::DestinationReached_revoker consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::DestinationReached(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Services::Maps::Guidance::GuidanceNavigator, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, DestinationReached_revoker>(this, DestinationReached(handler));
}

template <typename D> void consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::DestinationReached(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceNavigator)->remove_DestinationReached(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::Rerouting(Windows::Foundation::TypedEventHandler<Windows::Services::Maps::Guidance::GuidanceNavigator, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceNavigator)->add_Rerouting(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::Rerouting_revoker consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::Rerouting(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Services::Maps::Guidance::GuidanceNavigator, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, Rerouting_revoker>(this, Rerouting(handler));
}

template <typename D> void consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::Rerouting(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceNavigator)->remove_Rerouting(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::Rerouted(Windows::Foundation::TypedEventHandler<Windows::Services::Maps::Guidance::GuidanceNavigator, Windows::Services::Maps::Guidance::GuidanceReroutedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceNavigator)->add_Rerouted(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::Rerouted_revoker consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::Rerouted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Services::Maps::Guidance::GuidanceNavigator, Windows::Services::Maps::Guidance::GuidanceReroutedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Rerouted_revoker>(this, Rerouted(handler));
}

template <typename D> void consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::Rerouted(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceNavigator)->remove_Rerouted(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::RerouteFailed(Windows::Foundation::TypedEventHandler<Windows::Services::Maps::Guidance::GuidanceNavigator, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceNavigator)->add_RerouteFailed(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::RerouteFailed_revoker consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::RerouteFailed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Services::Maps::Guidance::GuidanceNavigator, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, RerouteFailed_revoker>(this, RerouteFailed(handler));
}

template <typename D> void consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::RerouteFailed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceNavigator)->remove_RerouteFailed(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::UserLocationLost(Windows::Foundation::TypedEventHandler<Windows::Services::Maps::Guidance::GuidanceNavigator, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceNavigator)->add_UserLocationLost(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::UserLocationLost_revoker consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::UserLocationLost(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Services::Maps::Guidance::GuidanceNavigator, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, UserLocationLost_revoker>(this, UserLocationLost(handler));
}

template <typename D> void consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::UserLocationLost(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceNavigator)->remove_UserLocationLost(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::UserLocationRestored(Windows::Foundation::TypedEventHandler<Windows::Services::Maps::Guidance::GuidanceNavigator, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceNavigator)->add_UserLocationRestored(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::UserLocationRestored_revoker consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::UserLocationRestored(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Services::Maps::Guidance::GuidanceNavigator, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, UserLocationRestored_revoker>(this, UserLocationRestored(handler));
}

template <typename D> void consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::UserLocationRestored(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceNavigator)->remove_UserLocationRestored(get_abi(token)));
}

template <typename D> void consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::SetGuidanceVoice(int32_t voiceId, param::hstring const& voiceFolder) const
{
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceNavigator)->SetGuidanceVoice(voiceId, get_abi(voiceFolder)));
}

template <typename D> void consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::UpdateUserLocation(Windows::Devices::Geolocation::Geocoordinate const& userLocation) const
{
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceNavigator)->UpdateUserLocation(get_abi(userLocation)));
}

template <typename D> void consume_Windows_Services_Maps_Guidance_IGuidanceNavigator<D>::UpdateUserLocation(Windows::Devices::Geolocation::Geocoordinate const& userLocation, Windows::Devices::Geolocation::BasicGeoposition const& positionOverride) const
{
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceNavigator)->UpdateUserLocationWithPositionOverride(get_abi(userLocation), get_abi(positionOverride)));
}

template <typename D> winrt::event_token consume_Windows_Services_Maps_Guidance_IGuidanceNavigator2<D>::AudioNotificationRequested(Windows::Foundation::TypedEventHandler<Windows::Services::Maps::Guidance::GuidanceNavigator, Windows::Services::Maps::Guidance::GuidanceAudioNotificationRequestedEventArgs> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceNavigator2)->add_AudioNotificationRequested(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Services_Maps_Guidance_IGuidanceNavigator2<D>::AudioNotificationRequested_revoker consume_Windows_Services_Maps_Guidance_IGuidanceNavigator2<D>::AudioNotificationRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Services::Maps::Guidance::GuidanceNavigator, Windows::Services::Maps::Guidance::GuidanceAudioNotificationRequestedEventArgs> const& value) const
{
    return impl::make_event_revoker<D, AudioNotificationRequested_revoker>(this, AudioNotificationRequested(value));
}

template <typename D> void consume_Windows_Services_Maps_Guidance_IGuidanceNavigator2<D>::AudioNotificationRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceNavigator2)->remove_AudioNotificationRequested(get_abi(token)));
}

template <typename D> bool consume_Windows_Services_Maps_Guidance_IGuidanceNavigator2<D>::IsGuidanceAudioMuted() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceNavigator2)->get_IsGuidanceAudioMuted(&value));
    return value;
}

template <typename D> void consume_Windows_Services_Maps_Guidance_IGuidanceNavigator2<D>::IsGuidanceAudioMuted(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceNavigator2)->put_IsGuidanceAudioMuted(value));
}

template <typename D> Windows::Services::Maps::Guidance::GuidanceNavigator consume_Windows_Services_Maps_Guidance_IGuidanceNavigatorStatics<D>::GetCurrent() const
{
    Windows::Services::Maps::Guidance::GuidanceNavigator result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceNavigatorStatics)->GetCurrent(put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_Services_Maps_Guidance_IGuidanceNavigatorStatics2<D>::UseAppProvidedVoice() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceNavigatorStatics2)->get_UseAppProvidedVoice(&value));
    return value;
}

template <typename D> Windows::Services::Maps::Guidance::GuidanceRoute consume_Windows_Services_Maps_Guidance_IGuidanceReroutedEventArgs<D>::Route() const
{
    Windows::Services::Maps::Guidance::GuidanceRoute result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceReroutedEventArgs)->get_Route(put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Services_Maps_Guidance_IGuidanceRoadSegment<D>::RoadName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceRoadSegment)->get_RoadName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Maps_Guidance_IGuidanceRoadSegment<D>::ShortRoadName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceRoadSegment)->get_ShortRoadName(put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_Services_Maps_Guidance_IGuidanceRoadSegment<D>::SpeedLimit() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceRoadSegment)->get_SpeedLimit(&value));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Services_Maps_Guidance_IGuidanceRoadSegment<D>::TravelTime() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceRoadSegment)->get_TravelTime(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Geolocation::Geopath consume_Windows_Services_Maps_Guidance_IGuidanceRoadSegment<D>::Path() const
{
    Windows::Devices::Geolocation::Geopath value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceRoadSegment)->get_Path(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Maps_Guidance_IGuidanceRoadSegment<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceRoadSegment)->get_Id(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Services_Maps_Guidance_IGuidanceRoadSegment<D>::IsHighway() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceRoadSegment)->get_IsHighway(&value));
    return value;
}

template <typename D> bool consume_Windows_Services_Maps_Guidance_IGuidanceRoadSegment<D>::IsTunnel() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceRoadSegment)->get_IsTunnel(&value));
    return value;
}

template <typename D> bool consume_Windows_Services_Maps_Guidance_IGuidanceRoadSegment<D>::IsTollRoad() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceRoadSegment)->get_IsTollRoad(&value));
    return value;
}

template <typename D> bool consume_Windows_Services_Maps_Guidance_IGuidanceRoadSegment2<D>::IsScenic() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceRoadSegment2)->get_IsScenic(&value));
    return value;
}

template <typename D> hstring consume_Windows_Services_Maps_Guidance_IGuidanceRoadSignpost<D>::ExitNumber() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceRoadSignpost)->get_ExitNumber(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Maps_Guidance_IGuidanceRoadSignpost<D>::Exit() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceRoadSignpost)->get_Exit(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_Services_Maps_Guidance_IGuidanceRoadSignpost<D>::BackgroundColor() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceRoadSignpost)->get_BackgroundColor(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_Services_Maps_Guidance_IGuidanceRoadSignpost<D>::ForegroundColor() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceRoadSignpost)->get_ForegroundColor(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<hstring> consume_Windows_Services_Maps_Guidance_IGuidanceRoadSignpost<D>::ExitDirections() const
{
    Windows::Foundation::Collections::IVectorView<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceRoadSignpost)->get_ExitDirections(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Services_Maps_Guidance_IGuidanceRoute<D>::Duration() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceRoute)->get_Duration(put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_Services_Maps_Guidance_IGuidanceRoute<D>::Distance() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceRoute)->get_Distance(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Services::Maps::Guidance::GuidanceManeuver> consume_Windows_Services_Maps_Guidance_IGuidanceRoute<D>::Maneuvers() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Services::Maps::Guidance::GuidanceManeuver> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceRoute)->get_Maneuvers(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Geolocation::GeoboundingBox consume_Windows_Services_Maps_Guidance_IGuidanceRoute<D>::BoundingBox() const
{
    Windows::Devices::Geolocation::GeoboundingBox value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceRoute)->get_BoundingBox(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Geolocation::Geopath consume_Windows_Services_Maps_Guidance_IGuidanceRoute<D>::Path() const
{
    Windows::Devices::Geolocation::Geopath value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceRoute)->get_Path(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Services::Maps::Guidance::GuidanceRoadSegment> consume_Windows_Services_Maps_Guidance_IGuidanceRoute<D>::RoadSegments() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Services::Maps::Guidance::GuidanceRoadSegment> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceRoute)->get_RoadSegments(put_abi(value)));
    return value;
}

template <typename D> Windows::Services::Maps::MapRoute consume_Windows_Services_Maps_Guidance_IGuidanceRoute<D>::ConvertToMapRoute() const
{
    Windows::Services::Maps::MapRoute result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceRoute)->ConvertToMapRoute(put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_Services_Maps_Guidance_IGuidanceRouteStatics<D>::CanCreateFromMapRoute(Windows::Services::Maps::MapRoute const& mapRoute) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceRouteStatics)->CanCreateFromMapRoute(get_abi(mapRoute), &result));
    return result;
}

template <typename D> Windows::Services::Maps::Guidance::GuidanceRoute consume_Windows_Services_Maps_Guidance_IGuidanceRouteStatics<D>::TryCreateFromMapRoute(Windows::Services::Maps::MapRoute const& mapRoute) const
{
    Windows::Services::Maps::Guidance::GuidanceRoute result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceRouteStatics)->TryCreateFromMapRoute(get_abi(mapRoute), put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_Services_Maps_Guidance_IGuidanceTelemetryCollector<D>::Enabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceTelemetryCollector)->get_Enabled(&value));
    return value;
}

template <typename D> void consume_Windows_Services_Maps_Guidance_IGuidanceTelemetryCollector<D>::Enabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceTelemetryCollector)->put_Enabled(value));
}

template <typename D> void consume_Windows_Services_Maps_Guidance_IGuidanceTelemetryCollector<D>::ClearLocalData() const
{
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceTelemetryCollector)->ClearLocalData());
}

template <typename D> double consume_Windows_Services_Maps_Guidance_IGuidanceTelemetryCollector<D>::SpeedTrigger() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceTelemetryCollector)->get_SpeedTrigger(&value));
    return value;
}

template <typename D> void consume_Windows_Services_Maps_Guidance_IGuidanceTelemetryCollector<D>::SpeedTrigger(double value) const
{
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceTelemetryCollector)->put_SpeedTrigger(value));
}

template <typename D> int32_t consume_Windows_Services_Maps_Guidance_IGuidanceTelemetryCollector<D>::UploadFrequency() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceTelemetryCollector)->get_UploadFrequency(&value));
    return value;
}

template <typename D> void consume_Windows_Services_Maps_Guidance_IGuidanceTelemetryCollector<D>::UploadFrequency(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceTelemetryCollector)->put_UploadFrequency(value));
}

template <typename D> Windows::Services::Maps::Guidance::GuidanceTelemetryCollector consume_Windows_Services_Maps_Guidance_IGuidanceTelemetryCollectorStatics<D>::GetCurrent() const
{
    Windows::Services::Maps::Guidance::GuidanceTelemetryCollector result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceTelemetryCollectorStatics)->GetCurrent(put_abi(result)));
    return result;
}

template <typename D> Windows::Services::Maps::Guidance::GuidanceMode consume_Windows_Services_Maps_Guidance_IGuidanceUpdatedEventArgs<D>::Mode() const
{
    Windows::Services::Maps::Guidance::GuidanceMode value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceUpdatedEventArgs)->get_Mode(put_abi(value)));
    return value;
}

template <typename D> Windows::Services::Maps::Guidance::GuidanceManeuver consume_Windows_Services_Maps_Guidance_IGuidanceUpdatedEventArgs<D>::NextManeuver() const
{
    Windows::Services::Maps::Guidance::GuidanceManeuver value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceUpdatedEventArgs)->get_NextManeuver(put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_Services_Maps_Guidance_IGuidanceUpdatedEventArgs<D>::NextManeuverDistance() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceUpdatedEventArgs)->get_NextManeuverDistance(&value));
    return value;
}

template <typename D> Windows::Services::Maps::Guidance::GuidanceManeuver consume_Windows_Services_Maps_Guidance_IGuidanceUpdatedEventArgs<D>::AfterNextManeuver() const
{
    Windows::Services::Maps::Guidance::GuidanceManeuver value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceUpdatedEventArgs)->get_AfterNextManeuver(put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_Services_Maps_Guidance_IGuidanceUpdatedEventArgs<D>::AfterNextManeuverDistance() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceUpdatedEventArgs)->get_AfterNextManeuverDistance(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Services_Maps_Guidance_IGuidanceUpdatedEventArgs<D>::DistanceToDestination() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceUpdatedEventArgs)->get_DistanceToDestination(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Services_Maps_Guidance_IGuidanceUpdatedEventArgs<D>::ElapsedDistance() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceUpdatedEventArgs)->get_ElapsedDistance(&value));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Services_Maps_Guidance_IGuidanceUpdatedEventArgs<D>::ElapsedTime() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceUpdatedEventArgs)->get_ElapsedTime(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Services_Maps_Guidance_IGuidanceUpdatedEventArgs<D>::TimeToDestination() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceUpdatedEventArgs)->get_TimeToDestination(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Maps_Guidance_IGuidanceUpdatedEventArgs<D>::RoadName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceUpdatedEventArgs)->get_RoadName(put_abi(value)));
    return value;
}

template <typename D> Windows::Services::Maps::Guidance::GuidanceRoute consume_Windows_Services_Maps_Guidance_IGuidanceUpdatedEventArgs<D>::Route() const
{
    Windows::Services::Maps::Guidance::GuidanceRoute result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceUpdatedEventArgs)->get_Route(put_abi(result)));
    return result;
}

template <typename D> Windows::Services::Maps::Guidance::GuidanceMapMatchedCoordinate consume_Windows_Services_Maps_Guidance_IGuidanceUpdatedEventArgs<D>::CurrentLocation() const
{
    Windows::Services::Maps::Guidance::GuidanceMapMatchedCoordinate result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceUpdatedEventArgs)->get_CurrentLocation(put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_Services_Maps_Guidance_IGuidanceUpdatedEventArgs<D>::IsNewManeuver() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceUpdatedEventArgs)->get_IsNewManeuver(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Services::Maps::Guidance::GuidanceLaneInfo> consume_Windows_Services_Maps_Guidance_IGuidanceUpdatedEventArgs<D>::LaneInfo() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Services::Maps::Guidance::GuidanceLaneInfo> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::Guidance::IGuidanceUpdatedEventArgs)->get_LaneInfo(put_abi(value)));
    return value;
}

template <typename D>
struct produce<D, Windows::Services::Maps::Guidance::IGuidanceAudioNotificationRequestedEventArgs> : produce_base<D, Windows::Services::Maps::Guidance::IGuidanceAudioNotificationRequestedEventArgs>
{
    int32_t WINRT_CALL get_AudioNotification(Windows::Services::Maps::Guidance::GuidanceAudioNotificationKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioNotification, WINRT_WRAP(Windows::Services::Maps::Guidance::GuidanceAudioNotificationKind));
            *value = detach_from<Windows::Services::Maps::Guidance::GuidanceAudioNotificationKind>(this->shim().AudioNotification());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AudioFilePaths(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioFilePaths, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().AudioFilePaths());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AudioText(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioText, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AudioText());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Maps::Guidance::IGuidanceLaneInfo> : produce_base<D, Windows::Services::Maps::Guidance::IGuidanceLaneInfo>
{
    int32_t WINRT_CALL get_LaneMarkers(Windows::Services::Maps::Guidance::GuidanceLaneMarkers* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LaneMarkers, WINRT_WRAP(Windows::Services::Maps::Guidance::GuidanceLaneMarkers));
            *value = detach_from<Windows::Services::Maps::Guidance::GuidanceLaneMarkers>(this->shim().LaneMarkers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsOnRoute(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsOnRoute, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsOnRoute());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Maps::Guidance::IGuidanceManeuver> : produce_base<D, Windows::Services::Maps::Guidance::IGuidanceManeuver>
{
    int32_t WINRT_CALL get_StartLocation(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartLocation, WINRT_WRAP(Windows::Devices::Geolocation::Geopoint));
            *value = detach_from<Windows::Devices::Geolocation::Geopoint>(this->shim().StartLocation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DistanceFromRouteStart(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DistanceFromRouteStart, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().DistanceFromRouteStart());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DistanceFromPreviousManeuver(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DistanceFromPreviousManeuver, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().DistanceFromPreviousManeuver());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DepartureRoadName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DepartureRoadName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DepartureRoadName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NextRoadName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NextRoadName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().NextRoadName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DepartureShortRoadName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DepartureShortRoadName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DepartureShortRoadName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NextShortRoadName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NextShortRoadName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().NextShortRoadName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Kind(Windows::Services::Maps::Guidance::GuidanceManeuverKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Kind, WINRT_WRAP(Windows::Services::Maps::Guidance::GuidanceManeuverKind));
            *value = detach_from<Windows::Services::Maps::Guidance::GuidanceManeuverKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StartAngle(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartAngle, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().StartAngle());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EndAngle(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EndAngle, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().EndAngle());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RoadSignpost(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RoadSignpost, WINRT_WRAP(Windows::Services::Maps::Guidance::GuidanceRoadSignpost));
            *value = detach_from<Windows::Services::Maps::Guidance::GuidanceRoadSignpost>(this->shim().RoadSignpost());
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
};

template <typename D>
struct produce<D, Windows::Services::Maps::Guidance::IGuidanceMapMatchedCoordinate> : produce_base<D, Windows::Services::Maps::Guidance::IGuidanceMapMatchedCoordinate>
{
    int32_t WINRT_CALL get_Location(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Location, WINRT_WRAP(Windows::Devices::Geolocation::Geopoint));
            *value = detach_from<Windows::Devices::Geolocation::Geopoint>(this->shim().Location());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CurrentHeading(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CurrentHeading, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().CurrentHeading());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CurrentSpeed(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CurrentSpeed, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().CurrentSpeed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsOnStreet(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsOnStreet, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsOnStreet());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Road(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Road, WINRT_WRAP(Windows::Services::Maps::Guidance::GuidanceRoadSegment));
            *value = detach_from<Windows::Services::Maps::Guidance::GuidanceRoadSegment>(this->shim().Road());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Maps::Guidance::IGuidanceNavigator> : produce_base<D, Windows::Services::Maps::Guidance::IGuidanceNavigator>
{
    int32_t WINRT_CALL StartNavigating(void* route) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartNavigating, WINRT_WRAP(void), Windows::Services::Maps::Guidance::GuidanceRoute const&);
            this->shim().StartNavigating(*reinterpret_cast<Windows::Services::Maps::Guidance::GuidanceRoute const*>(&route));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StartSimulating(void* route, int32_t speedInMetersPerSecond) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartSimulating, WINRT_WRAP(void), Windows::Services::Maps::Guidance::GuidanceRoute const&, int32_t);
            this->shim().StartSimulating(*reinterpret_cast<Windows::Services::Maps::Guidance::GuidanceRoute const*>(&route), speedInMetersPerSecond);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StartTracking() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartTracking, WINRT_WRAP(void));
            this->shim().StartTracking();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Pause() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Pause, WINRT_WRAP(void));
            this->shim().Pause();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Resume() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Resume, WINRT_WRAP(void));
            this->shim().Resume();
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

    int32_t WINRT_CALL RepeatLastAudioNotification() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RepeatLastAudioNotification, WINRT_WRAP(void));
            this->shim().RepeatLastAudioNotification();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AudioMeasurementSystem(Windows::Services::Maps::Guidance::GuidanceAudioMeasurementSystem* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioMeasurementSystem, WINRT_WRAP(Windows::Services::Maps::Guidance::GuidanceAudioMeasurementSystem));
            *value = detach_from<Windows::Services::Maps::Guidance::GuidanceAudioMeasurementSystem>(this->shim().AudioMeasurementSystem());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AudioMeasurementSystem(Windows::Services::Maps::Guidance::GuidanceAudioMeasurementSystem value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioMeasurementSystem, WINRT_WRAP(void), Windows::Services::Maps::Guidance::GuidanceAudioMeasurementSystem const&);
            this->shim().AudioMeasurementSystem(*reinterpret_cast<Windows::Services::Maps::Guidance::GuidanceAudioMeasurementSystem const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AudioNotifications(Windows::Services::Maps::Guidance::GuidanceAudioNotifications* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioNotifications, WINRT_WRAP(Windows::Services::Maps::Guidance::GuidanceAudioNotifications));
            *value = detach_from<Windows::Services::Maps::Guidance::GuidanceAudioNotifications>(this->shim().AudioNotifications());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AudioNotifications(Windows::Services::Maps::Guidance::GuidanceAudioNotifications value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioNotifications, WINRT_WRAP(void), Windows::Services::Maps::Guidance::GuidanceAudioNotifications const&);
            this->shim().AudioNotifications(*reinterpret_cast<Windows::Services::Maps::Guidance::GuidanceAudioNotifications const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_GuidanceUpdated(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GuidanceUpdated, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Services::Maps::Guidance::GuidanceNavigator, Windows::Services::Maps::Guidance::GuidanceUpdatedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().GuidanceUpdated(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Services::Maps::Guidance::GuidanceNavigator, Windows::Services::Maps::Guidance::GuidanceUpdatedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_GuidanceUpdated(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(GuidanceUpdated, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().GuidanceUpdated(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_DestinationReached(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DestinationReached, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Services::Maps::Guidance::GuidanceNavigator, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().DestinationReached(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Services::Maps::Guidance::GuidanceNavigator, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_DestinationReached(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(DestinationReached, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().DestinationReached(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_Rerouting(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Rerouting, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Services::Maps::Guidance::GuidanceNavigator, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().Rerouting(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Services::Maps::Guidance::GuidanceNavigator, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Rerouting(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Rerouting, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Rerouting(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_Rerouted(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Rerouted, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Services::Maps::Guidance::GuidanceNavigator, Windows::Services::Maps::Guidance::GuidanceReroutedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Rerouted(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Services::Maps::Guidance::GuidanceNavigator, Windows::Services::Maps::Guidance::GuidanceReroutedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Rerouted(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Rerouted, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Rerouted(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_RerouteFailed(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RerouteFailed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Services::Maps::Guidance::GuidanceNavigator, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().RerouteFailed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Services::Maps::Guidance::GuidanceNavigator, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_RerouteFailed(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(RerouteFailed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().RerouteFailed(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_UserLocationLost(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UserLocationLost, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Services::Maps::Guidance::GuidanceNavigator, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().UserLocationLost(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Services::Maps::Guidance::GuidanceNavigator, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_UserLocationLost(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(UserLocationLost, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().UserLocationLost(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_UserLocationRestored(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UserLocationRestored, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Services::Maps::Guidance::GuidanceNavigator, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().UserLocationRestored(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Services::Maps::Guidance::GuidanceNavigator, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_UserLocationRestored(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(UserLocationRestored, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().UserLocationRestored(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL SetGuidanceVoice(int32_t voiceId, void* voiceFolder) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetGuidanceVoice, WINRT_WRAP(void), int32_t, hstring const&);
            this->shim().SetGuidanceVoice(voiceId, *reinterpret_cast<hstring const*>(&voiceFolder));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UpdateUserLocation(void* userLocation) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpdateUserLocation, WINRT_WRAP(void), Windows::Devices::Geolocation::Geocoordinate const&);
            this->shim().UpdateUserLocation(*reinterpret_cast<Windows::Devices::Geolocation::Geocoordinate const*>(&userLocation));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UpdateUserLocationWithPositionOverride(void* userLocation, struct struct_Windows_Devices_Geolocation_BasicGeoposition positionOverride) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpdateUserLocation, WINRT_WRAP(void), Windows::Devices::Geolocation::Geocoordinate const&, Windows::Devices::Geolocation::BasicGeoposition const&);
            this->shim().UpdateUserLocation(*reinterpret_cast<Windows::Devices::Geolocation::Geocoordinate const*>(&userLocation), *reinterpret_cast<Windows::Devices::Geolocation::BasicGeoposition const*>(&positionOverride));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Maps::Guidance::IGuidanceNavigator2> : produce_base<D, Windows::Services::Maps::Guidance::IGuidanceNavigator2>
{
    int32_t WINRT_CALL add_AudioNotificationRequested(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AudioNotificationRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Services::Maps::Guidance::GuidanceNavigator, Windows::Services::Maps::Guidance::GuidanceAudioNotificationRequestedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().AudioNotificationRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Services::Maps::Guidance::GuidanceNavigator, Windows::Services::Maps::Guidance::GuidanceAudioNotificationRequestedEventArgs> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_AudioNotificationRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(AudioNotificationRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().AudioNotificationRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL get_IsGuidanceAudioMuted(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsGuidanceAudioMuted, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsGuidanceAudioMuted());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsGuidanceAudioMuted(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsGuidanceAudioMuted, WINRT_WRAP(void), bool);
            this->shim().IsGuidanceAudioMuted(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Maps::Guidance::IGuidanceNavigatorStatics> : produce_base<D, Windows::Services::Maps::Guidance::IGuidanceNavigatorStatics>
{
    int32_t WINRT_CALL GetCurrent(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCurrent, WINRT_WRAP(Windows::Services::Maps::Guidance::GuidanceNavigator));
            *result = detach_from<Windows::Services::Maps::Guidance::GuidanceNavigator>(this->shim().GetCurrent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Maps::Guidance::IGuidanceNavigatorStatics2> : produce_base<D, Windows::Services::Maps::Guidance::IGuidanceNavigatorStatics2>
{
    int32_t WINRT_CALL get_UseAppProvidedVoice(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UseAppProvidedVoice, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().UseAppProvidedVoice());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Maps::Guidance::IGuidanceReroutedEventArgs> : produce_base<D, Windows::Services::Maps::Guidance::IGuidanceReroutedEventArgs>
{
    int32_t WINRT_CALL get_Route(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Route, WINRT_WRAP(Windows::Services::Maps::Guidance::GuidanceRoute));
            *result = detach_from<Windows::Services::Maps::Guidance::GuidanceRoute>(this->shim().Route());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Maps::Guidance::IGuidanceRoadSegment> : produce_base<D, Windows::Services::Maps::Guidance::IGuidanceRoadSegment>
{
    int32_t WINRT_CALL get_RoadName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RoadName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().RoadName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ShortRoadName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShortRoadName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ShortRoadName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SpeedLimit(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SpeedLimit, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().SpeedLimit());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TravelTime(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TravelTime, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().TravelTime());
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

    int32_t WINRT_CALL get_IsHighway(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsHighway, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsHighway());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsTunnel(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsTunnel, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsTunnel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsTollRoad(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsTollRoad, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsTollRoad());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Maps::Guidance::IGuidanceRoadSegment2> : produce_base<D, Windows::Services::Maps::Guidance::IGuidanceRoadSegment2>
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
struct produce<D, Windows::Services::Maps::Guidance::IGuidanceRoadSignpost> : produce_base<D, Windows::Services::Maps::Guidance::IGuidanceRoadSignpost>
{
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

    int32_t WINRT_CALL get_Exit(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Exit, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Exit());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BackgroundColor(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BackgroundColor, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().BackgroundColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ForegroundColor(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ForegroundColor, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().ForegroundColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExitDirections(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExitDirections, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().ExitDirections());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Maps::Guidance::IGuidanceRoute> : produce_base<D, Windows::Services::Maps::Guidance::IGuidanceRoute>
{
    int32_t WINRT_CALL get_Duration(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Duration, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().Duration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Distance(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Distance, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().Distance());
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
            WINRT_ASSERT_DECLARATION(Maneuvers, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Services::Maps::Guidance::GuidanceManeuver>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Services::Maps::Guidance::GuidanceManeuver>>(this->shim().Maneuvers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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

    int32_t WINRT_CALL get_RoadSegments(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RoadSegments, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Services::Maps::Guidance::GuidanceRoadSegment>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Services::Maps::Guidance::GuidanceRoadSegment>>(this->shim().RoadSegments());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ConvertToMapRoute(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConvertToMapRoute, WINRT_WRAP(Windows::Services::Maps::MapRoute));
            *result = detach_from<Windows::Services::Maps::MapRoute>(this->shim().ConvertToMapRoute());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Maps::Guidance::IGuidanceRouteStatics> : produce_base<D, Windows::Services::Maps::Guidance::IGuidanceRouteStatics>
{
    int32_t WINRT_CALL CanCreateFromMapRoute(void* mapRoute, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanCreateFromMapRoute, WINRT_WRAP(bool), Windows::Services::Maps::MapRoute const&);
            *result = detach_from<bool>(this->shim().CanCreateFromMapRoute(*reinterpret_cast<Windows::Services::Maps::MapRoute const*>(&mapRoute)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryCreateFromMapRoute(void* mapRoute, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryCreateFromMapRoute, WINRT_WRAP(Windows::Services::Maps::Guidance::GuidanceRoute), Windows::Services::Maps::MapRoute const&);
            *result = detach_from<Windows::Services::Maps::Guidance::GuidanceRoute>(this->shim().TryCreateFromMapRoute(*reinterpret_cast<Windows::Services::Maps::MapRoute const*>(&mapRoute)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Maps::Guidance::IGuidanceTelemetryCollector> : produce_base<D, Windows::Services::Maps::Guidance::IGuidanceTelemetryCollector>
{
    int32_t WINRT_CALL get_Enabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Enabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Enabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Enabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Enabled, WINRT_WRAP(void), bool);
            this->shim().Enabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ClearLocalData() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClearLocalData, WINRT_WRAP(void));
            this->shim().ClearLocalData();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SpeedTrigger(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SpeedTrigger, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().SpeedTrigger());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SpeedTrigger(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SpeedTrigger, WINRT_WRAP(void), double);
            this->shim().SpeedTrigger(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UploadFrequency(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UploadFrequency, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().UploadFrequency());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_UploadFrequency(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UploadFrequency, WINRT_WRAP(void), int32_t);
            this->shim().UploadFrequency(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Maps::Guidance::IGuidanceTelemetryCollectorStatics> : produce_base<D, Windows::Services::Maps::Guidance::IGuidanceTelemetryCollectorStatics>
{
    int32_t WINRT_CALL GetCurrent(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCurrent, WINRT_WRAP(Windows::Services::Maps::Guidance::GuidanceTelemetryCollector));
            *result = detach_from<Windows::Services::Maps::Guidance::GuidanceTelemetryCollector>(this->shim().GetCurrent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Maps::Guidance::IGuidanceUpdatedEventArgs> : produce_base<D, Windows::Services::Maps::Guidance::IGuidanceUpdatedEventArgs>
{
    int32_t WINRT_CALL get_Mode(Windows::Services::Maps::Guidance::GuidanceMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Mode, WINRT_WRAP(Windows::Services::Maps::Guidance::GuidanceMode));
            *value = detach_from<Windows::Services::Maps::Guidance::GuidanceMode>(this->shim().Mode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NextManeuver(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NextManeuver, WINRT_WRAP(Windows::Services::Maps::Guidance::GuidanceManeuver));
            *value = detach_from<Windows::Services::Maps::Guidance::GuidanceManeuver>(this->shim().NextManeuver());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NextManeuverDistance(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NextManeuverDistance, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().NextManeuverDistance());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AfterNextManeuver(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AfterNextManeuver, WINRT_WRAP(Windows::Services::Maps::Guidance::GuidanceManeuver));
            *value = detach_from<Windows::Services::Maps::Guidance::GuidanceManeuver>(this->shim().AfterNextManeuver());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AfterNextManeuverDistance(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AfterNextManeuverDistance, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().AfterNextManeuverDistance());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DistanceToDestination(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DistanceToDestination, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().DistanceToDestination());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ElapsedDistance(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ElapsedDistance, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().ElapsedDistance());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ElapsedTime(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ElapsedTime, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().ElapsedTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TimeToDestination(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TimeToDestination, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().TimeToDestination());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RoadName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RoadName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().RoadName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Route(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Route, WINRT_WRAP(Windows::Services::Maps::Guidance::GuidanceRoute));
            *result = detach_from<Windows::Services::Maps::Guidance::GuidanceRoute>(this->shim().Route());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CurrentLocation(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CurrentLocation, WINRT_WRAP(Windows::Services::Maps::Guidance::GuidanceMapMatchedCoordinate));
            *result = detach_from<Windows::Services::Maps::Guidance::GuidanceMapMatchedCoordinate>(this->shim().CurrentLocation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsNewManeuver(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsNewManeuver, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsNewManeuver());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LaneInfo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LaneInfo, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Services::Maps::Guidance::GuidanceLaneInfo>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Services::Maps::Guidance::GuidanceLaneInfo>>(this->shim().LaneInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Services::Maps::Guidance {

inline Windows::Services::Maps::Guidance::GuidanceNavigator GuidanceNavigator::GetCurrent()
{
    return impl::call_factory<GuidanceNavigator, Windows::Services::Maps::Guidance::IGuidanceNavigatorStatics>([&](auto&& f) { return f.GetCurrent(); });
}

inline bool GuidanceNavigator::UseAppProvidedVoice()
{
    return impl::call_factory<GuidanceNavigator, Windows::Services::Maps::Guidance::IGuidanceNavigatorStatics2>([&](auto&& f) { return f.UseAppProvidedVoice(); });
}

inline bool GuidanceRoute::CanCreateFromMapRoute(Windows::Services::Maps::MapRoute const& mapRoute)
{
    return impl::call_factory<GuidanceRoute, Windows::Services::Maps::Guidance::IGuidanceRouteStatics>([&](auto&& f) { return f.CanCreateFromMapRoute(mapRoute); });
}

inline Windows::Services::Maps::Guidance::GuidanceRoute GuidanceRoute::TryCreateFromMapRoute(Windows::Services::Maps::MapRoute const& mapRoute)
{
    return impl::call_factory<GuidanceRoute, Windows::Services::Maps::Guidance::IGuidanceRouteStatics>([&](auto&& f) { return f.TryCreateFromMapRoute(mapRoute); });
}

inline Windows::Services::Maps::Guidance::GuidanceTelemetryCollector GuidanceTelemetryCollector::GetCurrent()
{
    return impl::call_factory<GuidanceTelemetryCollector, Windows::Services::Maps::Guidance::IGuidanceTelemetryCollectorStatics>([&](auto&& f) { return f.GetCurrent(); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Services::Maps::Guidance::IGuidanceAudioNotificationRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Services::Maps::Guidance::IGuidanceAudioNotificationRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Services::Maps::Guidance::IGuidanceLaneInfo> : winrt::impl::hash_base<winrt::Windows::Services::Maps::Guidance::IGuidanceLaneInfo> {};
template<> struct hash<winrt::Windows::Services::Maps::Guidance::IGuidanceManeuver> : winrt::impl::hash_base<winrt::Windows::Services::Maps::Guidance::IGuidanceManeuver> {};
template<> struct hash<winrt::Windows::Services::Maps::Guidance::IGuidanceMapMatchedCoordinate> : winrt::impl::hash_base<winrt::Windows::Services::Maps::Guidance::IGuidanceMapMatchedCoordinate> {};
template<> struct hash<winrt::Windows::Services::Maps::Guidance::IGuidanceNavigator> : winrt::impl::hash_base<winrt::Windows::Services::Maps::Guidance::IGuidanceNavigator> {};
template<> struct hash<winrt::Windows::Services::Maps::Guidance::IGuidanceNavigator2> : winrt::impl::hash_base<winrt::Windows::Services::Maps::Guidance::IGuidanceNavigator2> {};
template<> struct hash<winrt::Windows::Services::Maps::Guidance::IGuidanceNavigatorStatics> : winrt::impl::hash_base<winrt::Windows::Services::Maps::Guidance::IGuidanceNavigatorStatics> {};
template<> struct hash<winrt::Windows::Services::Maps::Guidance::IGuidanceNavigatorStatics2> : winrt::impl::hash_base<winrt::Windows::Services::Maps::Guidance::IGuidanceNavigatorStatics2> {};
template<> struct hash<winrt::Windows::Services::Maps::Guidance::IGuidanceReroutedEventArgs> : winrt::impl::hash_base<winrt::Windows::Services::Maps::Guidance::IGuidanceReroutedEventArgs> {};
template<> struct hash<winrt::Windows::Services::Maps::Guidance::IGuidanceRoadSegment> : winrt::impl::hash_base<winrt::Windows::Services::Maps::Guidance::IGuidanceRoadSegment> {};
template<> struct hash<winrt::Windows::Services::Maps::Guidance::IGuidanceRoadSegment2> : winrt::impl::hash_base<winrt::Windows::Services::Maps::Guidance::IGuidanceRoadSegment2> {};
template<> struct hash<winrt::Windows::Services::Maps::Guidance::IGuidanceRoadSignpost> : winrt::impl::hash_base<winrt::Windows::Services::Maps::Guidance::IGuidanceRoadSignpost> {};
template<> struct hash<winrt::Windows::Services::Maps::Guidance::IGuidanceRoute> : winrt::impl::hash_base<winrt::Windows::Services::Maps::Guidance::IGuidanceRoute> {};
template<> struct hash<winrt::Windows::Services::Maps::Guidance::IGuidanceRouteStatics> : winrt::impl::hash_base<winrt::Windows::Services::Maps::Guidance::IGuidanceRouteStatics> {};
template<> struct hash<winrt::Windows::Services::Maps::Guidance::IGuidanceTelemetryCollector> : winrt::impl::hash_base<winrt::Windows::Services::Maps::Guidance::IGuidanceTelemetryCollector> {};
template<> struct hash<winrt::Windows::Services::Maps::Guidance::IGuidanceTelemetryCollectorStatics> : winrt::impl::hash_base<winrt::Windows::Services::Maps::Guidance::IGuidanceTelemetryCollectorStatics> {};
template<> struct hash<winrt::Windows::Services::Maps::Guidance::IGuidanceUpdatedEventArgs> : winrt::impl::hash_base<winrt::Windows::Services::Maps::Guidance::IGuidanceUpdatedEventArgs> {};
template<> struct hash<winrt::Windows::Services::Maps::Guidance::GuidanceAudioNotificationRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Services::Maps::Guidance::GuidanceAudioNotificationRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Services::Maps::Guidance::GuidanceLaneInfo> : winrt::impl::hash_base<winrt::Windows::Services::Maps::Guidance::GuidanceLaneInfo> {};
template<> struct hash<winrt::Windows::Services::Maps::Guidance::GuidanceManeuver> : winrt::impl::hash_base<winrt::Windows::Services::Maps::Guidance::GuidanceManeuver> {};
template<> struct hash<winrt::Windows::Services::Maps::Guidance::GuidanceMapMatchedCoordinate> : winrt::impl::hash_base<winrt::Windows::Services::Maps::Guidance::GuidanceMapMatchedCoordinate> {};
template<> struct hash<winrt::Windows::Services::Maps::Guidance::GuidanceNavigator> : winrt::impl::hash_base<winrt::Windows::Services::Maps::Guidance::GuidanceNavigator> {};
template<> struct hash<winrt::Windows::Services::Maps::Guidance::GuidanceReroutedEventArgs> : winrt::impl::hash_base<winrt::Windows::Services::Maps::Guidance::GuidanceReroutedEventArgs> {};
template<> struct hash<winrt::Windows::Services::Maps::Guidance::GuidanceRoadSegment> : winrt::impl::hash_base<winrt::Windows::Services::Maps::Guidance::GuidanceRoadSegment> {};
template<> struct hash<winrt::Windows::Services::Maps::Guidance::GuidanceRoadSignpost> : winrt::impl::hash_base<winrt::Windows::Services::Maps::Guidance::GuidanceRoadSignpost> {};
template<> struct hash<winrt::Windows::Services::Maps::Guidance::GuidanceRoute> : winrt::impl::hash_base<winrt::Windows::Services::Maps::Guidance::GuidanceRoute> {};
template<> struct hash<winrt::Windows::Services::Maps::Guidance::GuidanceTelemetryCollector> : winrt::impl::hash_base<winrt::Windows::Services::Maps::Guidance::GuidanceTelemetryCollector> {};
template<> struct hash<winrt::Windows::Services::Maps::Guidance::GuidanceUpdatedEventArgs> : winrt::impl::hash_base<winrt::Windows::Services::Maps::Guidance::GuidanceUpdatedEventArgs> {};

}
