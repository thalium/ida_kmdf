// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Devices.Geolocation.2.h"
#include "winrt/impl/Windows.Devices.Geolocation.Geofencing.2.h"
#include "winrt/Windows.Devices.Geolocation.h"

namespace winrt::impl {

template <typename D> Windows::Foundation::DateTime consume_Windows_Devices_Geolocation_Geofencing_IGeofence<D>::StartTime() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::Geofencing::IGeofence)->get_StartTime(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Devices_Geolocation_Geofencing_IGeofence<D>::Duration() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::Geofencing::IGeofence)->get_Duration(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Devices_Geolocation_Geofencing_IGeofence<D>::DwellTime() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::Geofencing::IGeofence)->get_DwellTime(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Geolocation_Geofencing_IGeofence<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::Geofencing::IGeofence)->get_Id(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Geolocation::Geofencing::MonitoredGeofenceStates consume_Windows_Devices_Geolocation_Geofencing_IGeofence<D>::MonitoredStates() const
{
    Windows::Devices::Geolocation::Geofencing::MonitoredGeofenceStates value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::Geofencing::IGeofence)->get_MonitoredStates(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Geolocation::IGeoshape consume_Windows_Devices_Geolocation_Geofencing_IGeofence<D>::Geoshape() const
{
    Windows::Devices::Geolocation::IGeoshape value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::Geofencing::IGeofence)->get_Geoshape(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Devices_Geolocation_Geofencing_IGeofence<D>::SingleUse() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::Geofencing::IGeofence)->get_SingleUse(&value));
    return value;
}

template <typename D> Windows::Devices::Geolocation::Geofencing::Geofence consume_Windows_Devices_Geolocation_Geofencing_IGeofenceFactory<D>::Create(param::hstring const& id, Windows::Devices::Geolocation::IGeoshape const& geoshape) const
{
    Windows::Devices::Geolocation::Geofencing::Geofence geofence{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::Geofencing::IGeofenceFactory)->Create(get_abi(id), get_abi(geoshape), put_abi(geofence)));
    return geofence;
}

template <typename D> Windows::Devices::Geolocation::Geofencing::Geofence consume_Windows_Devices_Geolocation_Geofencing_IGeofenceFactory<D>::CreateWithMonitorStates(param::hstring const& id, Windows::Devices::Geolocation::IGeoshape const& geoshape, Windows::Devices::Geolocation::Geofencing::MonitoredGeofenceStates const& monitoredStates, bool singleUse) const
{
    Windows::Devices::Geolocation::Geofencing::Geofence geofence{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::Geofencing::IGeofenceFactory)->CreateWithMonitorStates(get_abi(id), get_abi(geoshape), get_abi(monitoredStates), singleUse, put_abi(geofence)));
    return geofence;
}

template <typename D> Windows::Devices::Geolocation::Geofencing::Geofence consume_Windows_Devices_Geolocation_Geofencing_IGeofenceFactory<D>::CreateWithMonitorStatesAndDwellTime(param::hstring const& id, Windows::Devices::Geolocation::IGeoshape const& geoshape, Windows::Devices::Geolocation::Geofencing::MonitoredGeofenceStates const& monitoredStates, bool singleUse, Windows::Foundation::TimeSpan const& dwellTime) const
{
    Windows::Devices::Geolocation::Geofencing::Geofence geofence{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::Geofencing::IGeofenceFactory)->CreateWithMonitorStatesAndDwellTime(get_abi(id), get_abi(geoshape), get_abi(monitoredStates), singleUse, get_abi(dwellTime), put_abi(geofence)));
    return geofence;
}

template <typename D> Windows::Devices::Geolocation::Geofencing::Geofence consume_Windows_Devices_Geolocation_Geofencing_IGeofenceFactory<D>::CreateWithMonitorStatesDwellTimeStartTimeAndDuration(param::hstring const& id, Windows::Devices::Geolocation::IGeoshape const& geoshape, Windows::Devices::Geolocation::Geofencing::MonitoredGeofenceStates const& monitoredStates, bool singleUse, Windows::Foundation::TimeSpan const& dwellTime, Windows::Foundation::DateTime const& startTime, Windows::Foundation::TimeSpan const& duration) const
{
    Windows::Devices::Geolocation::Geofencing::Geofence geofence{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::Geofencing::IGeofenceFactory)->CreateWithMonitorStatesDwellTimeStartTimeAndDuration(get_abi(id), get_abi(geoshape), get_abi(monitoredStates), singleUse, get_abi(dwellTime), get_abi(startTime), get_abi(duration), put_abi(geofence)));
    return geofence;
}

template <typename D> Windows::Devices::Geolocation::Geofencing::GeofenceMonitorStatus consume_Windows_Devices_Geolocation_Geofencing_IGeofenceMonitor<D>::Status() const
{
    Windows::Devices::Geolocation::Geofencing::GeofenceMonitorStatus value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::Geofencing::IGeofenceMonitor)->get_Status(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::Devices::Geolocation::Geofencing::Geofence> consume_Windows_Devices_Geolocation_Geofencing_IGeofenceMonitor<D>::Geofences() const
{
    Windows::Foundation::Collections::IVector<Windows::Devices::Geolocation::Geofencing::Geofence> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::Geofencing::IGeofenceMonitor)->get_Geofences(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Geolocation::Geoposition consume_Windows_Devices_Geolocation_Geofencing_IGeofenceMonitor<D>::LastKnownGeoposition() const
{
    Windows::Devices::Geolocation::Geoposition value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::Geofencing::IGeofenceMonitor)->get_LastKnownGeoposition(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Devices_Geolocation_Geofencing_IGeofenceMonitor<D>::GeofenceStateChanged(Windows::Foundation::TypedEventHandler<Windows::Devices::Geolocation::Geofencing::GeofenceMonitor, Windows::Foundation::IInspectable> const& eventHandler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::Geofencing::IGeofenceMonitor)->add_GeofenceStateChanged(get_abi(eventHandler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Geolocation_Geofencing_IGeofenceMonitor<D>::GeofenceStateChanged_revoker consume_Windows_Devices_Geolocation_Geofencing_IGeofenceMonitor<D>::GeofenceStateChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Geolocation::Geofencing::GeofenceMonitor, Windows::Foundation::IInspectable> const& eventHandler) const
{
    return impl::make_event_revoker<D, GeofenceStateChanged_revoker>(this, GeofenceStateChanged(eventHandler));
}

template <typename D> void consume_Windows_Devices_Geolocation_Geofencing_IGeofenceMonitor<D>::GeofenceStateChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Geolocation::Geofencing::IGeofenceMonitor)->remove_GeofenceStateChanged(get_abi(token)));
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::Geolocation::Geofencing::GeofenceStateChangeReport> consume_Windows_Devices_Geolocation_Geofencing_IGeofenceMonitor<D>::ReadReports() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Geolocation::Geofencing::GeofenceStateChangeReport> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::Geofencing::IGeofenceMonitor)->ReadReports(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Devices_Geolocation_Geofencing_IGeofenceMonitor<D>::StatusChanged(Windows::Foundation::TypedEventHandler<Windows::Devices::Geolocation::Geofencing::GeofenceMonitor, Windows::Foundation::IInspectable> const& eventHandler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::Geofencing::IGeofenceMonitor)->add_StatusChanged(get_abi(eventHandler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Geolocation_Geofencing_IGeofenceMonitor<D>::StatusChanged_revoker consume_Windows_Devices_Geolocation_Geofencing_IGeofenceMonitor<D>::StatusChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Geolocation::Geofencing::GeofenceMonitor, Windows::Foundation::IInspectable> const& eventHandler) const
{
    return impl::make_event_revoker<D, StatusChanged_revoker>(this, StatusChanged(eventHandler));
}

template <typename D> void consume_Windows_Devices_Geolocation_Geofencing_IGeofenceMonitor<D>::StatusChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Geolocation::Geofencing::IGeofenceMonitor)->remove_StatusChanged(get_abi(token)));
}

template <typename D> Windows::Devices::Geolocation::Geofencing::GeofenceMonitor consume_Windows_Devices_Geolocation_Geofencing_IGeofenceMonitorStatics<D>::Current() const
{
    Windows::Devices::Geolocation::Geofencing::GeofenceMonitor value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::Geofencing::IGeofenceMonitorStatics)->get_Current(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Geolocation::Geofencing::GeofenceState consume_Windows_Devices_Geolocation_Geofencing_IGeofenceStateChangeReport<D>::NewState() const
{
    Windows::Devices::Geolocation::Geofencing::GeofenceState value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::Geofencing::IGeofenceStateChangeReport)->get_NewState(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Geolocation::Geofencing::Geofence consume_Windows_Devices_Geolocation_Geofencing_IGeofenceStateChangeReport<D>::Geofence() const
{
    Windows::Devices::Geolocation::Geofencing::Geofence value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::Geofencing::IGeofenceStateChangeReport)->get_Geofence(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Geolocation::Geoposition consume_Windows_Devices_Geolocation_Geofencing_IGeofenceStateChangeReport<D>::Geoposition() const
{
    Windows::Devices::Geolocation::Geoposition value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::Geofencing::IGeofenceStateChangeReport)->get_Geoposition(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Geolocation::Geofencing::GeofenceRemovalReason consume_Windows_Devices_Geolocation_Geofencing_IGeofenceStateChangeReport<D>::RemovalReason() const
{
    Windows::Devices::Geolocation::Geofencing::GeofenceRemovalReason value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Geolocation::Geofencing::IGeofenceStateChangeReport)->get_RemovalReason(put_abi(value)));
    return value;
}

template <typename D>
struct produce<D, Windows::Devices::Geolocation::Geofencing::IGeofence> : produce_base<D, Windows::Devices::Geolocation::Geofencing::IGeofence>
{
    int32_t WINRT_CALL get_StartTime(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartTime, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().StartTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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

    int32_t WINRT_CALL get_DwellTime(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DwellTime, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().DwellTime());
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

    int32_t WINRT_CALL get_MonitoredStates(Windows::Devices::Geolocation::Geofencing::MonitoredGeofenceStates* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MonitoredStates, WINRT_WRAP(Windows::Devices::Geolocation::Geofencing::MonitoredGeofenceStates));
            *value = detach_from<Windows::Devices::Geolocation::Geofencing::MonitoredGeofenceStates>(this->shim().MonitoredStates());
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

    int32_t WINRT_CALL get_SingleUse(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SingleUse, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().SingleUse());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Geolocation::Geofencing::IGeofenceFactory> : produce_base<D, Windows::Devices::Geolocation::Geofencing::IGeofenceFactory>
{
    int32_t WINRT_CALL Create(void* id, void* geoshape, void** geofence) noexcept final
    {
        try
        {
            *geofence = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Devices::Geolocation::Geofencing::Geofence), hstring const&, Windows::Devices::Geolocation::IGeoshape const&);
            *geofence = detach_from<Windows::Devices::Geolocation::Geofencing::Geofence>(this->shim().Create(*reinterpret_cast<hstring const*>(&id), *reinterpret_cast<Windows::Devices::Geolocation::IGeoshape const*>(&geoshape)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithMonitorStates(void* id, void* geoshape, Windows::Devices::Geolocation::Geofencing::MonitoredGeofenceStates monitoredStates, bool singleUse, void** geofence) noexcept final
    {
        try
        {
            *geofence = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithMonitorStates, WINRT_WRAP(Windows::Devices::Geolocation::Geofencing::Geofence), hstring const&, Windows::Devices::Geolocation::IGeoshape const&, Windows::Devices::Geolocation::Geofencing::MonitoredGeofenceStates const&, bool);
            *geofence = detach_from<Windows::Devices::Geolocation::Geofencing::Geofence>(this->shim().CreateWithMonitorStates(*reinterpret_cast<hstring const*>(&id), *reinterpret_cast<Windows::Devices::Geolocation::IGeoshape const*>(&geoshape), *reinterpret_cast<Windows::Devices::Geolocation::Geofencing::MonitoredGeofenceStates const*>(&monitoredStates), singleUse));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithMonitorStatesAndDwellTime(void* id, void* geoshape, Windows::Devices::Geolocation::Geofencing::MonitoredGeofenceStates monitoredStates, bool singleUse, Windows::Foundation::TimeSpan dwellTime, void** geofence) noexcept final
    {
        try
        {
            *geofence = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithMonitorStatesAndDwellTime, WINRT_WRAP(Windows::Devices::Geolocation::Geofencing::Geofence), hstring const&, Windows::Devices::Geolocation::IGeoshape const&, Windows::Devices::Geolocation::Geofencing::MonitoredGeofenceStates const&, bool, Windows::Foundation::TimeSpan const&);
            *geofence = detach_from<Windows::Devices::Geolocation::Geofencing::Geofence>(this->shim().CreateWithMonitorStatesAndDwellTime(*reinterpret_cast<hstring const*>(&id), *reinterpret_cast<Windows::Devices::Geolocation::IGeoshape const*>(&geoshape), *reinterpret_cast<Windows::Devices::Geolocation::Geofencing::MonitoredGeofenceStates const*>(&monitoredStates), singleUse, *reinterpret_cast<Windows::Foundation::TimeSpan const*>(&dwellTime)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithMonitorStatesDwellTimeStartTimeAndDuration(void* id, void* geoshape, Windows::Devices::Geolocation::Geofencing::MonitoredGeofenceStates monitoredStates, bool singleUse, Windows::Foundation::TimeSpan dwellTime, Windows::Foundation::DateTime startTime, Windows::Foundation::TimeSpan duration, void** geofence) noexcept final
    {
        try
        {
            *geofence = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithMonitorStatesDwellTimeStartTimeAndDuration, WINRT_WRAP(Windows::Devices::Geolocation::Geofencing::Geofence), hstring const&, Windows::Devices::Geolocation::IGeoshape const&, Windows::Devices::Geolocation::Geofencing::MonitoredGeofenceStates const&, bool, Windows::Foundation::TimeSpan const&, Windows::Foundation::DateTime const&, Windows::Foundation::TimeSpan const&);
            *geofence = detach_from<Windows::Devices::Geolocation::Geofencing::Geofence>(this->shim().CreateWithMonitorStatesDwellTimeStartTimeAndDuration(*reinterpret_cast<hstring const*>(&id), *reinterpret_cast<Windows::Devices::Geolocation::IGeoshape const*>(&geoshape), *reinterpret_cast<Windows::Devices::Geolocation::Geofencing::MonitoredGeofenceStates const*>(&monitoredStates), singleUse, *reinterpret_cast<Windows::Foundation::TimeSpan const*>(&dwellTime), *reinterpret_cast<Windows::Foundation::DateTime const*>(&startTime), *reinterpret_cast<Windows::Foundation::TimeSpan const*>(&duration)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Geolocation::Geofencing::IGeofenceMonitor> : produce_base<D, Windows::Devices::Geolocation::Geofencing::IGeofenceMonitor>
{
    int32_t WINRT_CALL get_Status(Windows::Devices::Geolocation::Geofencing::GeofenceMonitorStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Devices::Geolocation::Geofencing::GeofenceMonitorStatus));
            *value = detach_from<Windows::Devices::Geolocation::Geofencing::GeofenceMonitorStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Geofences(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Geofences, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::Devices::Geolocation::Geofencing::Geofence>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::Devices::Geolocation::Geofencing::Geofence>>(this->shim().Geofences());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LastKnownGeoposition(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LastKnownGeoposition, WINRT_WRAP(Windows::Devices::Geolocation::Geoposition));
            *value = detach_from<Windows::Devices::Geolocation::Geoposition>(this->shim().LastKnownGeoposition());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_GeofenceStateChanged(void* eventHandler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GeofenceStateChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Geolocation::Geofencing::GeofenceMonitor, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().GeofenceStateChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Geolocation::Geofencing::GeofenceMonitor, Windows::Foundation::IInspectable> const*>(&eventHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_GeofenceStateChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(GeofenceStateChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().GeofenceStateChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL ReadReports(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadReports, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::Geolocation::Geofencing::GeofenceStateChangeReport>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::Geolocation::Geofencing::GeofenceStateChangeReport>>(this->shim().ReadReports());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_StatusChanged(void* eventHandler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StatusChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Geolocation::Geofencing::GeofenceMonitor, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().StatusChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Geolocation::Geofencing::GeofenceMonitor, Windows::Foundation::IInspectable> const*>(&eventHandler)));
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
struct produce<D, Windows::Devices::Geolocation::Geofencing::IGeofenceMonitorStatics> : produce_base<D, Windows::Devices::Geolocation::Geofencing::IGeofenceMonitorStatics>
{
    int32_t WINRT_CALL get_Current(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Current, WINRT_WRAP(Windows::Devices::Geolocation::Geofencing::GeofenceMonitor));
            *value = detach_from<Windows::Devices::Geolocation::Geofencing::GeofenceMonitor>(this->shim().Current());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Geolocation::Geofencing::IGeofenceStateChangeReport> : produce_base<D, Windows::Devices::Geolocation::Geofencing::IGeofenceStateChangeReport>
{
    int32_t WINRT_CALL get_NewState(Windows::Devices::Geolocation::Geofencing::GeofenceState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NewState, WINRT_WRAP(Windows::Devices::Geolocation::Geofencing::GeofenceState));
            *value = detach_from<Windows::Devices::Geolocation::Geofencing::GeofenceState>(this->shim().NewState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Geofence(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Geofence, WINRT_WRAP(Windows::Devices::Geolocation::Geofencing::Geofence));
            *value = detach_from<Windows::Devices::Geolocation::Geofencing::Geofence>(this->shim().Geofence());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Geoposition(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Geoposition, WINRT_WRAP(Windows::Devices::Geolocation::Geoposition));
            *value = detach_from<Windows::Devices::Geolocation::Geoposition>(this->shim().Geoposition());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RemovalReason(Windows::Devices::Geolocation::Geofencing::GeofenceRemovalReason* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemovalReason, WINRT_WRAP(Windows::Devices::Geolocation::Geofencing::GeofenceRemovalReason));
            *value = detach_from<Windows::Devices::Geolocation::Geofencing::GeofenceRemovalReason>(this->shim().RemovalReason());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Devices::Geolocation::Geofencing {

inline Geofence::Geofence(param::hstring const& id, Windows::Devices::Geolocation::IGeoshape const& geoshape) :
    Geofence(impl::call_factory<Geofence, Windows::Devices::Geolocation::Geofencing::IGeofenceFactory>([&](auto&& f) { return f.Create(id, geoshape); }))
{}

inline Geofence::Geofence(param::hstring const& id, Windows::Devices::Geolocation::IGeoshape const& geoshape, Windows::Devices::Geolocation::Geofencing::MonitoredGeofenceStates const& monitoredStates, bool singleUse) :
    Geofence(impl::call_factory<Geofence, Windows::Devices::Geolocation::Geofencing::IGeofenceFactory>([&](auto&& f) { return f.CreateWithMonitorStates(id, geoshape, monitoredStates, singleUse); }))
{}

inline Geofence::Geofence(param::hstring const& id, Windows::Devices::Geolocation::IGeoshape const& geoshape, Windows::Devices::Geolocation::Geofencing::MonitoredGeofenceStates const& monitoredStates, bool singleUse, Windows::Foundation::TimeSpan const& dwellTime) :
    Geofence(impl::call_factory<Geofence, Windows::Devices::Geolocation::Geofencing::IGeofenceFactory>([&](auto&& f) { return f.CreateWithMonitorStatesAndDwellTime(id, geoshape, monitoredStates, singleUse, dwellTime); }))
{}

inline Geofence::Geofence(param::hstring const& id, Windows::Devices::Geolocation::IGeoshape const& geoshape, Windows::Devices::Geolocation::Geofencing::MonitoredGeofenceStates const& monitoredStates, bool singleUse, Windows::Foundation::TimeSpan const& dwellTime, Windows::Foundation::DateTime const& startTime, Windows::Foundation::TimeSpan const& duration) :
    Geofence(impl::call_factory<Geofence, Windows::Devices::Geolocation::Geofencing::IGeofenceFactory>([&](auto&& f) { return f.CreateWithMonitorStatesDwellTimeStartTimeAndDuration(id, geoshape, monitoredStates, singleUse, dwellTime, startTime, duration); }))
{}

inline Windows::Devices::Geolocation::Geofencing::GeofenceMonitor GeofenceMonitor::Current()
{
    return impl::call_factory<GeofenceMonitor, Windows::Devices::Geolocation::Geofencing::IGeofenceMonitorStatics>([&](auto&& f) { return f.Current(); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Devices::Geolocation::Geofencing::IGeofence> : winrt::impl::hash_base<winrt::Windows::Devices::Geolocation::Geofencing::IGeofence> {};
template<> struct hash<winrt::Windows::Devices::Geolocation::Geofencing::IGeofenceFactory> : winrt::impl::hash_base<winrt::Windows::Devices::Geolocation::Geofencing::IGeofenceFactory> {};
template<> struct hash<winrt::Windows::Devices::Geolocation::Geofencing::IGeofenceMonitor> : winrt::impl::hash_base<winrt::Windows::Devices::Geolocation::Geofencing::IGeofenceMonitor> {};
template<> struct hash<winrt::Windows::Devices::Geolocation::Geofencing::IGeofenceMonitorStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Geolocation::Geofencing::IGeofenceMonitorStatics> {};
template<> struct hash<winrt::Windows::Devices::Geolocation::Geofencing::IGeofenceStateChangeReport> : winrt::impl::hash_base<winrt::Windows::Devices::Geolocation::Geofencing::IGeofenceStateChangeReport> {};
template<> struct hash<winrt::Windows::Devices::Geolocation::Geofencing::Geofence> : winrt::impl::hash_base<winrt::Windows::Devices::Geolocation::Geofencing::Geofence> {};
template<> struct hash<winrt::Windows::Devices::Geolocation::Geofencing::GeofenceMonitor> : winrt::impl::hash_base<winrt::Windows::Devices::Geolocation::Geofencing::GeofenceMonitor> {};
template<> struct hash<winrt::Windows::Devices::Geolocation::Geofencing::GeofenceStateChangeReport> : winrt::impl::hash_base<winrt::Windows::Devices::Geolocation::Geofencing::GeofenceStateChangeReport> {};

}
