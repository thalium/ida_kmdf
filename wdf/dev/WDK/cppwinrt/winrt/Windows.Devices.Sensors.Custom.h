// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Devices.Sensors.Custom.2.h"
#include "winrt/Windows.Devices.Sensors.h"

namespace winrt::impl {

template <typename D> Windows::Devices::Sensors::Custom::CustomSensorReading consume_Windows_Devices_Sensors_Custom_ICustomSensor<D>::GetCurrentReading() const
{
    Windows::Devices::Sensors::Custom::CustomSensorReading value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::Custom::ICustomSensor)->GetCurrentReading(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_Sensors_Custom_ICustomSensor<D>::MinimumReportInterval() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::Custom::ICustomSensor)->get_MinimumReportInterval(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_Sensors_Custom_ICustomSensor<D>::ReportInterval(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::Custom::ICustomSensor)->put_ReportInterval(value));
}

template <typename D> uint32_t consume_Windows_Devices_Sensors_Custom_ICustomSensor<D>::ReportInterval() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::Custom::ICustomSensor)->get_ReportInterval(&value));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Sensors_Custom_ICustomSensor<D>::DeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::Custom::ICustomSensor)->get_DeviceId(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Devices_Sensors_Custom_ICustomSensor<D>::ReadingChanged(Windows::Foundation::TypedEventHandler<Windows::Devices::Sensors::Custom::CustomSensor, Windows::Devices::Sensors::Custom::CustomSensorReadingChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::Custom::ICustomSensor)->add_ReadingChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Sensors_Custom_ICustomSensor<D>::ReadingChanged_revoker consume_Windows_Devices_Sensors_Custom_ICustomSensor<D>::ReadingChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Sensors::Custom::CustomSensor, Windows::Devices::Sensors::Custom::CustomSensorReadingChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ReadingChanged_revoker>(this, ReadingChanged(handler));
}

template <typename D> void consume_Windows_Devices_Sensors_Custom_ICustomSensor<D>::ReadingChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Sensors::Custom::ICustomSensor)->remove_ReadingChanged(get_abi(token)));
}

template <typename D> void consume_Windows_Devices_Sensors_Custom_ICustomSensor2<D>::ReportLatency(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::Custom::ICustomSensor2)->put_ReportLatency(value));
}

template <typename D> uint32_t consume_Windows_Devices_Sensors_Custom_ICustomSensor2<D>::ReportLatency() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::Custom::ICustomSensor2)->get_ReportLatency(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_Sensors_Custom_ICustomSensor2<D>::MaxBatchSize() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::Custom::ICustomSensor2)->get_MaxBatchSize(&value));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_Devices_Sensors_Custom_ICustomSensorReading<D>::Timestamp() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::Custom::ICustomSensorReading)->get_Timestamp(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable> consume_Windows_Devices_Sensors_Custom_ICustomSensorReading<D>::Properties() const
{
    Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::Custom::ICustomSensorReading)->get_Properties(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::TimeSpan> consume_Windows_Devices_Sensors_Custom_ICustomSensorReading2<D>::PerformanceCount() const
{
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::Custom::ICustomSensorReading2)->get_PerformanceCount(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sensors::Custom::CustomSensorReading consume_Windows_Devices_Sensors_Custom_ICustomSensorReadingChangedEventArgs<D>::Reading() const
{
    Windows::Devices::Sensors::Custom::CustomSensorReading value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::Custom::ICustomSensorReadingChangedEventArgs)->get_Reading(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Sensors_Custom_ICustomSensorStatics<D>::GetDeviceSelector(winrt::guid const& interfaceId) const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::Custom::ICustomSensorStatics)->GetDeviceSelector(get_abi(interfaceId), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::Custom::CustomSensor> consume_Windows_Devices_Sensors_Custom_ICustomSensorStatics<D>::FromIdAsync(param::hstring const& sensorId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::Custom::CustomSensor> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::Custom::ICustomSensorStatics)->FromIdAsync(get_abi(sensorId), put_abi(result)));
    return result;
}

template <typename D>
struct produce<D, Windows::Devices::Sensors::Custom::ICustomSensor> : produce_base<D, Windows::Devices::Sensors::Custom::ICustomSensor>
{
    int32_t WINRT_CALL GetCurrentReading(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCurrentReading, WINRT_WRAP(Windows::Devices::Sensors::Custom::CustomSensorReading));
            *value = detach_from<Windows::Devices::Sensors::Custom::CustomSensorReading>(this->shim().GetCurrentReading());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MinimumReportInterval(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinimumReportInterval, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().MinimumReportInterval());
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

    int32_t WINRT_CALL get_DeviceId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_ReadingChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadingChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Sensors::Custom::CustomSensor, Windows::Devices::Sensors::Custom::CustomSensorReadingChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ReadingChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Sensors::Custom::CustomSensor, Windows::Devices::Sensors::Custom::CustomSensorReadingChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ReadingChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ReadingChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ReadingChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::Custom::ICustomSensor2> : produce_base<D, Windows::Devices::Sensors::Custom::ICustomSensor2>
{
    int32_t WINRT_CALL put_ReportLatency(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportLatency, WINRT_WRAP(void), uint32_t);
            this->shim().ReportLatency(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ReportLatency(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportLatency, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().ReportLatency());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxBatchSize(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxBatchSize, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().MaxBatchSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::Custom::ICustomSensorReading> : produce_base<D, Windows::Devices::Sensors::Custom::ICustomSensorReading>
{
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

    int32_t WINRT_CALL get_Properties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Properties, WINRT_WRAP(Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable>));
            *value = detach_from<Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable>>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::Custom::ICustomSensorReading2> : produce_base<D, Windows::Devices::Sensors::Custom::ICustomSensorReading2>
{
    int32_t WINRT_CALL get_PerformanceCount(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PerformanceCount, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::TimeSpan>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::TimeSpan>>(this->shim().PerformanceCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::Custom::ICustomSensorReadingChangedEventArgs> : produce_base<D, Windows::Devices::Sensors::Custom::ICustomSensorReadingChangedEventArgs>
{
    int32_t WINRT_CALL get_Reading(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Reading, WINRT_WRAP(Windows::Devices::Sensors::Custom::CustomSensorReading));
            *value = detach_from<Windows::Devices::Sensors::Custom::CustomSensorReading>(this->shim().Reading());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::Custom::ICustomSensorStatics> : produce_base<D, Windows::Devices::Sensors::Custom::ICustomSensorStatics>
{
    int32_t WINRT_CALL GetDeviceSelector(winrt::guid interfaceId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelector, WINRT_WRAP(hstring), winrt::guid const&);
            *result = detach_from<hstring>(this->shim().GetDeviceSelector(*reinterpret_cast<winrt::guid const*>(&interfaceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FromIdAsync(void* sensorId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::Custom::CustomSensor>), hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::Custom::CustomSensor>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&sensorId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Devices::Sensors::Custom {

inline hstring CustomSensor::GetDeviceSelector(winrt::guid const& interfaceId)
{
    return impl::call_factory<CustomSensor, Windows::Devices::Sensors::Custom::ICustomSensorStatics>([&](auto&& f) { return f.GetDeviceSelector(interfaceId); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::Custom::CustomSensor> CustomSensor::FromIdAsync(param::hstring const& sensorId)
{
    return impl::call_factory<CustomSensor, Windows::Devices::Sensors::Custom::ICustomSensorStatics>([&](auto&& f) { return f.FromIdAsync(sensorId); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Devices::Sensors::Custom::ICustomSensor> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::Custom::ICustomSensor> {};
template<> struct hash<winrt::Windows::Devices::Sensors::Custom::ICustomSensor2> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::Custom::ICustomSensor2> {};
template<> struct hash<winrt::Windows::Devices::Sensors::Custom::ICustomSensorReading> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::Custom::ICustomSensorReading> {};
template<> struct hash<winrt::Windows::Devices::Sensors::Custom::ICustomSensorReading2> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::Custom::ICustomSensorReading2> {};
template<> struct hash<winrt::Windows::Devices::Sensors::Custom::ICustomSensorReadingChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::Custom::ICustomSensorReadingChangedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Sensors::Custom::ICustomSensorStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::Custom::ICustomSensorStatics> {};
template<> struct hash<winrt::Windows::Devices::Sensors::Custom::CustomSensor> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::Custom::CustomSensor> {};
template<> struct hash<winrt::Windows::Devices::Sensors::Custom::CustomSensorReading> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::Custom::CustomSensorReading> {};
template<> struct hash<winrt::Windows::Devices::Sensors::Custom::CustomSensorReadingChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::Custom::CustomSensorReadingChangedEventArgs> {};

}
