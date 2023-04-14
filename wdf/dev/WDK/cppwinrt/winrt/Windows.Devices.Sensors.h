// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Graphics.Display.2.h"
#include "winrt/impl/Windows.Devices.Sensors.2.h"
#include "winrt/Windows.Devices.h"

namespace winrt::impl {

template <typename D> Windows::Devices::Sensors::AccelerometerReading consume_Windows_Devices_Sensors_IAccelerometer<D>::GetCurrentReading() const
{
    Windows::Devices::Sensors::AccelerometerReading value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IAccelerometer)->GetCurrentReading(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_Sensors_IAccelerometer<D>::MinimumReportInterval() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IAccelerometer)->get_MinimumReportInterval(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_Sensors_IAccelerometer<D>::ReportInterval(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IAccelerometer)->put_ReportInterval(value));
}

template <typename D> uint32_t consume_Windows_Devices_Sensors_IAccelerometer<D>::ReportInterval() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IAccelerometer)->get_ReportInterval(&value));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Devices_Sensors_IAccelerometer<D>::ReadingChanged(Windows::Foundation::TypedEventHandler<Windows::Devices::Sensors::Accelerometer, Windows::Devices::Sensors::AccelerometerReadingChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IAccelerometer)->add_ReadingChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Sensors_IAccelerometer<D>::ReadingChanged_revoker consume_Windows_Devices_Sensors_IAccelerometer<D>::ReadingChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Sensors::Accelerometer, Windows::Devices::Sensors::AccelerometerReadingChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ReadingChanged_revoker>(this, ReadingChanged(handler));
}

template <typename D> void consume_Windows_Devices_Sensors_IAccelerometer<D>::ReadingChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Sensors::IAccelerometer)->remove_ReadingChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Devices_Sensors_IAccelerometer<D>::Shaken(Windows::Foundation::TypedEventHandler<Windows::Devices::Sensors::Accelerometer, Windows::Devices::Sensors::AccelerometerShakenEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IAccelerometer)->add_Shaken(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Sensors_IAccelerometer<D>::Shaken_revoker consume_Windows_Devices_Sensors_IAccelerometer<D>::Shaken(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Sensors::Accelerometer, Windows::Devices::Sensors::AccelerometerShakenEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Shaken_revoker>(this, Shaken(handler));
}

template <typename D> void consume_Windows_Devices_Sensors_IAccelerometer<D>::Shaken(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Sensors::IAccelerometer)->remove_Shaken(get_abi(token)));
}

template <typename D> void consume_Windows_Devices_Sensors_IAccelerometer2<D>::ReadingTransform(Windows::Graphics::Display::DisplayOrientations const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IAccelerometer2)->put_ReadingTransform(get_abi(value)));
}

template <typename D> Windows::Graphics::Display::DisplayOrientations consume_Windows_Devices_Sensors_IAccelerometer2<D>::ReadingTransform() const
{
    Windows::Graphics::Display::DisplayOrientations value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IAccelerometer2)->get_ReadingTransform(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Sensors_IAccelerometer3<D>::ReportLatency(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IAccelerometer3)->put_ReportLatency(value));
}

template <typename D> uint32_t consume_Windows_Devices_Sensors_IAccelerometer3<D>::ReportLatency() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IAccelerometer3)->get_ReportLatency(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_Sensors_IAccelerometer3<D>::MaxBatchSize() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IAccelerometer3)->get_MaxBatchSize(&value));
    return value;
}

template <typename D> Windows::Devices::Sensors::AccelerometerReadingType consume_Windows_Devices_Sensors_IAccelerometer4<D>::ReadingType() const
{
    Windows::Devices::Sensors::AccelerometerReadingType type{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IAccelerometer4)->get_ReadingType(put_abi(type)));
    return type;
}

template <typename D> hstring consume_Windows_Devices_Sensors_IAccelerometerDeviceId<D>::DeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IAccelerometerDeviceId)->get_DeviceId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_Devices_Sensors_IAccelerometerReading<D>::Timestamp() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IAccelerometerReading)->get_Timestamp(put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_Devices_Sensors_IAccelerometerReading<D>::AccelerationX() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IAccelerometerReading)->get_AccelerationX(&value));
    return value;
}

template <typename D> double consume_Windows_Devices_Sensors_IAccelerometerReading<D>::AccelerationY() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IAccelerometerReading)->get_AccelerationY(&value));
    return value;
}

template <typename D> double consume_Windows_Devices_Sensors_IAccelerometerReading<D>::AccelerationZ() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IAccelerometerReading)->get_AccelerationZ(&value));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::TimeSpan> consume_Windows_Devices_Sensors_IAccelerometerReading2<D>::PerformanceCount() const
{
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IAccelerometerReading2)->get_PerformanceCount(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable> consume_Windows_Devices_Sensors_IAccelerometerReading2<D>::Properties() const
{
    Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IAccelerometerReading2)->get_Properties(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sensors::AccelerometerReading consume_Windows_Devices_Sensors_IAccelerometerReadingChangedEventArgs<D>::Reading() const
{
    Windows::Devices::Sensors::AccelerometerReading value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IAccelerometerReadingChangedEventArgs)->get_Reading(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_Devices_Sensors_IAccelerometerShakenEventArgs<D>::Timestamp() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IAccelerometerShakenEventArgs)->get_Timestamp(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sensors::Accelerometer consume_Windows_Devices_Sensors_IAccelerometerStatics<D>::GetDefault() const
{
    Windows::Devices::Sensors::Accelerometer result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IAccelerometerStatics)->GetDefault(put_abi(result)));
    return result;
}

template <typename D> Windows::Devices::Sensors::Accelerometer consume_Windows_Devices_Sensors_IAccelerometerStatics2<D>::GetDefault(Windows::Devices::Sensors::AccelerometerReadingType const& readingType) const
{
    Windows::Devices::Sensors::Accelerometer result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IAccelerometerStatics2)->GetDefaultWithAccelerometerReadingType(get_abi(readingType), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::Accelerometer> consume_Windows_Devices_Sensors_IAccelerometerStatics3<D>::FromIdAsync(param::hstring const& deviceId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::Accelerometer> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IAccelerometerStatics3)->FromIdAsync(get_abi(deviceId), put_abi(operation)));
    return operation;
}

template <typename D> hstring consume_Windows_Devices_Sensors_IAccelerometerStatics3<D>::GetDeviceSelector(Windows::Devices::Sensors::AccelerometerReadingType const& readingType) const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IAccelerometerStatics3)->GetDeviceSelector(get_abi(readingType), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::ActivitySensorReading> consume_Windows_Devices_Sensors_IActivitySensor<D>::GetCurrentReadingAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::ActivitySensorReading> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IActivitySensor)->GetCurrentReadingAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::Devices::Sensors::ActivityType> consume_Windows_Devices_Sensors_IActivitySensor<D>::SubscribedActivities() const
{
    Windows::Foundation::Collections::IVector<Windows::Devices::Sensors::ActivityType> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IActivitySensor)->get_SubscribedActivities(put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_Devices_Sensors_IActivitySensor<D>::PowerInMilliwatts() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IActivitySensor)->get_PowerInMilliwatts(&value));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Sensors_IActivitySensor<D>::DeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IActivitySensor)->get_DeviceId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::Sensors::ActivityType> consume_Windows_Devices_Sensors_IActivitySensor<D>::SupportedActivities() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Sensors::ActivityType> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IActivitySensor)->get_SupportedActivities(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_Sensors_IActivitySensor<D>::MinimumReportInterval() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IActivitySensor)->get_MinimumReportInterval(&value));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Devices_Sensors_IActivitySensor<D>::ReadingChanged(Windows::Foundation::TypedEventHandler<Windows::Devices::Sensors::ActivitySensor, Windows::Devices::Sensors::ActivitySensorReadingChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IActivitySensor)->add_ReadingChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Sensors_IActivitySensor<D>::ReadingChanged_revoker consume_Windows_Devices_Sensors_IActivitySensor<D>::ReadingChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Sensors::ActivitySensor, Windows::Devices::Sensors::ActivitySensorReadingChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ReadingChanged_revoker>(this, ReadingChanged(handler));
}

template <typename D> void consume_Windows_Devices_Sensors_IActivitySensor<D>::ReadingChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Sensors::IActivitySensor)->remove_ReadingChanged(get_abi(token)));
}

template <typename D> Windows::Foundation::DateTime consume_Windows_Devices_Sensors_IActivitySensorReading<D>::Timestamp() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IActivitySensorReading)->get_Timestamp(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sensors::ActivityType consume_Windows_Devices_Sensors_IActivitySensorReading<D>::Activity() const
{
    Windows::Devices::Sensors::ActivityType value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IActivitySensorReading)->get_Activity(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sensors::ActivitySensorReadingConfidence consume_Windows_Devices_Sensors_IActivitySensorReading<D>::Confidence() const
{
    Windows::Devices::Sensors::ActivitySensorReadingConfidence value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IActivitySensorReading)->get_Confidence(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sensors::ActivitySensorReading consume_Windows_Devices_Sensors_IActivitySensorReadingChangeReport<D>::Reading() const
{
    Windows::Devices::Sensors::ActivitySensorReading value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IActivitySensorReadingChangeReport)->get_Reading(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sensors::ActivitySensorReading consume_Windows_Devices_Sensors_IActivitySensorReadingChangedEventArgs<D>::Reading() const
{
    Windows::Devices::Sensors::ActivitySensorReading value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IActivitySensorReadingChangedEventArgs)->get_Reading(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::ActivitySensor> consume_Windows_Devices_Sensors_IActivitySensorStatics<D>::GetDefaultAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::ActivitySensor> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IActivitySensorStatics)->GetDefaultAsync(put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Devices_Sensors_IActivitySensorStatics<D>::GetDeviceSelector() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IActivitySensorStatics)->GetDeviceSelector(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::ActivitySensor> consume_Windows_Devices_Sensors_IActivitySensorStatics<D>::FromIdAsync(param::hstring const& deviceId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::ActivitySensor> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IActivitySensorStatics)->FromIdAsync(get_abi(deviceId), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Sensors::ActivitySensorReading>> consume_Windows_Devices_Sensors_IActivitySensorStatics<D>::GetSystemHistoryAsync(Windows::Foundation::DateTime const& fromTime) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Sensors::ActivitySensorReading>> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IActivitySensorStatics)->GetSystemHistoryAsync(get_abi(fromTime), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Sensors::ActivitySensorReading>> consume_Windows_Devices_Sensors_IActivitySensorStatics<D>::GetSystemHistoryAsync(Windows::Foundation::DateTime const& fromTime, Windows::Foundation::TimeSpan const& duration) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Sensors::ActivitySensorReading>> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IActivitySensorStatics)->GetSystemHistoryWithDurationAsync(get_abi(fromTime), get_abi(duration), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::Sensors::ActivitySensorReadingChangeReport> consume_Windows_Devices_Sensors_IActivitySensorTriggerDetails<D>::ReadReports() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Sensors::ActivitySensorReadingChangeReport> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IActivitySensorTriggerDetails)->ReadReports(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sensors::AltimeterReading consume_Windows_Devices_Sensors_IAltimeter<D>::GetCurrentReading() const
{
    Windows::Devices::Sensors::AltimeterReading value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IAltimeter)->GetCurrentReading(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Sensors_IAltimeter<D>::DeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IAltimeter)->get_DeviceId(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_Sensors_IAltimeter<D>::MinimumReportInterval() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IAltimeter)->get_MinimumReportInterval(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_Sensors_IAltimeter<D>::ReportInterval(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IAltimeter)->put_ReportInterval(value));
}

template <typename D> uint32_t consume_Windows_Devices_Sensors_IAltimeter<D>::ReportInterval() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IAltimeter)->get_ReportInterval(&value));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Devices_Sensors_IAltimeter<D>::ReadingChanged(Windows::Foundation::TypedEventHandler<Windows::Devices::Sensors::Altimeter, Windows::Devices::Sensors::AltimeterReadingChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IAltimeter)->add_ReadingChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Sensors_IAltimeter<D>::ReadingChanged_revoker consume_Windows_Devices_Sensors_IAltimeter<D>::ReadingChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Sensors::Altimeter, Windows::Devices::Sensors::AltimeterReadingChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ReadingChanged_revoker>(this, ReadingChanged(handler));
}

template <typename D> void consume_Windows_Devices_Sensors_IAltimeter<D>::ReadingChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Sensors::IAltimeter)->remove_ReadingChanged(get_abi(token)));
}

template <typename D> void consume_Windows_Devices_Sensors_IAltimeter2<D>::ReportLatency(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IAltimeter2)->put_ReportLatency(value));
}

template <typename D> uint32_t consume_Windows_Devices_Sensors_IAltimeter2<D>::ReportLatency() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IAltimeter2)->get_ReportLatency(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_Sensors_IAltimeter2<D>::MaxBatchSize() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IAltimeter2)->get_MaxBatchSize(&value));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_Devices_Sensors_IAltimeterReading<D>::Timestamp() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IAltimeterReading)->get_Timestamp(put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_Devices_Sensors_IAltimeterReading<D>::AltitudeChangeInMeters() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IAltimeterReading)->get_AltitudeChangeInMeters(&value));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::TimeSpan> consume_Windows_Devices_Sensors_IAltimeterReading2<D>::PerformanceCount() const
{
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IAltimeterReading2)->get_PerformanceCount(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable> consume_Windows_Devices_Sensors_IAltimeterReading2<D>::Properties() const
{
    Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IAltimeterReading2)->get_Properties(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sensors::AltimeterReading consume_Windows_Devices_Sensors_IAltimeterReadingChangedEventArgs<D>::Reading() const
{
    Windows::Devices::Sensors::AltimeterReading value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IAltimeterReadingChangedEventArgs)->get_Reading(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sensors::Altimeter consume_Windows_Devices_Sensors_IAltimeterStatics<D>::GetDefault() const
{
    Windows::Devices::Sensors::Altimeter result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IAltimeterStatics)->GetDefault(put_abi(result)));
    return result;
}

template <typename D> Windows::Devices::Sensors::BarometerReading consume_Windows_Devices_Sensors_IBarometer<D>::GetCurrentReading() const
{
    Windows::Devices::Sensors::BarometerReading value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IBarometer)->GetCurrentReading(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Sensors_IBarometer<D>::DeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IBarometer)->get_DeviceId(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_Sensors_IBarometer<D>::MinimumReportInterval() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IBarometer)->get_MinimumReportInterval(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_Sensors_IBarometer<D>::ReportInterval(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IBarometer)->put_ReportInterval(value));
}

template <typename D> uint32_t consume_Windows_Devices_Sensors_IBarometer<D>::ReportInterval() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IBarometer)->get_ReportInterval(&value));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Devices_Sensors_IBarometer<D>::ReadingChanged(Windows::Foundation::TypedEventHandler<Windows::Devices::Sensors::Barometer, Windows::Devices::Sensors::BarometerReadingChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IBarometer)->add_ReadingChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Sensors_IBarometer<D>::ReadingChanged_revoker consume_Windows_Devices_Sensors_IBarometer<D>::ReadingChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Sensors::Barometer, Windows::Devices::Sensors::BarometerReadingChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ReadingChanged_revoker>(this, ReadingChanged(handler));
}

template <typename D> void consume_Windows_Devices_Sensors_IBarometer<D>::ReadingChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Sensors::IBarometer)->remove_ReadingChanged(get_abi(token)));
}

template <typename D> void consume_Windows_Devices_Sensors_IBarometer2<D>::ReportLatency(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IBarometer2)->put_ReportLatency(value));
}

template <typename D> uint32_t consume_Windows_Devices_Sensors_IBarometer2<D>::ReportLatency() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IBarometer2)->get_ReportLatency(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_Sensors_IBarometer2<D>::MaxBatchSize() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IBarometer2)->get_MaxBatchSize(&value));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_Devices_Sensors_IBarometerReading<D>::Timestamp() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IBarometerReading)->get_Timestamp(put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_Devices_Sensors_IBarometerReading<D>::StationPressureInHectopascals() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IBarometerReading)->get_StationPressureInHectopascals(&value));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::TimeSpan> consume_Windows_Devices_Sensors_IBarometerReading2<D>::PerformanceCount() const
{
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IBarometerReading2)->get_PerformanceCount(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable> consume_Windows_Devices_Sensors_IBarometerReading2<D>::Properties() const
{
    Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IBarometerReading2)->get_Properties(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sensors::BarometerReading consume_Windows_Devices_Sensors_IBarometerReadingChangedEventArgs<D>::Reading() const
{
    Windows::Devices::Sensors::BarometerReading value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IBarometerReadingChangedEventArgs)->get_Reading(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sensors::Barometer consume_Windows_Devices_Sensors_IBarometerStatics<D>::GetDefault() const
{
    Windows::Devices::Sensors::Barometer result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IBarometerStatics)->GetDefault(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::Barometer> consume_Windows_Devices_Sensors_IBarometerStatics2<D>::FromIdAsync(param::hstring const& deviceId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::Barometer> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IBarometerStatics2)->FromIdAsync(get_abi(deviceId), put_abi(operation)));
    return operation;
}

template <typename D> hstring consume_Windows_Devices_Sensors_IBarometerStatics2<D>::GetDeviceSelector() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IBarometerStatics2)->GetDeviceSelector(put_abi(result)));
    return result;
}

template <typename D> Windows::Devices::Sensors::CompassReading consume_Windows_Devices_Sensors_ICompass<D>::GetCurrentReading() const
{
    Windows::Devices::Sensors::CompassReading value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::ICompass)->GetCurrentReading(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_Sensors_ICompass<D>::MinimumReportInterval() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::ICompass)->get_MinimumReportInterval(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_Sensors_ICompass<D>::ReportInterval(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::ICompass)->put_ReportInterval(value));
}

template <typename D> uint32_t consume_Windows_Devices_Sensors_ICompass<D>::ReportInterval() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::ICompass)->get_ReportInterval(&value));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Devices_Sensors_ICompass<D>::ReadingChanged(Windows::Foundation::TypedEventHandler<Windows::Devices::Sensors::Compass, Windows::Devices::Sensors::CompassReadingChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::ICompass)->add_ReadingChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Sensors_ICompass<D>::ReadingChanged_revoker consume_Windows_Devices_Sensors_ICompass<D>::ReadingChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Sensors::Compass, Windows::Devices::Sensors::CompassReadingChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ReadingChanged_revoker>(this, ReadingChanged(handler));
}

template <typename D> void consume_Windows_Devices_Sensors_ICompass<D>::ReadingChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Sensors::ICompass)->remove_ReadingChanged(get_abi(token)));
}

template <typename D> void consume_Windows_Devices_Sensors_ICompass2<D>::ReadingTransform(Windows::Graphics::Display::DisplayOrientations const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::ICompass2)->put_ReadingTransform(get_abi(value)));
}

template <typename D> Windows::Graphics::Display::DisplayOrientations consume_Windows_Devices_Sensors_ICompass2<D>::ReadingTransform() const
{
    Windows::Graphics::Display::DisplayOrientations value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::ICompass2)->get_ReadingTransform(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Sensors_ICompass3<D>::ReportLatency(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::ICompass3)->put_ReportLatency(value));
}

template <typename D> uint32_t consume_Windows_Devices_Sensors_ICompass3<D>::ReportLatency() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::ICompass3)->get_ReportLatency(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_Sensors_ICompass3<D>::MaxBatchSize() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::ICompass3)->get_MaxBatchSize(&value));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Sensors_ICompassDeviceId<D>::DeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::ICompassDeviceId)->get_DeviceId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_Devices_Sensors_ICompassReading<D>::Timestamp() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::ICompassReading)->get_Timestamp(put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_Devices_Sensors_ICompassReading<D>::HeadingMagneticNorth() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::ICompassReading)->get_HeadingMagneticNorth(&value));
    return value;
}

template <typename D> Windows::Foundation::IReference<double> consume_Windows_Devices_Sensors_ICompassReading<D>::HeadingTrueNorth() const
{
    Windows::Foundation::IReference<double> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::ICompassReading)->get_HeadingTrueNorth(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::TimeSpan> consume_Windows_Devices_Sensors_ICompassReading2<D>::PerformanceCount() const
{
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::ICompassReading2)->get_PerformanceCount(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable> consume_Windows_Devices_Sensors_ICompassReading2<D>::Properties() const
{
    Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::ICompassReading2)->get_Properties(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sensors::CompassReading consume_Windows_Devices_Sensors_ICompassReadingChangedEventArgs<D>::Reading() const
{
    Windows::Devices::Sensors::CompassReading value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::ICompassReadingChangedEventArgs)->get_Reading(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sensors::MagnetometerAccuracy consume_Windows_Devices_Sensors_ICompassReadingHeadingAccuracy<D>::HeadingAccuracy() const
{
    Windows::Devices::Sensors::MagnetometerAccuracy value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::ICompassReadingHeadingAccuracy)->get_HeadingAccuracy(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sensors::Compass consume_Windows_Devices_Sensors_ICompassStatics<D>::GetDefault() const
{
    Windows::Devices::Sensors::Compass result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::ICompassStatics)->GetDefault(put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Devices_Sensors_ICompassStatics2<D>::GetDeviceSelector() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::ICompassStatics2)->GetDeviceSelector(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::Compass> consume_Windows_Devices_Sensors_ICompassStatics2<D>::FromIdAsync(param::hstring const& deviceId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::Compass> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::ICompassStatics2)->FromIdAsync(get_abi(deviceId), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Devices::Sensors::GyrometerReading consume_Windows_Devices_Sensors_IGyrometer<D>::GetCurrentReading() const
{
    Windows::Devices::Sensors::GyrometerReading value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IGyrometer)->GetCurrentReading(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_Sensors_IGyrometer<D>::MinimumReportInterval() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IGyrometer)->get_MinimumReportInterval(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_Sensors_IGyrometer<D>::ReportInterval(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IGyrometer)->put_ReportInterval(value));
}

template <typename D> uint32_t consume_Windows_Devices_Sensors_IGyrometer<D>::ReportInterval() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IGyrometer)->get_ReportInterval(&value));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Devices_Sensors_IGyrometer<D>::ReadingChanged(Windows::Foundation::TypedEventHandler<Windows::Devices::Sensors::Gyrometer, Windows::Devices::Sensors::GyrometerReadingChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IGyrometer)->add_ReadingChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Sensors_IGyrometer<D>::ReadingChanged_revoker consume_Windows_Devices_Sensors_IGyrometer<D>::ReadingChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Sensors::Gyrometer, Windows::Devices::Sensors::GyrometerReadingChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ReadingChanged_revoker>(this, ReadingChanged(handler));
}

template <typename D> void consume_Windows_Devices_Sensors_IGyrometer<D>::ReadingChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Sensors::IGyrometer)->remove_ReadingChanged(get_abi(token)));
}

template <typename D> void consume_Windows_Devices_Sensors_IGyrometer2<D>::ReadingTransform(Windows::Graphics::Display::DisplayOrientations const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IGyrometer2)->put_ReadingTransform(get_abi(value)));
}

template <typename D> Windows::Graphics::Display::DisplayOrientations consume_Windows_Devices_Sensors_IGyrometer2<D>::ReadingTransform() const
{
    Windows::Graphics::Display::DisplayOrientations value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IGyrometer2)->get_ReadingTransform(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Sensors_IGyrometer3<D>::ReportLatency(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IGyrometer3)->put_ReportLatency(value));
}

template <typename D> uint32_t consume_Windows_Devices_Sensors_IGyrometer3<D>::ReportLatency() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IGyrometer3)->get_ReportLatency(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_Sensors_IGyrometer3<D>::MaxBatchSize() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IGyrometer3)->get_MaxBatchSize(&value));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Sensors_IGyrometerDeviceId<D>::DeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IGyrometerDeviceId)->get_DeviceId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_Devices_Sensors_IGyrometerReading<D>::Timestamp() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IGyrometerReading)->get_Timestamp(put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_Devices_Sensors_IGyrometerReading<D>::AngularVelocityX() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IGyrometerReading)->get_AngularVelocityX(&value));
    return value;
}

template <typename D> double consume_Windows_Devices_Sensors_IGyrometerReading<D>::AngularVelocityY() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IGyrometerReading)->get_AngularVelocityY(&value));
    return value;
}

template <typename D> double consume_Windows_Devices_Sensors_IGyrometerReading<D>::AngularVelocityZ() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IGyrometerReading)->get_AngularVelocityZ(&value));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::TimeSpan> consume_Windows_Devices_Sensors_IGyrometerReading2<D>::PerformanceCount() const
{
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IGyrometerReading2)->get_PerformanceCount(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable> consume_Windows_Devices_Sensors_IGyrometerReading2<D>::Properties() const
{
    Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IGyrometerReading2)->get_Properties(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sensors::GyrometerReading consume_Windows_Devices_Sensors_IGyrometerReadingChangedEventArgs<D>::Reading() const
{
    Windows::Devices::Sensors::GyrometerReading value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IGyrometerReadingChangedEventArgs)->get_Reading(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sensors::Gyrometer consume_Windows_Devices_Sensors_IGyrometerStatics<D>::GetDefault() const
{
    Windows::Devices::Sensors::Gyrometer result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IGyrometerStatics)->GetDefault(put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Devices_Sensors_IGyrometerStatics2<D>::GetDeviceSelector() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IGyrometerStatics2)->GetDeviceSelector(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::Gyrometer> consume_Windows_Devices_Sensors_IGyrometerStatics2<D>::FromIdAsync(param::hstring const& deviceId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::Gyrometer> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IGyrometerStatics2)->FromIdAsync(get_abi(deviceId), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_Devices_Sensors_IHingeAngleReading<D>::Timestamp() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IHingeAngleReading)->get_Timestamp(put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_Devices_Sensors_IHingeAngleReading<D>::AngleInDegrees() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IHingeAngleReading)->get_AngleInDegrees(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable> consume_Windows_Devices_Sensors_IHingeAngleReading<D>::Properties() const
{
    Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IHingeAngleReading)->get_Properties(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::HingeAngleReading> consume_Windows_Devices_Sensors_IHingeAngleSensor<D>::GetCurrentReadingAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::HingeAngleReading> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IHingeAngleSensor)->GetCurrentReadingAsync(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Sensors_IHingeAngleSensor<D>::DeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IHingeAngleSensor)->get_DeviceId(put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_Devices_Sensors_IHingeAngleSensor<D>::MinReportThresholdInDegrees() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IHingeAngleSensor)->get_MinReportThresholdInDegrees(&value));
    return value;
}

template <typename D> double consume_Windows_Devices_Sensors_IHingeAngleSensor<D>::ReportThresholdInDegrees() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IHingeAngleSensor)->get_ReportThresholdInDegrees(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_Sensors_IHingeAngleSensor<D>::ReportThresholdInDegrees(double value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IHingeAngleSensor)->put_ReportThresholdInDegrees(value));
}

template <typename D> winrt::event_token consume_Windows_Devices_Sensors_IHingeAngleSensor<D>::ReadingChanged(Windows::Foundation::TypedEventHandler<Windows::Devices::Sensors::HingeAngleSensor, Windows::Devices::Sensors::HingeAngleSensorReadingChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IHingeAngleSensor)->add_ReadingChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Sensors_IHingeAngleSensor<D>::ReadingChanged_revoker consume_Windows_Devices_Sensors_IHingeAngleSensor<D>::ReadingChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Sensors::HingeAngleSensor, Windows::Devices::Sensors::HingeAngleSensorReadingChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ReadingChanged_revoker>(this, ReadingChanged(handler));
}

template <typename D> void consume_Windows_Devices_Sensors_IHingeAngleSensor<D>::ReadingChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Sensors::IHingeAngleSensor)->remove_ReadingChanged(get_abi(token)));
}

template <typename D> Windows::Devices::Sensors::HingeAngleReading consume_Windows_Devices_Sensors_IHingeAngleSensorReadingChangedEventArgs<D>::Reading() const
{
    Windows::Devices::Sensors::HingeAngleReading value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IHingeAngleSensorReadingChangedEventArgs)->get_Reading(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Sensors_IHingeAngleSensorStatics<D>::GetDeviceSelector() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IHingeAngleSensorStatics)->GetDeviceSelector(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::HingeAngleSensor> consume_Windows_Devices_Sensors_IHingeAngleSensorStatics<D>::GetDefaultAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::HingeAngleSensor> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IHingeAngleSensorStatics)->GetDefaultAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::HingeAngleSensor> consume_Windows_Devices_Sensors_IHingeAngleSensorStatics<D>::GetRelatedToAdjacentPanelsAsync(param::hstring const& firstPanelId, param::hstring const& secondPanelId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::HingeAngleSensor> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IHingeAngleSensorStatics)->GetRelatedToAdjacentPanelsAsync(get_abi(firstPanelId), get_abi(secondPanelId), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::HingeAngleSensor> consume_Windows_Devices_Sensors_IHingeAngleSensorStatics<D>::FromIdAsync(param::hstring const& deviceId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::HingeAngleSensor> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IHingeAngleSensorStatics)->FromIdAsync(get_abi(deviceId), put_abi(result)));
    return result;
}

template <typename D> Windows::Devices::Sensors::InclinometerReading consume_Windows_Devices_Sensors_IInclinometer<D>::GetCurrentReading() const
{
    Windows::Devices::Sensors::InclinometerReading value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IInclinometer)->GetCurrentReading(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_Sensors_IInclinometer<D>::MinimumReportInterval() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IInclinometer)->get_MinimumReportInterval(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_Sensors_IInclinometer<D>::ReportInterval(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IInclinometer)->put_ReportInterval(value));
}

template <typename D> uint32_t consume_Windows_Devices_Sensors_IInclinometer<D>::ReportInterval() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IInclinometer)->get_ReportInterval(&value));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Devices_Sensors_IInclinometer<D>::ReadingChanged(Windows::Foundation::TypedEventHandler<Windows::Devices::Sensors::Inclinometer, Windows::Devices::Sensors::InclinometerReadingChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IInclinometer)->add_ReadingChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Sensors_IInclinometer<D>::ReadingChanged_revoker consume_Windows_Devices_Sensors_IInclinometer<D>::ReadingChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Sensors::Inclinometer, Windows::Devices::Sensors::InclinometerReadingChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ReadingChanged_revoker>(this, ReadingChanged(handler));
}

template <typename D> void consume_Windows_Devices_Sensors_IInclinometer<D>::ReadingChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Sensors::IInclinometer)->remove_ReadingChanged(get_abi(token)));
}

template <typename D> void consume_Windows_Devices_Sensors_IInclinometer2<D>::ReadingTransform(Windows::Graphics::Display::DisplayOrientations const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IInclinometer2)->put_ReadingTransform(get_abi(value)));
}

template <typename D> Windows::Graphics::Display::DisplayOrientations consume_Windows_Devices_Sensors_IInclinometer2<D>::ReadingTransform() const
{
    Windows::Graphics::Display::DisplayOrientations value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IInclinometer2)->get_ReadingTransform(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sensors::SensorReadingType consume_Windows_Devices_Sensors_IInclinometer2<D>::ReadingType() const
{
    Windows::Devices::Sensors::SensorReadingType type{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IInclinometer2)->get_ReadingType(put_abi(type)));
    return type;
}

template <typename D> void consume_Windows_Devices_Sensors_IInclinometer3<D>::ReportLatency(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IInclinometer3)->put_ReportLatency(value));
}

template <typename D> uint32_t consume_Windows_Devices_Sensors_IInclinometer3<D>::ReportLatency() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IInclinometer3)->get_ReportLatency(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_Sensors_IInclinometer3<D>::MaxBatchSize() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IInclinometer3)->get_MaxBatchSize(&value));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Sensors_IInclinometerDeviceId<D>::DeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IInclinometerDeviceId)->get_DeviceId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_Devices_Sensors_IInclinometerReading<D>::Timestamp() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IInclinometerReading)->get_Timestamp(put_abi(value)));
    return value;
}

template <typename D> float consume_Windows_Devices_Sensors_IInclinometerReading<D>::PitchDegrees() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IInclinometerReading)->get_PitchDegrees(&value));
    return value;
}

template <typename D> float consume_Windows_Devices_Sensors_IInclinometerReading<D>::RollDegrees() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IInclinometerReading)->get_RollDegrees(&value));
    return value;
}

template <typename D> float consume_Windows_Devices_Sensors_IInclinometerReading<D>::YawDegrees() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IInclinometerReading)->get_YawDegrees(&value));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::TimeSpan> consume_Windows_Devices_Sensors_IInclinometerReading2<D>::PerformanceCount() const
{
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IInclinometerReading2)->get_PerformanceCount(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable> consume_Windows_Devices_Sensors_IInclinometerReading2<D>::Properties() const
{
    Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IInclinometerReading2)->get_Properties(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sensors::InclinometerReading consume_Windows_Devices_Sensors_IInclinometerReadingChangedEventArgs<D>::Reading() const
{
    Windows::Devices::Sensors::InclinometerReading value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IInclinometerReadingChangedEventArgs)->get_Reading(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sensors::MagnetometerAccuracy consume_Windows_Devices_Sensors_IInclinometerReadingYawAccuracy<D>::YawAccuracy() const
{
    Windows::Devices::Sensors::MagnetometerAccuracy value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IInclinometerReadingYawAccuracy)->get_YawAccuracy(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sensors::Inclinometer consume_Windows_Devices_Sensors_IInclinometerStatics<D>::GetDefault() const
{
    Windows::Devices::Sensors::Inclinometer result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IInclinometerStatics)->GetDefault(put_abi(result)));
    return result;
}

template <typename D> Windows::Devices::Sensors::Inclinometer consume_Windows_Devices_Sensors_IInclinometerStatics2<D>::GetDefaultForRelativeReadings() const
{
    Windows::Devices::Sensors::Inclinometer result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IInclinometerStatics2)->GetDefaultForRelativeReadings(put_abi(result)));
    return result;
}

template <typename D> Windows::Devices::Sensors::Inclinometer consume_Windows_Devices_Sensors_IInclinometerStatics3<D>::GetDefault(Windows::Devices::Sensors::SensorReadingType const& sensorReadingtype) const
{
    Windows::Devices::Sensors::Inclinometer result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IInclinometerStatics3)->GetDefaultWithSensorReadingType(get_abi(sensorReadingtype), put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Devices_Sensors_IInclinometerStatics4<D>::GetDeviceSelector(Windows::Devices::Sensors::SensorReadingType const& readingType) const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IInclinometerStatics4)->GetDeviceSelector(get_abi(readingType), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::Inclinometer> consume_Windows_Devices_Sensors_IInclinometerStatics4<D>::FromIdAsync(param::hstring const& deviceId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::Inclinometer> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IInclinometerStatics4)->FromIdAsync(get_abi(deviceId), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Devices::Sensors::LightSensorReading consume_Windows_Devices_Sensors_ILightSensor<D>::GetCurrentReading() const
{
    Windows::Devices::Sensors::LightSensorReading value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::ILightSensor)->GetCurrentReading(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_Sensors_ILightSensor<D>::MinimumReportInterval() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::ILightSensor)->get_MinimumReportInterval(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_Sensors_ILightSensor<D>::ReportInterval(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::ILightSensor)->put_ReportInterval(value));
}

template <typename D> uint32_t consume_Windows_Devices_Sensors_ILightSensor<D>::ReportInterval() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::ILightSensor)->get_ReportInterval(&value));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Devices_Sensors_ILightSensor<D>::ReadingChanged(Windows::Foundation::TypedEventHandler<Windows::Devices::Sensors::LightSensor, Windows::Devices::Sensors::LightSensorReadingChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::ILightSensor)->add_ReadingChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Sensors_ILightSensor<D>::ReadingChanged_revoker consume_Windows_Devices_Sensors_ILightSensor<D>::ReadingChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Sensors::LightSensor, Windows::Devices::Sensors::LightSensorReadingChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ReadingChanged_revoker>(this, ReadingChanged(handler));
}

template <typename D> void consume_Windows_Devices_Sensors_ILightSensor<D>::ReadingChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Sensors::ILightSensor)->remove_ReadingChanged(get_abi(token)));
}

template <typename D> void consume_Windows_Devices_Sensors_ILightSensor2<D>::ReportLatency(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::ILightSensor2)->put_ReportLatency(value));
}

template <typename D> uint32_t consume_Windows_Devices_Sensors_ILightSensor2<D>::ReportLatency() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::ILightSensor2)->get_ReportLatency(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_Sensors_ILightSensor2<D>::MaxBatchSize() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::ILightSensor2)->get_MaxBatchSize(&value));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Sensors_ILightSensorDeviceId<D>::DeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::ILightSensorDeviceId)->get_DeviceId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_Devices_Sensors_ILightSensorReading<D>::Timestamp() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::ILightSensorReading)->get_Timestamp(put_abi(value)));
    return value;
}

template <typename D> float consume_Windows_Devices_Sensors_ILightSensorReading<D>::IlluminanceInLux() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::ILightSensorReading)->get_IlluminanceInLux(&value));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::TimeSpan> consume_Windows_Devices_Sensors_ILightSensorReading2<D>::PerformanceCount() const
{
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::ILightSensorReading2)->get_PerformanceCount(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable> consume_Windows_Devices_Sensors_ILightSensorReading2<D>::Properties() const
{
    Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::ILightSensorReading2)->get_Properties(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sensors::LightSensorReading consume_Windows_Devices_Sensors_ILightSensorReadingChangedEventArgs<D>::Reading() const
{
    Windows::Devices::Sensors::LightSensorReading value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::ILightSensorReadingChangedEventArgs)->get_Reading(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sensors::LightSensor consume_Windows_Devices_Sensors_ILightSensorStatics<D>::GetDefault() const
{
    Windows::Devices::Sensors::LightSensor result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::ILightSensorStatics)->GetDefault(put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Devices_Sensors_ILightSensorStatics2<D>::GetDeviceSelector() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::ILightSensorStatics2)->GetDeviceSelector(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::LightSensor> consume_Windows_Devices_Sensors_ILightSensorStatics2<D>::FromIdAsync(param::hstring const& deviceId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::LightSensor> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::ILightSensorStatics2)->FromIdAsync(get_abi(deviceId), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Devices::Sensors::MagnetometerReading consume_Windows_Devices_Sensors_IMagnetometer<D>::GetCurrentReading() const
{
    Windows::Devices::Sensors::MagnetometerReading value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IMagnetometer)->GetCurrentReading(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_Sensors_IMagnetometer<D>::MinimumReportInterval() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IMagnetometer)->get_MinimumReportInterval(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_Sensors_IMagnetometer<D>::ReportInterval(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IMagnetometer)->put_ReportInterval(value));
}

template <typename D> uint32_t consume_Windows_Devices_Sensors_IMagnetometer<D>::ReportInterval() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IMagnetometer)->get_ReportInterval(&value));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Devices_Sensors_IMagnetometer<D>::ReadingChanged(Windows::Foundation::TypedEventHandler<Windows::Devices::Sensors::Magnetometer, Windows::Devices::Sensors::MagnetometerReadingChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IMagnetometer)->add_ReadingChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Sensors_IMagnetometer<D>::ReadingChanged_revoker consume_Windows_Devices_Sensors_IMagnetometer<D>::ReadingChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Sensors::Magnetometer, Windows::Devices::Sensors::MagnetometerReadingChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ReadingChanged_revoker>(this, ReadingChanged(handler));
}

template <typename D> void consume_Windows_Devices_Sensors_IMagnetometer<D>::ReadingChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Sensors::IMagnetometer)->remove_ReadingChanged(get_abi(token)));
}

template <typename D> void consume_Windows_Devices_Sensors_IMagnetometer2<D>::ReadingTransform(Windows::Graphics::Display::DisplayOrientations const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IMagnetometer2)->put_ReadingTransform(get_abi(value)));
}

template <typename D> Windows::Graphics::Display::DisplayOrientations consume_Windows_Devices_Sensors_IMagnetometer2<D>::ReadingTransform() const
{
    Windows::Graphics::Display::DisplayOrientations value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IMagnetometer2)->get_ReadingTransform(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Sensors_IMagnetometer3<D>::ReportLatency(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IMagnetometer3)->put_ReportLatency(value));
}

template <typename D> uint32_t consume_Windows_Devices_Sensors_IMagnetometer3<D>::ReportLatency() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IMagnetometer3)->get_ReportLatency(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_Sensors_IMagnetometer3<D>::MaxBatchSize() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IMagnetometer3)->get_MaxBatchSize(&value));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Sensors_IMagnetometerDeviceId<D>::DeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IMagnetometerDeviceId)->get_DeviceId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_Devices_Sensors_IMagnetometerReading<D>::Timestamp() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IMagnetometerReading)->get_Timestamp(put_abi(value)));
    return value;
}

template <typename D> float consume_Windows_Devices_Sensors_IMagnetometerReading<D>::MagneticFieldX() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IMagnetometerReading)->get_MagneticFieldX(&value));
    return value;
}

template <typename D> float consume_Windows_Devices_Sensors_IMagnetometerReading<D>::MagneticFieldY() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IMagnetometerReading)->get_MagneticFieldY(&value));
    return value;
}

template <typename D> float consume_Windows_Devices_Sensors_IMagnetometerReading<D>::MagneticFieldZ() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IMagnetometerReading)->get_MagneticFieldZ(&value));
    return value;
}

template <typename D> Windows::Devices::Sensors::MagnetometerAccuracy consume_Windows_Devices_Sensors_IMagnetometerReading<D>::DirectionalAccuracy() const
{
    Windows::Devices::Sensors::MagnetometerAccuracy value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IMagnetometerReading)->get_DirectionalAccuracy(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::TimeSpan> consume_Windows_Devices_Sensors_IMagnetometerReading2<D>::PerformanceCount() const
{
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IMagnetometerReading2)->get_PerformanceCount(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable> consume_Windows_Devices_Sensors_IMagnetometerReading2<D>::Properties() const
{
    Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IMagnetometerReading2)->get_Properties(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sensors::MagnetometerReading consume_Windows_Devices_Sensors_IMagnetometerReadingChangedEventArgs<D>::Reading() const
{
    Windows::Devices::Sensors::MagnetometerReading value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IMagnetometerReadingChangedEventArgs)->get_Reading(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sensors::Magnetometer consume_Windows_Devices_Sensors_IMagnetometerStatics<D>::GetDefault() const
{
    Windows::Devices::Sensors::Magnetometer result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IMagnetometerStatics)->GetDefault(put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Devices_Sensors_IMagnetometerStatics2<D>::GetDeviceSelector() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IMagnetometerStatics2)->GetDeviceSelector(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::Magnetometer> consume_Windows_Devices_Sensors_IMagnetometerStatics2<D>::FromIdAsync(param::hstring const& deviceId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::Magnetometer> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IMagnetometerStatics2)->FromIdAsync(get_abi(deviceId), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Devices::Sensors::OrientationSensorReading consume_Windows_Devices_Sensors_IOrientationSensor<D>::GetCurrentReading() const
{
    Windows::Devices::Sensors::OrientationSensorReading value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IOrientationSensor)->GetCurrentReading(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_Sensors_IOrientationSensor<D>::MinimumReportInterval() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IOrientationSensor)->get_MinimumReportInterval(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_Sensors_IOrientationSensor<D>::ReportInterval(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IOrientationSensor)->put_ReportInterval(value));
}

template <typename D> uint32_t consume_Windows_Devices_Sensors_IOrientationSensor<D>::ReportInterval() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IOrientationSensor)->get_ReportInterval(&value));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Devices_Sensors_IOrientationSensor<D>::ReadingChanged(Windows::Foundation::TypedEventHandler<Windows::Devices::Sensors::OrientationSensor, Windows::Devices::Sensors::OrientationSensorReadingChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IOrientationSensor)->add_ReadingChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Sensors_IOrientationSensor<D>::ReadingChanged_revoker consume_Windows_Devices_Sensors_IOrientationSensor<D>::ReadingChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Sensors::OrientationSensor, Windows::Devices::Sensors::OrientationSensorReadingChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ReadingChanged_revoker>(this, ReadingChanged(handler));
}

template <typename D> void consume_Windows_Devices_Sensors_IOrientationSensor<D>::ReadingChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Sensors::IOrientationSensor)->remove_ReadingChanged(get_abi(token)));
}

template <typename D> void consume_Windows_Devices_Sensors_IOrientationSensor2<D>::ReadingTransform(Windows::Graphics::Display::DisplayOrientations const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IOrientationSensor2)->put_ReadingTransform(get_abi(value)));
}

template <typename D> Windows::Graphics::Display::DisplayOrientations consume_Windows_Devices_Sensors_IOrientationSensor2<D>::ReadingTransform() const
{
    Windows::Graphics::Display::DisplayOrientations value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IOrientationSensor2)->get_ReadingTransform(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sensors::SensorReadingType consume_Windows_Devices_Sensors_IOrientationSensor2<D>::ReadingType() const
{
    Windows::Devices::Sensors::SensorReadingType type{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IOrientationSensor2)->get_ReadingType(put_abi(type)));
    return type;
}

template <typename D> void consume_Windows_Devices_Sensors_IOrientationSensor3<D>::ReportLatency(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IOrientationSensor3)->put_ReportLatency(value));
}

template <typename D> uint32_t consume_Windows_Devices_Sensors_IOrientationSensor3<D>::ReportLatency() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IOrientationSensor3)->get_ReportLatency(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_Sensors_IOrientationSensor3<D>::MaxBatchSize() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IOrientationSensor3)->get_MaxBatchSize(&value));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Sensors_IOrientationSensorDeviceId<D>::DeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IOrientationSensorDeviceId)->get_DeviceId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_Devices_Sensors_IOrientationSensorReading<D>::Timestamp() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IOrientationSensorReading)->get_Timestamp(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sensors::SensorRotationMatrix consume_Windows_Devices_Sensors_IOrientationSensorReading<D>::RotationMatrix() const
{
    Windows::Devices::Sensors::SensorRotationMatrix value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IOrientationSensorReading)->get_RotationMatrix(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sensors::SensorQuaternion consume_Windows_Devices_Sensors_IOrientationSensorReading<D>::Quaternion() const
{
    Windows::Devices::Sensors::SensorQuaternion value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IOrientationSensorReading)->get_Quaternion(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::TimeSpan> consume_Windows_Devices_Sensors_IOrientationSensorReading2<D>::PerformanceCount() const
{
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IOrientationSensorReading2)->get_PerformanceCount(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable> consume_Windows_Devices_Sensors_IOrientationSensorReading2<D>::Properties() const
{
    Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IOrientationSensorReading2)->get_Properties(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sensors::OrientationSensorReading consume_Windows_Devices_Sensors_IOrientationSensorReadingChangedEventArgs<D>::Reading() const
{
    Windows::Devices::Sensors::OrientationSensorReading value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IOrientationSensorReadingChangedEventArgs)->get_Reading(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sensors::MagnetometerAccuracy consume_Windows_Devices_Sensors_IOrientationSensorReadingYawAccuracy<D>::YawAccuracy() const
{
    Windows::Devices::Sensors::MagnetometerAccuracy value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IOrientationSensorReadingYawAccuracy)->get_YawAccuracy(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sensors::OrientationSensor consume_Windows_Devices_Sensors_IOrientationSensorStatics<D>::GetDefault() const
{
    Windows::Devices::Sensors::OrientationSensor result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IOrientationSensorStatics)->GetDefault(put_abi(result)));
    return result;
}

template <typename D> Windows::Devices::Sensors::OrientationSensor consume_Windows_Devices_Sensors_IOrientationSensorStatics2<D>::GetDefaultForRelativeReadings() const
{
    Windows::Devices::Sensors::OrientationSensor result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IOrientationSensorStatics2)->GetDefaultForRelativeReadings(put_abi(result)));
    return result;
}

template <typename D> Windows::Devices::Sensors::OrientationSensor consume_Windows_Devices_Sensors_IOrientationSensorStatics3<D>::GetDefault(Windows::Devices::Sensors::SensorReadingType const& sensorReadingtype) const
{
    Windows::Devices::Sensors::OrientationSensor result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IOrientationSensorStatics3)->GetDefaultWithSensorReadingType(get_abi(sensorReadingtype), put_abi(result)));
    return result;
}

template <typename D> Windows::Devices::Sensors::OrientationSensor consume_Windows_Devices_Sensors_IOrientationSensorStatics3<D>::GetDefault(Windows::Devices::Sensors::SensorReadingType const& sensorReadingType, Windows::Devices::Sensors::SensorOptimizationGoal const& optimizationGoal) const
{
    Windows::Devices::Sensors::OrientationSensor result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IOrientationSensorStatics3)->GetDefaultWithSensorReadingTypeAndSensorOptimizationGoal(get_abi(sensorReadingType), get_abi(optimizationGoal), put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Devices_Sensors_IOrientationSensorStatics4<D>::GetDeviceSelector(Windows::Devices::Sensors::SensorReadingType const& readingType) const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IOrientationSensorStatics4)->GetDeviceSelector(get_abi(readingType), put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Devices_Sensors_IOrientationSensorStatics4<D>::GetDeviceSelector(Windows::Devices::Sensors::SensorReadingType const& readingType, Windows::Devices::Sensors::SensorOptimizationGoal const& optimizationGoal) const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IOrientationSensorStatics4)->GetDeviceSelectorWithSensorReadingTypeAndSensorOptimizationGoal(get_abi(readingType), get_abi(optimizationGoal), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::OrientationSensor> consume_Windows_Devices_Sensors_IOrientationSensorStatics4<D>::FromIdAsync(param::hstring const& deviceId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::OrientationSensor> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IOrientationSensorStatics4)->FromIdAsync(get_abi(deviceId), put_abi(operation)));
    return operation;
}

template <typename D> hstring consume_Windows_Devices_Sensors_IPedometer<D>::DeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IPedometer)->get_DeviceId(put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_Devices_Sensors_IPedometer<D>::PowerInMilliwatts() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IPedometer)->get_PowerInMilliwatts(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_Sensors_IPedometer<D>::MinimumReportInterval() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IPedometer)->get_MinimumReportInterval(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_Sensors_IPedometer<D>::ReportInterval(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IPedometer)->put_ReportInterval(value));
}

template <typename D> uint32_t consume_Windows_Devices_Sensors_IPedometer<D>::ReportInterval() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IPedometer)->get_ReportInterval(&value));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Devices_Sensors_IPedometer<D>::ReadingChanged(Windows::Foundation::TypedEventHandler<Windows::Devices::Sensors::Pedometer, Windows::Devices::Sensors::PedometerReadingChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IPedometer)->add_ReadingChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Sensors_IPedometer<D>::ReadingChanged_revoker consume_Windows_Devices_Sensors_IPedometer<D>::ReadingChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Sensors::Pedometer, Windows::Devices::Sensors::PedometerReadingChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ReadingChanged_revoker>(this, ReadingChanged(handler));
}

template <typename D> void consume_Windows_Devices_Sensors_IPedometer<D>::ReadingChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Sensors::IPedometer)->remove_ReadingChanged(get_abi(token)));
}

template <typename D> Windows::Foundation::Collections::IMapView<Windows::Devices::Sensors::PedometerStepKind, Windows::Devices::Sensors::PedometerReading> consume_Windows_Devices_Sensors_IPedometer2<D>::GetCurrentReadings() const
{
    Windows::Foundation::Collections::IMapView<Windows::Devices::Sensors::PedometerStepKind, Windows::Devices::Sensors::PedometerReading> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IPedometer2)->GetCurrentReadings(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sensors::PedometerDataThreshold consume_Windows_Devices_Sensors_IPedometerDataThresholdFactory<D>::Create(Windows::Devices::Sensors::Pedometer const& sensor, int32_t stepGoal) const
{
    Windows::Devices::Sensors::PedometerDataThreshold threshold{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IPedometerDataThresholdFactory)->Create(get_abi(sensor), stepGoal, put_abi(threshold)));
    return threshold;
}

template <typename D> Windows::Devices::Sensors::PedometerStepKind consume_Windows_Devices_Sensors_IPedometerReading<D>::StepKind() const
{
    Windows::Devices::Sensors::PedometerStepKind value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IPedometerReading)->get_StepKind(put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_Devices_Sensors_IPedometerReading<D>::CumulativeSteps() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IPedometerReading)->get_CumulativeSteps(&value));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_Devices_Sensors_IPedometerReading<D>::Timestamp() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IPedometerReading)->get_Timestamp(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Devices_Sensors_IPedometerReading<D>::CumulativeStepsDuration() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IPedometerReading)->get_CumulativeStepsDuration(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sensors::PedometerReading consume_Windows_Devices_Sensors_IPedometerReadingChangedEventArgs<D>::Reading() const
{
    Windows::Devices::Sensors::PedometerReading value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IPedometerReadingChangedEventArgs)->get_Reading(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::Pedometer> consume_Windows_Devices_Sensors_IPedometerStatics<D>::FromIdAsync(param::hstring const& deviceId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::Pedometer> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IPedometerStatics)->FromIdAsync(get_abi(deviceId), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::Pedometer> consume_Windows_Devices_Sensors_IPedometerStatics<D>::GetDefaultAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::Pedometer> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IPedometerStatics)->GetDefaultAsync(put_abi(operation)));
    return operation;
}

template <typename D> hstring consume_Windows_Devices_Sensors_IPedometerStatics<D>::GetDeviceSelector() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IPedometerStatics)->GetDeviceSelector(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Sensors::PedometerReading>> consume_Windows_Devices_Sensors_IPedometerStatics<D>::GetSystemHistoryAsync(Windows::Foundation::DateTime const& fromTime) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Sensors::PedometerReading>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IPedometerStatics)->GetSystemHistoryAsync(get_abi(fromTime), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Sensors::PedometerReading>> consume_Windows_Devices_Sensors_IPedometerStatics<D>::GetSystemHistoryAsync(Windows::Foundation::DateTime const& fromTime, Windows::Foundation::TimeSpan const& duration) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Sensors::PedometerReading>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IPedometerStatics)->GetSystemHistoryWithDurationAsync(get_abi(fromTime), get_abi(duration), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::Sensors::PedometerReading> consume_Windows_Devices_Sensors_IPedometerStatics2<D>::GetReadingsFromTriggerDetails(Windows::Devices::Sensors::SensorDataThresholdTriggerDetails const& triggerDetails) const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Sensors::PedometerReading> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IPedometerStatics2)->GetReadingsFromTriggerDetails(get_abi(triggerDetails), put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Devices_Sensors_IProximitySensor<D>::DeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IProximitySensor)->get_DeviceId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<uint32_t> consume_Windows_Devices_Sensors_IProximitySensor<D>::MaxDistanceInMillimeters() const
{
    Windows::Foundation::IReference<uint32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IProximitySensor)->get_MaxDistanceInMillimeters(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<uint32_t> consume_Windows_Devices_Sensors_IProximitySensor<D>::MinDistanceInMillimeters() const
{
    Windows::Foundation::IReference<uint32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IProximitySensor)->get_MinDistanceInMillimeters(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sensors::ProximitySensorReading consume_Windows_Devices_Sensors_IProximitySensor<D>::GetCurrentReading() const
{
    Windows::Devices::Sensors::ProximitySensorReading value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IProximitySensor)->GetCurrentReading(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Devices_Sensors_IProximitySensor<D>::ReadingChanged(Windows::Foundation::TypedEventHandler<Windows::Devices::Sensors::ProximitySensor, Windows::Devices::Sensors::ProximitySensorReadingChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IProximitySensor)->add_ReadingChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Sensors_IProximitySensor<D>::ReadingChanged_revoker consume_Windows_Devices_Sensors_IProximitySensor<D>::ReadingChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Sensors::ProximitySensor, Windows::Devices::Sensors::ProximitySensorReadingChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ReadingChanged_revoker>(this, ReadingChanged(handler));
}

template <typename D> void consume_Windows_Devices_Sensors_IProximitySensor<D>::ReadingChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Sensors::IProximitySensor)->remove_ReadingChanged(get_abi(token)));
}

template <typename D> Windows::Devices::Sensors::ProximitySensorDisplayOnOffController consume_Windows_Devices_Sensors_IProximitySensor<D>::CreateDisplayOnOffController() const
{
    Windows::Devices::Sensors::ProximitySensorDisplayOnOffController controller{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IProximitySensor)->CreateDisplayOnOffController(put_abi(controller)));
    return controller;
}

template <typename D> Windows::Devices::Sensors::ProximitySensorDataThreshold consume_Windows_Devices_Sensors_IProximitySensorDataThresholdFactory<D>::Create(Windows::Devices::Sensors::ProximitySensor const& sensor) const
{
    Windows::Devices::Sensors::ProximitySensorDataThreshold threshold{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IProximitySensorDataThresholdFactory)->Create(get_abi(sensor), put_abi(threshold)));
    return threshold;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_Devices_Sensors_IProximitySensorReading<D>::Timestamp() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IProximitySensorReading)->get_Timestamp(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Devices_Sensors_IProximitySensorReading<D>::IsDetected() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IProximitySensorReading)->get_IsDetected(&value));
    return value;
}

template <typename D> Windows::Foundation::IReference<uint32_t> consume_Windows_Devices_Sensors_IProximitySensorReading<D>::DistanceInMillimeters() const
{
    Windows::Foundation::IReference<uint32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IProximitySensorReading)->get_DistanceInMillimeters(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sensors::ProximitySensorReading consume_Windows_Devices_Sensors_IProximitySensorReadingChangedEventArgs<D>::Reading() const
{
    Windows::Devices::Sensors::ProximitySensorReading value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IProximitySensorReadingChangedEventArgs)->get_Reading(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Sensors_IProximitySensorStatics<D>::GetDeviceSelector() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IProximitySensorStatics)->GetDeviceSelector(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sensors::ProximitySensor consume_Windows_Devices_Sensors_IProximitySensorStatics<D>::FromId(param::hstring const& sensorId) const
{
    Windows::Devices::Sensors::ProximitySensor result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IProximitySensorStatics)->FromId(get_abi(sensorId), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::Sensors::ProximitySensorReading> consume_Windows_Devices_Sensors_IProximitySensorStatics2<D>::GetReadingsFromTriggerDetails(Windows::Devices::Sensors::SensorDataThresholdTriggerDetails const& triggerDetails) const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Sensors::ProximitySensorReading> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::IProximitySensorStatics2)->GetReadingsFromTriggerDetails(get_abi(triggerDetails), put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Devices_Sensors_ISensorDataThresholdTriggerDetails<D>::DeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::ISensorDataThresholdTriggerDetails)->get_DeviceId(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sensors::SensorType consume_Windows_Devices_Sensors_ISensorDataThresholdTriggerDetails<D>::SensorType() const
{
    Windows::Devices::Sensors::SensorType value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::ISensorDataThresholdTriggerDetails)->get_SensorType(put_abi(value)));
    return value;
}

template <typename D> float consume_Windows_Devices_Sensors_ISensorQuaternion<D>::W() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::ISensorQuaternion)->get_W(&value));
    return value;
}

template <typename D> float consume_Windows_Devices_Sensors_ISensorQuaternion<D>::X() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::ISensorQuaternion)->get_X(&value));
    return value;
}

template <typename D> float consume_Windows_Devices_Sensors_ISensorQuaternion<D>::Y() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::ISensorQuaternion)->get_Y(&value));
    return value;
}

template <typename D> float consume_Windows_Devices_Sensors_ISensorQuaternion<D>::Z() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::ISensorQuaternion)->get_Z(&value));
    return value;
}

template <typename D> float consume_Windows_Devices_Sensors_ISensorRotationMatrix<D>::M11() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::ISensorRotationMatrix)->get_M11(&value));
    return value;
}

template <typename D> float consume_Windows_Devices_Sensors_ISensorRotationMatrix<D>::M12() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::ISensorRotationMatrix)->get_M12(&value));
    return value;
}

template <typename D> float consume_Windows_Devices_Sensors_ISensorRotationMatrix<D>::M13() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::ISensorRotationMatrix)->get_M13(&value));
    return value;
}

template <typename D> float consume_Windows_Devices_Sensors_ISensorRotationMatrix<D>::M21() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::ISensorRotationMatrix)->get_M21(&value));
    return value;
}

template <typename D> float consume_Windows_Devices_Sensors_ISensorRotationMatrix<D>::M22() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::ISensorRotationMatrix)->get_M22(&value));
    return value;
}

template <typename D> float consume_Windows_Devices_Sensors_ISensorRotationMatrix<D>::M23() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::ISensorRotationMatrix)->get_M23(&value));
    return value;
}

template <typename D> float consume_Windows_Devices_Sensors_ISensorRotationMatrix<D>::M31() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::ISensorRotationMatrix)->get_M31(&value));
    return value;
}

template <typename D> float consume_Windows_Devices_Sensors_ISensorRotationMatrix<D>::M32() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::ISensorRotationMatrix)->get_M32(&value));
    return value;
}

template <typename D> float consume_Windows_Devices_Sensors_ISensorRotationMatrix<D>::M33() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::ISensorRotationMatrix)->get_M33(&value));
    return value;
}

template <typename D> Windows::Devices::Sensors::SimpleOrientation consume_Windows_Devices_Sensors_ISimpleOrientationSensor<D>::GetCurrentOrientation() const
{
    Windows::Devices::Sensors::SimpleOrientation value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::ISimpleOrientationSensor)->GetCurrentOrientation(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Devices_Sensors_ISimpleOrientationSensor<D>::OrientationChanged(Windows::Foundation::TypedEventHandler<Windows::Devices::Sensors::SimpleOrientationSensor, Windows::Devices::Sensors::SimpleOrientationSensorOrientationChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::ISimpleOrientationSensor)->add_OrientationChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Sensors_ISimpleOrientationSensor<D>::OrientationChanged_revoker consume_Windows_Devices_Sensors_ISimpleOrientationSensor<D>::OrientationChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Sensors::SimpleOrientationSensor, Windows::Devices::Sensors::SimpleOrientationSensorOrientationChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, OrientationChanged_revoker>(this, OrientationChanged(handler));
}

template <typename D> void consume_Windows_Devices_Sensors_ISimpleOrientationSensor<D>::OrientationChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Sensors::ISimpleOrientationSensor)->remove_OrientationChanged(get_abi(token)));
}

template <typename D> void consume_Windows_Devices_Sensors_ISimpleOrientationSensor2<D>::ReadingTransform(Windows::Graphics::Display::DisplayOrientations const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::ISimpleOrientationSensor2)->put_ReadingTransform(get_abi(value)));
}

template <typename D> Windows::Graphics::Display::DisplayOrientations consume_Windows_Devices_Sensors_ISimpleOrientationSensor2<D>::ReadingTransform() const
{
    Windows::Graphics::Display::DisplayOrientations value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::ISimpleOrientationSensor2)->get_ReadingTransform(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Sensors_ISimpleOrientationSensorDeviceId<D>::DeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::ISimpleOrientationSensorDeviceId)->get_DeviceId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_Devices_Sensors_ISimpleOrientationSensorOrientationChangedEventArgs<D>::Timestamp() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::ISimpleOrientationSensorOrientationChangedEventArgs)->get_Timestamp(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sensors::SimpleOrientation consume_Windows_Devices_Sensors_ISimpleOrientationSensorOrientationChangedEventArgs<D>::Orientation() const
{
    Windows::Devices::Sensors::SimpleOrientation value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::ISimpleOrientationSensorOrientationChangedEventArgs)->get_Orientation(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Sensors::SimpleOrientationSensor consume_Windows_Devices_Sensors_ISimpleOrientationSensorStatics<D>::GetDefault() const
{
    Windows::Devices::Sensors::SimpleOrientationSensor result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::ISimpleOrientationSensorStatics)->GetDefault(put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Devices_Sensors_ISimpleOrientationSensorStatics2<D>::GetDeviceSelector() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::ISimpleOrientationSensorStatics2)->GetDeviceSelector(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::SimpleOrientationSensor> consume_Windows_Devices_Sensors_ISimpleOrientationSensorStatics2<D>::FromIdAsync(param::hstring const& deviceId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::SimpleOrientationSensor> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Sensors::ISimpleOrientationSensorStatics2)->FromIdAsync(get_abi(deviceId), put_abi(result)));
    return result;
}

template <typename D>
struct produce<D, Windows::Devices::Sensors::IAccelerometer> : produce_base<D, Windows::Devices::Sensors::IAccelerometer>
{
    int32_t WINRT_CALL GetCurrentReading(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCurrentReading, WINRT_WRAP(Windows::Devices::Sensors::AccelerometerReading));
            *value = detach_from<Windows::Devices::Sensors::AccelerometerReading>(this->shim().GetCurrentReading());
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

    int32_t WINRT_CALL add_ReadingChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadingChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Sensors::Accelerometer, Windows::Devices::Sensors::AccelerometerReadingChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ReadingChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Sensors::Accelerometer, Windows::Devices::Sensors::AccelerometerReadingChangedEventArgs> const*>(&handler)));
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

    int32_t WINRT_CALL add_Shaken(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Shaken, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Sensors::Accelerometer, Windows::Devices::Sensors::AccelerometerShakenEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Shaken(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Sensors::Accelerometer, Windows::Devices::Sensors::AccelerometerShakenEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Shaken(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Shaken, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Shaken(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::IAccelerometer2> : produce_base<D, Windows::Devices::Sensors::IAccelerometer2>
{
    int32_t WINRT_CALL put_ReadingTransform(Windows::Graphics::Display::DisplayOrientations value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadingTransform, WINRT_WRAP(void), Windows::Graphics::Display::DisplayOrientations const&);
            this->shim().ReadingTransform(*reinterpret_cast<Windows::Graphics::Display::DisplayOrientations const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ReadingTransform(Windows::Graphics::Display::DisplayOrientations* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadingTransform, WINRT_WRAP(Windows::Graphics::Display::DisplayOrientations));
            *value = detach_from<Windows::Graphics::Display::DisplayOrientations>(this->shim().ReadingTransform());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::IAccelerometer3> : produce_base<D, Windows::Devices::Sensors::IAccelerometer3>
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
struct produce<D, Windows::Devices::Sensors::IAccelerometer4> : produce_base<D, Windows::Devices::Sensors::IAccelerometer4>
{
    int32_t WINRT_CALL get_ReadingType(Windows::Devices::Sensors::AccelerometerReadingType* type) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadingType, WINRT_WRAP(Windows::Devices::Sensors::AccelerometerReadingType));
            *type = detach_from<Windows::Devices::Sensors::AccelerometerReadingType>(this->shim().ReadingType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::IAccelerometerDeviceId> : produce_base<D, Windows::Devices::Sensors::IAccelerometerDeviceId>
{
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
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::IAccelerometerReading> : produce_base<D, Windows::Devices::Sensors::IAccelerometerReading>
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

    int32_t WINRT_CALL get_AccelerationX(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AccelerationX, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().AccelerationX());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AccelerationY(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AccelerationY, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().AccelerationY());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AccelerationZ(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AccelerationZ, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().AccelerationZ());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::IAccelerometerReading2> : produce_base<D, Windows::Devices::Sensors::IAccelerometerReading2>
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
struct produce<D, Windows::Devices::Sensors::IAccelerometerReadingChangedEventArgs> : produce_base<D, Windows::Devices::Sensors::IAccelerometerReadingChangedEventArgs>
{
    int32_t WINRT_CALL get_Reading(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Reading, WINRT_WRAP(Windows::Devices::Sensors::AccelerometerReading));
            *value = detach_from<Windows::Devices::Sensors::AccelerometerReading>(this->shim().Reading());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::IAccelerometerShakenEventArgs> : produce_base<D, Windows::Devices::Sensors::IAccelerometerShakenEventArgs>
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
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::IAccelerometerStatics> : produce_base<D, Windows::Devices::Sensors::IAccelerometerStatics>
{
    int32_t WINRT_CALL GetDefault(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefault, WINRT_WRAP(Windows::Devices::Sensors::Accelerometer));
            *result = detach_from<Windows::Devices::Sensors::Accelerometer>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::IAccelerometerStatics2> : produce_base<D, Windows::Devices::Sensors::IAccelerometerStatics2>
{
    int32_t WINRT_CALL GetDefaultWithAccelerometerReadingType(Windows::Devices::Sensors::AccelerometerReadingType readingType, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefault, WINRT_WRAP(Windows::Devices::Sensors::Accelerometer), Windows::Devices::Sensors::AccelerometerReadingType const&);
            *result = detach_from<Windows::Devices::Sensors::Accelerometer>(this->shim().GetDefault(*reinterpret_cast<Windows::Devices::Sensors::AccelerometerReadingType const*>(&readingType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::IAccelerometerStatics3> : produce_base<D, Windows::Devices::Sensors::IAccelerometerStatics3>
{
    int32_t WINRT_CALL FromIdAsync(void* deviceId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::Accelerometer>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::Accelerometer>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeviceSelector(Windows::Devices::Sensors::AccelerometerReadingType readingType, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelector, WINRT_WRAP(hstring), Windows::Devices::Sensors::AccelerometerReadingType const&);
            *result = detach_from<hstring>(this->shim().GetDeviceSelector(*reinterpret_cast<Windows::Devices::Sensors::AccelerometerReadingType const*>(&readingType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::IActivitySensor> : produce_base<D, Windows::Devices::Sensors::IActivitySensor>
{
    int32_t WINRT_CALL GetCurrentReadingAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCurrentReadingAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::ActivitySensorReading>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::ActivitySensorReading>>(this->shim().GetCurrentReadingAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SubscribedActivities(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SubscribedActivities, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::Devices::Sensors::ActivityType>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::Devices::Sensors::ActivityType>>(this->shim().SubscribedActivities());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PowerInMilliwatts(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PowerInMilliwatts, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().PowerInMilliwatts());
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

    int32_t WINRT_CALL get_SupportedActivities(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedActivities, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::Sensors::ActivityType>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::Sensors::ActivityType>>(this->shim().SupportedActivities());
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

    int32_t WINRT_CALL add_ReadingChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadingChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Sensors::ActivitySensor, Windows::Devices::Sensors::ActivitySensorReadingChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ReadingChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Sensors::ActivitySensor, Windows::Devices::Sensors::ActivitySensorReadingChangedEventArgs> const*>(&handler)));
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
struct produce<D, Windows::Devices::Sensors::IActivitySensorReading> : produce_base<D, Windows::Devices::Sensors::IActivitySensorReading>
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

    int32_t WINRT_CALL get_Activity(Windows::Devices::Sensors::ActivityType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Activity, WINRT_WRAP(Windows::Devices::Sensors::ActivityType));
            *value = detach_from<Windows::Devices::Sensors::ActivityType>(this->shim().Activity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Confidence(Windows::Devices::Sensors::ActivitySensorReadingConfidence* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Confidence, WINRT_WRAP(Windows::Devices::Sensors::ActivitySensorReadingConfidence));
            *value = detach_from<Windows::Devices::Sensors::ActivitySensorReadingConfidence>(this->shim().Confidence());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::IActivitySensorReadingChangeReport> : produce_base<D, Windows::Devices::Sensors::IActivitySensorReadingChangeReport>
{
    int32_t WINRT_CALL get_Reading(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Reading, WINRT_WRAP(Windows::Devices::Sensors::ActivitySensorReading));
            *value = detach_from<Windows::Devices::Sensors::ActivitySensorReading>(this->shim().Reading());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::IActivitySensorReadingChangedEventArgs> : produce_base<D, Windows::Devices::Sensors::IActivitySensorReadingChangedEventArgs>
{
    int32_t WINRT_CALL get_Reading(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Reading, WINRT_WRAP(Windows::Devices::Sensors::ActivitySensorReading));
            *value = detach_from<Windows::Devices::Sensors::ActivitySensorReading>(this->shim().Reading());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::IActivitySensorStatics> : produce_base<D, Windows::Devices::Sensors::IActivitySensorStatics>
{
    int32_t WINRT_CALL GetDefaultAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefaultAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::ActivitySensor>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::ActivitySensor>>(this->shim().GetDefaultAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeviceSelector(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelector, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().GetDeviceSelector());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FromIdAsync(void* deviceId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::ActivitySensor>), hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::ActivitySensor>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetSystemHistoryAsync(Windows::Foundation::DateTime fromTime, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetSystemHistoryAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Sensors::ActivitySensorReading>>), Windows::Foundation::DateTime const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Sensors::ActivitySensorReading>>>(this->shim().GetSystemHistoryAsync(*reinterpret_cast<Windows::Foundation::DateTime const*>(&fromTime)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetSystemHistoryWithDurationAsync(Windows::Foundation::DateTime fromTime, Windows::Foundation::TimeSpan duration, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetSystemHistoryAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Sensors::ActivitySensorReading>>), Windows::Foundation::DateTime const, Windows::Foundation::TimeSpan const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Sensors::ActivitySensorReading>>>(this->shim().GetSystemHistoryAsync(*reinterpret_cast<Windows::Foundation::DateTime const*>(&fromTime), *reinterpret_cast<Windows::Foundation::TimeSpan const*>(&duration)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::IActivitySensorTriggerDetails> : produce_base<D, Windows::Devices::Sensors::IActivitySensorTriggerDetails>
{
    int32_t WINRT_CALL ReadReports(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadReports, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::Sensors::ActivitySensorReadingChangeReport>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::Sensors::ActivitySensorReadingChangeReport>>(this->shim().ReadReports());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::IAltimeter> : produce_base<D, Windows::Devices::Sensors::IAltimeter>
{
    int32_t WINRT_CALL GetCurrentReading(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCurrentReading, WINRT_WRAP(Windows::Devices::Sensors::AltimeterReading));
            *value = detach_from<Windows::Devices::Sensors::AltimeterReading>(this->shim().GetCurrentReading());
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

    int32_t WINRT_CALL add_ReadingChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadingChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Sensors::Altimeter, Windows::Devices::Sensors::AltimeterReadingChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ReadingChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Sensors::Altimeter, Windows::Devices::Sensors::AltimeterReadingChangedEventArgs> const*>(&handler)));
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
struct produce<D, Windows::Devices::Sensors::IAltimeter2> : produce_base<D, Windows::Devices::Sensors::IAltimeter2>
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
struct produce<D, Windows::Devices::Sensors::IAltimeterReading> : produce_base<D, Windows::Devices::Sensors::IAltimeterReading>
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

    int32_t WINRT_CALL get_AltitudeChangeInMeters(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AltitudeChangeInMeters, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().AltitudeChangeInMeters());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::IAltimeterReading2> : produce_base<D, Windows::Devices::Sensors::IAltimeterReading2>
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
struct produce<D, Windows::Devices::Sensors::IAltimeterReadingChangedEventArgs> : produce_base<D, Windows::Devices::Sensors::IAltimeterReadingChangedEventArgs>
{
    int32_t WINRT_CALL get_Reading(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Reading, WINRT_WRAP(Windows::Devices::Sensors::AltimeterReading));
            *value = detach_from<Windows::Devices::Sensors::AltimeterReading>(this->shim().Reading());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::IAltimeterStatics> : produce_base<D, Windows::Devices::Sensors::IAltimeterStatics>
{
    int32_t WINRT_CALL GetDefault(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefault, WINRT_WRAP(Windows::Devices::Sensors::Altimeter));
            *result = detach_from<Windows::Devices::Sensors::Altimeter>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::IBarometer> : produce_base<D, Windows::Devices::Sensors::IBarometer>
{
    int32_t WINRT_CALL GetCurrentReading(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCurrentReading, WINRT_WRAP(Windows::Devices::Sensors::BarometerReading));
            *value = detach_from<Windows::Devices::Sensors::BarometerReading>(this->shim().GetCurrentReading());
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

    int32_t WINRT_CALL add_ReadingChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadingChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Sensors::Barometer, Windows::Devices::Sensors::BarometerReadingChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ReadingChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Sensors::Barometer, Windows::Devices::Sensors::BarometerReadingChangedEventArgs> const*>(&handler)));
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
struct produce<D, Windows::Devices::Sensors::IBarometer2> : produce_base<D, Windows::Devices::Sensors::IBarometer2>
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
struct produce<D, Windows::Devices::Sensors::IBarometerReading> : produce_base<D, Windows::Devices::Sensors::IBarometerReading>
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

    int32_t WINRT_CALL get_StationPressureInHectopascals(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StationPressureInHectopascals, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().StationPressureInHectopascals());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::IBarometerReading2> : produce_base<D, Windows::Devices::Sensors::IBarometerReading2>
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
struct produce<D, Windows::Devices::Sensors::IBarometerReadingChangedEventArgs> : produce_base<D, Windows::Devices::Sensors::IBarometerReadingChangedEventArgs>
{
    int32_t WINRT_CALL get_Reading(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Reading, WINRT_WRAP(Windows::Devices::Sensors::BarometerReading));
            *value = detach_from<Windows::Devices::Sensors::BarometerReading>(this->shim().Reading());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::IBarometerStatics> : produce_base<D, Windows::Devices::Sensors::IBarometerStatics>
{
    int32_t WINRT_CALL GetDefault(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefault, WINRT_WRAP(Windows::Devices::Sensors::Barometer));
            *result = detach_from<Windows::Devices::Sensors::Barometer>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::IBarometerStatics2> : produce_base<D, Windows::Devices::Sensors::IBarometerStatics2>
{
    int32_t WINRT_CALL FromIdAsync(void* deviceId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::Barometer>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::Barometer>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeviceSelector(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelector, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().GetDeviceSelector());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::ICompass> : produce_base<D, Windows::Devices::Sensors::ICompass>
{
    int32_t WINRT_CALL GetCurrentReading(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCurrentReading, WINRT_WRAP(Windows::Devices::Sensors::CompassReading));
            *value = detach_from<Windows::Devices::Sensors::CompassReading>(this->shim().GetCurrentReading());
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

    int32_t WINRT_CALL add_ReadingChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadingChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Sensors::Compass, Windows::Devices::Sensors::CompassReadingChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ReadingChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Sensors::Compass, Windows::Devices::Sensors::CompassReadingChangedEventArgs> const*>(&handler)));
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
struct produce<D, Windows::Devices::Sensors::ICompass2> : produce_base<D, Windows::Devices::Sensors::ICompass2>
{
    int32_t WINRT_CALL put_ReadingTransform(Windows::Graphics::Display::DisplayOrientations value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadingTransform, WINRT_WRAP(void), Windows::Graphics::Display::DisplayOrientations const&);
            this->shim().ReadingTransform(*reinterpret_cast<Windows::Graphics::Display::DisplayOrientations const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ReadingTransform(Windows::Graphics::Display::DisplayOrientations* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadingTransform, WINRT_WRAP(Windows::Graphics::Display::DisplayOrientations));
            *value = detach_from<Windows::Graphics::Display::DisplayOrientations>(this->shim().ReadingTransform());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::ICompass3> : produce_base<D, Windows::Devices::Sensors::ICompass3>
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
struct produce<D, Windows::Devices::Sensors::ICompassDeviceId> : produce_base<D, Windows::Devices::Sensors::ICompassDeviceId>
{
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
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::ICompassReading> : produce_base<D, Windows::Devices::Sensors::ICompassReading>
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

    int32_t WINRT_CALL get_HeadingMagneticNorth(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HeadingMagneticNorth, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().HeadingMagneticNorth());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HeadingTrueNorth(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HeadingTrueNorth, WINRT_WRAP(Windows::Foundation::IReference<double>));
            *value = detach_from<Windows::Foundation::IReference<double>>(this->shim().HeadingTrueNorth());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::ICompassReading2> : produce_base<D, Windows::Devices::Sensors::ICompassReading2>
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
struct produce<D, Windows::Devices::Sensors::ICompassReadingChangedEventArgs> : produce_base<D, Windows::Devices::Sensors::ICompassReadingChangedEventArgs>
{
    int32_t WINRT_CALL get_Reading(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Reading, WINRT_WRAP(Windows::Devices::Sensors::CompassReading));
            *value = detach_from<Windows::Devices::Sensors::CompassReading>(this->shim().Reading());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::ICompassReadingHeadingAccuracy> : produce_base<D, Windows::Devices::Sensors::ICompassReadingHeadingAccuracy>
{
    int32_t WINRT_CALL get_HeadingAccuracy(Windows::Devices::Sensors::MagnetometerAccuracy* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HeadingAccuracy, WINRT_WRAP(Windows::Devices::Sensors::MagnetometerAccuracy));
            *value = detach_from<Windows::Devices::Sensors::MagnetometerAccuracy>(this->shim().HeadingAccuracy());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::ICompassStatics> : produce_base<D, Windows::Devices::Sensors::ICompassStatics>
{
    int32_t WINRT_CALL GetDefault(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefault, WINRT_WRAP(Windows::Devices::Sensors::Compass));
            *result = detach_from<Windows::Devices::Sensors::Compass>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::ICompassStatics2> : produce_base<D, Windows::Devices::Sensors::ICompassStatics2>
{
    int32_t WINRT_CALL GetDeviceSelector(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelector, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().GetDeviceSelector());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FromIdAsync(void* deviceId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::Compass>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::Compass>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::IGyrometer> : produce_base<D, Windows::Devices::Sensors::IGyrometer>
{
    int32_t WINRT_CALL GetCurrentReading(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCurrentReading, WINRT_WRAP(Windows::Devices::Sensors::GyrometerReading));
            *value = detach_from<Windows::Devices::Sensors::GyrometerReading>(this->shim().GetCurrentReading());
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

    int32_t WINRT_CALL add_ReadingChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadingChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Sensors::Gyrometer, Windows::Devices::Sensors::GyrometerReadingChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ReadingChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Sensors::Gyrometer, Windows::Devices::Sensors::GyrometerReadingChangedEventArgs> const*>(&handler)));
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
struct produce<D, Windows::Devices::Sensors::IGyrometer2> : produce_base<D, Windows::Devices::Sensors::IGyrometer2>
{
    int32_t WINRT_CALL put_ReadingTransform(Windows::Graphics::Display::DisplayOrientations value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadingTransform, WINRT_WRAP(void), Windows::Graphics::Display::DisplayOrientations const&);
            this->shim().ReadingTransform(*reinterpret_cast<Windows::Graphics::Display::DisplayOrientations const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ReadingTransform(Windows::Graphics::Display::DisplayOrientations* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadingTransform, WINRT_WRAP(Windows::Graphics::Display::DisplayOrientations));
            *value = detach_from<Windows::Graphics::Display::DisplayOrientations>(this->shim().ReadingTransform());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::IGyrometer3> : produce_base<D, Windows::Devices::Sensors::IGyrometer3>
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
struct produce<D, Windows::Devices::Sensors::IGyrometerDeviceId> : produce_base<D, Windows::Devices::Sensors::IGyrometerDeviceId>
{
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
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::IGyrometerReading> : produce_base<D, Windows::Devices::Sensors::IGyrometerReading>
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

    int32_t WINRT_CALL get_AngularVelocityX(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AngularVelocityX, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().AngularVelocityX());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AngularVelocityY(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AngularVelocityY, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().AngularVelocityY());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AngularVelocityZ(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AngularVelocityZ, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().AngularVelocityZ());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::IGyrometerReading2> : produce_base<D, Windows::Devices::Sensors::IGyrometerReading2>
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
struct produce<D, Windows::Devices::Sensors::IGyrometerReadingChangedEventArgs> : produce_base<D, Windows::Devices::Sensors::IGyrometerReadingChangedEventArgs>
{
    int32_t WINRT_CALL get_Reading(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Reading, WINRT_WRAP(Windows::Devices::Sensors::GyrometerReading));
            *value = detach_from<Windows::Devices::Sensors::GyrometerReading>(this->shim().Reading());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::IGyrometerStatics> : produce_base<D, Windows::Devices::Sensors::IGyrometerStatics>
{
    int32_t WINRT_CALL GetDefault(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefault, WINRT_WRAP(Windows::Devices::Sensors::Gyrometer));
            *result = detach_from<Windows::Devices::Sensors::Gyrometer>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::IGyrometerStatics2> : produce_base<D, Windows::Devices::Sensors::IGyrometerStatics2>
{
    int32_t WINRT_CALL GetDeviceSelector(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelector, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().GetDeviceSelector());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FromIdAsync(void* deviceId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::Gyrometer>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::Gyrometer>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::IHingeAngleReading> : produce_base<D, Windows::Devices::Sensors::IHingeAngleReading>
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

    int32_t WINRT_CALL get_AngleInDegrees(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AngleInDegrees, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().AngleInDegrees());
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
struct produce<D, Windows::Devices::Sensors::IHingeAngleSensor> : produce_base<D, Windows::Devices::Sensors::IHingeAngleSensor>
{
    int32_t WINRT_CALL GetCurrentReadingAsync(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCurrentReadingAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::HingeAngleReading>));
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::HingeAngleReading>>(this->shim().GetCurrentReadingAsync());
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

    int32_t WINRT_CALL get_MinReportThresholdInDegrees(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinReportThresholdInDegrees, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().MinReportThresholdInDegrees());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ReportThresholdInDegrees(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportThresholdInDegrees, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().ReportThresholdInDegrees());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ReportThresholdInDegrees(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportThresholdInDegrees, WINRT_WRAP(void), double);
            this->shim().ReportThresholdInDegrees(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_ReadingChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadingChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Sensors::HingeAngleSensor, Windows::Devices::Sensors::HingeAngleSensorReadingChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ReadingChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Sensors::HingeAngleSensor, Windows::Devices::Sensors::HingeAngleSensorReadingChangedEventArgs> const*>(&handler)));
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
struct produce<D, Windows::Devices::Sensors::IHingeAngleSensorReadingChangedEventArgs> : produce_base<D, Windows::Devices::Sensors::IHingeAngleSensorReadingChangedEventArgs>
{
    int32_t WINRT_CALL get_Reading(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Reading, WINRT_WRAP(Windows::Devices::Sensors::HingeAngleReading));
            *value = detach_from<Windows::Devices::Sensors::HingeAngleReading>(this->shim().Reading());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::IHingeAngleSensorStatics> : produce_base<D, Windows::Devices::Sensors::IHingeAngleSensorStatics>
{
    int32_t WINRT_CALL GetDeviceSelector(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelector, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().GetDeviceSelector());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDefaultAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefaultAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::HingeAngleSensor>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::HingeAngleSensor>>(this->shim().GetDefaultAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetRelatedToAdjacentPanelsAsync(void* firstPanelId, void* secondPanelId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetRelatedToAdjacentPanelsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::HingeAngleSensor>), hstring const, hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::HingeAngleSensor>>(this->shim().GetRelatedToAdjacentPanelsAsync(*reinterpret_cast<hstring const*>(&firstPanelId), *reinterpret_cast<hstring const*>(&secondPanelId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FromIdAsync(void* deviceId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::HingeAngleSensor>), hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::HingeAngleSensor>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::IInclinometer> : produce_base<D, Windows::Devices::Sensors::IInclinometer>
{
    int32_t WINRT_CALL GetCurrentReading(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCurrentReading, WINRT_WRAP(Windows::Devices::Sensors::InclinometerReading));
            *value = detach_from<Windows::Devices::Sensors::InclinometerReading>(this->shim().GetCurrentReading());
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

    int32_t WINRT_CALL add_ReadingChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadingChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Sensors::Inclinometer, Windows::Devices::Sensors::InclinometerReadingChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ReadingChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Sensors::Inclinometer, Windows::Devices::Sensors::InclinometerReadingChangedEventArgs> const*>(&handler)));
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
struct produce<D, Windows::Devices::Sensors::IInclinometer2> : produce_base<D, Windows::Devices::Sensors::IInclinometer2>
{
    int32_t WINRT_CALL put_ReadingTransform(Windows::Graphics::Display::DisplayOrientations value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadingTransform, WINRT_WRAP(void), Windows::Graphics::Display::DisplayOrientations const&);
            this->shim().ReadingTransform(*reinterpret_cast<Windows::Graphics::Display::DisplayOrientations const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ReadingTransform(Windows::Graphics::Display::DisplayOrientations* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadingTransform, WINRT_WRAP(Windows::Graphics::Display::DisplayOrientations));
            *value = detach_from<Windows::Graphics::Display::DisplayOrientations>(this->shim().ReadingTransform());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ReadingType(Windows::Devices::Sensors::SensorReadingType* type) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadingType, WINRT_WRAP(Windows::Devices::Sensors::SensorReadingType));
            *type = detach_from<Windows::Devices::Sensors::SensorReadingType>(this->shim().ReadingType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::IInclinometer3> : produce_base<D, Windows::Devices::Sensors::IInclinometer3>
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
struct produce<D, Windows::Devices::Sensors::IInclinometerDeviceId> : produce_base<D, Windows::Devices::Sensors::IInclinometerDeviceId>
{
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
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::IInclinometerReading> : produce_base<D, Windows::Devices::Sensors::IInclinometerReading>
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

    int32_t WINRT_CALL get_PitchDegrees(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PitchDegrees, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().PitchDegrees());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RollDegrees(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RollDegrees, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().RollDegrees());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_YawDegrees(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(YawDegrees, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().YawDegrees());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::IInclinometerReading2> : produce_base<D, Windows::Devices::Sensors::IInclinometerReading2>
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
struct produce<D, Windows::Devices::Sensors::IInclinometerReadingChangedEventArgs> : produce_base<D, Windows::Devices::Sensors::IInclinometerReadingChangedEventArgs>
{
    int32_t WINRT_CALL get_Reading(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Reading, WINRT_WRAP(Windows::Devices::Sensors::InclinometerReading));
            *value = detach_from<Windows::Devices::Sensors::InclinometerReading>(this->shim().Reading());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::IInclinometerReadingYawAccuracy> : produce_base<D, Windows::Devices::Sensors::IInclinometerReadingYawAccuracy>
{
    int32_t WINRT_CALL get_YawAccuracy(Windows::Devices::Sensors::MagnetometerAccuracy* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(YawAccuracy, WINRT_WRAP(Windows::Devices::Sensors::MagnetometerAccuracy));
            *value = detach_from<Windows::Devices::Sensors::MagnetometerAccuracy>(this->shim().YawAccuracy());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::IInclinometerStatics> : produce_base<D, Windows::Devices::Sensors::IInclinometerStatics>
{
    int32_t WINRT_CALL GetDefault(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefault, WINRT_WRAP(Windows::Devices::Sensors::Inclinometer));
            *result = detach_from<Windows::Devices::Sensors::Inclinometer>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::IInclinometerStatics2> : produce_base<D, Windows::Devices::Sensors::IInclinometerStatics2>
{
    int32_t WINRT_CALL GetDefaultForRelativeReadings(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefaultForRelativeReadings, WINRT_WRAP(Windows::Devices::Sensors::Inclinometer));
            *result = detach_from<Windows::Devices::Sensors::Inclinometer>(this->shim().GetDefaultForRelativeReadings());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::IInclinometerStatics3> : produce_base<D, Windows::Devices::Sensors::IInclinometerStatics3>
{
    int32_t WINRT_CALL GetDefaultWithSensorReadingType(Windows::Devices::Sensors::SensorReadingType sensorReadingtype, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefault, WINRT_WRAP(Windows::Devices::Sensors::Inclinometer), Windows::Devices::Sensors::SensorReadingType const&);
            *result = detach_from<Windows::Devices::Sensors::Inclinometer>(this->shim().GetDefault(*reinterpret_cast<Windows::Devices::Sensors::SensorReadingType const*>(&sensorReadingtype)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::IInclinometerStatics4> : produce_base<D, Windows::Devices::Sensors::IInclinometerStatics4>
{
    int32_t WINRT_CALL GetDeviceSelector(Windows::Devices::Sensors::SensorReadingType readingType, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelector, WINRT_WRAP(hstring), Windows::Devices::Sensors::SensorReadingType const&);
            *result = detach_from<hstring>(this->shim().GetDeviceSelector(*reinterpret_cast<Windows::Devices::Sensors::SensorReadingType const*>(&readingType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FromIdAsync(void* deviceId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::Inclinometer>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::Inclinometer>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::ILightSensor> : produce_base<D, Windows::Devices::Sensors::ILightSensor>
{
    int32_t WINRT_CALL GetCurrentReading(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCurrentReading, WINRT_WRAP(Windows::Devices::Sensors::LightSensorReading));
            *value = detach_from<Windows::Devices::Sensors::LightSensorReading>(this->shim().GetCurrentReading());
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

    int32_t WINRT_CALL add_ReadingChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadingChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Sensors::LightSensor, Windows::Devices::Sensors::LightSensorReadingChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ReadingChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Sensors::LightSensor, Windows::Devices::Sensors::LightSensorReadingChangedEventArgs> const*>(&handler)));
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
struct produce<D, Windows::Devices::Sensors::ILightSensor2> : produce_base<D, Windows::Devices::Sensors::ILightSensor2>
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
struct produce<D, Windows::Devices::Sensors::ILightSensorDeviceId> : produce_base<D, Windows::Devices::Sensors::ILightSensorDeviceId>
{
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
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::ILightSensorReading> : produce_base<D, Windows::Devices::Sensors::ILightSensorReading>
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

    int32_t WINRT_CALL get_IlluminanceInLux(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IlluminanceInLux, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().IlluminanceInLux());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::ILightSensorReading2> : produce_base<D, Windows::Devices::Sensors::ILightSensorReading2>
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
struct produce<D, Windows::Devices::Sensors::ILightSensorReadingChangedEventArgs> : produce_base<D, Windows::Devices::Sensors::ILightSensorReadingChangedEventArgs>
{
    int32_t WINRT_CALL get_Reading(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Reading, WINRT_WRAP(Windows::Devices::Sensors::LightSensorReading));
            *value = detach_from<Windows::Devices::Sensors::LightSensorReading>(this->shim().Reading());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::ILightSensorStatics> : produce_base<D, Windows::Devices::Sensors::ILightSensorStatics>
{
    int32_t WINRT_CALL GetDefault(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefault, WINRT_WRAP(Windows::Devices::Sensors::LightSensor));
            *result = detach_from<Windows::Devices::Sensors::LightSensor>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::ILightSensorStatics2> : produce_base<D, Windows::Devices::Sensors::ILightSensorStatics2>
{
    int32_t WINRT_CALL GetDeviceSelector(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelector, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().GetDeviceSelector());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FromIdAsync(void* deviceId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::LightSensor>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::LightSensor>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::IMagnetometer> : produce_base<D, Windows::Devices::Sensors::IMagnetometer>
{
    int32_t WINRT_CALL GetCurrentReading(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCurrentReading, WINRT_WRAP(Windows::Devices::Sensors::MagnetometerReading));
            *value = detach_from<Windows::Devices::Sensors::MagnetometerReading>(this->shim().GetCurrentReading());
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

    int32_t WINRT_CALL add_ReadingChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadingChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Sensors::Magnetometer, Windows::Devices::Sensors::MagnetometerReadingChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ReadingChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Sensors::Magnetometer, Windows::Devices::Sensors::MagnetometerReadingChangedEventArgs> const*>(&handler)));
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
struct produce<D, Windows::Devices::Sensors::IMagnetometer2> : produce_base<D, Windows::Devices::Sensors::IMagnetometer2>
{
    int32_t WINRT_CALL put_ReadingTransform(Windows::Graphics::Display::DisplayOrientations value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadingTransform, WINRT_WRAP(void), Windows::Graphics::Display::DisplayOrientations const&);
            this->shim().ReadingTransform(*reinterpret_cast<Windows::Graphics::Display::DisplayOrientations const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ReadingTransform(Windows::Graphics::Display::DisplayOrientations* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadingTransform, WINRT_WRAP(Windows::Graphics::Display::DisplayOrientations));
            *value = detach_from<Windows::Graphics::Display::DisplayOrientations>(this->shim().ReadingTransform());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::IMagnetometer3> : produce_base<D, Windows::Devices::Sensors::IMagnetometer3>
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
struct produce<D, Windows::Devices::Sensors::IMagnetometerDeviceId> : produce_base<D, Windows::Devices::Sensors::IMagnetometerDeviceId>
{
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
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::IMagnetometerReading> : produce_base<D, Windows::Devices::Sensors::IMagnetometerReading>
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

    int32_t WINRT_CALL get_MagneticFieldX(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MagneticFieldX, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().MagneticFieldX());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MagneticFieldY(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MagneticFieldY, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().MagneticFieldY());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MagneticFieldZ(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MagneticFieldZ, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().MagneticFieldZ());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DirectionalAccuracy(Windows::Devices::Sensors::MagnetometerAccuracy* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DirectionalAccuracy, WINRT_WRAP(Windows::Devices::Sensors::MagnetometerAccuracy));
            *value = detach_from<Windows::Devices::Sensors::MagnetometerAccuracy>(this->shim().DirectionalAccuracy());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::IMagnetometerReading2> : produce_base<D, Windows::Devices::Sensors::IMagnetometerReading2>
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
struct produce<D, Windows::Devices::Sensors::IMagnetometerReadingChangedEventArgs> : produce_base<D, Windows::Devices::Sensors::IMagnetometerReadingChangedEventArgs>
{
    int32_t WINRT_CALL get_Reading(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Reading, WINRT_WRAP(Windows::Devices::Sensors::MagnetometerReading));
            *value = detach_from<Windows::Devices::Sensors::MagnetometerReading>(this->shim().Reading());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::IMagnetometerStatics> : produce_base<D, Windows::Devices::Sensors::IMagnetometerStatics>
{
    int32_t WINRT_CALL GetDefault(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefault, WINRT_WRAP(Windows::Devices::Sensors::Magnetometer));
            *result = detach_from<Windows::Devices::Sensors::Magnetometer>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::IMagnetometerStatics2> : produce_base<D, Windows::Devices::Sensors::IMagnetometerStatics2>
{
    int32_t WINRT_CALL GetDeviceSelector(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelector, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().GetDeviceSelector());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FromIdAsync(void* deviceId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::Magnetometer>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::Magnetometer>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::IOrientationSensor> : produce_base<D, Windows::Devices::Sensors::IOrientationSensor>
{
    int32_t WINRT_CALL GetCurrentReading(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCurrentReading, WINRT_WRAP(Windows::Devices::Sensors::OrientationSensorReading));
            *value = detach_from<Windows::Devices::Sensors::OrientationSensorReading>(this->shim().GetCurrentReading());
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

    int32_t WINRT_CALL add_ReadingChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadingChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Sensors::OrientationSensor, Windows::Devices::Sensors::OrientationSensorReadingChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ReadingChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Sensors::OrientationSensor, Windows::Devices::Sensors::OrientationSensorReadingChangedEventArgs> const*>(&handler)));
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
struct produce<D, Windows::Devices::Sensors::IOrientationSensor2> : produce_base<D, Windows::Devices::Sensors::IOrientationSensor2>
{
    int32_t WINRT_CALL put_ReadingTransform(Windows::Graphics::Display::DisplayOrientations value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadingTransform, WINRT_WRAP(void), Windows::Graphics::Display::DisplayOrientations const&);
            this->shim().ReadingTransform(*reinterpret_cast<Windows::Graphics::Display::DisplayOrientations const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ReadingTransform(Windows::Graphics::Display::DisplayOrientations* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadingTransform, WINRT_WRAP(Windows::Graphics::Display::DisplayOrientations));
            *value = detach_from<Windows::Graphics::Display::DisplayOrientations>(this->shim().ReadingTransform());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ReadingType(Windows::Devices::Sensors::SensorReadingType* type) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadingType, WINRT_WRAP(Windows::Devices::Sensors::SensorReadingType));
            *type = detach_from<Windows::Devices::Sensors::SensorReadingType>(this->shim().ReadingType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::IOrientationSensor3> : produce_base<D, Windows::Devices::Sensors::IOrientationSensor3>
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
struct produce<D, Windows::Devices::Sensors::IOrientationSensorDeviceId> : produce_base<D, Windows::Devices::Sensors::IOrientationSensorDeviceId>
{
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
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::IOrientationSensorReading> : produce_base<D, Windows::Devices::Sensors::IOrientationSensorReading>
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

    int32_t WINRT_CALL get_RotationMatrix(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RotationMatrix, WINRT_WRAP(Windows::Devices::Sensors::SensorRotationMatrix));
            *value = detach_from<Windows::Devices::Sensors::SensorRotationMatrix>(this->shim().RotationMatrix());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Quaternion(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Quaternion, WINRT_WRAP(Windows::Devices::Sensors::SensorQuaternion));
            *value = detach_from<Windows::Devices::Sensors::SensorQuaternion>(this->shim().Quaternion());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::IOrientationSensorReading2> : produce_base<D, Windows::Devices::Sensors::IOrientationSensorReading2>
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
struct produce<D, Windows::Devices::Sensors::IOrientationSensorReadingChangedEventArgs> : produce_base<D, Windows::Devices::Sensors::IOrientationSensorReadingChangedEventArgs>
{
    int32_t WINRT_CALL get_Reading(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Reading, WINRT_WRAP(Windows::Devices::Sensors::OrientationSensorReading));
            *value = detach_from<Windows::Devices::Sensors::OrientationSensorReading>(this->shim().Reading());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::IOrientationSensorReadingYawAccuracy> : produce_base<D, Windows::Devices::Sensors::IOrientationSensorReadingYawAccuracy>
{
    int32_t WINRT_CALL get_YawAccuracy(Windows::Devices::Sensors::MagnetometerAccuracy* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(YawAccuracy, WINRT_WRAP(Windows::Devices::Sensors::MagnetometerAccuracy));
            *value = detach_from<Windows::Devices::Sensors::MagnetometerAccuracy>(this->shim().YawAccuracy());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::IOrientationSensorStatics> : produce_base<D, Windows::Devices::Sensors::IOrientationSensorStatics>
{
    int32_t WINRT_CALL GetDefault(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefault, WINRT_WRAP(Windows::Devices::Sensors::OrientationSensor));
            *result = detach_from<Windows::Devices::Sensors::OrientationSensor>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::IOrientationSensorStatics2> : produce_base<D, Windows::Devices::Sensors::IOrientationSensorStatics2>
{
    int32_t WINRT_CALL GetDefaultForRelativeReadings(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefaultForRelativeReadings, WINRT_WRAP(Windows::Devices::Sensors::OrientationSensor));
            *result = detach_from<Windows::Devices::Sensors::OrientationSensor>(this->shim().GetDefaultForRelativeReadings());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::IOrientationSensorStatics3> : produce_base<D, Windows::Devices::Sensors::IOrientationSensorStatics3>
{
    int32_t WINRT_CALL GetDefaultWithSensorReadingType(Windows::Devices::Sensors::SensorReadingType sensorReadingtype, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefault, WINRT_WRAP(Windows::Devices::Sensors::OrientationSensor), Windows::Devices::Sensors::SensorReadingType const&);
            *result = detach_from<Windows::Devices::Sensors::OrientationSensor>(this->shim().GetDefault(*reinterpret_cast<Windows::Devices::Sensors::SensorReadingType const*>(&sensorReadingtype)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDefaultWithSensorReadingTypeAndSensorOptimizationGoal(Windows::Devices::Sensors::SensorReadingType sensorReadingType, Windows::Devices::Sensors::SensorOptimizationGoal optimizationGoal, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefault, WINRT_WRAP(Windows::Devices::Sensors::OrientationSensor), Windows::Devices::Sensors::SensorReadingType const&, Windows::Devices::Sensors::SensorOptimizationGoal const&);
            *result = detach_from<Windows::Devices::Sensors::OrientationSensor>(this->shim().GetDefault(*reinterpret_cast<Windows::Devices::Sensors::SensorReadingType const*>(&sensorReadingType), *reinterpret_cast<Windows::Devices::Sensors::SensorOptimizationGoal const*>(&optimizationGoal)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::IOrientationSensorStatics4> : produce_base<D, Windows::Devices::Sensors::IOrientationSensorStatics4>
{
    int32_t WINRT_CALL GetDeviceSelector(Windows::Devices::Sensors::SensorReadingType readingType, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelector, WINRT_WRAP(hstring), Windows::Devices::Sensors::SensorReadingType const&);
            *result = detach_from<hstring>(this->shim().GetDeviceSelector(*reinterpret_cast<Windows::Devices::Sensors::SensorReadingType const*>(&readingType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeviceSelectorWithSensorReadingTypeAndSensorOptimizationGoal(Windows::Devices::Sensors::SensorReadingType readingType, Windows::Devices::Sensors::SensorOptimizationGoal optimizationGoal, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelector, WINRT_WRAP(hstring), Windows::Devices::Sensors::SensorReadingType const&, Windows::Devices::Sensors::SensorOptimizationGoal const&);
            *result = detach_from<hstring>(this->shim().GetDeviceSelector(*reinterpret_cast<Windows::Devices::Sensors::SensorReadingType const*>(&readingType), *reinterpret_cast<Windows::Devices::Sensors::SensorOptimizationGoal const*>(&optimizationGoal)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FromIdAsync(void* deviceId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::OrientationSensor>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::OrientationSensor>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::IPedometer> : produce_base<D, Windows::Devices::Sensors::IPedometer>
{
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

    int32_t WINRT_CALL get_PowerInMilliwatts(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PowerInMilliwatts, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().PowerInMilliwatts());
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

    int32_t WINRT_CALL add_ReadingChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadingChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Sensors::Pedometer, Windows::Devices::Sensors::PedometerReadingChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ReadingChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Sensors::Pedometer, Windows::Devices::Sensors::PedometerReadingChangedEventArgs> const*>(&handler)));
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
struct produce<D, Windows::Devices::Sensors::IPedometer2> : produce_base<D, Windows::Devices::Sensors::IPedometer2>
{
    int32_t WINRT_CALL GetCurrentReadings(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCurrentReadings, WINRT_WRAP(Windows::Foundation::Collections::IMapView<Windows::Devices::Sensors::PedometerStepKind, Windows::Devices::Sensors::PedometerReading>));
            *value = detach_from<Windows::Foundation::Collections::IMapView<Windows::Devices::Sensors::PedometerStepKind, Windows::Devices::Sensors::PedometerReading>>(this->shim().GetCurrentReadings());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::IPedometerDataThresholdFactory> : produce_base<D, Windows::Devices::Sensors::IPedometerDataThresholdFactory>
{
    int32_t WINRT_CALL Create(void* sensor, int32_t stepGoal, void** threshold) noexcept final
    {
        try
        {
            *threshold = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Devices::Sensors::PedometerDataThreshold), Windows::Devices::Sensors::Pedometer const&, int32_t);
            *threshold = detach_from<Windows::Devices::Sensors::PedometerDataThreshold>(this->shim().Create(*reinterpret_cast<Windows::Devices::Sensors::Pedometer const*>(&sensor), stepGoal));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::IPedometerReading> : produce_base<D, Windows::Devices::Sensors::IPedometerReading>
{
    int32_t WINRT_CALL get_StepKind(Windows::Devices::Sensors::PedometerStepKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StepKind, WINRT_WRAP(Windows::Devices::Sensors::PedometerStepKind));
            *value = detach_from<Windows::Devices::Sensors::PedometerStepKind>(this->shim().StepKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CumulativeSteps(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CumulativeSteps, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().CumulativeSteps());
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

    int32_t WINRT_CALL get_CumulativeStepsDuration(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CumulativeStepsDuration, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().CumulativeStepsDuration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::IPedometerReadingChangedEventArgs> : produce_base<D, Windows::Devices::Sensors::IPedometerReadingChangedEventArgs>
{
    int32_t WINRT_CALL get_Reading(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Reading, WINRT_WRAP(Windows::Devices::Sensors::PedometerReading));
            *value = detach_from<Windows::Devices::Sensors::PedometerReading>(this->shim().Reading());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::IPedometerStatics> : produce_base<D, Windows::Devices::Sensors::IPedometerStatics>
{
    int32_t WINRT_CALL FromIdAsync(void* deviceId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::Pedometer>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::Pedometer>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDefaultAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefaultAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::Pedometer>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::Pedometer>>(this->shim().GetDefaultAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeviceSelector(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelector, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().GetDeviceSelector());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetSystemHistoryAsync(Windows::Foundation::DateTime fromTime, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetSystemHistoryAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Sensors::PedometerReading>>), Windows::Foundation::DateTime const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Sensors::PedometerReading>>>(this->shim().GetSystemHistoryAsync(*reinterpret_cast<Windows::Foundation::DateTime const*>(&fromTime)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetSystemHistoryWithDurationAsync(Windows::Foundation::DateTime fromTime, Windows::Foundation::TimeSpan duration, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetSystemHistoryAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Sensors::PedometerReading>>), Windows::Foundation::DateTime const, Windows::Foundation::TimeSpan const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Sensors::PedometerReading>>>(this->shim().GetSystemHistoryAsync(*reinterpret_cast<Windows::Foundation::DateTime const*>(&fromTime), *reinterpret_cast<Windows::Foundation::TimeSpan const*>(&duration)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::IPedometerStatics2> : produce_base<D, Windows::Devices::Sensors::IPedometerStatics2>
{
    int32_t WINRT_CALL GetReadingsFromTriggerDetails(void* triggerDetails, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetReadingsFromTriggerDetails, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::Sensors::PedometerReading>), Windows::Devices::Sensors::SensorDataThresholdTriggerDetails const&);
            *result = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::Sensors::PedometerReading>>(this->shim().GetReadingsFromTriggerDetails(*reinterpret_cast<Windows::Devices::Sensors::SensorDataThresholdTriggerDetails const*>(&triggerDetails)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::IProximitySensor> : produce_base<D, Windows::Devices::Sensors::IProximitySensor>
{
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

    int32_t WINRT_CALL get_MaxDistanceInMillimeters(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxDistanceInMillimeters, WINRT_WRAP(Windows::Foundation::IReference<uint32_t>));
            *value = detach_from<Windows::Foundation::IReference<uint32_t>>(this->shim().MaxDistanceInMillimeters());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MinDistanceInMillimeters(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinDistanceInMillimeters, WINRT_WRAP(Windows::Foundation::IReference<uint32_t>));
            *value = detach_from<Windows::Foundation::IReference<uint32_t>>(this->shim().MinDistanceInMillimeters());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetCurrentReading(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCurrentReading, WINRT_WRAP(Windows::Devices::Sensors::ProximitySensorReading));
            *value = detach_from<Windows::Devices::Sensors::ProximitySensorReading>(this->shim().GetCurrentReading());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_ReadingChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadingChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Sensors::ProximitySensor, Windows::Devices::Sensors::ProximitySensorReadingChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ReadingChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Sensors::ProximitySensor, Windows::Devices::Sensors::ProximitySensorReadingChangedEventArgs> const*>(&handler)));
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

    int32_t WINRT_CALL CreateDisplayOnOffController(void** controller) noexcept final
    {
        try
        {
            *controller = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateDisplayOnOffController, WINRT_WRAP(Windows::Devices::Sensors::ProximitySensorDisplayOnOffController));
            *controller = detach_from<Windows::Devices::Sensors::ProximitySensorDisplayOnOffController>(this->shim().CreateDisplayOnOffController());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::IProximitySensorDataThresholdFactory> : produce_base<D, Windows::Devices::Sensors::IProximitySensorDataThresholdFactory>
{
    int32_t WINRT_CALL Create(void* sensor, void** threshold) noexcept final
    {
        try
        {
            *threshold = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Devices::Sensors::ProximitySensorDataThreshold), Windows::Devices::Sensors::ProximitySensor const&);
            *threshold = detach_from<Windows::Devices::Sensors::ProximitySensorDataThreshold>(this->shim().Create(*reinterpret_cast<Windows::Devices::Sensors::ProximitySensor const*>(&sensor)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::IProximitySensorReading> : produce_base<D, Windows::Devices::Sensors::IProximitySensorReading>
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

    int32_t WINRT_CALL get_IsDetected(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDetected, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsDetected());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DistanceInMillimeters(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DistanceInMillimeters, WINRT_WRAP(Windows::Foundation::IReference<uint32_t>));
            *value = detach_from<Windows::Foundation::IReference<uint32_t>>(this->shim().DistanceInMillimeters());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::IProximitySensorReadingChangedEventArgs> : produce_base<D, Windows::Devices::Sensors::IProximitySensorReadingChangedEventArgs>
{
    int32_t WINRT_CALL get_Reading(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Reading, WINRT_WRAP(Windows::Devices::Sensors::ProximitySensorReading));
            *value = detach_from<Windows::Devices::Sensors::ProximitySensorReading>(this->shim().Reading());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::IProximitySensorStatics> : produce_base<D, Windows::Devices::Sensors::IProximitySensorStatics>
{
    int32_t WINRT_CALL GetDeviceSelector(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelector, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().GetDeviceSelector());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FromId(void* sensorId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromId, WINRT_WRAP(Windows::Devices::Sensors::ProximitySensor), hstring const&);
            *result = detach_from<Windows::Devices::Sensors::ProximitySensor>(this->shim().FromId(*reinterpret_cast<hstring const*>(&sensorId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::IProximitySensorStatics2> : produce_base<D, Windows::Devices::Sensors::IProximitySensorStatics2>
{
    int32_t WINRT_CALL GetReadingsFromTriggerDetails(void* triggerDetails, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetReadingsFromTriggerDetails, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::Sensors::ProximitySensorReading>), Windows::Devices::Sensors::SensorDataThresholdTriggerDetails const&);
            *result = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::Sensors::ProximitySensorReading>>(this->shim().GetReadingsFromTriggerDetails(*reinterpret_cast<Windows::Devices::Sensors::SensorDataThresholdTriggerDetails const*>(&triggerDetails)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::ISensorDataThreshold> : produce_base<D, Windows::Devices::Sensors::ISensorDataThreshold>
{};

template <typename D>
struct produce<D, Windows::Devices::Sensors::ISensorDataThresholdTriggerDetails> : produce_base<D, Windows::Devices::Sensors::ISensorDataThresholdTriggerDetails>
{
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

    int32_t WINRT_CALL get_SensorType(Windows::Devices::Sensors::SensorType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SensorType, WINRT_WRAP(Windows::Devices::Sensors::SensorType));
            *value = detach_from<Windows::Devices::Sensors::SensorType>(this->shim().SensorType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::ISensorQuaternion> : produce_base<D, Windows::Devices::Sensors::ISensorQuaternion>
{
    int32_t WINRT_CALL get_W(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(W, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().W());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_X(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(X, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().X());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Y(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Y, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().Y());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Z(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Z, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().Z());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::ISensorRotationMatrix> : produce_base<D, Windows::Devices::Sensors::ISensorRotationMatrix>
{
    int32_t WINRT_CALL get_M11(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(M11, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().M11());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_M12(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(M12, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().M12());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_M13(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(M13, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().M13());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_M21(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(M21, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().M21());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_M22(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(M22, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().M22());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_M23(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(M23, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().M23());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_M31(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(M31, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().M31());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_M32(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(M32, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().M32());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_M33(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(M33, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().M33());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::ISimpleOrientationSensor> : produce_base<D, Windows::Devices::Sensors::ISimpleOrientationSensor>
{
    int32_t WINRT_CALL GetCurrentOrientation(Windows::Devices::Sensors::SimpleOrientation* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCurrentOrientation, WINRT_WRAP(Windows::Devices::Sensors::SimpleOrientation));
            *value = detach_from<Windows::Devices::Sensors::SimpleOrientation>(this->shim().GetCurrentOrientation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_OrientationChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OrientationChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Sensors::SimpleOrientationSensor, Windows::Devices::Sensors::SimpleOrientationSensorOrientationChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().OrientationChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Sensors::SimpleOrientationSensor, Windows::Devices::Sensors::SimpleOrientationSensorOrientationChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_OrientationChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(OrientationChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().OrientationChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::ISimpleOrientationSensor2> : produce_base<D, Windows::Devices::Sensors::ISimpleOrientationSensor2>
{
    int32_t WINRT_CALL put_ReadingTransform(Windows::Graphics::Display::DisplayOrientations value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadingTransform, WINRT_WRAP(void), Windows::Graphics::Display::DisplayOrientations const&);
            this->shim().ReadingTransform(*reinterpret_cast<Windows::Graphics::Display::DisplayOrientations const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ReadingTransform(Windows::Graphics::Display::DisplayOrientations* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadingTransform, WINRT_WRAP(Windows::Graphics::Display::DisplayOrientations));
            *value = detach_from<Windows::Graphics::Display::DisplayOrientations>(this->shim().ReadingTransform());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::ISimpleOrientationSensorDeviceId> : produce_base<D, Windows::Devices::Sensors::ISimpleOrientationSensorDeviceId>
{
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
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::ISimpleOrientationSensorOrientationChangedEventArgs> : produce_base<D, Windows::Devices::Sensors::ISimpleOrientationSensorOrientationChangedEventArgs>
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

    int32_t WINRT_CALL get_Orientation(Windows::Devices::Sensors::SimpleOrientation* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Orientation, WINRT_WRAP(Windows::Devices::Sensors::SimpleOrientation));
            *value = detach_from<Windows::Devices::Sensors::SimpleOrientation>(this->shim().Orientation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::ISimpleOrientationSensorStatics> : produce_base<D, Windows::Devices::Sensors::ISimpleOrientationSensorStatics>
{
    int32_t WINRT_CALL GetDefault(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefault, WINRT_WRAP(Windows::Devices::Sensors::SimpleOrientationSensor));
            *result = detach_from<Windows::Devices::Sensors::SimpleOrientationSensor>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Sensors::ISimpleOrientationSensorStatics2> : produce_base<D, Windows::Devices::Sensors::ISimpleOrientationSensorStatics2>
{
    int32_t WINRT_CALL GetDeviceSelector(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelector, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().GetDeviceSelector());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FromIdAsync(void* deviceId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::SimpleOrientationSensor>), hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::SimpleOrientationSensor>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Devices::Sensors {

inline Windows::Devices::Sensors::Accelerometer Accelerometer::GetDefault()
{
    return impl::call_factory<Accelerometer, Windows::Devices::Sensors::IAccelerometerStatics>([&](auto&& f) { return f.GetDefault(); });
}

inline Windows::Devices::Sensors::Accelerometer Accelerometer::GetDefault(Windows::Devices::Sensors::AccelerometerReadingType const& readingType)
{
    return impl::call_factory<Accelerometer, Windows::Devices::Sensors::IAccelerometerStatics2>([&](auto&& f) { return f.GetDefault(readingType); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::Accelerometer> Accelerometer::FromIdAsync(param::hstring const& deviceId)
{
    return impl::call_factory<Accelerometer, Windows::Devices::Sensors::IAccelerometerStatics3>([&](auto&& f) { return f.FromIdAsync(deviceId); });
}

inline hstring Accelerometer::GetDeviceSelector(Windows::Devices::Sensors::AccelerometerReadingType const& readingType)
{
    return impl::call_factory<Accelerometer, Windows::Devices::Sensors::IAccelerometerStatics3>([&](auto&& f) { return f.GetDeviceSelector(readingType); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::ActivitySensor> ActivitySensor::GetDefaultAsync()
{
    return impl::call_factory<ActivitySensor, Windows::Devices::Sensors::IActivitySensorStatics>([&](auto&& f) { return f.GetDefaultAsync(); });
}

inline hstring ActivitySensor::GetDeviceSelector()
{
    return impl::call_factory<ActivitySensor, Windows::Devices::Sensors::IActivitySensorStatics>([&](auto&& f) { return f.GetDeviceSelector(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::ActivitySensor> ActivitySensor::FromIdAsync(param::hstring const& deviceId)
{
    return impl::call_factory<ActivitySensor, Windows::Devices::Sensors::IActivitySensorStatics>([&](auto&& f) { return f.FromIdAsync(deviceId); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Sensors::ActivitySensorReading>> ActivitySensor::GetSystemHistoryAsync(Windows::Foundation::DateTime const& fromTime)
{
    return impl::call_factory<ActivitySensor, Windows::Devices::Sensors::IActivitySensorStatics>([&](auto&& f) { return f.GetSystemHistoryAsync(fromTime); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Sensors::ActivitySensorReading>> ActivitySensor::GetSystemHistoryAsync(Windows::Foundation::DateTime const& fromTime, Windows::Foundation::TimeSpan const& duration)
{
    return impl::call_factory<ActivitySensor, Windows::Devices::Sensors::IActivitySensorStatics>([&](auto&& f) { return f.GetSystemHistoryAsync(fromTime, duration); });
}

inline Windows::Devices::Sensors::Altimeter Altimeter::GetDefault()
{
    return impl::call_factory<Altimeter, Windows::Devices::Sensors::IAltimeterStatics>([&](auto&& f) { return f.GetDefault(); });
}

inline Windows::Devices::Sensors::Barometer Barometer::GetDefault()
{
    return impl::call_factory<Barometer, Windows::Devices::Sensors::IBarometerStatics>([&](auto&& f) { return f.GetDefault(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::Barometer> Barometer::FromIdAsync(param::hstring const& deviceId)
{
    return impl::call_factory<Barometer, Windows::Devices::Sensors::IBarometerStatics2>([&](auto&& f) { return f.FromIdAsync(deviceId); });
}

inline hstring Barometer::GetDeviceSelector()
{
    return impl::call_factory<Barometer, Windows::Devices::Sensors::IBarometerStatics2>([&](auto&& f) { return f.GetDeviceSelector(); });
}

inline Windows::Devices::Sensors::Compass Compass::GetDefault()
{
    return impl::call_factory<Compass, Windows::Devices::Sensors::ICompassStatics>([&](auto&& f) { return f.GetDefault(); });
}

inline hstring Compass::GetDeviceSelector()
{
    return impl::call_factory<Compass, Windows::Devices::Sensors::ICompassStatics2>([&](auto&& f) { return f.GetDeviceSelector(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::Compass> Compass::FromIdAsync(param::hstring const& deviceId)
{
    return impl::call_factory<Compass, Windows::Devices::Sensors::ICompassStatics2>([&](auto&& f) { return f.FromIdAsync(deviceId); });
}

inline Windows::Devices::Sensors::Gyrometer Gyrometer::GetDefault()
{
    return impl::call_factory<Gyrometer, Windows::Devices::Sensors::IGyrometerStatics>([&](auto&& f) { return f.GetDefault(); });
}

inline hstring Gyrometer::GetDeviceSelector()
{
    return impl::call_factory<Gyrometer, Windows::Devices::Sensors::IGyrometerStatics2>([&](auto&& f) { return f.GetDeviceSelector(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::Gyrometer> Gyrometer::FromIdAsync(param::hstring const& deviceId)
{
    return impl::call_factory<Gyrometer, Windows::Devices::Sensors::IGyrometerStatics2>([&](auto&& f) { return f.FromIdAsync(deviceId); });
}

inline hstring HingeAngleSensor::GetDeviceSelector()
{
    return impl::call_factory<HingeAngleSensor, Windows::Devices::Sensors::IHingeAngleSensorStatics>([&](auto&& f) { return f.GetDeviceSelector(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::HingeAngleSensor> HingeAngleSensor::GetDefaultAsync()
{
    return impl::call_factory<HingeAngleSensor, Windows::Devices::Sensors::IHingeAngleSensorStatics>([&](auto&& f) { return f.GetDefaultAsync(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::HingeAngleSensor> HingeAngleSensor::GetRelatedToAdjacentPanelsAsync(param::hstring const& firstPanelId, param::hstring const& secondPanelId)
{
    return impl::call_factory<HingeAngleSensor, Windows::Devices::Sensors::IHingeAngleSensorStatics>([&](auto&& f) { return f.GetRelatedToAdjacentPanelsAsync(firstPanelId, secondPanelId); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::HingeAngleSensor> HingeAngleSensor::FromIdAsync(param::hstring const& deviceId)
{
    return impl::call_factory<HingeAngleSensor, Windows::Devices::Sensors::IHingeAngleSensorStatics>([&](auto&& f) { return f.FromIdAsync(deviceId); });
}

inline Windows::Devices::Sensors::Inclinometer Inclinometer::GetDefault()
{
    return impl::call_factory<Inclinometer, Windows::Devices::Sensors::IInclinometerStatics>([&](auto&& f) { return f.GetDefault(); });
}

inline Windows::Devices::Sensors::Inclinometer Inclinometer::GetDefaultForRelativeReadings()
{
    return impl::call_factory<Inclinometer, Windows::Devices::Sensors::IInclinometerStatics2>([&](auto&& f) { return f.GetDefaultForRelativeReadings(); });
}

inline Windows::Devices::Sensors::Inclinometer Inclinometer::GetDefault(Windows::Devices::Sensors::SensorReadingType const& sensorReadingtype)
{
    return impl::call_factory<Inclinometer, Windows::Devices::Sensors::IInclinometerStatics3>([&](auto&& f) { return f.GetDefault(sensorReadingtype); });
}

inline hstring Inclinometer::GetDeviceSelector(Windows::Devices::Sensors::SensorReadingType const& readingType)
{
    return impl::call_factory<Inclinometer, Windows::Devices::Sensors::IInclinometerStatics4>([&](auto&& f) { return f.GetDeviceSelector(readingType); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::Inclinometer> Inclinometer::FromIdAsync(param::hstring const& deviceId)
{
    return impl::call_factory<Inclinometer, Windows::Devices::Sensors::IInclinometerStatics4>([&](auto&& f) { return f.FromIdAsync(deviceId); });
}

inline Windows::Devices::Sensors::LightSensor LightSensor::GetDefault()
{
    return impl::call_factory<LightSensor, Windows::Devices::Sensors::ILightSensorStatics>([&](auto&& f) { return f.GetDefault(); });
}

inline hstring LightSensor::GetDeviceSelector()
{
    return impl::call_factory<LightSensor, Windows::Devices::Sensors::ILightSensorStatics2>([&](auto&& f) { return f.GetDeviceSelector(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::LightSensor> LightSensor::FromIdAsync(param::hstring const& deviceId)
{
    return impl::call_factory<LightSensor, Windows::Devices::Sensors::ILightSensorStatics2>([&](auto&& f) { return f.FromIdAsync(deviceId); });
}

inline Windows::Devices::Sensors::Magnetometer Magnetometer::GetDefault()
{
    return impl::call_factory<Magnetometer, Windows::Devices::Sensors::IMagnetometerStatics>([&](auto&& f) { return f.GetDefault(); });
}

inline hstring Magnetometer::GetDeviceSelector()
{
    return impl::call_factory<Magnetometer, Windows::Devices::Sensors::IMagnetometerStatics2>([&](auto&& f) { return f.GetDeviceSelector(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::Magnetometer> Magnetometer::FromIdAsync(param::hstring const& deviceId)
{
    return impl::call_factory<Magnetometer, Windows::Devices::Sensors::IMagnetometerStatics2>([&](auto&& f) { return f.FromIdAsync(deviceId); });
}

inline Windows::Devices::Sensors::OrientationSensor OrientationSensor::GetDefault()
{
    return impl::call_factory<OrientationSensor, Windows::Devices::Sensors::IOrientationSensorStatics>([&](auto&& f) { return f.GetDefault(); });
}

inline Windows::Devices::Sensors::OrientationSensor OrientationSensor::GetDefaultForRelativeReadings()
{
    return impl::call_factory<OrientationSensor, Windows::Devices::Sensors::IOrientationSensorStatics2>([&](auto&& f) { return f.GetDefaultForRelativeReadings(); });
}

inline Windows::Devices::Sensors::OrientationSensor OrientationSensor::GetDefault(Windows::Devices::Sensors::SensorReadingType const& sensorReadingtype)
{
    return impl::call_factory<OrientationSensor, Windows::Devices::Sensors::IOrientationSensorStatics3>([&](auto&& f) { return f.GetDefault(sensorReadingtype); });
}

inline Windows::Devices::Sensors::OrientationSensor OrientationSensor::GetDefault(Windows::Devices::Sensors::SensorReadingType const& sensorReadingType, Windows::Devices::Sensors::SensorOptimizationGoal const& optimizationGoal)
{
    return impl::call_factory<OrientationSensor, Windows::Devices::Sensors::IOrientationSensorStatics3>([&](auto&& f) { return f.GetDefault(sensorReadingType, optimizationGoal); });
}

inline hstring OrientationSensor::GetDeviceSelector(Windows::Devices::Sensors::SensorReadingType const& readingType)
{
    return impl::call_factory<OrientationSensor, Windows::Devices::Sensors::IOrientationSensorStatics4>([&](auto&& f) { return f.GetDeviceSelector(readingType); });
}

inline hstring OrientationSensor::GetDeviceSelector(Windows::Devices::Sensors::SensorReadingType const& readingType, Windows::Devices::Sensors::SensorOptimizationGoal const& optimizationGoal)
{
    return impl::call_factory<OrientationSensor, Windows::Devices::Sensors::IOrientationSensorStatics4>([&](auto&& f) { return f.GetDeviceSelector(readingType, optimizationGoal); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::OrientationSensor> OrientationSensor::FromIdAsync(param::hstring const& deviceId)
{
    return impl::call_factory<OrientationSensor, Windows::Devices::Sensors::IOrientationSensorStatics4>([&](auto&& f) { return f.FromIdAsync(deviceId); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::Pedometer> Pedometer::FromIdAsync(param::hstring const& deviceId)
{
    return impl::call_factory<Pedometer, Windows::Devices::Sensors::IPedometerStatics>([&](auto&& f) { return f.FromIdAsync(deviceId); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::Pedometer> Pedometer::GetDefaultAsync()
{
    return impl::call_factory<Pedometer, Windows::Devices::Sensors::IPedometerStatics>([&](auto&& f) { return f.GetDefaultAsync(); });
}

inline hstring Pedometer::GetDeviceSelector()
{
    return impl::call_factory<Pedometer, Windows::Devices::Sensors::IPedometerStatics>([&](auto&& f) { return f.GetDeviceSelector(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Sensors::PedometerReading>> Pedometer::GetSystemHistoryAsync(Windows::Foundation::DateTime const& fromTime)
{
    return impl::call_factory<Pedometer, Windows::Devices::Sensors::IPedometerStatics>([&](auto&& f) { return f.GetSystemHistoryAsync(fromTime); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Sensors::PedometerReading>> Pedometer::GetSystemHistoryAsync(Windows::Foundation::DateTime const& fromTime, Windows::Foundation::TimeSpan const& duration)
{
    return impl::call_factory<Pedometer, Windows::Devices::Sensors::IPedometerStatics>([&](auto&& f) { return f.GetSystemHistoryAsync(fromTime, duration); });
}

inline Windows::Foundation::Collections::IVectorView<Windows::Devices::Sensors::PedometerReading> Pedometer::GetReadingsFromTriggerDetails(Windows::Devices::Sensors::SensorDataThresholdTriggerDetails const& triggerDetails)
{
    return impl::call_factory<Pedometer, Windows::Devices::Sensors::IPedometerStatics2>([&](auto&& f) { return f.GetReadingsFromTriggerDetails(triggerDetails); });
}

inline PedometerDataThreshold::PedometerDataThreshold(Windows::Devices::Sensors::Pedometer const& sensor, int32_t stepGoal) :
    PedometerDataThreshold(impl::call_factory<PedometerDataThreshold, Windows::Devices::Sensors::IPedometerDataThresholdFactory>([&](auto&& f) { return f.Create(sensor, stepGoal); }))
{}

inline hstring ProximitySensor::GetDeviceSelector()
{
    return impl::call_factory<ProximitySensor, Windows::Devices::Sensors::IProximitySensorStatics>([&](auto&& f) { return f.GetDeviceSelector(); });
}

inline Windows::Devices::Sensors::ProximitySensor ProximitySensor::FromId(param::hstring const& sensorId)
{
    return impl::call_factory<ProximitySensor, Windows::Devices::Sensors::IProximitySensorStatics>([&](auto&& f) { return f.FromId(sensorId); });
}

inline Windows::Foundation::Collections::IVectorView<Windows::Devices::Sensors::ProximitySensorReading> ProximitySensor::GetReadingsFromTriggerDetails(Windows::Devices::Sensors::SensorDataThresholdTriggerDetails const& triggerDetails)
{
    return impl::call_factory<ProximitySensor, Windows::Devices::Sensors::IProximitySensorStatics2>([&](auto&& f) { return f.GetReadingsFromTriggerDetails(triggerDetails); });
}

inline ProximitySensorDataThreshold::ProximitySensorDataThreshold(Windows::Devices::Sensors::ProximitySensor const& sensor) :
    ProximitySensorDataThreshold(impl::call_factory<ProximitySensorDataThreshold, Windows::Devices::Sensors::IProximitySensorDataThresholdFactory>([&](auto&& f) { return f.Create(sensor); }))
{}

inline Windows::Devices::Sensors::SimpleOrientationSensor SimpleOrientationSensor::GetDefault()
{
    return impl::call_factory<SimpleOrientationSensor, Windows::Devices::Sensors::ISimpleOrientationSensorStatics>([&](auto&& f) { return f.GetDefault(); });
}

inline hstring SimpleOrientationSensor::GetDeviceSelector()
{
    return impl::call_factory<SimpleOrientationSensor, Windows::Devices::Sensors::ISimpleOrientationSensorStatics2>([&](auto&& f) { return f.GetDeviceSelector(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::Sensors::SimpleOrientationSensor> SimpleOrientationSensor::FromIdAsync(param::hstring const& deviceId)
{
    return impl::call_factory<SimpleOrientationSensor, Windows::Devices::Sensors::ISimpleOrientationSensorStatics2>([&](auto&& f) { return f.FromIdAsync(deviceId); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Devices::Sensors::IAccelerometer> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IAccelerometer> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IAccelerometer2> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IAccelerometer2> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IAccelerometer3> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IAccelerometer3> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IAccelerometer4> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IAccelerometer4> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IAccelerometerDeviceId> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IAccelerometerDeviceId> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IAccelerometerReading> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IAccelerometerReading> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IAccelerometerReading2> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IAccelerometerReading2> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IAccelerometerReadingChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IAccelerometerReadingChangedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IAccelerometerShakenEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IAccelerometerShakenEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IAccelerometerStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IAccelerometerStatics> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IAccelerometerStatics2> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IAccelerometerStatics2> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IAccelerometerStatics3> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IAccelerometerStatics3> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IActivitySensor> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IActivitySensor> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IActivitySensorReading> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IActivitySensorReading> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IActivitySensorReadingChangeReport> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IActivitySensorReadingChangeReport> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IActivitySensorReadingChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IActivitySensorReadingChangedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IActivitySensorStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IActivitySensorStatics> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IActivitySensorTriggerDetails> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IActivitySensorTriggerDetails> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IAltimeter> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IAltimeter> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IAltimeter2> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IAltimeter2> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IAltimeterReading> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IAltimeterReading> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IAltimeterReading2> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IAltimeterReading2> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IAltimeterReadingChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IAltimeterReadingChangedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IAltimeterStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IAltimeterStatics> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IBarometer> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IBarometer> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IBarometer2> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IBarometer2> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IBarometerReading> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IBarometerReading> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IBarometerReading2> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IBarometerReading2> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IBarometerReadingChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IBarometerReadingChangedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IBarometerStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IBarometerStatics> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IBarometerStatics2> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IBarometerStatics2> {};
template<> struct hash<winrt::Windows::Devices::Sensors::ICompass> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::ICompass> {};
template<> struct hash<winrt::Windows::Devices::Sensors::ICompass2> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::ICompass2> {};
template<> struct hash<winrt::Windows::Devices::Sensors::ICompass3> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::ICompass3> {};
template<> struct hash<winrt::Windows::Devices::Sensors::ICompassDeviceId> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::ICompassDeviceId> {};
template<> struct hash<winrt::Windows::Devices::Sensors::ICompassReading> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::ICompassReading> {};
template<> struct hash<winrt::Windows::Devices::Sensors::ICompassReading2> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::ICompassReading2> {};
template<> struct hash<winrt::Windows::Devices::Sensors::ICompassReadingChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::ICompassReadingChangedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Sensors::ICompassReadingHeadingAccuracy> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::ICompassReadingHeadingAccuracy> {};
template<> struct hash<winrt::Windows::Devices::Sensors::ICompassStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::ICompassStatics> {};
template<> struct hash<winrt::Windows::Devices::Sensors::ICompassStatics2> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::ICompassStatics2> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IGyrometer> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IGyrometer> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IGyrometer2> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IGyrometer2> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IGyrometer3> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IGyrometer3> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IGyrometerDeviceId> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IGyrometerDeviceId> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IGyrometerReading> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IGyrometerReading> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IGyrometerReading2> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IGyrometerReading2> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IGyrometerReadingChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IGyrometerReadingChangedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IGyrometerStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IGyrometerStatics> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IGyrometerStatics2> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IGyrometerStatics2> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IHingeAngleReading> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IHingeAngleReading> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IHingeAngleSensor> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IHingeAngleSensor> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IHingeAngleSensorReadingChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IHingeAngleSensorReadingChangedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IHingeAngleSensorStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IHingeAngleSensorStatics> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IInclinometer> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IInclinometer> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IInclinometer2> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IInclinometer2> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IInclinometer3> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IInclinometer3> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IInclinometerDeviceId> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IInclinometerDeviceId> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IInclinometerReading> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IInclinometerReading> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IInclinometerReading2> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IInclinometerReading2> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IInclinometerReadingChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IInclinometerReadingChangedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IInclinometerReadingYawAccuracy> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IInclinometerReadingYawAccuracy> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IInclinometerStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IInclinometerStatics> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IInclinometerStatics2> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IInclinometerStatics2> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IInclinometerStatics3> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IInclinometerStatics3> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IInclinometerStatics4> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IInclinometerStatics4> {};
template<> struct hash<winrt::Windows::Devices::Sensors::ILightSensor> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::ILightSensor> {};
template<> struct hash<winrt::Windows::Devices::Sensors::ILightSensor2> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::ILightSensor2> {};
template<> struct hash<winrt::Windows::Devices::Sensors::ILightSensorDeviceId> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::ILightSensorDeviceId> {};
template<> struct hash<winrt::Windows::Devices::Sensors::ILightSensorReading> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::ILightSensorReading> {};
template<> struct hash<winrt::Windows::Devices::Sensors::ILightSensorReading2> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::ILightSensorReading2> {};
template<> struct hash<winrt::Windows::Devices::Sensors::ILightSensorReadingChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::ILightSensorReadingChangedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Sensors::ILightSensorStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::ILightSensorStatics> {};
template<> struct hash<winrt::Windows::Devices::Sensors::ILightSensorStatics2> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::ILightSensorStatics2> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IMagnetometer> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IMagnetometer> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IMagnetometer2> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IMagnetometer2> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IMagnetometer3> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IMagnetometer3> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IMagnetometerDeviceId> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IMagnetometerDeviceId> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IMagnetometerReading> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IMagnetometerReading> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IMagnetometerReading2> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IMagnetometerReading2> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IMagnetometerReadingChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IMagnetometerReadingChangedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IMagnetometerStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IMagnetometerStatics> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IMagnetometerStatics2> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IMagnetometerStatics2> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IOrientationSensor> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IOrientationSensor> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IOrientationSensor2> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IOrientationSensor2> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IOrientationSensor3> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IOrientationSensor3> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IOrientationSensorDeviceId> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IOrientationSensorDeviceId> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IOrientationSensorReading> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IOrientationSensorReading> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IOrientationSensorReading2> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IOrientationSensorReading2> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IOrientationSensorReadingChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IOrientationSensorReadingChangedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IOrientationSensorReadingYawAccuracy> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IOrientationSensorReadingYawAccuracy> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IOrientationSensorStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IOrientationSensorStatics> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IOrientationSensorStatics2> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IOrientationSensorStatics2> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IOrientationSensorStatics3> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IOrientationSensorStatics3> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IOrientationSensorStatics4> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IOrientationSensorStatics4> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IPedometer> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IPedometer> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IPedometer2> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IPedometer2> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IPedometerDataThresholdFactory> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IPedometerDataThresholdFactory> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IPedometerReading> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IPedometerReading> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IPedometerReadingChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IPedometerReadingChangedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IPedometerStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IPedometerStatics> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IPedometerStatics2> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IPedometerStatics2> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IProximitySensor> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IProximitySensor> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IProximitySensorDataThresholdFactory> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IProximitySensorDataThresholdFactory> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IProximitySensorReading> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IProximitySensorReading> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IProximitySensorReadingChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IProximitySensorReadingChangedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IProximitySensorStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IProximitySensorStatics> {};
template<> struct hash<winrt::Windows::Devices::Sensors::IProximitySensorStatics2> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::IProximitySensorStatics2> {};
template<> struct hash<winrt::Windows::Devices::Sensors::ISensorDataThreshold> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::ISensorDataThreshold> {};
template<> struct hash<winrt::Windows::Devices::Sensors::ISensorDataThresholdTriggerDetails> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::ISensorDataThresholdTriggerDetails> {};
template<> struct hash<winrt::Windows::Devices::Sensors::ISensorQuaternion> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::ISensorQuaternion> {};
template<> struct hash<winrt::Windows::Devices::Sensors::ISensorRotationMatrix> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::ISensorRotationMatrix> {};
template<> struct hash<winrt::Windows::Devices::Sensors::ISimpleOrientationSensor> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::ISimpleOrientationSensor> {};
template<> struct hash<winrt::Windows::Devices::Sensors::ISimpleOrientationSensor2> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::ISimpleOrientationSensor2> {};
template<> struct hash<winrt::Windows::Devices::Sensors::ISimpleOrientationSensorDeviceId> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::ISimpleOrientationSensorDeviceId> {};
template<> struct hash<winrt::Windows::Devices::Sensors::ISimpleOrientationSensorOrientationChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::ISimpleOrientationSensorOrientationChangedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Sensors::ISimpleOrientationSensorStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::ISimpleOrientationSensorStatics> {};
template<> struct hash<winrt::Windows::Devices::Sensors::ISimpleOrientationSensorStatics2> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::ISimpleOrientationSensorStatics2> {};
template<> struct hash<winrt::Windows::Devices::Sensors::Accelerometer> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::Accelerometer> {};
template<> struct hash<winrt::Windows::Devices::Sensors::AccelerometerReading> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::AccelerometerReading> {};
template<> struct hash<winrt::Windows::Devices::Sensors::AccelerometerReadingChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::AccelerometerReadingChangedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Sensors::AccelerometerShakenEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::AccelerometerShakenEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Sensors::ActivitySensor> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::ActivitySensor> {};
template<> struct hash<winrt::Windows::Devices::Sensors::ActivitySensorReading> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::ActivitySensorReading> {};
template<> struct hash<winrt::Windows::Devices::Sensors::ActivitySensorReadingChangeReport> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::ActivitySensorReadingChangeReport> {};
template<> struct hash<winrt::Windows::Devices::Sensors::ActivitySensorReadingChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::ActivitySensorReadingChangedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Sensors::ActivitySensorTriggerDetails> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::ActivitySensorTriggerDetails> {};
template<> struct hash<winrt::Windows::Devices::Sensors::Altimeter> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::Altimeter> {};
template<> struct hash<winrt::Windows::Devices::Sensors::AltimeterReading> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::AltimeterReading> {};
template<> struct hash<winrt::Windows::Devices::Sensors::AltimeterReadingChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::AltimeterReadingChangedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Sensors::Barometer> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::Barometer> {};
template<> struct hash<winrt::Windows::Devices::Sensors::BarometerReading> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::BarometerReading> {};
template<> struct hash<winrt::Windows::Devices::Sensors::BarometerReadingChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::BarometerReadingChangedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Sensors::Compass> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::Compass> {};
template<> struct hash<winrt::Windows::Devices::Sensors::CompassReading> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::CompassReading> {};
template<> struct hash<winrt::Windows::Devices::Sensors::CompassReadingChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::CompassReadingChangedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Sensors::Gyrometer> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::Gyrometer> {};
template<> struct hash<winrt::Windows::Devices::Sensors::GyrometerReading> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::GyrometerReading> {};
template<> struct hash<winrt::Windows::Devices::Sensors::GyrometerReadingChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::GyrometerReadingChangedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Sensors::HingeAngleReading> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::HingeAngleReading> {};
template<> struct hash<winrt::Windows::Devices::Sensors::HingeAngleSensor> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::HingeAngleSensor> {};
template<> struct hash<winrt::Windows::Devices::Sensors::HingeAngleSensorReadingChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::HingeAngleSensorReadingChangedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Sensors::Inclinometer> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::Inclinometer> {};
template<> struct hash<winrt::Windows::Devices::Sensors::InclinometerReading> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::InclinometerReading> {};
template<> struct hash<winrt::Windows::Devices::Sensors::InclinometerReadingChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::InclinometerReadingChangedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Sensors::LightSensor> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::LightSensor> {};
template<> struct hash<winrt::Windows::Devices::Sensors::LightSensorReading> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::LightSensorReading> {};
template<> struct hash<winrt::Windows::Devices::Sensors::LightSensorReadingChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::LightSensorReadingChangedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Sensors::Magnetometer> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::Magnetometer> {};
template<> struct hash<winrt::Windows::Devices::Sensors::MagnetometerReading> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::MagnetometerReading> {};
template<> struct hash<winrt::Windows::Devices::Sensors::MagnetometerReadingChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::MagnetometerReadingChangedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Sensors::OrientationSensor> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::OrientationSensor> {};
template<> struct hash<winrt::Windows::Devices::Sensors::OrientationSensorReading> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::OrientationSensorReading> {};
template<> struct hash<winrt::Windows::Devices::Sensors::OrientationSensorReadingChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::OrientationSensorReadingChangedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Sensors::Pedometer> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::Pedometer> {};
template<> struct hash<winrt::Windows::Devices::Sensors::PedometerDataThreshold> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::PedometerDataThreshold> {};
template<> struct hash<winrt::Windows::Devices::Sensors::PedometerReading> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::PedometerReading> {};
template<> struct hash<winrt::Windows::Devices::Sensors::PedometerReadingChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::PedometerReadingChangedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Sensors::ProximitySensor> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::ProximitySensor> {};
template<> struct hash<winrt::Windows::Devices::Sensors::ProximitySensorDataThreshold> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::ProximitySensorDataThreshold> {};
template<> struct hash<winrt::Windows::Devices::Sensors::ProximitySensorDisplayOnOffController> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::ProximitySensorDisplayOnOffController> {};
template<> struct hash<winrt::Windows::Devices::Sensors::ProximitySensorReading> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::ProximitySensorReading> {};
template<> struct hash<winrt::Windows::Devices::Sensors::ProximitySensorReadingChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::ProximitySensorReadingChangedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Sensors::SensorDataThresholdTriggerDetails> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::SensorDataThresholdTriggerDetails> {};
template<> struct hash<winrt::Windows::Devices::Sensors::SensorQuaternion> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::SensorQuaternion> {};
template<> struct hash<winrt::Windows::Devices::Sensors::SensorRotationMatrix> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::SensorRotationMatrix> {};
template<> struct hash<winrt::Windows::Devices::Sensors::SimpleOrientationSensor> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::SimpleOrientationSensor> {};
template<> struct hash<winrt::Windows::Devices::Sensors::SimpleOrientationSensorOrientationChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Sensors::SimpleOrientationSensorOrientationChangedEventArgs> {};

}
