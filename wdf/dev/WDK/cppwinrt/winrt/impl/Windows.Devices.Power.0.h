// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::System::Power {

enum class BatteryStatus;

}

WINRT_EXPORT namespace winrt::Windows::Devices::Power {

struct IBattery;
struct IBatteryReport;
struct IBatteryStatics;
struct Battery;
struct BatteryReport;

}

namespace winrt::impl {

template <> struct category<Windows::Devices::Power::IBattery>{ using type = interface_category; };
template <> struct category<Windows::Devices::Power::IBatteryReport>{ using type = interface_category; };
template <> struct category<Windows::Devices::Power::IBatteryStatics>{ using type = interface_category; };
template <> struct category<Windows::Devices::Power::Battery>{ using type = class_category; };
template <> struct category<Windows::Devices::Power::BatteryReport>{ using type = class_category; };
template <> struct name<Windows::Devices::Power::IBattery>{ static constexpr auto & value{ L"Windows.Devices.Power.IBattery" }; };
template <> struct name<Windows::Devices::Power::IBatteryReport>{ static constexpr auto & value{ L"Windows.Devices.Power.IBatteryReport" }; };
template <> struct name<Windows::Devices::Power::IBatteryStatics>{ static constexpr auto & value{ L"Windows.Devices.Power.IBatteryStatics" }; };
template <> struct name<Windows::Devices::Power::Battery>{ static constexpr auto & value{ L"Windows.Devices.Power.Battery" }; };
template <> struct name<Windows::Devices::Power::BatteryReport>{ static constexpr auto & value{ L"Windows.Devices.Power.BatteryReport" }; };
template <> struct guid_storage<Windows::Devices::Power::IBattery>{ static constexpr guid value{ 0xBC894FC6,0x0072,0x47C8,{ 0x8B,0x5D,0x61,0x4A,0xAA,0x7A,0x43,0x7E } }; };
template <> struct guid_storage<Windows::Devices::Power::IBatteryReport>{ static constexpr guid value{ 0xC9858C3A,0x4E13,0x420A,{ 0xA8,0xD0,0x24,0xF1,0x8F,0x39,0x54,0x01 } }; };
template <> struct guid_storage<Windows::Devices::Power::IBatteryStatics>{ static constexpr guid value{ 0x79CD72B6,0x9E5E,0x4452,{ 0xBE,0xA6,0xDF,0xCD,0x54,0x1E,0x59,0x7F } }; };
template <> struct default_interface<Windows::Devices::Power::Battery>{ using type = Windows::Devices::Power::IBattery; };
template <> struct default_interface<Windows::Devices::Power::BatteryReport>{ using type = Windows::Devices::Power::IBatteryReport; };

template <> struct abi<Windows::Devices::Power::IBattery>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_DeviceId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetReport(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL add_ReportUpdated(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_ReportUpdated(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Power::IBatteryReport>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_ChargeRateInMilliwatts(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DesignCapacityInMilliwattHours(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_FullChargeCapacityInMilliwattHours(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RemainingCapacityInMilliwattHours(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Status(Windows::System::Power::BatteryStatus* value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Power::IBatteryStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_AggregateBattery(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL FromIdAsync(void* deviceId, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL GetDeviceSelector(void** result) noexcept = 0;
};};

template <typename D>
struct consume_Windows_Devices_Power_IBattery
{
    hstring DeviceId() const;
    Windows::Devices::Power::BatteryReport GetReport() const;
    winrt::event_token ReportUpdated(Windows::Foundation::TypedEventHandler<Windows::Devices::Power::Battery, Windows::Foundation::IInspectable> const& handler) const;
    using ReportUpdated_revoker = impl::event_revoker<Windows::Devices::Power::IBattery, &impl::abi_t<Windows::Devices::Power::IBattery>::remove_ReportUpdated>;
    ReportUpdated_revoker ReportUpdated(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Power::Battery, Windows::Foundation::IInspectable> const& handler) const;
    void ReportUpdated(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::Devices::Power::IBattery> { template <typename D> using type = consume_Windows_Devices_Power_IBattery<D>; };

template <typename D>
struct consume_Windows_Devices_Power_IBatteryReport
{
    Windows::Foundation::IReference<int32_t> ChargeRateInMilliwatts() const;
    Windows::Foundation::IReference<int32_t> DesignCapacityInMilliwattHours() const;
    Windows::Foundation::IReference<int32_t> FullChargeCapacityInMilliwattHours() const;
    Windows::Foundation::IReference<int32_t> RemainingCapacityInMilliwattHours() const;
    Windows::System::Power::BatteryStatus Status() const;
};
template <> struct consume<Windows::Devices::Power::IBatteryReport> { template <typename D> using type = consume_Windows_Devices_Power_IBatteryReport<D>; };

template <typename D>
struct consume_Windows_Devices_Power_IBatteryStatics
{
    Windows::Devices::Power::Battery AggregateBattery() const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::Power::Battery> FromIdAsync(param::hstring const& deviceId) const;
    hstring GetDeviceSelector() const;
};
template <> struct consume<Windows::Devices::Power::IBatteryStatics> { template <typename D> using type = consume_Windows_Devices_Power_IBatteryStatics<D>; };

}
