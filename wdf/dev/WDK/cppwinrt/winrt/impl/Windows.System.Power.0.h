// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::System::Power {

enum class BatteryStatus : int32_t
{
    NotPresent = 0,
    Discharging = 1,
    Idle = 2,
    Charging = 3,
};

enum class EnergySaverStatus : int32_t
{
    Disabled = 0,
    Off = 1,
    On = 2,
};

enum class PowerSupplyStatus : int32_t
{
    NotPresent = 0,
    Inadequate = 1,
    Adequate = 2,
};

struct IBackgroundEnergyManagerStatics;
struct IForegroundEnergyManagerStatics;
struct IPowerManagerStatics;
struct BackgroundEnergyManager;
struct ForegroundEnergyManager;
struct PowerManager;

}

namespace winrt::impl {

template <> struct category<Windows::System::Power::IBackgroundEnergyManagerStatics>{ using type = interface_category; };
template <> struct category<Windows::System::Power::IForegroundEnergyManagerStatics>{ using type = interface_category; };
template <> struct category<Windows::System::Power::IPowerManagerStatics>{ using type = interface_category; };
template <> struct category<Windows::System::Power::BackgroundEnergyManager>{ using type = class_category; };
template <> struct category<Windows::System::Power::ForegroundEnergyManager>{ using type = class_category; };
template <> struct category<Windows::System::Power::PowerManager>{ using type = class_category; };
template <> struct category<Windows::System::Power::BatteryStatus>{ using type = enum_category; };
template <> struct category<Windows::System::Power::EnergySaverStatus>{ using type = enum_category; };
template <> struct category<Windows::System::Power::PowerSupplyStatus>{ using type = enum_category; };
template <> struct name<Windows::System::Power::IBackgroundEnergyManagerStatics>{ static constexpr auto & value{ L"Windows.System.Power.IBackgroundEnergyManagerStatics" }; };
template <> struct name<Windows::System::Power::IForegroundEnergyManagerStatics>{ static constexpr auto & value{ L"Windows.System.Power.IForegroundEnergyManagerStatics" }; };
template <> struct name<Windows::System::Power::IPowerManagerStatics>{ static constexpr auto & value{ L"Windows.System.Power.IPowerManagerStatics" }; };
template <> struct name<Windows::System::Power::BackgroundEnergyManager>{ static constexpr auto & value{ L"Windows.System.Power.BackgroundEnergyManager" }; };
template <> struct name<Windows::System::Power::ForegroundEnergyManager>{ static constexpr auto & value{ L"Windows.System.Power.ForegroundEnergyManager" }; };
template <> struct name<Windows::System::Power::PowerManager>{ static constexpr auto & value{ L"Windows.System.Power.PowerManager" }; };
template <> struct name<Windows::System::Power::BatteryStatus>{ static constexpr auto & value{ L"Windows.System.Power.BatteryStatus" }; };
template <> struct name<Windows::System::Power::EnergySaverStatus>{ static constexpr auto & value{ L"Windows.System.Power.EnergySaverStatus" }; };
template <> struct name<Windows::System::Power::PowerSupplyStatus>{ static constexpr auto & value{ L"Windows.System.Power.PowerSupplyStatus" }; };
template <> struct guid_storage<Windows::System::Power::IBackgroundEnergyManagerStatics>{ static constexpr guid value{ 0xB3161D95,0x1180,0x4376,{ 0x96,0xE1,0x40,0x95,0x56,0x81,0x47,0xCE } }; };
template <> struct guid_storage<Windows::System::Power::IForegroundEnergyManagerStatics>{ static constexpr guid value{ 0x9FF86872,0xE677,0x4814,{ 0x9A,0x20,0x53,0x37,0xCA,0x73,0x2B,0x98 } }; };
template <> struct guid_storage<Windows::System::Power::IPowerManagerStatics>{ static constexpr guid value{ 0x1394825D,0x62CE,0x4364,{ 0x98,0xD5,0xAA,0x28,0xC7,0xFB,0xD1,0x5B } }; };

template <> struct abi<Windows::System::Power::IBackgroundEnergyManagerStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_LowUsageLevel(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_NearMaxAcceptableUsageLevel(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MaxAcceptableUsageLevel(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ExcessiveUsageLevel(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_NearTerminationUsageLevel(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_TerminationUsageLevel(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RecentEnergyUsage(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RecentEnergyUsageLevel(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL add_RecentEnergyUsageIncreased(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_RecentEnergyUsageIncreased(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_RecentEnergyUsageReturnedToLow(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_RecentEnergyUsageReturnedToLow(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::System::Power::IForegroundEnergyManagerStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_LowUsageLevel(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_NearMaxAcceptableUsageLevel(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MaxAcceptableUsageLevel(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ExcessiveUsageLevel(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RecentEnergyUsage(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RecentEnergyUsageLevel(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL add_RecentEnergyUsageIncreased(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_RecentEnergyUsageIncreased(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_RecentEnergyUsageReturnedToLow(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_RecentEnergyUsageReturnedToLow(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::System::Power::IPowerManagerStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_EnergySaverStatus(Windows::System::Power::EnergySaverStatus* value) noexcept = 0;
    virtual int32_t WINRT_CALL add_EnergySaverStatusChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_EnergySaverStatusChanged(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL get_BatteryStatus(Windows::System::Power::BatteryStatus* value) noexcept = 0;
    virtual int32_t WINRT_CALL add_BatteryStatusChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_BatteryStatusChanged(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL get_PowerSupplyStatus(Windows::System::Power::PowerSupplyStatus* value) noexcept = 0;
    virtual int32_t WINRT_CALL add_PowerSupplyStatusChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_PowerSupplyStatusChanged(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL get_RemainingChargePercent(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL add_RemainingChargePercentChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_RemainingChargePercentChanged(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL get_RemainingDischargeTime(Windows::Foundation::TimeSpan* value) noexcept = 0;
    virtual int32_t WINRT_CALL add_RemainingDischargeTimeChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_RemainingDischargeTimeChanged(winrt::event_token token) noexcept = 0;
};};

template <typename D>
struct consume_Windows_System_Power_IBackgroundEnergyManagerStatics
{
    uint32_t LowUsageLevel() const;
    uint32_t NearMaxAcceptableUsageLevel() const;
    uint32_t MaxAcceptableUsageLevel() const;
    uint32_t ExcessiveUsageLevel() const;
    uint32_t NearTerminationUsageLevel() const;
    uint32_t TerminationUsageLevel() const;
    uint32_t RecentEnergyUsage() const;
    uint32_t RecentEnergyUsageLevel() const;
    winrt::event_token RecentEnergyUsageIncreased(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const;
    using RecentEnergyUsageIncreased_revoker = impl::event_revoker<Windows::System::Power::IBackgroundEnergyManagerStatics, &impl::abi_t<Windows::System::Power::IBackgroundEnergyManagerStatics>::remove_RecentEnergyUsageIncreased>;
    RecentEnergyUsageIncreased_revoker RecentEnergyUsageIncreased(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const;
    void RecentEnergyUsageIncreased(winrt::event_token const& token) const noexcept;
    winrt::event_token RecentEnergyUsageReturnedToLow(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const;
    using RecentEnergyUsageReturnedToLow_revoker = impl::event_revoker<Windows::System::Power::IBackgroundEnergyManagerStatics, &impl::abi_t<Windows::System::Power::IBackgroundEnergyManagerStatics>::remove_RecentEnergyUsageReturnedToLow>;
    RecentEnergyUsageReturnedToLow_revoker RecentEnergyUsageReturnedToLow(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const;
    void RecentEnergyUsageReturnedToLow(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::System::Power::IBackgroundEnergyManagerStatics> { template <typename D> using type = consume_Windows_System_Power_IBackgroundEnergyManagerStatics<D>; };

template <typename D>
struct consume_Windows_System_Power_IForegroundEnergyManagerStatics
{
    uint32_t LowUsageLevel() const;
    uint32_t NearMaxAcceptableUsageLevel() const;
    uint32_t MaxAcceptableUsageLevel() const;
    uint32_t ExcessiveUsageLevel() const;
    uint32_t RecentEnergyUsage() const;
    uint32_t RecentEnergyUsageLevel() const;
    winrt::event_token RecentEnergyUsageIncreased(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const;
    using RecentEnergyUsageIncreased_revoker = impl::event_revoker<Windows::System::Power::IForegroundEnergyManagerStatics, &impl::abi_t<Windows::System::Power::IForegroundEnergyManagerStatics>::remove_RecentEnergyUsageIncreased>;
    RecentEnergyUsageIncreased_revoker RecentEnergyUsageIncreased(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const;
    void RecentEnergyUsageIncreased(winrt::event_token const& token) const noexcept;
    winrt::event_token RecentEnergyUsageReturnedToLow(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const;
    using RecentEnergyUsageReturnedToLow_revoker = impl::event_revoker<Windows::System::Power::IForegroundEnergyManagerStatics, &impl::abi_t<Windows::System::Power::IForegroundEnergyManagerStatics>::remove_RecentEnergyUsageReturnedToLow>;
    RecentEnergyUsageReturnedToLow_revoker RecentEnergyUsageReturnedToLow(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const;
    void RecentEnergyUsageReturnedToLow(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::System::Power::IForegroundEnergyManagerStatics> { template <typename D> using type = consume_Windows_System_Power_IForegroundEnergyManagerStatics<D>; };

template <typename D>
struct consume_Windows_System_Power_IPowerManagerStatics
{
    Windows::System::Power::EnergySaverStatus EnergySaverStatus() const;
    winrt::event_token EnergySaverStatusChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const;
    using EnergySaverStatusChanged_revoker = impl::event_revoker<Windows::System::Power::IPowerManagerStatics, &impl::abi_t<Windows::System::Power::IPowerManagerStatics>::remove_EnergySaverStatusChanged>;
    EnergySaverStatusChanged_revoker EnergySaverStatusChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const;
    void EnergySaverStatusChanged(winrt::event_token const& token) const noexcept;
    Windows::System::Power::BatteryStatus BatteryStatus() const;
    winrt::event_token BatteryStatusChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const;
    using BatteryStatusChanged_revoker = impl::event_revoker<Windows::System::Power::IPowerManagerStatics, &impl::abi_t<Windows::System::Power::IPowerManagerStatics>::remove_BatteryStatusChanged>;
    BatteryStatusChanged_revoker BatteryStatusChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const;
    void BatteryStatusChanged(winrt::event_token const& token) const noexcept;
    Windows::System::Power::PowerSupplyStatus PowerSupplyStatus() const;
    winrt::event_token PowerSupplyStatusChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const;
    using PowerSupplyStatusChanged_revoker = impl::event_revoker<Windows::System::Power::IPowerManagerStatics, &impl::abi_t<Windows::System::Power::IPowerManagerStatics>::remove_PowerSupplyStatusChanged>;
    PowerSupplyStatusChanged_revoker PowerSupplyStatusChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const;
    void PowerSupplyStatusChanged(winrt::event_token const& token) const noexcept;
    int32_t RemainingChargePercent() const;
    winrt::event_token RemainingChargePercentChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const;
    using RemainingChargePercentChanged_revoker = impl::event_revoker<Windows::System::Power::IPowerManagerStatics, &impl::abi_t<Windows::System::Power::IPowerManagerStatics>::remove_RemainingChargePercentChanged>;
    RemainingChargePercentChanged_revoker RemainingChargePercentChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const;
    void RemainingChargePercentChanged(winrt::event_token const& token) const noexcept;
    Windows::Foundation::TimeSpan RemainingDischargeTime() const;
    winrt::event_token RemainingDischargeTimeChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const;
    using RemainingDischargeTimeChanged_revoker = impl::event_revoker<Windows::System::Power::IPowerManagerStatics, &impl::abi_t<Windows::System::Power::IPowerManagerStatics>::remove_RemainingDischargeTimeChanged>;
    RemainingDischargeTimeChanged_revoker RemainingDischargeTimeChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const;
    void RemainingDischargeTimeChanged(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::System::Power::IPowerManagerStatics> { template <typename D> using type = consume_Windows_System_Power_IPowerManagerStatics<D>; };

}
