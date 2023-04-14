// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.System.Power.1.h"

WINRT_EXPORT namespace winrt::Windows::System::Power {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::System::Power {

struct BackgroundEnergyManager
{
    BackgroundEnergyManager() = delete;
    static uint32_t LowUsageLevel();
    static uint32_t NearMaxAcceptableUsageLevel();
    static uint32_t MaxAcceptableUsageLevel();
    static uint32_t ExcessiveUsageLevel();
    static uint32_t NearTerminationUsageLevel();
    static uint32_t TerminationUsageLevel();
    static uint32_t RecentEnergyUsage();
    static uint32_t RecentEnergyUsageLevel();
    static winrt::event_token RecentEnergyUsageIncreased(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler);
    using RecentEnergyUsageIncreased_revoker = impl::factory_event_revoker<Windows::System::Power::IBackgroundEnergyManagerStatics, &impl::abi_t<Windows::System::Power::IBackgroundEnergyManagerStatics>::remove_RecentEnergyUsageIncreased>;
    static RecentEnergyUsageIncreased_revoker RecentEnergyUsageIncreased(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler);
    static void RecentEnergyUsageIncreased(winrt::event_token const& token);
    static winrt::event_token RecentEnergyUsageReturnedToLow(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler);
    using RecentEnergyUsageReturnedToLow_revoker = impl::factory_event_revoker<Windows::System::Power::IBackgroundEnergyManagerStatics, &impl::abi_t<Windows::System::Power::IBackgroundEnergyManagerStatics>::remove_RecentEnergyUsageReturnedToLow>;
    static RecentEnergyUsageReturnedToLow_revoker RecentEnergyUsageReturnedToLow(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler);
    static void RecentEnergyUsageReturnedToLow(winrt::event_token const& token);
};

struct ForegroundEnergyManager
{
    ForegroundEnergyManager() = delete;
    static uint32_t LowUsageLevel();
    static uint32_t NearMaxAcceptableUsageLevel();
    static uint32_t MaxAcceptableUsageLevel();
    static uint32_t ExcessiveUsageLevel();
    static uint32_t RecentEnergyUsage();
    static uint32_t RecentEnergyUsageLevel();
    static winrt::event_token RecentEnergyUsageIncreased(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler);
    using RecentEnergyUsageIncreased_revoker = impl::factory_event_revoker<Windows::System::Power::IForegroundEnergyManagerStatics, &impl::abi_t<Windows::System::Power::IForegroundEnergyManagerStatics>::remove_RecentEnergyUsageIncreased>;
    static RecentEnergyUsageIncreased_revoker RecentEnergyUsageIncreased(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler);
    static void RecentEnergyUsageIncreased(winrt::event_token const& token);
    static winrt::event_token RecentEnergyUsageReturnedToLow(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler);
    using RecentEnergyUsageReturnedToLow_revoker = impl::factory_event_revoker<Windows::System::Power::IForegroundEnergyManagerStatics, &impl::abi_t<Windows::System::Power::IForegroundEnergyManagerStatics>::remove_RecentEnergyUsageReturnedToLow>;
    static RecentEnergyUsageReturnedToLow_revoker RecentEnergyUsageReturnedToLow(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler);
    static void RecentEnergyUsageReturnedToLow(winrt::event_token const& token);
};

struct PowerManager
{
    PowerManager() = delete;
    static Windows::System::Power::EnergySaverStatus EnergySaverStatus();
    static winrt::event_token EnergySaverStatusChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler);
    using EnergySaverStatusChanged_revoker = impl::factory_event_revoker<Windows::System::Power::IPowerManagerStatics, &impl::abi_t<Windows::System::Power::IPowerManagerStatics>::remove_EnergySaverStatusChanged>;
    static EnergySaverStatusChanged_revoker EnergySaverStatusChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler);
    static void EnergySaverStatusChanged(winrt::event_token const& token);
    static Windows::System::Power::BatteryStatus BatteryStatus();
    static winrt::event_token BatteryStatusChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler);
    using BatteryStatusChanged_revoker = impl::factory_event_revoker<Windows::System::Power::IPowerManagerStatics, &impl::abi_t<Windows::System::Power::IPowerManagerStatics>::remove_BatteryStatusChanged>;
    static BatteryStatusChanged_revoker BatteryStatusChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler);
    static void BatteryStatusChanged(winrt::event_token const& token);
    static Windows::System::Power::PowerSupplyStatus PowerSupplyStatus();
    static winrt::event_token PowerSupplyStatusChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler);
    using PowerSupplyStatusChanged_revoker = impl::factory_event_revoker<Windows::System::Power::IPowerManagerStatics, &impl::abi_t<Windows::System::Power::IPowerManagerStatics>::remove_PowerSupplyStatusChanged>;
    static PowerSupplyStatusChanged_revoker PowerSupplyStatusChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler);
    static void PowerSupplyStatusChanged(winrt::event_token const& token);
    static int32_t RemainingChargePercent();
    static winrt::event_token RemainingChargePercentChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler);
    using RemainingChargePercentChanged_revoker = impl::factory_event_revoker<Windows::System::Power::IPowerManagerStatics, &impl::abi_t<Windows::System::Power::IPowerManagerStatics>::remove_RemainingChargePercentChanged>;
    static RemainingChargePercentChanged_revoker RemainingChargePercentChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler);
    static void RemainingChargePercentChanged(winrt::event_token const& token);
    static Windows::Foundation::TimeSpan RemainingDischargeTime();
    static winrt::event_token RemainingDischargeTimeChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler);
    using RemainingDischargeTimeChanged_revoker = impl::factory_event_revoker<Windows::System::Power::IPowerManagerStatics, &impl::abi_t<Windows::System::Power::IPowerManagerStatics>::remove_RemainingDischargeTimeChanged>;
    static RemainingDischargeTimeChanged_revoker RemainingDischargeTimeChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler);
    static void RemainingDischargeTimeChanged(winrt::event_token const& token);
};

}
