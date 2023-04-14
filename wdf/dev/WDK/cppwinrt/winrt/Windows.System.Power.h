// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.System.Power.2.h"
#include "winrt/Windows.System.h"

namespace winrt::impl {

template <typename D> uint32_t consume_Windows_System_Power_IBackgroundEnergyManagerStatics<D>::LowUsageLevel() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::System::Power::IBackgroundEnergyManagerStatics)->get_LowUsageLevel(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_System_Power_IBackgroundEnergyManagerStatics<D>::NearMaxAcceptableUsageLevel() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::System::Power::IBackgroundEnergyManagerStatics)->get_NearMaxAcceptableUsageLevel(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_System_Power_IBackgroundEnergyManagerStatics<D>::MaxAcceptableUsageLevel() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::System::Power::IBackgroundEnergyManagerStatics)->get_MaxAcceptableUsageLevel(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_System_Power_IBackgroundEnergyManagerStatics<D>::ExcessiveUsageLevel() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::System::Power::IBackgroundEnergyManagerStatics)->get_ExcessiveUsageLevel(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_System_Power_IBackgroundEnergyManagerStatics<D>::NearTerminationUsageLevel() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::System::Power::IBackgroundEnergyManagerStatics)->get_NearTerminationUsageLevel(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_System_Power_IBackgroundEnergyManagerStatics<D>::TerminationUsageLevel() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::System::Power::IBackgroundEnergyManagerStatics)->get_TerminationUsageLevel(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_System_Power_IBackgroundEnergyManagerStatics<D>::RecentEnergyUsage() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::System::Power::IBackgroundEnergyManagerStatics)->get_RecentEnergyUsage(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_System_Power_IBackgroundEnergyManagerStatics<D>::RecentEnergyUsageLevel() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::System::Power::IBackgroundEnergyManagerStatics)->get_RecentEnergyUsageLevel(&value));
    return value;
}

template <typename D> winrt::event_token consume_Windows_System_Power_IBackgroundEnergyManagerStatics<D>::RecentEnergyUsageIncreased(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::System::Power::IBackgroundEnergyManagerStatics)->add_RecentEnergyUsageIncreased(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_System_Power_IBackgroundEnergyManagerStatics<D>::RecentEnergyUsageIncreased_revoker consume_Windows_System_Power_IBackgroundEnergyManagerStatics<D>::RecentEnergyUsageIncreased(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, RecentEnergyUsageIncreased_revoker>(this, RecentEnergyUsageIncreased(handler));
}

template <typename D> void consume_Windows_System_Power_IBackgroundEnergyManagerStatics<D>::RecentEnergyUsageIncreased(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::System::Power::IBackgroundEnergyManagerStatics)->remove_RecentEnergyUsageIncreased(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_System_Power_IBackgroundEnergyManagerStatics<D>::RecentEnergyUsageReturnedToLow(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::System::Power::IBackgroundEnergyManagerStatics)->add_RecentEnergyUsageReturnedToLow(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_System_Power_IBackgroundEnergyManagerStatics<D>::RecentEnergyUsageReturnedToLow_revoker consume_Windows_System_Power_IBackgroundEnergyManagerStatics<D>::RecentEnergyUsageReturnedToLow(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, RecentEnergyUsageReturnedToLow_revoker>(this, RecentEnergyUsageReturnedToLow(handler));
}

template <typename D> void consume_Windows_System_Power_IBackgroundEnergyManagerStatics<D>::RecentEnergyUsageReturnedToLow(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::System::Power::IBackgroundEnergyManagerStatics)->remove_RecentEnergyUsageReturnedToLow(get_abi(token)));
}

template <typename D> uint32_t consume_Windows_System_Power_IForegroundEnergyManagerStatics<D>::LowUsageLevel() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::System::Power::IForegroundEnergyManagerStatics)->get_LowUsageLevel(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_System_Power_IForegroundEnergyManagerStatics<D>::NearMaxAcceptableUsageLevel() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::System::Power::IForegroundEnergyManagerStatics)->get_NearMaxAcceptableUsageLevel(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_System_Power_IForegroundEnergyManagerStatics<D>::MaxAcceptableUsageLevel() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::System::Power::IForegroundEnergyManagerStatics)->get_MaxAcceptableUsageLevel(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_System_Power_IForegroundEnergyManagerStatics<D>::ExcessiveUsageLevel() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::System::Power::IForegroundEnergyManagerStatics)->get_ExcessiveUsageLevel(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_System_Power_IForegroundEnergyManagerStatics<D>::RecentEnergyUsage() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::System::Power::IForegroundEnergyManagerStatics)->get_RecentEnergyUsage(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_System_Power_IForegroundEnergyManagerStatics<D>::RecentEnergyUsageLevel() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::System::Power::IForegroundEnergyManagerStatics)->get_RecentEnergyUsageLevel(&value));
    return value;
}

template <typename D> winrt::event_token consume_Windows_System_Power_IForegroundEnergyManagerStatics<D>::RecentEnergyUsageIncreased(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::System::Power::IForegroundEnergyManagerStatics)->add_RecentEnergyUsageIncreased(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_System_Power_IForegroundEnergyManagerStatics<D>::RecentEnergyUsageIncreased_revoker consume_Windows_System_Power_IForegroundEnergyManagerStatics<D>::RecentEnergyUsageIncreased(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, RecentEnergyUsageIncreased_revoker>(this, RecentEnergyUsageIncreased(handler));
}

template <typename D> void consume_Windows_System_Power_IForegroundEnergyManagerStatics<D>::RecentEnergyUsageIncreased(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::System::Power::IForegroundEnergyManagerStatics)->remove_RecentEnergyUsageIncreased(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_System_Power_IForegroundEnergyManagerStatics<D>::RecentEnergyUsageReturnedToLow(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::System::Power::IForegroundEnergyManagerStatics)->add_RecentEnergyUsageReturnedToLow(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_System_Power_IForegroundEnergyManagerStatics<D>::RecentEnergyUsageReturnedToLow_revoker consume_Windows_System_Power_IForegroundEnergyManagerStatics<D>::RecentEnergyUsageReturnedToLow(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, RecentEnergyUsageReturnedToLow_revoker>(this, RecentEnergyUsageReturnedToLow(handler));
}

template <typename D> void consume_Windows_System_Power_IForegroundEnergyManagerStatics<D>::RecentEnergyUsageReturnedToLow(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::System::Power::IForegroundEnergyManagerStatics)->remove_RecentEnergyUsageReturnedToLow(get_abi(token)));
}

template <typename D> Windows::System::Power::EnergySaverStatus consume_Windows_System_Power_IPowerManagerStatics<D>::EnergySaverStatus() const
{
    Windows::System::Power::EnergySaverStatus value{};
    check_hresult(WINRT_SHIM(Windows::System::Power::IPowerManagerStatics)->get_EnergySaverStatus(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_System_Power_IPowerManagerStatics<D>::EnergySaverStatusChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::System::Power::IPowerManagerStatics)->add_EnergySaverStatusChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_System_Power_IPowerManagerStatics<D>::EnergySaverStatusChanged_revoker consume_Windows_System_Power_IPowerManagerStatics<D>::EnergySaverStatusChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, EnergySaverStatusChanged_revoker>(this, EnergySaverStatusChanged(handler));
}

template <typename D> void consume_Windows_System_Power_IPowerManagerStatics<D>::EnergySaverStatusChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::System::Power::IPowerManagerStatics)->remove_EnergySaverStatusChanged(get_abi(token)));
}

template <typename D> Windows::System::Power::BatteryStatus consume_Windows_System_Power_IPowerManagerStatics<D>::BatteryStatus() const
{
    Windows::System::Power::BatteryStatus value{};
    check_hresult(WINRT_SHIM(Windows::System::Power::IPowerManagerStatics)->get_BatteryStatus(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_System_Power_IPowerManagerStatics<D>::BatteryStatusChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::System::Power::IPowerManagerStatics)->add_BatteryStatusChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_System_Power_IPowerManagerStatics<D>::BatteryStatusChanged_revoker consume_Windows_System_Power_IPowerManagerStatics<D>::BatteryStatusChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, BatteryStatusChanged_revoker>(this, BatteryStatusChanged(handler));
}

template <typename D> void consume_Windows_System_Power_IPowerManagerStatics<D>::BatteryStatusChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::System::Power::IPowerManagerStatics)->remove_BatteryStatusChanged(get_abi(token)));
}

template <typename D> Windows::System::Power::PowerSupplyStatus consume_Windows_System_Power_IPowerManagerStatics<D>::PowerSupplyStatus() const
{
    Windows::System::Power::PowerSupplyStatus value{};
    check_hresult(WINRT_SHIM(Windows::System::Power::IPowerManagerStatics)->get_PowerSupplyStatus(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_System_Power_IPowerManagerStatics<D>::PowerSupplyStatusChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::System::Power::IPowerManagerStatics)->add_PowerSupplyStatusChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_System_Power_IPowerManagerStatics<D>::PowerSupplyStatusChanged_revoker consume_Windows_System_Power_IPowerManagerStatics<D>::PowerSupplyStatusChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, PowerSupplyStatusChanged_revoker>(this, PowerSupplyStatusChanged(handler));
}

template <typename D> void consume_Windows_System_Power_IPowerManagerStatics<D>::PowerSupplyStatusChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::System::Power::IPowerManagerStatics)->remove_PowerSupplyStatusChanged(get_abi(token)));
}

template <typename D> int32_t consume_Windows_System_Power_IPowerManagerStatics<D>::RemainingChargePercent() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::System::Power::IPowerManagerStatics)->get_RemainingChargePercent(&value));
    return value;
}

template <typename D> winrt::event_token consume_Windows_System_Power_IPowerManagerStatics<D>::RemainingChargePercentChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::System::Power::IPowerManagerStatics)->add_RemainingChargePercentChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_System_Power_IPowerManagerStatics<D>::RemainingChargePercentChanged_revoker consume_Windows_System_Power_IPowerManagerStatics<D>::RemainingChargePercentChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, RemainingChargePercentChanged_revoker>(this, RemainingChargePercentChanged(handler));
}

template <typename D> void consume_Windows_System_Power_IPowerManagerStatics<D>::RemainingChargePercentChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::System::Power::IPowerManagerStatics)->remove_RemainingChargePercentChanged(get_abi(token)));
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_System_Power_IPowerManagerStatics<D>::RemainingDischargeTime() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::System::Power::IPowerManagerStatics)->get_RemainingDischargeTime(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_System_Power_IPowerManagerStatics<D>::RemainingDischargeTimeChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::System::Power::IPowerManagerStatics)->add_RemainingDischargeTimeChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_System_Power_IPowerManagerStatics<D>::RemainingDischargeTimeChanged_revoker consume_Windows_System_Power_IPowerManagerStatics<D>::RemainingDischargeTimeChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, RemainingDischargeTimeChanged_revoker>(this, RemainingDischargeTimeChanged(handler));
}

template <typename D> void consume_Windows_System_Power_IPowerManagerStatics<D>::RemainingDischargeTimeChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::System::Power::IPowerManagerStatics)->remove_RemainingDischargeTimeChanged(get_abi(token)));
}

template <typename D>
struct produce<D, Windows::System::Power::IBackgroundEnergyManagerStatics> : produce_base<D, Windows::System::Power::IBackgroundEnergyManagerStatics>
{
    int32_t WINRT_CALL get_LowUsageLevel(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LowUsageLevel, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().LowUsageLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NearMaxAcceptableUsageLevel(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NearMaxAcceptableUsageLevel, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().NearMaxAcceptableUsageLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxAcceptableUsageLevel(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxAcceptableUsageLevel, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().MaxAcceptableUsageLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExcessiveUsageLevel(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExcessiveUsageLevel, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().ExcessiveUsageLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NearTerminationUsageLevel(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NearTerminationUsageLevel, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().NearTerminationUsageLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TerminationUsageLevel(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TerminationUsageLevel, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().TerminationUsageLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RecentEnergyUsage(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RecentEnergyUsage, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().RecentEnergyUsage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RecentEnergyUsageLevel(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RecentEnergyUsageLevel, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().RecentEnergyUsageLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_RecentEnergyUsageIncreased(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RecentEnergyUsageIncreased, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().RecentEnergyUsageIncreased(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_RecentEnergyUsageIncreased(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(RecentEnergyUsageIncreased, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().RecentEnergyUsageIncreased(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_RecentEnergyUsageReturnedToLow(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RecentEnergyUsageReturnedToLow, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().RecentEnergyUsageReturnedToLow(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_RecentEnergyUsageReturnedToLow(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(RecentEnergyUsageReturnedToLow, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().RecentEnergyUsageReturnedToLow(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::System::Power::IForegroundEnergyManagerStatics> : produce_base<D, Windows::System::Power::IForegroundEnergyManagerStatics>
{
    int32_t WINRT_CALL get_LowUsageLevel(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LowUsageLevel, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().LowUsageLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NearMaxAcceptableUsageLevel(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NearMaxAcceptableUsageLevel, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().NearMaxAcceptableUsageLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxAcceptableUsageLevel(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxAcceptableUsageLevel, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().MaxAcceptableUsageLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExcessiveUsageLevel(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExcessiveUsageLevel, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().ExcessiveUsageLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RecentEnergyUsage(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RecentEnergyUsage, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().RecentEnergyUsage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RecentEnergyUsageLevel(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RecentEnergyUsageLevel, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().RecentEnergyUsageLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_RecentEnergyUsageIncreased(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RecentEnergyUsageIncreased, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().RecentEnergyUsageIncreased(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_RecentEnergyUsageIncreased(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(RecentEnergyUsageIncreased, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().RecentEnergyUsageIncreased(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_RecentEnergyUsageReturnedToLow(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RecentEnergyUsageReturnedToLow, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().RecentEnergyUsageReturnedToLow(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_RecentEnergyUsageReturnedToLow(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(RecentEnergyUsageReturnedToLow, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().RecentEnergyUsageReturnedToLow(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::System::Power::IPowerManagerStatics> : produce_base<D, Windows::System::Power::IPowerManagerStatics>
{
    int32_t WINRT_CALL get_EnergySaverStatus(Windows::System::Power::EnergySaverStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnergySaverStatus, WINRT_WRAP(Windows::System::Power::EnergySaverStatus));
            *value = detach_from<Windows::System::Power::EnergySaverStatus>(this->shim().EnergySaverStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_EnergySaverStatusChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnergySaverStatusChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().EnergySaverStatusChanged(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_EnergySaverStatusChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(EnergySaverStatusChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().EnergySaverStatusChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL get_BatteryStatus(Windows::System::Power::BatteryStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BatteryStatus, WINRT_WRAP(Windows::System::Power::BatteryStatus));
            *value = detach_from<Windows::System::Power::BatteryStatus>(this->shim().BatteryStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_BatteryStatusChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BatteryStatusChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().BatteryStatusChanged(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_BatteryStatusChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(BatteryStatusChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().BatteryStatusChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL get_PowerSupplyStatus(Windows::System::Power::PowerSupplyStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PowerSupplyStatus, WINRT_WRAP(Windows::System::Power::PowerSupplyStatus));
            *value = detach_from<Windows::System::Power::PowerSupplyStatus>(this->shim().PowerSupplyStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_PowerSupplyStatusChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PowerSupplyStatusChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().PowerSupplyStatusChanged(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PowerSupplyStatusChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PowerSupplyStatusChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PowerSupplyStatusChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL get_RemainingChargePercent(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemainingChargePercent, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().RemainingChargePercent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_RemainingChargePercentChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemainingChargePercentChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().RemainingChargePercentChanged(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_RemainingChargePercentChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(RemainingChargePercentChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().RemainingChargePercentChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL get_RemainingDischargeTime(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemainingDischargeTime, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().RemainingDischargeTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_RemainingDischargeTimeChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemainingDischargeTimeChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().RemainingDischargeTimeChanged(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_RemainingDischargeTimeChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(RemainingDischargeTimeChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().RemainingDischargeTimeChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

}

WINRT_EXPORT namespace winrt::Windows::System::Power {

inline uint32_t BackgroundEnergyManager::LowUsageLevel()
{
    return impl::call_factory<BackgroundEnergyManager, Windows::System::Power::IBackgroundEnergyManagerStatics>([&](auto&& f) { return f.LowUsageLevel(); });
}

inline uint32_t BackgroundEnergyManager::NearMaxAcceptableUsageLevel()
{
    return impl::call_factory<BackgroundEnergyManager, Windows::System::Power::IBackgroundEnergyManagerStatics>([&](auto&& f) { return f.NearMaxAcceptableUsageLevel(); });
}

inline uint32_t BackgroundEnergyManager::MaxAcceptableUsageLevel()
{
    return impl::call_factory<BackgroundEnergyManager, Windows::System::Power::IBackgroundEnergyManagerStatics>([&](auto&& f) { return f.MaxAcceptableUsageLevel(); });
}

inline uint32_t BackgroundEnergyManager::ExcessiveUsageLevel()
{
    return impl::call_factory<BackgroundEnergyManager, Windows::System::Power::IBackgroundEnergyManagerStatics>([&](auto&& f) { return f.ExcessiveUsageLevel(); });
}

inline uint32_t BackgroundEnergyManager::NearTerminationUsageLevel()
{
    return impl::call_factory<BackgroundEnergyManager, Windows::System::Power::IBackgroundEnergyManagerStatics>([&](auto&& f) { return f.NearTerminationUsageLevel(); });
}

inline uint32_t BackgroundEnergyManager::TerminationUsageLevel()
{
    return impl::call_factory<BackgroundEnergyManager, Windows::System::Power::IBackgroundEnergyManagerStatics>([&](auto&& f) { return f.TerminationUsageLevel(); });
}

inline uint32_t BackgroundEnergyManager::RecentEnergyUsage()
{
    return impl::call_factory<BackgroundEnergyManager, Windows::System::Power::IBackgroundEnergyManagerStatics>([&](auto&& f) { return f.RecentEnergyUsage(); });
}

inline uint32_t BackgroundEnergyManager::RecentEnergyUsageLevel()
{
    return impl::call_factory<BackgroundEnergyManager, Windows::System::Power::IBackgroundEnergyManagerStatics>([&](auto&& f) { return f.RecentEnergyUsageLevel(); });
}

inline winrt::event_token BackgroundEnergyManager::RecentEnergyUsageIncreased(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    return impl::call_factory<BackgroundEnergyManager, Windows::System::Power::IBackgroundEnergyManagerStatics>([&](auto&& f) { return f.RecentEnergyUsageIncreased(handler); });
}

inline BackgroundEnergyManager::RecentEnergyUsageIncreased_revoker BackgroundEnergyManager::RecentEnergyUsageIncreased(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    auto f = get_activation_factory<BackgroundEnergyManager, Windows::System::Power::IBackgroundEnergyManagerStatics>();
    return { f, f.RecentEnergyUsageIncreased(handler) };
}

inline void BackgroundEnergyManager::RecentEnergyUsageIncreased(winrt::event_token const& token)
{
    impl::call_factory<BackgroundEnergyManager, Windows::System::Power::IBackgroundEnergyManagerStatics>([&](auto&& f) { return f.RecentEnergyUsageIncreased(token); });
}

inline winrt::event_token BackgroundEnergyManager::RecentEnergyUsageReturnedToLow(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    return impl::call_factory<BackgroundEnergyManager, Windows::System::Power::IBackgroundEnergyManagerStatics>([&](auto&& f) { return f.RecentEnergyUsageReturnedToLow(handler); });
}

inline BackgroundEnergyManager::RecentEnergyUsageReturnedToLow_revoker BackgroundEnergyManager::RecentEnergyUsageReturnedToLow(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    auto f = get_activation_factory<BackgroundEnergyManager, Windows::System::Power::IBackgroundEnergyManagerStatics>();
    return { f, f.RecentEnergyUsageReturnedToLow(handler) };
}

inline void BackgroundEnergyManager::RecentEnergyUsageReturnedToLow(winrt::event_token const& token)
{
    impl::call_factory<BackgroundEnergyManager, Windows::System::Power::IBackgroundEnergyManagerStatics>([&](auto&& f) { return f.RecentEnergyUsageReturnedToLow(token); });
}

inline uint32_t ForegroundEnergyManager::LowUsageLevel()
{
    return impl::call_factory<ForegroundEnergyManager, Windows::System::Power::IForegroundEnergyManagerStatics>([&](auto&& f) { return f.LowUsageLevel(); });
}

inline uint32_t ForegroundEnergyManager::NearMaxAcceptableUsageLevel()
{
    return impl::call_factory<ForegroundEnergyManager, Windows::System::Power::IForegroundEnergyManagerStatics>([&](auto&& f) { return f.NearMaxAcceptableUsageLevel(); });
}

inline uint32_t ForegroundEnergyManager::MaxAcceptableUsageLevel()
{
    return impl::call_factory<ForegroundEnergyManager, Windows::System::Power::IForegroundEnergyManagerStatics>([&](auto&& f) { return f.MaxAcceptableUsageLevel(); });
}

inline uint32_t ForegroundEnergyManager::ExcessiveUsageLevel()
{
    return impl::call_factory<ForegroundEnergyManager, Windows::System::Power::IForegroundEnergyManagerStatics>([&](auto&& f) { return f.ExcessiveUsageLevel(); });
}

inline uint32_t ForegroundEnergyManager::RecentEnergyUsage()
{
    return impl::call_factory<ForegroundEnergyManager, Windows::System::Power::IForegroundEnergyManagerStatics>([&](auto&& f) { return f.RecentEnergyUsage(); });
}

inline uint32_t ForegroundEnergyManager::RecentEnergyUsageLevel()
{
    return impl::call_factory<ForegroundEnergyManager, Windows::System::Power::IForegroundEnergyManagerStatics>([&](auto&& f) { return f.RecentEnergyUsageLevel(); });
}

inline winrt::event_token ForegroundEnergyManager::RecentEnergyUsageIncreased(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    return impl::call_factory<ForegroundEnergyManager, Windows::System::Power::IForegroundEnergyManagerStatics>([&](auto&& f) { return f.RecentEnergyUsageIncreased(handler); });
}

inline ForegroundEnergyManager::RecentEnergyUsageIncreased_revoker ForegroundEnergyManager::RecentEnergyUsageIncreased(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    auto f = get_activation_factory<ForegroundEnergyManager, Windows::System::Power::IForegroundEnergyManagerStatics>();
    return { f, f.RecentEnergyUsageIncreased(handler) };
}

inline void ForegroundEnergyManager::RecentEnergyUsageIncreased(winrt::event_token const& token)
{
    impl::call_factory<ForegroundEnergyManager, Windows::System::Power::IForegroundEnergyManagerStatics>([&](auto&& f) { return f.RecentEnergyUsageIncreased(token); });
}

inline winrt::event_token ForegroundEnergyManager::RecentEnergyUsageReturnedToLow(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    return impl::call_factory<ForegroundEnergyManager, Windows::System::Power::IForegroundEnergyManagerStatics>([&](auto&& f) { return f.RecentEnergyUsageReturnedToLow(handler); });
}

inline ForegroundEnergyManager::RecentEnergyUsageReturnedToLow_revoker ForegroundEnergyManager::RecentEnergyUsageReturnedToLow(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    auto f = get_activation_factory<ForegroundEnergyManager, Windows::System::Power::IForegroundEnergyManagerStatics>();
    return { f, f.RecentEnergyUsageReturnedToLow(handler) };
}

inline void ForegroundEnergyManager::RecentEnergyUsageReturnedToLow(winrt::event_token const& token)
{
    impl::call_factory<ForegroundEnergyManager, Windows::System::Power::IForegroundEnergyManagerStatics>([&](auto&& f) { return f.RecentEnergyUsageReturnedToLow(token); });
}

inline Windows::System::Power::EnergySaverStatus PowerManager::EnergySaverStatus()
{
    return impl::call_factory<PowerManager, Windows::System::Power::IPowerManagerStatics>([&](auto&& f) { return f.EnergySaverStatus(); });
}

inline winrt::event_token PowerManager::EnergySaverStatusChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    return impl::call_factory<PowerManager, Windows::System::Power::IPowerManagerStatics>([&](auto&& f) { return f.EnergySaverStatusChanged(handler); });
}

inline PowerManager::EnergySaverStatusChanged_revoker PowerManager::EnergySaverStatusChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    auto f = get_activation_factory<PowerManager, Windows::System::Power::IPowerManagerStatics>();
    return { f, f.EnergySaverStatusChanged(handler) };
}

inline void PowerManager::EnergySaverStatusChanged(winrt::event_token const& token)
{
    impl::call_factory<PowerManager, Windows::System::Power::IPowerManagerStatics>([&](auto&& f) { return f.EnergySaverStatusChanged(token); });
}

inline Windows::System::Power::BatteryStatus PowerManager::BatteryStatus()
{
    return impl::call_factory<PowerManager, Windows::System::Power::IPowerManagerStatics>([&](auto&& f) { return f.BatteryStatus(); });
}

inline winrt::event_token PowerManager::BatteryStatusChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    return impl::call_factory<PowerManager, Windows::System::Power::IPowerManagerStatics>([&](auto&& f) { return f.BatteryStatusChanged(handler); });
}

inline PowerManager::BatteryStatusChanged_revoker PowerManager::BatteryStatusChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    auto f = get_activation_factory<PowerManager, Windows::System::Power::IPowerManagerStatics>();
    return { f, f.BatteryStatusChanged(handler) };
}

inline void PowerManager::BatteryStatusChanged(winrt::event_token const& token)
{
    impl::call_factory<PowerManager, Windows::System::Power::IPowerManagerStatics>([&](auto&& f) { return f.BatteryStatusChanged(token); });
}

inline Windows::System::Power::PowerSupplyStatus PowerManager::PowerSupplyStatus()
{
    return impl::call_factory<PowerManager, Windows::System::Power::IPowerManagerStatics>([&](auto&& f) { return f.PowerSupplyStatus(); });
}

inline winrt::event_token PowerManager::PowerSupplyStatusChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    return impl::call_factory<PowerManager, Windows::System::Power::IPowerManagerStatics>([&](auto&& f) { return f.PowerSupplyStatusChanged(handler); });
}

inline PowerManager::PowerSupplyStatusChanged_revoker PowerManager::PowerSupplyStatusChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    auto f = get_activation_factory<PowerManager, Windows::System::Power::IPowerManagerStatics>();
    return { f, f.PowerSupplyStatusChanged(handler) };
}

inline void PowerManager::PowerSupplyStatusChanged(winrt::event_token const& token)
{
    impl::call_factory<PowerManager, Windows::System::Power::IPowerManagerStatics>([&](auto&& f) { return f.PowerSupplyStatusChanged(token); });
}

inline int32_t PowerManager::RemainingChargePercent()
{
    return impl::call_factory<PowerManager, Windows::System::Power::IPowerManagerStatics>([&](auto&& f) { return f.RemainingChargePercent(); });
}

inline winrt::event_token PowerManager::RemainingChargePercentChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    return impl::call_factory<PowerManager, Windows::System::Power::IPowerManagerStatics>([&](auto&& f) { return f.RemainingChargePercentChanged(handler); });
}

inline PowerManager::RemainingChargePercentChanged_revoker PowerManager::RemainingChargePercentChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    auto f = get_activation_factory<PowerManager, Windows::System::Power::IPowerManagerStatics>();
    return { f, f.RemainingChargePercentChanged(handler) };
}

inline void PowerManager::RemainingChargePercentChanged(winrt::event_token const& token)
{
    impl::call_factory<PowerManager, Windows::System::Power::IPowerManagerStatics>([&](auto&& f) { return f.RemainingChargePercentChanged(token); });
}

inline Windows::Foundation::TimeSpan PowerManager::RemainingDischargeTime()
{
    return impl::call_factory<PowerManager, Windows::System::Power::IPowerManagerStatics>([&](auto&& f) { return f.RemainingDischargeTime(); });
}

inline winrt::event_token PowerManager::RemainingDischargeTimeChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    return impl::call_factory<PowerManager, Windows::System::Power::IPowerManagerStatics>([&](auto&& f) { return f.RemainingDischargeTimeChanged(handler); });
}

inline PowerManager::RemainingDischargeTimeChanged_revoker PowerManager::RemainingDischargeTimeChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler)
{
    auto f = get_activation_factory<PowerManager, Windows::System::Power::IPowerManagerStatics>();
    return { f, f.RemainingDischargeTimeChanged(handler) };
}

inline void PowerManager::RemainingDischargeTimeChanged(winrt::event_token const& token)
{
    impl::call_factory<PowerManager, Windows::System::Power::IPowerManagerStatics>([&](auto&& f) { return f.RemainingDischargeTimeChanged(token); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::System::Power::IBackgroundEnergyManagerStatics> : winrt::impl::hash_base<winrt::Windows::System::Power::IBackgroundEnergyManagerStatics> {};
template<> struct hash<winrt::Windows::System::Power::IForegroundEnergyManagerStatics> : winrt::impl::hash_base<winrt::Windows::System::Power::IForegroundEnergyManagerStatics> {};
template<> struct hash<winrt::Windows::System::Power::IPowerManagerStatics> : winrt::impl::hash_base<winrt::Windows::System::Power::IPowerManagerStatics> {};
template<> struct hash<winrt::Windows::System::Power::BackgroundEnergyManager> : winrt::impl::hash_base<winrt::Windows::System::Power::BackgroundEnergyManager> {};
template<> struct hash<winrt::Windows::System::Power::ForegroundEnergyManager> : winrt::impl::hash_base<winrt::Windows::System::Power::ForegroundEnergyManager> {};
template<> struct hash<winrt::Windows::System::Power::PowerManager> : winrt::impl::hash_base<winrt::Windows::System::Power::PowerManager> {};

}
