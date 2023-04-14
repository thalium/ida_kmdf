// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.System.Power.2.h"
#include "winrt/impl/Windows.Devices.Power.2.h"
#include "winrt/Windows.Devices.h"

namespace winrt::impl {

template <typename D> hstring consume_Windows_Devices_Power_IBattery<D>::DeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Power::IBattery)->get_DeviceId(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Power::BatteryReport consume_Windows_Devices_Power_IBattery<D>::GetReport() const
{
    Windows::Devices::Power::BatteryReport result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Power::IBattery)->GetReport(put_abi(result)));
    return result;
}

template <typename D> winrt::event_token consume_Windows_Devices_Power_IBattery<D>::ReportUpdated(Windows::Foundation::TypedEventHandler<Windows::Devices::Power::Battery, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Power::IBattery)->add_ReportUpdated(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Power_IBattery<D>::ReportUpdated_revoker consume_Windows_Devices_Power_IBattery<D>::ReportUpdated(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Power::Battery, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, ReportUpdated_revoker>(this, ReportUpdated(handler));
}

template <typename D> void consume_Windows_Devices_Power_IBattery<D>::ReportUpdated(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Power::IBattery)->remove_ReportUpdated(get_abi(token)));
}

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_Devices_Power_IBatteryReport<D>::ChargeRateInMilliwatts() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Power::IBatteryReport)->get_ChargeRateInMilliwatts(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_Devices_Power_IBatteryReport<D>::DesignCapacityInMilliwattHours() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Power::IBatteryReport)->get_DesignCapacityInMilliwattHours(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_Devices_Power_IBatteryReport<D>::FullChargeCapacityInMilliwattHours() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Power::IBatteryReport)->get_FullChargeCapacityInMilliwattHours(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<int32_t> consume_Windows_Devices_Power_IBatteryReport<D>::RemainingCapacityInMilliwattHours() const
{
    Windows::Foundation::IReference<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Power::IBatteryReport)->get_RemainingCapacityInMilliwattHours(put_abi(value)));
    return value;
}

template <typename D> Windows::System::Power::BatteryStatus consume_Windows_Devices_Power_IBatteryReport<D>::Status() const
{
    Windows::System::Power::BatteryStatus value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Power::IBatteryReport)->get_Status(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Power::Battery consume_Windows_Devices_Power_IBatteryStatics<D>::AggregateBattery() const
{
    Windows::Devices::Power::Battery result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Power::IBatteryStatics)->get_AggregateBattery(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Power::Battery> consume_Windows_Devices_Power_IBatteryStatics<D>::FromIdAsync(param::hstring const& deviceId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Power::Battery> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Power::IBatteryStatics)->FromIdAsync(get_abi(deviceId), put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Devices_Power_IBatteryStatics<D>::GetDeviceSelector() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::Devices::Power::IBatteryStatics)->GetDeviceSelector(put_abi(result)));
    return result;
}

template <typename D>
struct produce<D, Windows::Devices::Power::IBattery> : produce_base<D, Windows::Devices::Power::IBattery>
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

    int32_t WINRT_CALL GetReport(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetReport, WINRT_WRAP(Windows::Devices::Power::BatteryReport));
            *result = detach_from<Windows::Devices::Power::BatteryReport>(this->shim().GetReport());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_ReportUpdated(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportUpdated, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Power::Battery, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().ReportUpdated(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Power::Battery, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ReportUpdated(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ReportUpdated, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ReportUpdated(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Devices::Power::IBatteryReport> : produce_base<D, Windows::Devices::Power::IBatteryReport>
{
    int32_t WINRT_CALL get_ChargeRateInMilliwatts(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChargeRateInMilliwatts, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().ChargeRateInMilliwatts());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DesignCapacityInMilliwattHours(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesignCapacityInMilliwattHours, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().DesignCapacityInMilliwattHours());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FullChargeCapacityInMilliwattHours(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FullChargeCapacityInMilliwattHours, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().FullChargeCapacityInMilliwattHours());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RemainingCapacityInMilliwattHours(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemainingCapacityInMilliwattHours, WINRT_WRAP(Windows::Foundation::IReference<int32_t>));
            *value = detach_from<Windows::Foundation::IReference<int32_t>>(this->shim().RemainingCapacityInMilliwattHours());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Status(Windows::System::Power::BatteryStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::System::Power::BatteryStatus));
            *value = detach_from<Windows::System::Power::BatteryStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Power::IBatteryStatics> : produce_base<D, Windows::Devices::Power::IBatteryStatics>
{
    int32_t WINRT_CALL get_AggregateBattery(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AggregateBattery, WINRT_WRAP(Windows::Devices::Power::Battery));
            *result = detach_from<Windows::Devices::Power::Battery>(this->shim().AggregateBattery());
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
            WINRT_ASSERT_DECLARATION(FromIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Power::Battery>), hstring const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Power::Battery>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
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

}

WINRT_EXPORT namespace winrt::Windows::Devices::Power {

inline Windows::Devices::Power::Battery Battery::AggregateBattery()
{
    return impl::call_factory<Battery, Windows::Devices::Power::IBatteryStatics>([&](auto&& f) { return f.AggregateBattery(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::Power::Battery> Battery::FromIdAsync(param::hstring const& deviceId)
{
    return impl::call_factory<Battery, Windows::Devices::Power::IBatteryStatics>([&](auto&& f) { return f.FromIdAsync(deviceId); });
}

inline hstring Battery::GetDeviceSelector()
{
    return impl::call_factory<Battery, Windows::Devices::Power::IBatteryStatics>([&](auto&& f) { return f.GetDeviceSelector(); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Devices::Power::IBattery> : winrt::impl::hash_base<winrt::Windows::Devices::Power::IBattery> {};
template<> struct hash<winrt::Windows::Devices::Power::IBatteryReport> : winrt::impl::hash_base<winrt::Windows::Devices::Power::IBatteryReport> {};
template<> struct hash<winrt::Windows::Devices::Power::IBatteryStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Power::IBatteryStatics> {};
template<> struct hash<winrt::Windows::Devices::Power::Battery> : winrt::impl::hash_base<winrt::Windows::Devices::Power::Battery> {};
template<> struct hash<winrt::Windows::Devices::Power::BatteryReport> : winrt::impl::hash_base<winrt::Windows::Devices::Power::BatteryReport> {};

}
