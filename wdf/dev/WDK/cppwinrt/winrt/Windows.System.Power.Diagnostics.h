// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.System.Power.Diagnostics.2.h"
#include "winrt/Windows.System.Power.h"

namespace winrt::impl {

template <typename D> double consume_Windows_System_Power_Diagnostics_IBackgroundEnergyDiagnosticsStatics<D>::DeviceSpecificConversionFactor() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::System::Power::Diagnostics::IBackgroundEnergyDiagnosticsStatics)->get_DeviceSpecificConversionFactor(&value));
    return value;
}

template <typename D> uint64_t consume_Windows_System_Power_Diagnostics_IBackgroundEnergyDiagnosticsStatics<D>::ComputeTotalEnergyUsage() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::System::Power::Diagnostics::IBackgroundEnergyDiagnosticsStatics)->ComputeTotalEnergyUsage(&value));
    return value;
}

template <typename D> void consume_Windows_System_Power_Diagnostics_IBackgroundEnergyDiagnosticsStatics<D>::ResetTotalEnergyUsage() const
{
    check_hresult(WINRT_SHIM(Windows::System::Power::Diagnostics::IBackgroundEnergyDiagnosticsStatics)->ResetTotalEnergyUsage());
}

template <typename D> double consume_Windows_System_Power_Diagnostics_IForegroundEnergyDiagnosticsStatics<D>::DeviceSpecificConversionFactor() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::System::Power::Diagnostics::IForegroundEnergyDiagnosticsStatics)->get_DeviceSpecificConversionFactor(&value));
    return value;
}

template <typename D> uint64_t consume_Windows_System_Power_Diagnostics_IForegroundEnergyDiagnosticsStatics<D>::ComputeTotalEnergyUsage() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::System::Power::Diagnostics::IForegroundEnergyDiagnosticsStatics)->ComputeTotalEnergyUsage(&value));
    return value;
}

template <typename D> void consume_Windows_System_Power_Diagnostics_IForegroundEnergyDiagnosticsStatics<D>::ResetTotalEnergyUsage() const
{
    check_hresult(WINRT_SHIM(Windows::System::Power::Diagnostics::IForegroundEnergyDiagnosticsStatics)->ResetTotalEnergyUsage());
}

template <typename D>
struct produce<D, Windows::System::Power::Diagnostics::IBackgroundEnergyDiagnosticsStatics> : produce_base<D, Windows::System::Power::Diagnostics::IBackgroundEnergyDiagnosticsStatics>
{
    int32_t WINRT_CALL get_DeviceSpecificConversionFactor(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceSpecificConversionFactor, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().DeviceSpecificConversionFactor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ComputeTotalEnergyUsage(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ComputeTotalEnergyUsage, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().ComputeTotalEnergyUsage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ResetTotalEnergyUsage() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResetTotalEnergyUsage, WINRT_WRAP(void));
            this->shim().ResetTotalEnergyUsage();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::Power::Diagnostics::IForegroundEnergyDiagnosticsStatics> : produce_base<D, Windows::System::Power::Diagnostics::IForegroundEnergyDiagnosticsStatics>
{
    int32_t WINRT_CALL get_DeviceSpecificConversionFactor(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceSpecificConversionFactor, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().DeviceSpecificConversionFactor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ComputeTotalEnergyUsage(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ComputeTotalEnergyUsage, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().ComputeTotalEnergyUsage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ResetTotalEnergyUsage() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResetTotalEnergyUsage, WINRT_WRAP(void));
            this->shim().ResetTotalEnergyUsage();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::System::Power::Diagnostics {

inline double BackgroundEnergyDiagnostics::DeviceSpecificConversionFactor()
{
    return impl::call_factory<BackgroundEnergyDiagnostics, Windows::System::Power::Diagnostics::IBackgroundEnergyDiagnosticsStatics>([&](auto&& f) { return f.DeviceSpecificConversionFactor(); });
}

inline uint64_t BackgroundEnergyDiagnostics::ComputeTotalEnergyUsage()
{
    return impl::call_factory<BackgroundEnergyDiagnostics, Windows::System::Power::Diagnostics::IBackgroundEnergyDiagnosticsStatics>([&](auto&& f) { return f.ComputeTotalEnergyUsage(); });
}

inline void BackgroundEnergyDiagnostics::ResetTotalEnergyUsage()
{
    impl::call_factory<BackgroundEnergyDiagnostics, Windows::System::Power::Diagnostics::IBackgroundEnergyDiagnosticsStatics>([&](auto&& f) { return f.ResetTotalEnergyUsage(); });
}

inline double ForegroundEnergyDiagnostics::DeviceSpecificConversionFactor()
{
    return impl::call_factory<ForegroundEnergyDiagnostics, Windows::System::Power::Diagnostics::IForegroundEnergyDiagnosticsStatics>([&](auto&& f) { return f.DeviceSpecificConversionFactor(); });
}

inline uint64_t ForegroundEnergyDiagnostics::ComputeTotalEnergyUsage()
{
    return impl::call_factory<ForegroundEnergyDiagnostics, Windows::System::Power::Diagnostics::IForegroundEnergyDiagnosticsStatics>([&](auto&& f) { return f.ComputeTotalEnergyUsage(); });
}

inline void ForegroundEnergyDiagnostics::ResetTotalEnergyUsage()
{
    impl::call_factory<ForegroundEnergyDiagnostics, Windows::System::Power::Diagnostics::IForegroundEnergyDiagnosticsStatics>([&](auto&& f) { return f.ResetTotalEnergyUsage(); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::System::Power::Diagnostics::IBackgroundEnergyDiagnosticsStatics> : winrt::impl::hash_base<winrt::Windows::System::Power::Diagnostics::IBackgroundEnergyDiagnosticsStatics> {};
template<> struct hash<winrt::Windows::System::Power::Diagnostics::IForegroundEnergyDiagnosticsStatics> : winrt::impl::hash_base<winrt::Windows::System::Power::Diagnostics::IForegroundEnergyDiagnosticsStatics> {};
template<> struct hash<winrt::Windows::System::Power::Diagnostics::BackgroundEnergyDiagnostics> : winrt::impl::hash_base<winrt::Windows::System::Power::Diagnostics::BackgroundEnergyDiagnostics> {};
template<> struct hash<winrt::Windows::System::Power::Diagnostics::ForegroundEnergyDiagnostics> : winrt::impl::hash_base<winrt::Windows::System::Power::Diagnostics::ForegroundEnergyDiagnostics> {};

}
