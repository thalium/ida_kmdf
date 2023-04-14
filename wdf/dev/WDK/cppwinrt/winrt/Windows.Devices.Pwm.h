// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Devices.Pwm.Provider.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Devices.Pwm.2.h"
#include "winrt/Windows.Devices.h"

namespace winrt::impl {

template <typename D> int32_t consume_Windows_Devices_Pwm_IPwmController<D>::PinCount() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Pwm::IPwmController)->get_PinCount(&value));
    return value;
}

template <typename D> double consume_Windows_Devices_Pwm_IPwmController<D>::ActualFrequency() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Pwm::IPwmController)->get_ActualFrequency(&value));
    return value;
}

template <typename D> double consume_Windows_Devices_Pwm_IPwmController<D>::SetDesiredFrequency(double desiredFrequency) const
{
    double result{};
    check_hresult(WINRT_SHIM(Windows::Devices::Pwm::IPwmController)->SetDesiredFrequency(desiredFrequency, &result));
    return result;
}

template <typename D> double consume_Windows_Devices_Pwm_IPwmController<D>::MinFrequency() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Pwm::IPwmController)->get_MinFrequency(&value));
    return value;
}

template <typename D> double consume_Windows_Devices_Pwm_IPwmController<D>::MaxFrequency() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Pwm::IPwmController)->get_MaxFrequency(&value));
    return value;
}

template <typename D> Windows::Devices::Pwm::PwmPin consume_Windows_Devices_Pwm_IPwmController<D>::OpenPin(int32_t pinNumber) const
{
    Windows::Devices::Pwm::PwmPin pin{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Pwm::IPwmController)->OpenPin(pinNumber, put_abi(pin)));
    return pin;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Pwm::PwmController>> consume_Windows_Devices_Pwm_IPwmControllerStatics<D>::GetControllersAsync(Windows::Devices::Pwm::Provider::IPwmProvider const& provider) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Pwm::PwmController>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Pwm::IPwmControllerStatics)->GetControllersAsync(get_abi(provider), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Pwm::PwmController> consume_Windows_Devices_Pwm_IPwmControllerStatics2<D>::GetDefaultAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Pwm::PwmController> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Pwm::IPwmControllerStatics2)->GetDefaultAsync(put_abi(operation)));
    return operation;
}

template <typename D> hstring consume_Windows_Devices_Pwm_IPwmControllerStatics3<D>::GetDeviceSelector() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::Devices::Pwm::IPwmControllerStatics3)->GetDeviceSelector(put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Devices_Pwm_IPwmControllerStatics3<D>::GetDeviceSelector(param::hstring const& friendlyName) const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::Devices::Pwm::IPwmControllerStatics3)->GetDeviceSelectorFromFriendlyName(get_abi(friendlyName), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Pwm::PwmController> consume_Windows_Devices_Pwm_IPwmControllerStatics3<D>::FromIdAsync(param::hstring const& deviceId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Pwm::PwmController> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Pwm::IPwmControllerStatics3)->FromIdAsync(get_abi(deviceId), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Devices::Pwm::PwmController consume_Windows_Devices_Pwm_IPwmPin<D>::Controller() const
{
    Windows::Devices::Pwm::PwmController value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Pwm::IPwmPin)->get_Controller(put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_Devices_Pwm_IPwmPin<D>::GetActiveDutyCyclePercentage() const
{
    double result{};
    check_hresult(WINRT_SHIM(Windows::Devices::Pwm::IPwmPin)->GetActiveDutyCyclePercentage(&result));
    return result;
}

template <typename D> void consume_Windows_Devices_Pwm_IPwmPin<D>::SetActiveDutyCyclePercentage(double dutyCyclePercentage) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Pwm::IPwmPin)->SetActiveDutyCyclePercentage(dutyCyclePercentage));
}

template <typename D> Windows::Devices::Pwm::PwmPulsePolarity consume_Windows_Devices_Pwm_IPwmPin<D>::Polarity() const
{
    Windows::Devices::Pwm::PwmPulsePolarity value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Pwm::IPwmPin)->get_Polarity(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Pwm_IPwmPin<D>::Polarity(Windows::Devices::Pwm::PwmPulsePolarity const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Pwm::IPwmPin)->put_Polarity(get_abi(value)));
}

template <typename D> void consume_Windows_Devices_Pwm_IPwmPin<D>::Start() const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Pwm::IPwmPin)->Start());
}

template <typename D> void consume_Windows_Devices_Pwm_IPwmPin<D>::Stop() const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Pwm::IPwmPin)->Stop());
}

template <typename D> bool consume_Windows_Devices_Pwm_IPwmPin<D>::IsStarted() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Pwm::IPwmPin)->get_IsStarted(&value));
    return value;
}

template <typename D>
struct produce<D, Windows::Devices::Pwm::IPwmController> : produce_base<D, Windows::Devices::Pwm::IPwmController>
{
    int32_t WINRT_CALL get_PinCount(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PinCount, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().PinCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ActualFrequency(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ActualFrequency, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().ActualFrequency());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetDesiredFrequency(double desiredFrequency, double* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetDesiredFrequency, WINRT_WRAP(double), double);
            *result = detach_from<double>(this->shim().SetDesiredFrequency(desiredFrequency));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MinFrequency(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinFrequency, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().MinFrequency());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxFrequency(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxFrequency, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().MaxFrequency());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL OpenPin(int32_t pinNumber, void** pin) noexcept final
    {
        try
        {
            *pin = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OpenPin, WINRT_WRAP(Windows::Devices::Pwm::PwmPin), int32_t);
            *pin = detach_from<Windows::Devices::Pwm::PwmPin>(this->shim().OpenPin(pinNumber));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Pwm::IPwmControllerStatics> : produce_base<D, Windows::Devices::Pwm::IPwmControllerStatics>
{
    int32_t WINRT_CALL GetControllersAsync(void* provider, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetControllersAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Pwm::PwmController>>), Windows::Devices::Pwm::Provider::IPwmProvider const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Pwm::PwmController>>>(this->shim().GetControllersAsync(*reinterpret_cast<Windows::Devices::Pwm::Provider::IPwmProvider const*>(&provider)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Pwm::IPwmControllerStatics2> : produce_base<D, Windows::Devices::Pwm::IPwmControllerStatics2>
{
    int32_t WINRT_CALL GetDefaultAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefaultAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Pwm::PwmController>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Pwm::PwmController>>(this->shim().GetDefaultAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Pwm::IPwmControllerStatics3> : produce_base<D, Windows::Devices::Pwm::IPwmControllerStatics3>
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

    int32_t WINRT_CALL GetDeviceSelectorFromFriendlyName(void* friendlyName, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelector, WINRT_WRAP(hstring), hstring const&);
            *result = detach_from<hstring>(this->shim().GetDeviceSelector(*reinterpret_cast<hstring const*>(&friendlyName)));
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
            WINRT_ASSERT_DECLARATION(FromIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Pwm::PwmController>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Pwm::PwmController>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Pwm::IPwmPin> : produce_base<D, Windows::Devices::Pwm::IPwmPin>
{
    int32_t WINRT_CALL get_Controller(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Controller, WINRT_WRAP(Windows::Devices::Pwm::PwmController));
            *value = detach_from<Windows::Devices::Pwm::PwmController>(this->shim().Controller());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetActiveDutyCyclePercentage(double* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetActiveDutyCyclePercentage, WINRT_WRAP(double));
            *result = detach_from<double>(this->shim().GetActiveDutyCyclePercentage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetActiveDutyCyclePercentage(double dutyCyclePercentage) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetActiveDutyCyclePercentage, WINRT_WRAP(void), double);
            this->shim().SetActiveDutyCyclePercentage(dutyCyclePercentage);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Polarity(Windows::Devices::Pwm::PwmPulsePolarity* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Polarity, WINRT_WRAP(Windows::Devices::Pwm::PwmPulsePolarity));
            *value = detach_from<Windows::Devices::Pwm::PwmPulsePolarity>(this->shim().Polarity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Polarity(Windows::Devices::Pwm::PwmPulsePolarity value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Polarity, WINRT_WRAP(void), Windows::Devices::Pwm::PwmPulsePolarity const&);
            this->shim().Polarity(*reinterpret_cast<Windows::Devices::Pwm::PwmPulsePolarity const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Start() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Start, WINRT_WRAP(void));
            this->shim().Start();
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

    int32_t WINRT_CALL get_IsStarted(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsStarted, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsStarted());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Devices::Pwm {

inline Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Pwm::PwmController>> PwmController::GetControllersAsync(Windows::Devices::Pwm::Provider::IPwmProvider const& provider)
{
    return impl::call_factory<PwmController, Windows::Devices::Pwm::IPwmControllerStatics>([&](auto&& f) { return f.GetControllersAsync(provider); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::Pwm::PwmController> PwmController::GetDefaultAsync()
{
    return impl::call_factory<PwmController, Windows::Devices::Pwm::IPwmControllerStatics2>([&](auto&& f) { return f.GetDefaultAsync(); });
}

inline hstring PwmController::GetDeviceSelector()
{
    return impl::call_factory<PwmController, Windows::Devices::Pwm::IPwmControllerStatics3>([&](auto&& f) { return f.GetDeviceSelector(); });
}

inline hstring PwmController::GetDeviceSelector(param::hstring const& friendlyName)
{
    return impl::call_factory<PwmController, Windows::Devices::Pwm::IPwmControllerStatics3>([&](auto&& f) { return f.GetDeviceSelector(friendlyName); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::Pwm::PwmController> PwmController::FromIdAsync(param::hstring const& deviceId)
{
    return impl::call_factory<PwmController, Windows::Devices::Pwm::IPwmControllerStatics3>([&](auto&& f) { return f.FromIdAsync(deviceId); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Devices::Pwm::IPwmController> : winrt::impl::hash_base<winrt::Windows::Devices::Pwm::IPwmController> {};
template<> struct hash<winrt::Windows::Devices::Pwm::IPwmControllerStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Pwm::IPwmControllerStatics> {};
template<> struct hash<winrt::Windows::Devices::Pwm::IPwmControllerStatics2> : winrt::impl::hash_base<winrt::Windows::Devices::Pwm::IPwmControllerStatics2> {};
template<> struct hash<winrt::Windows::Devices::Pwm::IPwmControllerStatics3> : winrt::impl::hash_base<winrt::Windows::Devices::Pwm::IPwmControllerStatics3> {};
template<> struct hash<winrt::Windows::Devices::Pwm::IPwmPin> : winrt::impl::hash_base<winrt::Windows::Devices::Pwm::IPwmPin> {};
template<> struct hash<winrt::Windows::Devices::Pwm::PwmController> : winrt::impl::hash_base<winrt::Windows::Devices::Pwm::PwmController> {};
template<> struct hash<winrt::Windows::Devices::Pwm::PwmPin> : winrt::impl::hash_base<winrt::Windows::Devices::Pwm::PwmPin> {};

}
