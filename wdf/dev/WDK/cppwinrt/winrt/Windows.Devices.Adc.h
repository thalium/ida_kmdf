// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Devices.Adc.Provider.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Devices.Adc.2.h"
#include "winrt/Windows.Devices.h"

namespace winrt::impl {

template <typename D> Windows::Devices::Adc::AdcController consume_Windows_Devices_Adc_IAdcChannel<D>::Controller() const
{
    Windows::Devices::Adc::AdcController value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Adc::IAdcChannel)->get_Controller(put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_Devices_Adc_IAdcChannel<D>::ReadValue() const
{
    int32_t result{};
    check_hresult(WINRT_SHIM(Windows::Devices::Adc::IAdcChannel)->ReadValue(&result));
    return result;
}

template <typename D> double consume_Windows_Devices_Adc_IAdcChannel<D>::ReadRatio() const
{
    double result{};
    check_hresult(WINRT_SHIM(Windows::Devices::Adc::IAdcChannel)->ReadRatio(&result));
    return result;
}

template <typename D> int32_t consume_Windows_Devices_Adc_IAdcController<D>::ChannelCount() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Adc::IAdcController)->get_ChannelCount(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Devices_Adc_IAdcController<D>::ResolutionInBits() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Adc::IAdcController)->get_ResolutionInBits(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Devices_Adc_IAdcController<D>::MinValue() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Adc::IAdcController)->get_MinValue(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Devices_Adc_IAdcController<D>::MaxValue() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Adc::IAdcController)->get_MaxValue(&value));
    return value;
}

template <typename D> Windows::Devices::Adc::AdcChannelMode consume_Windows_Devices_Adc_IAdcController<D>::ChannelMode() const
{
    Windows::Devices::Adc::AdcChannelMode value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Adc::IAdcController)->get_ChannelMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Adc_IAdcController<D>::ChannelMode(Windows::Devices::Adc::AdcChannelMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Adc::IAdcController)->put_ChannelMode(get_abi(value)));
}

template <typename D> bool consume_Windows_Devices_Adc_IAdcController<D>::IsChannelModeSupported(Windows::Devices::Adc::AdcChannelMode const& channelMode) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::Devices::Adc::IAdcController)->IsChannelModeSupported(get_abi(channelMode), &result));
    return result;
}

template <typename D> Windows::Devices::Adc::AdcChannel consume_Windows_Devices_Adc_IAdcController<D>::OpenChannel(int32_t channelNumber) const
{
    Windows::Devices::Adc::AdcChannel result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Adc::IAdcController)->OpenChannel(channelNumber, put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Adc::AdcController>> consume_Windows_Devices_Adc_IAdcControllerStatics<D>::GetControllersAsync(Windows::Devices::Adc::Provider::IAdcProvider const& provider) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Adc::AdcController>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Adc::IAdcControllerStatics)->GetControllersAsync(get_abi(provider), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Adc::AdcController> consume_Windows_Devices_Adc_IAdcControllerStatics2<D>::GetDefaultAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Adc::AdcController> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Adc::IAdcControllerStatics2)->GetDefaultAsync(put_abi(operation)));
    return operation;
}

template <typename D>
struct produce<D, Windows::Devices::Adc::IAdcChannel> : produce_base<D, Windows::Devices::Adc::IAdcChannel>
{
    int32_t WINRT_CALL get_Controller(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Controller, WINRT_WRAP(Windows::Devices::Adc::AdcController));
            *value = detach_from<Windows::Devices::Adc::AdcController>(this->shim().Controller());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReadValue(int32_t* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadValue, WINRT_WRAP(int32_t));
            *result = detach_from<int32_t>(this->shim().ReadValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReadRatio(double* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadRatio, WINRT_WRAP(double));
            *result = detach_from<double>(this->shim().ReadRatio());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Adc::IAdcController> : produce_base<D, Windows::Devices::Adc::IAdcController>
{
    int32_t WINRT_CALL get_ChannelCount(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChannelCount, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().ChannelCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ResolutionInBits(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResolutionInBits, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().ResolutionInBits());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MinValue(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinValue, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().MinValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxValue(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxValue, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().MaxValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ChannelMode(Windows::Devices::Adc::AdcChannelMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChannelMode, WINRT_WRAP(Windows::Devices::Adc::AdcChannelMode));
            *value = detach_from<Windows::Devices::Adc::AdcChannelMode>(this->shim().ChannelMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ChannelMode(Windows::Devices::Adc::AdcChannelMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChannelMode, WINRT_WRAP(void), Windows::Devices::Adc::AdcChannelMode const&);
            this->shim().ChannelMode(*reinterpret_cast<Windows::Devices::Adc::AdcChannelMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsChannelModeSupported(Windows::Devices::Adc::AdcChannelMode channelMode, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsChannelModeSupported, WINRT_WRAP(bool), Windows::Devices::Adc::AdcChannelMode const&);
            *result = detach_from<bool>(this->shim().IsChannelModeSupported(*reinterpret_cast<Windows::Devices::Adc::AdcChannelMode const*>(&channelMode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL OpenChannel(int32_t channelNumber, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OpenChannel, WINRT_WRAP(Windows::Devices::Adc::AdcChannel), int32_t);
            *result = detach_from<Windows::Devices::Adc::AdcChannel>(this->shim().OpenChannel(channelNumber));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Adc::IAdcControllerStatics> : produce_base<D, Windows::Devices::Adc::IAdcControllerStatics>
{
    int32_t WINRT_CALL GetControllersAsync(void* provider, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetControllersAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Adc::AdcController>>), Windows::Devices::Adc::Provider::IAdcProvider const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Adc::AdcController>>>(this->shim().GetControllersAsync(*reinterpret_cast<Windows::Devices::Adc::Provider::IAdcProvider const*>(&provider)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Adc::IAdcControllerStatics2> : produce_base<D, Windows::Devices::Adc::IAdcControllerStatics2>
{
    int32_t WINRT_CALL GetDefaultAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefaultAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Adc::AdcController>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Adc::AdcController>>(this->shim().GetDefaultAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Devices::Adc {

inline Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Adc::AdcController>> AdcController::GetControllersAsync(Windows::Devices::Adc::Provider::IAdcProvider const& provider)
{
    return impl::call_factory<AdcController, Windows::Devices::Adc::IAdcControllerStatics>([&](auto&& f) { return f.GetControllersAsync(provider); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::Adc::AdcController> AdcController::GetDefaultAsync()
{
    return impl::call_factory<AdcController, Windows::Devices::Adc::IAdcControllerStatics2>([&](auto&& f) { return f.GetDefaultAsync(); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Devices::Adc::IAdcChannel> : winrt::impl::hash_base<winrt::Windows::Devices::Adc::IAdcChannel> {};
template<> struct hash<winrt::Windows::Devices::Adc::IAdcController> : winrt::impl::hash_base<winrt::Windows::Devices::Adc::IAdcController> {};
template<> struct hash<winrt::Windows::Devices::Adc::IAdcControllerStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Adc::IAdcControllerStatics> {};
template<> struct hash<winrt::Windows::Devices::Adc::IAdcControllerStatics2> : winrt::impl::hash_base<winrt::Windows::Devices::Adc::IAdcControllerStatics2> {};
template<> struct hash<winrt::Windows::Devices::Adc::AdcChannel> : winrt::impl::hash_base<winrt::Windows::Devices::Adc::AdcChannel> {};
template<> struct hash<winrt::Windows::Devices::Adc::AdcController> : winrt::impl::hash_base<winrt::Windows::Devices::Adc::AdcController> {};

}
