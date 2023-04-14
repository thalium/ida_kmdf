// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Devices.Gpio.Provider.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Devices.Gpio.2.h"
#include "winrt/Windows.Devices.h"

namespace winrt::impl {

template <typename D> void consume_Windows_Devices_Gpio_IGpioChangeCounter<D>::Polarity(Windows::Devices::Gpio::GpioChangePolarity const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Gpio::IGpioChangeCounter)->put_Polarity(get_abi(value)));
}

template <typename D> Windows::Devices::Gpio::GpioChangePolarity consume_Windows_Devices_Gpio_IGpioChangeCounter<D>::Polarity() const
{
    Windows::Devices::Gpio::GpioChangePolarity value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Gpio::IGpioChangeCounter)->get_Polarity(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Devices_Gpio_IGpioChangeCounter<D>::IsStarted() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Gpio::IGpioChangeCounter)->get_IsStarted(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_Gpio_IGpioChangeCounter<D>::Start() const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Gpio::IGpioChangeCounter)->Start());
}

template <typename D> void consume_Windows_Devices_Gpio_IGpioChangeCounter<D>::Stop() const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Gpio::IGpioChangeCounter)->Stop());
}

template <typename D> Windows::Devices::Gpio::GpioChangeCount consume_Windows_Devices_Gpio_IGpioChangeCounter<D>::Read() const
{
    Windows::Devices::Gpio::GpioChangeCount value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Gpio::IGpioChangeCounter)->Read(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Gpio::GpioChangeCount consume_Windows_Devices_Gpio_IGpioChangeCounter<D>::Reset() const
{
    Windows::Devices::Gpio::GpioChangeCount value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Gpio::IGpioChangeCounter)->Reset(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Gpio::GpioChangeCounter consume_Windows_Devices_Gpio_IGpioChangeCounterFactory<D>::Create(Windows::Devices::Gpio::GpioPin const& pin) const
{
    Windows::Devices::Gpio::GpioChangeCounter value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Gpio::IGpioChangeCounterFactory)->Create(get_abi(pin), put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_Devices_Gpio_IGpioChangeReader<D>::Capacity() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Gpio::IGpioChangeReader)->get_Capacity(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Devices_Gpio_IGpioChangeReader<D>::Length() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Gpio::IGpioChangeReader)->get_Length(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_Gpio_IGpioChangeReader<D>::IsEmpty() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Gpio::IGpioChangeReader)->get_IsEmpty(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_Gpio_IGpioChangeReader<D>::IsOverflowed() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Gpio::IGpioChangeReader)->get_IsOverflowed(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_Gpio_IGpioChangeReader<D>::Polarity(Windows::Devices::Gpio::GpioChangePolarity const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Gpio::IGpioChangeReader)->put_Polarity(get_abi(value)));
}

template <typename D> Windows::Devices::Gpio::GpioChangePolarity consume_Windows_Devices_Gpio_IGpioChangeReader<D>::Polarity() const
{
    Windows::Devices::Gpio::GpioChangePolarity value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Gpio::IGpioChangeReader)->get_Polarity(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Devices_Gpio_IGpioChangeReader<D>::IsStarted() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Gpio::IGpioChangeReader)->get_IsStarted(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_Gpio_IGpioChangeReader<D>::Start() const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Gpio::IGpioChangeReader)->Start());
}

template <typename D> void consume_Windows_Devices_Gpio_IGpioChangeReader<D>::Stop() const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Gpio::IGpioChangeReader)->Stop());
}

template <typename D> void consume_Windows_Devices_Gpio_IGpioChangeReader<D>::Clear() const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Gpio::IGpioChangeReader)->Clear());
}

template <typename D> Windows::Devices::Gpio::GpioChangeRecord consume_Windows_Devices_Gpio_IGpioChangeReader<D>::GetNextItem() const
{
    Windows::Devices::Gpio::GpioChangeRecord value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Gpio::IGpioChangeReader)->GetNextItem(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Gpio::GpioChangeRecord consume_Windows_Devices_Gpio_IGpioChangeReader<D>::PeekNextItem() const
{
    Windows::Devices::Gpio::GpioChangeRecord value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Gpio::IGpioChangeReader)->PeekNextItem(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::Devices::Gpio::GpioChangeRecord> consume_Windows_Devices_Gpio_IGpioChangeReader<D>::GetAllItems() const
{
    Windows::Foundation::Collections::IVector<Windows::Devices::Gpio::GpioChangeRecord> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Gpio::IGpioChangeReader)->GetAllItems(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Devices_Gpio_IGpioChangeReader<D>::WaitForItemsAsync(int32_t count) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Gpio::IGpioChangeReader)->WaitForItemsAsync(count, put_abi(operation)));
    return operation;
}

template <typename D> Windows::Devices::Gpio::GpioChangeReader consume_Windows_Devices_Gpio_IGpioChangeReaderFactory<D>::Create(Windows::Devices::Gpio::GpioPin const& pin) const
{
    Windows::Devices::Gpio::GpioChangeReader value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Gpio::IGpioChangeReaderFactory)->Create(get_abi(pin), put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Gpio::GpioChangeReader consume_Windows_Devices_Gpio_IGpioChangeReaderFactory<D>::CreateWithCapacity(Windows::Devices::Gpio::GpioPin const& pin, int32_t minCapacity) const
{
    Windows::Devices::Gpio::GpioChangeReader value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Gpio::IGpioChangeReaderFactory)->CreateWithCapacity(get_abi(pin), minCapacity, put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_Devices_Gpio_IGpioController<D>::PinCount() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Gpio::IGpioController)->get_PinCount(&value));
    return value;
}

template <typename D> Windows::Devices::Gpio::GpioPin consume_Windows_Devices_Gpio_IGpioController<D>::OpenPin(int32_t pinNumber) const
{
    Windows::Devices::Gpio::GpioPin pin{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Gpio::IGpioController)->OpenPin(pinNumber, put_abi(pin)));
    return pin;
}

template <typename D> Windows::Devices::Gpio::GpioPin consume_Windows_Devices_Gpio_IGpioController<D>::OpenPin(int32_t pinNumber, Windows::Devices::Gpio::GpioSharingMode const& sharingMode) const
{
    Windows::Devices::Gpio::GpioPin pin{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Gpio::IGpioController)->OpenPinWithSharingMode(pinNumber, get_abi(sharingMode), put_abi(pin)));
    return pin;
}

template <typename D> bool consume_Windows_Devices_Gpio_IGpioController<D>::TryOpenPin(int32_t pinNumber, Windows::Devices::Gpio::GpioSharingMode const& sharingMode, Windows::Devices::Gpio::GpioPin& pin, Windows::Devices::Gpio::GpioOpenStatus& openStatus) const
{
    bool succeeded{};
    check_hresult(WINRT_SHIM(Windows::Devices::Gpio::IGpioController)->TryOpenPin(pinNumber, get_abi(sharingMode), put_abi(pin), put_abi(openStatus), &succeeded));
    return succeeded;
}

template <typename D> Windows::Devices::Gpio::GpioController consume_Windows_Devices_Gpio_IGpioControllerStatics<D>::GetDefault() const
{
    Windows::Devices::Gpio::GpioController value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Gpio::IGpioControllerStatics)->GetDefault(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Gpio::GpioController>> consume_Windows_Devices_Gpio_IGpioControllerStatics2<D>::GetControllersAsync(Windows::Devices::Gpio::Provider::IGpioProvider const& provider) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Gpio::GpioController>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Gpio::IGpioControllerStatics2)->GetControllersAsync(get_abi(provider), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Gpio::GpioController> consume_Windows_Devices_Gpio_IGpioControllerStatics2<D>::GetDefaultAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Gpio::GpioController> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Gpio::IGpioControllerStatics2)->GetDefaultAsync(put_abi(operation)));
    return operation;
}

template <typename D> winrt::event_token consume_Windows_Devices_Gpio_IGpioPin<D>::ValueChanged(Windows::Foundation::TypedEventHandler<Windows::Devices::Gpio::GpioPin, Windows::Devices::Gpio::GpioPinValueChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Gpio::IGpioPin)->add_ValueChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Gpio_IGpioPin<D>::ValueChanged_revoker consume_Windows_Devices_Gpio_IGpioPin<D>::ValueChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Gpio::GpioPin, Windows::Devices::Gpio::GpioPinValueChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ValueChanged_revoker>(this, ValueChanged(handler));
}

template <typename D> void consume_Windows_Devices_Gpio_IGpioPin<D>::ValueChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Gpio::IGpioPin)->remove_ValueChanged(get_abi(token)));
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Devices_Gpio_IGpioPin<D>::DebounceTimeout() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Gpio::IGpioPin)->get_DebounceTimeout(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Gpio_IGpioPin<D>::DebounceTimeout(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Gpio::IGpioPin)->put_DebounceTimeout(get_abi(value)));
}

template <typename D> int32_t consume_Windows_Devices_Gpio_IGpioPin<D>::PinNumber() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Gpio::IGpioPin)->get_PinNumber(&value));
    return value;
}

template <typename D> Windows::Devices::Gpio::GpioSharingMode consume_Windows_Devices_Gpio_IGpioPin<D>::SharingMode() const
{
    Windows::Devices::Gpio::GpioSharingMode value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Gpio::IGpioPin)->get_SharingMode(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Devices_Gpio_IGpioPin<D>::IsDriveModeSupported(Windows::Devices::Gpio::GpioPinDriveMode const& driveMode) const
{
    bool supported{};
    check_hresult(WINRT_SHIM(Windows::Devices::Gpio::IGpioPin)->IsDriveModeSupported(get_abi(driveMode), &supported));
    return supported;
}

template <typename D> Windows::Devices::Gpio::GpioPinDriveMode consume_Windows_Devices_Gpio_IGpioPin<D>::GetDriveMode() const
{
    Windows::Devices::Gpio::GpioPinDriveMode value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Gpio::IGpioPin)->GetDriveMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Gpio_IGpioPin<D>::SetDriveMode(Windows::Devices::Gpio::GpioPinDriveMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Gpio::IGpioPin)->SetDriveMode(get_abi(value)));
}

template <typename D> void consume_Windows_Devices_Gpio_IGpioPin<D>::Write(Windows::Devices::Gpio::GpioPinValue const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Gpio::IGpioPin)->Write(get_abi(value)));
}

template <typename D> Windows::Devices::Gpio::GpioPinValue consume_Windows_Devices_Gpio_IGpioPin<D>::Read() const
{
    Windows::Devices::Gpio::GpioPinValue value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Gpio::IGpioPin)->Read(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Gpio::GpioPinEdge consume_Windows_Devices_Gpio_IGpioPinValueChangedEventArgs<D>::Edge() const
{
    Windows::Devices::Gpio::GpioPinEdge value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Gpio::IGpioPinValueChangedEventArgs)->get_Edge(put_abi(value)));
    return value;
}

template <typename D>
struct produce<D, Windows::Devices::Gpio::IGpioChangeCounter> : produce_base<D, Windows::Devices::Gpio::IGpioChangeCounter>
{
    int32_t WINRT_CALL put_Polarity(Windows::Devices::Gpio::GpioChangePolarity value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Polarity, WINRT_WRAP(void), Windows::Devices::Gpio::GpioChangePolarity const&);
            this->shim().Polarity(*reinterpret_cast<Windows::Devices::Gpio::GpioChangePolarity const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Polarity(Windows::Devices::Gpio::GpioChangePolarity* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Polarity, WINRT_WRAP(Windows::Devices::Gpio::GpioChangePolarity));
            *value = detach_from<Windows::Devices::Gpio::GpioChangePolarity>(this->shim().Polarity());
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

    int32_t WINRT_CALL Read(struct struct_Windows_Devices_Gpio_GpioChangeCount* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Read, WINRT_WRAP(Windows::Devices::Gpio::GpioChangeCount));
            *value = detach_from<Windows::Devices::Gpio::GpioChangeCount>(this->shim().Read());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Reset(struct struct_Windows_Devices_Gpio_GpioChangeCount* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Reset, WINRT_WRAP(Windows::Devices::Gpio::GpioChangeCount));
            *value = detach_from<Windows::Devices::Gpio::GpioChangeCount>(this->shim().Reset());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Gpio::IGpioChangeCounterFactory> : produce_base<D, Windows::Devices::Gpio::IGpioChangeCounterFactory>
{
    int32_t WINRT_CALL Create(void* pin, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Devices::Gpio::GpioChangeCounter), Windows::Devices::Gpio::GpioPin const&);
            *value = detach_from<Windows::Devices::Gpio::GpioChangeCounter>(this->shim().Create(*reinterpret_cast<Windows::Devices::Gpio::GpioPin const*>(&pin)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Gpio::IGpioChangeReader> : produce_base<D, Windows::Devices::Gpio::IGpioChangeReader>
{
    int32_t WINRT_CALL get_Capacity(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Capacity, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().Capacity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Length(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Length, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().Length());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsEmpty(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsEmpty, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsEmpty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsOverflowed(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsOverflowed, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsOverflowed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Polarity(Windows::Devices::Gpio::GpioChangePolarity value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Polarity, WINRT_WRAP(void), Windows::Devices::Gpio::GpioChangePolarity const&);
            this->shim().Polarity(*reinterpret_cast<Windows::Devices::Gpio::GpioChangePolarity const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Polarity(Windows::Devices::Gpio::GpioChangePolarity* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Polarity, WINRT_WRAP(Windows::Devices::Gpio::GpioChangePolarity));
            *value = detach_from<Windows::Devices::Gpio::GpioChangePolarity>(this->shim().Polarity());
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

    int32_t WINRT_CALL Clear() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Clear, WINRT_WRAP(void));
            this->shim().Clear();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetNextItem(struct struct_Windows_Devices_Gpio_GpioChangeRecord* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetNextItem, WINRT_WRAP(Windows::Devices::Gpio::GpioChangeRecord));
            *value = detach_from<Windows::Devices::Gpio::GpioChangeRecord>(this->shim().GetNextItem());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PeekNextItem(struct struct_Windows_Devices_Gpio_GpioChangeRecord* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PeekNextItem, WINRT_WRAP(Windows::Devices::Gpio::GpioChangeRecord));
            *value = detach_from<Windows::Devices::Gpio::GpioChangeRecord>(this->shim().PeekNextItem());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetAllItems(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAllItems, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::Devices::Gpio::GpioChangeRecord>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::Devices::Gpio::GpioChangeRecord>>(this->shim().GetAllItems());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL WaitForItemsAsync(int32_t count, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WaitForItemsAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), int32_t);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().WaitForItemsAsync(count));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Gpio::IGpioChangeReaderFactory> : produce_base<D, Windows::Devices::Gpio::IGpioChangeReaderFactory>
{
    int32_t WINRT_CALL Create(void* pin, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Devices::Gpio::GpioChangeReader), Windows::Devices::Gpio::GpioPin const&);
            *value = detach_from<Windows::Devices::Gpio::GpioChangeReader>(this->shim().Create(*reinterpret_cast<Windows::Devices::Gpio::GpioPin const*>(&pin)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithCapacity(void* pin, int32_t minCapacity, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithCapacity, WINRT_WRAP(Windows::Devices::Gpio::GpioChangeReader), Windows::Devices::Gpio::GpioPin const&, int32_t);
            *value = detach_from<Windows::Devices::Gpio::GpioChangeReader>(this->shim().CreateWithCapacity(*reinterpret_cast<Windows::Devices::Gpio::GpioPin const*>(&pin), minCapacity));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Gpio::IGpioController> : produce_base<D, Windows::Devices::Gpio::IGpioController>
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

    int32_t WINRT_CALL OpenPin(int32_t pinNumber, void** pin) noexcept final
    {
        try
        {
            *pin = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OpenPin, WINRT_WRAP(Windows::Devices::Gpio::GpioPin), int32_t);
            *pin = detach_from<Windows::Devices::Gpio::GpioPin>(this->shim().OpenPin(pinNumber));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL OpenPinWithSharingMode(int32_t pinNumber, Windows::Devices::Gpio::GpioSharingMode sharingMode, void** pin) noexcept final
    {
        try
        {
            *pin = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OpenPin, WINRT_WRAP(Windows::Devices::Gpio::GpioPin), int32_t, Windows::Devices::Gpio::GpioSharingMode const&);
            *pin = detach_from<Windows::Devices::Gpio::GpioPin>(this->shim().OpenPin(pinNumber, *reinterpret_cast<Windows::Devices::Gpio::GpioSharingMode const*>(&sharingMode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryOpenPin(int32_t pinNumber, Windows::Devices::Gpio::GpioSharingMode sharingMode, void** pin, Windows::Devices::Gpio::GpioOpenStatus* openStatus, bool* succeeded) noexcept final
    {
        try
        {
            *pin = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryOpenPin, WINRT_WRAP(bool), int32_t, Windows::Devices::Gpio::GpioSharingMode const&, Windows::Devices::Gpio::GpioPin&, Windows::Devices::Gpio::GpioOpenStatus&);
            *succeeded = detach_from<bool>(this->shim().TryOpenPin(pinNumber, *reinterpret_cast<Windows::Devices::Gpio::GpioSharingMode const*>(&sharingMode), *reinterpret_cast<Windows::Devices::Gpio::GpioPin*>(pin), *reinterpret_cast<Windows::Devices::Gpio::GpioOpenStatus*>(openStatus)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Gpio::IGpioControllerStatics> : produce_base<D, Windows::Devices::Gpio::IGpioControllerStatics>
{
    int32_t WINRT_CALL GetDefault(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefault, WINRT_WRAP(Windows::Devices::Gpio::GpioController));
            *value = detach_from<Windows::Devices::Gpio::GpioController>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Gpio::IGpioControllerStatics2> : produce_base<D, Windows::Devices::Gpio::IGpioControllerStatics2>
{
    int32_t WINRT_CALL GetControllersAsync(void* provider, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetControllersAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Gpio::GpioController>>), Windows::Devices::Gpio::Provider::IGpioProvider const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Gpio::GpioController>>>(this->shim().GetControllersAsync(*reinterpret_cast<Windows::Devices::Gpio::Provider::IGpioProvider const*>(&provider)));
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
            WINRT_ASSERT_DECLARATION(GetDefaultAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Gpio::GpioController>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Gpio::GpioController>>(this->shim().GetDefaultAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Gpio::IGpioPin> : produce_base<D, Windows::Devices::Gpio::IGpioPin>
{
    int32_t WINRT_CALL add_ValueChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ValueChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Gpio::GpioPin, Windows::Devices::Gpio::GpioPinValueChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ValueChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Gpio::GpioPin, Windows::Devices::Gpio::GpioPinValueChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ValueChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ValueChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ValueChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL get_DebounceTimeout(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DebounceTimeout, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().DebounceTimeout());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DebounceTimeout(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DebounceTimeout, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().DebounceTimeout(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PinNumber(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PinNumber, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().PinNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SharingMode(Windows::Devices::Gpio::GpioSharingMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SharingMode, WINRT_WRAP(Windows::Devices::Gpio::GpioSharingMode));
            *value = detach_from<Windows::Devices::Gpio::GpioSharingMode>(this->shim().SharingMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsDriveModeSupported(Windows::Devices::Gpio::GpioPinDriveMode driveMode, bool* supported) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDriveModeSupported, WINRT_WRAP(bool), Windows::Devices::Gpio::GpioPinDriveMode const&);
            *supported = detach_from<bool>(this->shim().IsDriveModeSupported(*reinterpret_cast<Windows::Devices::Gpio::GpioPinDriveMode const*>(&driveMode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDriveMode(Windows::Devices::Gpio::GpioPinDriveMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDriveMode, WINRT_WRAP(Windows::Devices::Gpio::GpioPinDriveMode));
            *value = detach_from<Windows::Devices::Gpio::GpioPinDriveMode>(this->shim().GetDriveMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetDriveMode(Windows::Devices::Gpio::GpioPinDriveMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetDriveMode, WINRT_WRAP(void), Windows::Devices::Gpio::GpioPinDriveMode const&);
            this->shim().SetDriveMode(*reinterpret_cast<Windows::Devices::Gpio::GpioPinDriveMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Write(Windows::Devices::Gpio::GpioPinValue value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Write, WINRT_WRAP(void), Windows::Devices::Gpio::GpioPinValue const&);
            this->shim().Write(*reinterpret_cast<Windows::Devices::Gpio::GpioPinValue const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Read(Windows::Devices::Gpio::GpioPinValue* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Read, WINRT_WRAP(Windows::Devices::Gpio::GpioPinValue));
            *value = detach_from<Windows::Devices::Gpio::GpioPinValue>(this->shim().Read());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Gpio::IGpioPinValueChangedEventArgs> : produce_base<D, Windows::Devices::Gpio::IGpioPinValueChangedEventArgs>
{
    int32_t WINRT_CALL get_Edge(Windows::Devices::Gpio::GpioPinEdge* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Edge, WINRT_WRAP(Windows::Devices::Gpio::GpioPinEdge));
            *value = detach_from<Windows::Devices::Gpio::GpioPinEdge>(this->shim().Edge());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Devices::Gpio {

inline GpioChangeCounter::GpioChangeCounter(Windows::Devices::Gpio::GpioPin const& pin) :
    GpioChangeCounter(impl::call_factory<GpioChangeCounter, Windows::Devices::Gpio::IGpioChangeCounterFactory>([&](auto&& f) { return f.Create(pin); }))
{}

inline GpioChangeReader::GpioChangeReader(Windows::Devices::Gpio::GpioPin const& pin) :
    GpioChangeReader(impl::call_factory<GpioChangeReader, Windows::Devices::Gpio::IGpioChangeReaderFactory>([&](auto&& f) { return f.Create(pin); }))
{}

inline GpioChangeReader::GpioChangeReader(Windows::Devices::Gpio::GpioPin const& pin, int32_t minCapacity) :
    GpioChangeReader(impl::call_factory<GpioChangeReader, Windows::Devices::Gpio::IGpioChangeReaderFactory>([&](auto&& f) { return f.CreateWithCapacity(pin, minCapacity); }))
{}

inline Windows::Devices::Gpio::GpioController GpioController::GetDefault()
{
    return impl::call_factory<GpioController, Windows::Devices::Gpio::IGpioControllerStatics>([&](auto&& f) { return f.GetDefault(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Gpio::GpioController>> GpioController::GetControllersAsync(Windows::Devices::Gpio::Provider::IGpioProvider const& provider)
{
    return impl::call_factory<GpioController, Windows::Devices::Gpio::IGpioControllerStatics2>([&](auto&& f) { return f.GetControllersAsync(provider); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::Gpio::GpioController> GpioController::GetDefaultAsync()
{
    return impl::call_factory<GpioController, Windows::Devices::Gpio::IGpioControllerStatics2>([&](auto&& f) { return f.GetDefaultAsync(); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Devices::Gpio::IGpioChangeCounter> : winrt::impl::hash_base<winrt::Windows::Devices::Gpio::IGpioChangeCounter> {};
template<> struct hash<winrt::Windows::Devices::Gpio::IGpioChangeCounterFactory> : winrt::impl::hash_base<winrt::Windows::Devices::Gpio::IGpioChangeCounterFactory> {};
template<> struct hash<winrt::Windows::Devices::Gpio::IGpioChangeReader> : winrt::impl::hash_base<winrt::Windows::Devices::Gpio::IGpioChangeReader> {};
template<> struct hash<winrt::Windows::Devices::Gpio::IGpioChangeReaderFactory> : winrt::impl::hash_base<winrt::Windows::Devices::Gpio::IGpioChangeReaderFactory> {};
template<> struct hash<winrt::Windows::Devices::Gpio::IGpioController> : winrt::impl::hash_base<winrt::Windows::Devices::Gpio::IGpioController> {};
template<> struct hash<winrt::Windows::Devices::Gpio::IGpioControllerStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Gpio::IGpioControllerStatics> {};
template<> struct hash<winrt::Windows::Devices::Gpio::IGpioControllerStatics2> : winrt::impl::hash_base<winrt::Windows::Devices::Gpio::IGpioControllerStatics2> {};
template<> struct hash<winrt::Windows::Devices::Gpio::IGpioPin> : winrt::impl::hash_base<winrt::Windows::Devices::Gpio::IGpioPin> {};
template<> struct hash<winrt::Windows::Devices::Gpio::IGpioPinValueChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Gpio::IGpioPinValueChangedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Gpio::GpioChangeCounter> : winrt::impl::hash_base<winrt::Windows::Devices::Gpio::GpioChangeCounter> {};
template<> struct hash<winrt::Windows::Devices::Gpio::GpioChangeReader> : winrt::impl::hash_base<winrt::Windows::Devices::Gpio::GpioChangeReader> {};
template<> struct hash<winrt::Windows::Devices::Gpio::GpioController> : winrt::impl::hash_base<winrt::Windows::Devices::Gpio::GpioController> {};
template<> struct hash<winrt::Windows::Devices::Gpio::GpioPin> : winrt::impl::hash_base<winrt::Windows::Devices::Gpio::GpioPin> {};
template<> struct hash<winrt::Windows::Devices::Gpio::GpioPinValueChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Gpio::GpioPinValueChangedEventArgs> {};

}
