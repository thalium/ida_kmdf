// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Devices.Spi.Provider.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Devices.Spi.2.h"
#include "winrt/Windows.Devices.h"

namespace winrt::impl {

template <typename D> int32_t consume_Windows_Devices_Spi_ISpiBusInfo<D>::ChipSelectLineCount() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Spi::ISpiBusInfo)->get_ChipSelectLineCount(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Devices_Spi_ISpiBusInfo<D>::MinClockFrequency() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Spi::ISpiBusInfo)->get_MinClockFrequency(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Devices_Spi_ISpiBusInfo<D>::MaxClockFrequency() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Spi::ISpiBusInfo)->get_MaxClockFrequency(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<int32_t> consume_Windows_Devices_Spi_ISpiBusInfo<D>::SupportedDataBitLengths() const
{
    Windows::Foundation::Collections::IVectorView<int32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Spi::ISpiBusInfo)->get_SupportedDataBitLengths(put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_Devices_Spi_ISpiConnectionSettings<D>::ChipSelectLine() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Spi::ISpiConnectionSettings)->get_ChipSelectLine(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_Spi_ISpiConnectionSettings<D>::ChipSelectLine(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Spi::ISpiConnectionSettings)->put_ChipSelectLine(value));
}

template <typename D> Windows::Devices::Spi::SpiMode consume_Windows_Devices_Spi_ISpiConnectionSettings<D>::Mode() const
{
    Windows::Devices::Spi::SpiMode value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Spi::ISpiConnectionSettings)->get_Mode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Spi_ISpiConnectionSettings<D>::Mode(Windows::Devices::Spi::SpiMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Spi::ISpiConnectionSettings)->put_Mode(get_abi(value)));
}

template <typename D> int32_t consume_Windows_Devices_Spi_ISpiConnectionSettings<D>::DataBitLength() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Spi::ISpiConnectionSettings)->get_DataBitLength(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_Spi_ISpiConnectionSettings<D>::DataBitLength(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Spi::ISpiConnectionSettings)->put_DataBitLength(value));
}

template <typename D> int32_t consume_Windows_Devices_Spi_ISpiConnectionSettings<D>::ClockFrequency() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Spi::ISpiConnectionSettings)->get_ClockFrequency(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_Spi_ISpiConnectionSettings<D>::ClockFrequency(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Spi::ISpiConnectionSettings)->put_ClockFrequency(value));
}

template <typename D> Windows::Devices::Spi::SpiSharingMode consume_Windows_Devices_Spi_ISpiConnectionSettings<D>::SharingMode() const
{
    Windows::Devices::Spi::SpiSharingMode value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Spi::ISpiConnectionSettings)->get_SharingMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Spi_ISpiConnectionSettings<D>::SharingMode(Windows::Devices::Spi::SpiSharingMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Spi::ISpiConnectionSettings)->put_SharingMode(get_abi(value)));
}

template <typename D> Windows::Devices::Spi::SpiConnectionSettings consume_Windows_Devices_Spi_ISpiConnectionSettingsFactory<D>::Create(int32_t chipSelectLine) const
{
    Windows::Devices::Spi::SpiConnectionSettings value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Spi::ISpiConnectionSettingsFactory)->Create(chipSelectLine, put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Spi::SpiDevice consume_Windows_Devices_Spi_ISpiController<D>::GetDevice(Windows::Devices::Spi::SpiConnectionSettings const& settings) const
{
    Windows::Devices::Spi::SpiDevice device{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Spi::ISpiController)->GetDevice(get_abi(settings), put_abi(device)));
    return device;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Spi::SpiController> consume_Windows_Devices_Spi_ISpiControllerStatics<D>::GetDefaultAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Spi::SpiController> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Spi::ISpiControllerStatics)->GetDefaultAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Spi::SpiController>> consume_Windows_Devices_Spi_ISpiControllerStatics<D>::GetControllersAsync(Windows::Devices::Spi::Provider::ISpiProvider const& provider) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Spi::SpiController>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Spi::ISpiControllerStatics)->GetControllersAsync(get_abi(provider), put_abi(operation)));
    return operation;
}

template <typename D> hstring consume_Windows_Devices_Spi_ISpiDevice<D>::DeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Spi::ISpiDevice)->get_DeviceId(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Spi::SpiConnectionSettings consume_Windows_Devices_Spi_ISpiDevice<D>::ConnectionSettings() const
{
    Windows::Devices::Spi::SpiConnectionSettings value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Spi::ISpiDevice)->get_ConnectionSettings(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Spi_ISpiDevice<D>::Write(array_view<uint8_t const> buffer) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Spi::ISpiDevice)->Write(buffer.size(), get_abi(buffer)));
}

template <typename D> void consume_Windows_Devices_Spi_ISpiDevice<D>::Read(array_view<uint8_t> buffer) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Spi::ISpiDevice)->Read(buffer.size(), get_abi(buffer)));
}

template <typename D> void consume_Windows_Devices_Spi_ISpiDevice<D>::TransferSequential(array_view<uint8_t const> writeBuffer, array_view<uint8_t> readBuffer) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Spi::ISpiDevice)->TransferSequential(writeBuffer.size(), get_abi(writeBuffer), readBuffer.size(), get_abi(readBuffer)));
}

template <typename D> void consume_Windows_Devices_Spi_ISpiDevice<D>::TransferFullDuplex(array_view<uint8_t const> writeBuffer, array_view<uint8_t> readBuffer) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Spi::ISpiDevice)->TransferFullDuplex(writeBuffer.size(), get_abi(writeBuffer), readBuffer.size(), get_abi(readBuffer)));
}

template <typename D> hstring consume_Windows_Devices_Spi_ISpiDeviceStatics<D>::GetDeviceSelector() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Spi::ISpiDeviceStatics)->GetDeviceSelector(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Spi_ISpiDeviceStatics<D>::GetDeviceSelector(param::hstring const& friendlyName) const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Spi::ISpiDeviceStatics)->GetDeviceSelectorFromFriendlyName(get_abi(friendlyName), put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Spi::SpiBusInfo consume_Windows_Devices_Spi_ISpiDeviceStatics<D>::GetBusInfo(param::hstring const& busId) const
{
    Windows::Devices::Spi::SpiBusInfo busInfo{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Spi::ISpiDeviceStatics)->GetBusInfo(get_abi(busId), put_abi(busInfo)));
    return busInfo;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Spi::SpiDevice> consume_Windows_Devices_Spi_ISpiDeviceStatics<D>::FromIdAsync(param::hstring const& busId, Windows::Devices::Spi::SpiConnectionSettings const& settings) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Spi::SpiDevice> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Spi::ISpiDeviceStatics)->FromIdAsync(get_abi(busId), get_abi(settings), put_abi(operation)));
    return operation;
}

template <typename D>
struct produce<D, Windows::Devices::Spi::ISpiBusInfo> : produce_base<D, Windows::Devices::Spi::ISpiBusInfo>
{
    int32_t WINRT_CALL get_ChipSelectLineCount(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChipSelectLineCount, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().ChipSelectLineCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MinClockFrequency(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinClockFrequency, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().MinClockFrequency());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxClockFrequency(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxClockFrequency, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().MaxClockFrequency());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportedDataBitLengths(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedDataBitLengths, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<int32_t>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<int32_t>>(this->shim().SupportedDataBitLengths());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Spi::ISpiConnectionSettings> : produce_base<D, Windows::Devices::Spi::ISpiConnectionSettings>
{
    int32_t WINRT_CALL get_ChipSelectLine(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChipSelectLine, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().ChipSelectLine());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ChipSelectLine(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChipSelectLine, WINRT_WRAP(void), int32_t);
            this->shim().ChipSelectLine(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Mode(Windows::Devices::Spi::SpiMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Mode, WINRT_WRAP(Windows::Devices::Spi::SpiMode));
            *value = detach_from<Windows::Devices::Spi::SpiMode>(this->shim().Mode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Mode(Windows::Devices::Spi::SpiMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Mode, WINRT_WRAP(void), Windows::Devices::Spi::SpiMode const&);
            this->shim().Mode(*reinterpret_cast<Windows::Devices::Spi::SpiMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DataBitLength(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DataBitLength, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().DataBitLength());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DataBitLength(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DataBitLength, WINRT_WRAP(void), int32_t);
            this->shim().DataBitLength(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ClockFrequency(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClockFrequency, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().ClockFrequency());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ClockFrequency(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClockFrequency, WINRT_WRAP(void), int32_t);
            this->shim().ClockFrequency(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SharingMode(Windows::Devices::Spi::SpiSharingMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SharingMode, WINRT_WRAP(Windows::Devices::Spi::SpiSharingMode));
            *value = detach_from<Windows::Devices::Spi::SpiSharingMode>(this->shim().SharingMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SharingMode(Windows::Devices::Spi::SpiSharingMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SharingMode, WINRT_WRAP(void), Windows::Devices::Spi::SpiSharingMode const&);
            this->shim().SharingMode(*reinterpret_cast<Windows::Devices::Spi::SpiSharingMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Spi::ISpiConnectionSettingsFactory> : produce_base<D, Windows::Devices::Spi::ISpiConnectionSettingsFactory>
{
    int32_t WINRT_CALL Create(int32_t chipSelectLine, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Devices::Spi::SpiConnectionSettings), int32_t);
            *value = detach_from<Windows::Devices::Spi::SpiConnectionSettings>(this->shim().Create(chipSelectLine));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Spi::ISpiController> : produce_base<D, Windows::Devices::Spi::ISpiController>
{
    int32_t WINRT_CALL GetDevice(void* settings, void** device) noexcept final
    {
        try
        {
            *device = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDevice, WINRT_WRAP(Windows::Devices::Spi::SpiDevice), Windows::Devices::Spi::SpiConnectionSettings const&);
            *device = detach_from<Windows::Devices::Spi::SpiDevice>(this->shim().GetDevice(*reinterpret_cast<Windows::Devices::Spi::SpiConnectionSettings const*>(&settings)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Spi::ISpiControllerStatics> : produce_base<D, Windows::Devices::Spi::ISpiControllerStatics>
{
    int32_t WINRT_CALL GetDefaultAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefaultAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Spi::SpiController>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Spi::SpiController>>(this->shim().GetDefaultAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetControllersAsync(void* provider, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetControllersAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Spi::SpiController>>), Windows::Devices::Spi::Provider::ISpiProvider const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Spi::SpiController>>>(this->shim().GetControllersAsync(*reinterpret_cast<Windows::Devices::Spi::Provider::ISpiProvider const*>(&provider)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Spi::ISpiDevice> : produce_base<D, Windows::Devices::Spi::ISpiDevice>
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

    int32_t WINRT_CALL get_ConnectionSettings(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConnectionSettings, WINRT_WRAP(Windows::Devices::Spi::SpiConnectionSettings));
            *value = detach_from<Windows::Devices::Spi::SpiConnectionSettings>(this->shim().ConnectionSettings());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Write(uint32_t __bufferSize, uint8_t* buffer) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Write, WINRT_WRAP(void), array_view<uint8_t const>);
            this->shim().Write(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(buffer), reinterpret_cast<uint8_t const *>(buffer) + __bufferSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Read(uint32_t __bufferSize, uint8_t* buffer) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Read, WINRT_WRAP(void), array_view<uint8_t>);
            this->shim().Read(array_view<uint8_t>(reinterpret_cast<uint8_t*>(buffer), reinterpret_cast<uint8_t*>(buffer) + __bufferSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TransferSequential(uint32_t __writeBufferSize, uint8_t* writeBuffer, uint32_t __readBufferSize, uint8_t* readBuffer) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransferSequential, WINRT_WRAP(void), array_view<uint8_t const>, array_view<uint8_t>);
            this->shim().TransferSequential(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(writeBuffer), reinterpret_cast<uint8_t const *>(writeBuffer) + __writeBufferSize), array_view<uint8_t>(reinterpret_cast<uint8_t*>(readBuffer), reinterpret_cast<uint8_t*>(readBuffer) + __readBufferSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TransferFullDuplex(uint32_t __writeBufferSize, uint8_t* writeBuffer, uint32_t __readBufferSize, uint8_t* readBuffer) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransferFullDuplex, WINRT_WRAP(void), array_view<uint8_t const>, array_view<uint8_t>);
            this->shim().TransferFullDuplex(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(writeBuffer), reinterpret_cast<uint8_t const *>(writeBuffer) + __writeBufferSize), array_view<uint8_t>(reinterpret_cast<uint8_t*>(readBuffer), reinterpret_cast<uint8_t*>(readBuffer) + __readBufferSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Spi::ISpiDeviceStatics> : produce_base<D, Windows::Devices::Spi::ISpiDeviceStatics>
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

    int32_t WINRT_CALL GetDeviceSelectorFromFriendlyName(void* friendlyName, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelector, WINRT_WRAP(hstring), hstring const&);
            *value = detach_from<hstring>(this->shim().GetDeviceSelector(*reinterpret_cast<hstring const*>(&friendlyName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetBusInfo(void* busId, void** busInfo) noexcept final
    {
        try
        {
            *busInfo = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetBusInfo, WINRT_WRAP(Windows::Devices::Spi::SpiBusInfo), hstring const&);
            *busInfo = detach_from<Windows::Devices::Spi::SpiBusInfo>(this->shim().GetBusInfo(*reinterpret_cast<hstring const*>(&busId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FromIdAsync(void* busId, void* settings, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Spi::SpiDevice>), hstring const, Windows::Devices::Spi::SpiConnectionSettings const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Spi::SpiDevice>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&busId), *reinterpret_cast<Windows::Devices::Spi::SpiConnectionSettings const*>(&settings)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Devices::Spi {

inline SpiConnectionSettings::SpiConnectionSettings(int32_t chipSelectLine) :
    SpiConnectionSettings(impl::call_factory<SpiConnectionSettings, Windows::Devices::Spi::ISpiConnectionSettingsFactory>([&](auto&& f) { return f.Create(chipSelectLine); }))
{}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::Spi::SpiController> SpiController::GetDefaultAsync()
{
    return impl::call_factory<SpiController, Windows::Devices::Spi::ISpiControllerStatics>([&](auto&& f) { return f.GetDefaultAsync(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Spi::SpiController>> SpiController::GetControllersAsync(Windows::Devices::Spi::Provider::ISpiProvider const& provider)
{
    return impl::call_factory<SpiController, Windows::Devices::Spi::ISpiControllerStatics>([&](auto&& f) { return f.GetControllersAsync(provider); });
}

inline hstring SpiDevice::GetDeviceSelector()
{
    return impl::call_factory<SpiDevice, Windows::Devices::Spi::ISpiDeviceStatics>([&](auto&& f) { return f.GetDeviceSelector(); });
}

inline hstring SpiDevice::GetDeviceSelector(param::hstring const& friendlyName)
{
    return impl::call_factory<SpiDevice, Windows::Devices::Spi::ISpiDeviceStatics>([&](auto&& f) { return f.GetDeviceSelector(friendlyName); });
}

inline Windows::Devices::Spi::SpiBusInfo SpiDevice::GetBusInfo(param::hstring const& busId)
{
    return impl::call_factory<SpiDevice, Windows::Devices::Spi::ISpiDeviceStatics>([&](auto&& f) { return f.GetBusInfo(busId); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::Spi::SpiDevice> SpiDevice::FromIdAsync(param::hstring const& busId, Windows::Devices::Spi::SpiConnectionSettings const& settings)
{
    return impl::call_factory<SpiDevice, Windows::Devices::Spi::ISpiDeviceStatics>([&](auto&& f) { return f.FromIdAsync(busId, settings); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Devices::Spi::ISpiBusInfo> : winrt::impl::hash_base<winrt::Windows::Devices::Spi::ISpiBusInfo> {};
template<> struct hash<winrt::Windows::Devices::Spi::ISpiConnectionSettings> : winrt::impl::hash_base<winrt::Windows::Devices::Spi::ISpiConnectionSettings> {};
template<> struct hash<winrt::Windows::Devices::Spi::ISpiConnectionSettingsFactory> : winrt::impl::hash_base<winrt::Windows::Devices::Spi::ISpiConnectionSettingsFactory> {};
template<> struct hash<winrt::Windows::Devices::Spi::ISpiController> : winrt::impl::hash_base<winrt::Windows::Devices::Spi::ISpiController> {};
template<> struct hash<winrt::Windows::Devices::Spi::ISpiControllerStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Spi::ISpiControllerStatics> {};
template<> struct hash<winrt::Windows::Devices::Spi::ISpiDevice> : winrt::impl::hash_base<winrt::Windows::Devices::Spi::ISpiDevice> {};
template<> struct hash<winrt::Windows::Devices::Spi::ISpiDeviceStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Spi::ISpiDeviceStatics> {};
template<> struct hash<winrt::Windows::Devices::Spi::SpiBusInfo> : winrt::impl::hash_base<winrt::Windows::Devices::Spi::SpiBusInfo> {};
template<> struct hash<winrt::Windows::Devices::Spi::SpiConnectionSettings> : winrt::impl::hash_base<winrt::Windows::Devices::Spi::SpiConnectionSettings> {};
template<> struct hash<winrt::Windows::Devices::Spi::SpiController> : winrt::impl::hash_base<winrt::Windows::Devices::Spi::SpiController> {};
template<> struct hash<winrt::Windows::Devices::Spi::SpiDevice> : winrt::impl::hash_base<winrt::Windows::Devices::Spi::SpiDevice> {};

}
