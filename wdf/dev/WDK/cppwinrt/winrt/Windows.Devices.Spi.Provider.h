// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Devices.Spi.Provider.2.h"
#include "winrt/Windows.Devices.Spi.h"

namespace winrt::impl {

template <typename D> int32_t consume_Windows_Devices_Spi_Provider_IProviderSpiConnectionSettings<D>::ChipSelectLine() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Spi::Provider::IProviderSpiConnectionSettings)->get_ChipSelectLine(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_Spi_Provider_IProviderSpiConnectionSettings<D>::ChipSelectLine(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Spi::Provider::IProviderSpiConnectionSettings)->put_ChipSelectLine(value));
}

template <typename D> Windows::Devices::Spi::Provider::ProviderSpiMode consume_Windows_Devices_Spi_Provider_IProviderSpiConnectionSettings<D>::Mode() const
{
    Windows::Devices::Spi::Provider::ProviderSpiMode value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Spi::Provider::IProviderSpiConnectionSettings)->get_Mode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Spi_Provider_IProviderSpiConnectionSettings<D>::Mode(Windows::Devices::Spi::Provider::ProviderSpiMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Spi::Provider::IProviderSpiConnectionSettings)->put_Mode(get_abi(value)));
}

template <typename D> int32_t consume_Windows_Devices_Spi_Provider_IProviderSpiConnectionSettings<D>::DataBitLength() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Spi::Provider::IProviderSpiConnectionSettings)->get_DataBitLength(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_Spi_Provider_IProviderSpiConnectionSettings<D>::DataBitLength(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Spi::Provider::IProviderSpiConnectionSettings)->put_DataBitLength(value));
}

template <typename D> int32_t consume_Windows_Devices_Spi_Provider_IProviderSpiConnectionSettings<D>::ClockFrequency() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Spi::Provider::IProviderSpiConnectionSettings)->get_ClockFrequency(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_Spi_Provider_IProviderSpiConnectionSettings<D>::ClockFrequency(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Spi::Provider::IProviderSpiConnectionSettings)->put_ClockFrequency(value));
}

template <typename D> Windows::Devices::Spi::Provider::ProviderSpiSharingMode consume_Windows_Devices_Spi_Provider_IProviderSpiConnectionSettings<D>::SharingMode() const
{
    Windows::Devices::Spi::Provider::ProviderSpiSharingMode value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Spi::Provider::IProviderSpiConnectionSettings)->get_SharingMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Spi_Provider_IProviderSpiConnectionSettings<D>::SharingMode(Windows::Devices::Spi::Provider::ProviderSpiSharingMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Spi::Provider::IProviderSpiConnectionSettings)->put_SharingMode(get_abi(value)));
}

template <typename D> Windows::Devices::Spi::Provider::ProviderSpiConnectionSettings consume_Windows_Devices_Spi_Provider_IProviderSpiConnectionSettingsFactory<D>::Create(int32_t chipSelectLine) const
{
    Windows::Devices::Spi::Provider::ProviderSpiConnectionSettings value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Spi::Provider::IProviderSpiConnectionSettingsFactory)->Create(chipSelectLine, put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Spi::Provider::ISpiDeviceProvider consume_Windows_Devices_Spi_Provider_ISpiControllerProvider<D>::GetDeviceProvider(Windows::Devices::Spi::Provider::ProviderSpiConnectionSettings const& settings) const
{
    Windows::Devices::Spi::Provider::ISpiDeviceProvider result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Spi::Provider::ISpiControllerProvider)->GetDeviceProvider(get_abi(settings), put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Devices_Spi_Provider_ISpiDeviceProvider<D>::DeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Spi::Provider::ISpiDeviceProvider)->get_DeviceId(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Spi::Provider::ProviderSpiConnectionSettings consume_Windows_Devices_Spi_Provider_ISpiDeviceProvider<D>::ConnectionSettings() const
{
    Windows::Devices::Spi::Provider::ProviderSpiConnectionSettings value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Spi::Provider::ISpiDeviceProvider)->get_ConnectionSettings(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Spi_Provider_ISpiDeviceProvider<D>::Write(array_view<uint8_t const> buffer) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Spi::Provider::ISpiDeviceProvider)->Write(buffer.size(), get_abi(buffer)));
}

template <typename D> void consume_Windows_Devices_Spi_Provider_ISpiDeviceProvider<D>::Read(array_view<uint8_t> buffer) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Spi::Provider::ISpiDeviceProvider)->Read(buffer.size(), get_abi(buffer)));
}

template <typename D> void consume_Windows_Devices_Spi_Provider_ISpiDeviceProvider<D>::TransferSequential(array_view<uint8_t const> writeBuffer, array_view<uint8_t> readBuffer) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Spi::Provider::ISpiDeviceProvider)->TransferSequential(writeBuffer.size(), get_abi(writeBuffer), readBuffer.size(), get_abi(readBuffer)));
}

template <typename D> void consume_Windows_Devices_Spi_Provider_ISpiDeviceProvider<D>::TransferFullDuplex(array_view<uint8_t const> writeBuffer, array_view<uint8_t> readBuffer) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Spi::Provider::ISpiDeviceProvider)->TransferFullDuplex(writeBuffer.size(), get_abi(writeBuffer), readBuffer.size(), get_abi(readBuffer)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Spi::Provider::ISpiControllerProvider>> consume_Windows_Devices_Spi_Provider_ISpiProvider<D>::GetControllersAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Spi::Provider::ISpiControllerProvider>> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Spi::Provider::ISpiProvider)->GetControllersAsync(put_abi(result)));
    return result;
}

template <typename D>
struct produce<D, Windows::Devices::Spi::Provider::IProviderSpiConnectionSettings> : produce_base<D, Windows::Devices::Spi::Provider::IProviderSpiConnectionSettings>
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

    int32_t WINRT_CALL get_Mode(Windows::Devices::Spi::Provider::ProviderSpiMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Mode, WINRT_WRAP(Windows::Devices::Spi::Provider::ProviderSpiMode));
            *value = detach_from<Windows::Devices::Spi::Provider::ProviderSpiMode>(this->shim().Mode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Mode(Windows::Devices::Spi::Provider::ProviderSpiMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Mode, WINRT_WRAP(void), Windows::Devices::Spi::Provider::ProviderSpiMode const&);
            this->shim().Mode(*reinterpret_cast<Windows::Devices::Spi::Provider::ProviderSpiMode const*>(&value));
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

    int32_t WINRT_CALL get_SharingMode(Windows::Devices::Spi::Provider::ProviderSpiSharingMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SharingMode, WINRT_WRAP(Windows::Devices::Spi::Provider::ProviderSpiSharingMode));
            *value = detach_from<Windows::Devices::Spi::Provider::ProviderSpiSharingMode>(this->shim().SharingMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SharingMode(Windows::Devices::Spi::Provider::ProviderSpiSharingMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SharingMode, WINRT_WRAP(void), Windows::Devices::Spi::Provider::ProviderSpiSharingMode const&);
            this->shim().SharingMode(*reinterpret_cast<Windows::Devices::Spi::Provider::ProviderSpiSharingMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Spi::Provider::IProviderSpiConnectionSettingsFactory> : produce_base<D, Windows::Devices::Spi::Provider::IProviderSpiConnectionSettingsFactory>
{
    int32_t WINRT_CALL Create(int32_t chipSelectLine, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Devices::Spi::Provider::ProviderSpiConnectionSettings), int32_t);
            *value = detach_from<Windows::Devices::Spi::Provider::ProviderSpiConnectionSettings>(this->shim().Create(chipSelectLine));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Spi::Provider::ISpiControllerProvider> : produce_base<D, Windows::Devices::Spi::Provider::ISpiControllerProvider>
{
    int32_t WINRT_CALL GetDeviceProvider(void* settings, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceProvider, WINRT_WRAP(Windows::Devices::Spi::Provider::ISpiDeviceProvider), Windows::Devices::Spi::Provider::ProviderSpiConnectionSettings const&);
            *result = detach_from<Windows::Devices::Spi::Provider::ISpiDeviceProvider>(this->shim().GetDeviceProvider(*reinterpret_cast<Windows::Devices::Spi::Provider::ProviderSpiConnectionSettings const*>(&settings)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Spi::Provider::ISpiDeviceProvider> : produce_base<D, Windows::Devices::Spi::Provider::ISpiDeviceProvider>
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
            WINRT_ASSERT_DECLARATION(ConnectionSettings, WINRT_WRAP(Windows::Devices::Spi::Provider::ProviderSpiConnectionSettings));
            *value = detach_from<Windows::Devices::Spi::Provider::ProviderSpiConnectionSettings>(this->shim().ConnectionSettings());
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
struct produce<D, Windows::Devices::Spi::Provider::ISpiProvider> : produce_base<D, Windows::Devices::Spi::Provider::ISpiProvider>
{
    int32_t WINRT_CALL GetControllersAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetControllersAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Spi::Provider::ISpiControllerProvider>>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Spi::Provider::ISpiControllerProvider>>>(this->shim().GetControllersAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Devices::Spi::Provider {

inline ProviderSpiConnectionSettings::ProviderSpiConnectionSettings(int32_t chipSelectLine) :
    ProviderSpiConnectionSettings(impl::call_factory<ProviderSpiConnectionSettings, Windows::Devices::Spi::Provider::IProviderSpiConnectionSettingsFactory>([&](auto&& f) { return f.Create(chipSelectLine); }))
{}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Devices::Spi::Provider::IProviderSpiConnectionSettings> : winrt::impl::hash_base<winrt::Windows::Devices::Spi::Provider::IProviderSpiConnectionSettings> {};
template<> struct hash<winrt::Windows::Devices::Spi::Provider::IProviderSpiConnectionSettingsFactory> : winrt::impl::hash_base<winrt::Windows::Devices::Spi::Provider::IProviderSpiConnectionSettingsFactory> {};
template<> struct hash<winrt::Windows::Devices::Spi::Provider::ISpiControllerProvider> : winrt::impl::hash_base<winrt::Windows::Devices::Spi::Provider::ISpiControllerProvider> {};
template<> struct hash<winrt::Windows::Devices::Spi::Provider::ISpiDeviceProvider> : winrt::impl::hash_base<winrt::Windows::Devices::Spi::Provider::ISpiDeviceProvider> {};
template<> struct hash<winrt::Windows::Devices::Spi::Provider::ISpiProvider> : winrt::impl::hash_base<winrt::Windows::Devices::Spi::Provider::ISpiProvider> {};
template<> struct hash<winrt::Windows::Devices::Spi::Provider::ProviderSpiConnectionSettings> : winrt::impl::hash_base<winrt::Windows::Devices::Spi::Provider::ProviderSpiConnectionSettings> {};

}
