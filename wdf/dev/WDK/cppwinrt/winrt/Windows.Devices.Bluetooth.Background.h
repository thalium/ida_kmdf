// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Devices.Bluetooth.2.h"
#include "winrt/impl/Windows.Devices.Bluetooth.Advertisement.2.h"
#include "winrt/impl/Windows.Devices.Bluetooth.GenericAttributeProfile.2.h"
#include "winrt/impl/Windows.Devices.Bluetooth.Rfcomm.2.h"
#include "winrt/impl/Windows.Networking.Sockets.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Devices.Bluetooth.Background.2.h"
#include "winrt/Windows.Devices.Bluetooth.h"

namespace winrt::impl {

template <typename D> Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementPublisherStatus consume_Windows_Devices_Bluetooth_Background_IBluetoothLEAdvertisementPublisherTriggerDetails<D>::Status() const
{
    Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementPublisherStatus value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Background::IBluetoothLEAdvertisementPublisherTriggerDetails)->get_Status(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Bluetooth::BluetoothError consume_Windows_Devices_Bluetooth_Background_IBluetoothLEAdvertisementPublisherTriggerDetails<D>::Error() const
{
    Windows::Devices::Bluetooth::BluetoothError value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Background::IBluetoothLEAdvertisementPublisherTriggerDetails)->get_Error(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Bluetooth::BluetoothError consume_Windows_Devices_Bluetooth_Background_IBluetoothLEAdvertisementWatcherTriggerDetails<D>::Error() const
{
    Windows::Devices::Bluetooth::BluetoothError value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Background::IBluetoothLEAdvertisementWatcherTriggerDetails)->get_Error(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementReceivedEventArgs> consume_Windows_Devices_Bluetooth_Background_IBluetoothLEAdvertisementWatcherTriggerDetails<D>::Advertisements() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementReceivedEventArgs> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Background::IBluetoothLEAdvertisementWatcherTriggerDetails)->get_Advertisements(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Bluetooth::BluetoothSignalStrengthFilter consume_Windows_Devices_Bluetooth_Background_IBluetoothLEAdvertisementWatcherTriggerDetails<D>::SignalStrengthFilter() const
{
    Windows::Devices::Bluetooth::BluetoothSignalStrengthFilter value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Background::IBluetoothLEAdvertisementWatcherTriggerDetails)->get_SignalStrengthFilter(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristic consume_Windows_Devices_Bluetooth_Background_IGattCharacteristicNotificationTriggerDetails<D>::Characteristic() const
{
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristic value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Background::IGattCharacteristicNotificationTriggerDetails)->get_Characteristic(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Devices_Bluetooth_Background_IGattCharacteristicNotificationTriggerDetails<D>::Value() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Background::IGattCharacteristicNotificationTriggerDetails)->get_Value(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Bluetooth::BluetoothError consume_Windows_Devices_Bluetooth_Background_IGattCharacteristicNotificationTriggerDetails2<D>::Error() const
{
    Windows::Devices::Bluetooth::BluetoothError value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Background::IGattCharacteristicNotificationTriggerDetails2)->get_Error(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Bluetooth::Background::BluetoothEventTriggeringMode consume_Windows_Devices_Bluetooth_Background_IGattCharacteristicNotificationTriggerDetails2<D>::EventTriggeringMode() const
{
    Windows::Devices::Bluetooth::Background::BluetoothEventTriggeringMode value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Background::IGattCharacteristicNotificationTriggerDetails2)->get_EventTriggeringMode(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattValueChangedEventArgs> consume_Windows_Devices_Bluetooth_Background_IGattCharacteristicNotificationTriggerDetails2<D>::ValueChangedEvents() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattValueChangedEventArgs> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Background::IGattCharacteristicNotificationTriggerDetails2)->get_ValueChangedEvents(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Bluetooth_Background_IGattServiceProviderConnection<D>::TriggerId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Background::IGattServiceProviderConnection)->get_TriggerId(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalService consume_Windows_Devices_Bluetooth_Background_IGattServiceProviderConnection<D>::Service() const
{
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalService value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Background::IGattServiceProviderConnection)->get_Service(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Bluetooth_Background_IGattServiceProviderConnection<D>::Start() const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Background::IGattServiceProviderConnection)->Start());
}

template <typename D> Windows::Foundation::Collections::IMapView<hstring, Windows::Devices::Bluetooth::Background::GattServiceProviderConnection> consume_Windows_Devices_Bluetooth_Background_IGattServiceProviderConnectionStatics<D>::AllServices() const
{
    Windows::Foundation::Collections::IMapView<hstring, Windows::Devices::Bluetooth::Background::GattServiceProviderConnection> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Background::IGattServiceProviderConnectionStatics)->get_AllServices(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Bluetooth::Background::GattServiceProviderConnection consume_Windows_Devices_Bluetooth_Background_IGattServiceProviderTriggerDetails<D>::Connection() const
{
    Windows::Devices::Bluetooth::Background::GattServiceProviderConnection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Background::IGattServiceProviderTriggerDetails)->get_Connection(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::Sockets::StreamSocket consume_Windows_Devices_Bluetooth_Background_IRfcommConnectionTriggerDetails<D>::Socket() const
{
    Windows::Networking::Sockets::StreamSocket value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Background::IRfcommConnectionTriggerDetails)->get_Socket(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Devices_Bluetooth_Background_IRfcommConnectionTriggerDetails<D>::Incoming() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Background::IRfcommConnectionTriggerDetails)->get_Incoming(&value));
    return value;
}

template <typename D> Windows::Devices::Bluetooth::BluetoothDevice consume_Windows_Devices_Bluetooth_Background_IRfcommConnectionTriggerDetails<D>::RemoteDevice() const
{
    Windows::Devices::Bluetooth::BluetoothDevice value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Background::IRfcommConnectionTriggerDetails)->get_RemoteDevice(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Devices_Bluetooth_Background_IRfcommInboundConnectionInformation<D>::SdpRecord() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Background::IRfcommInboundConnectionInformation)->get_SdpRecord(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Bluetooth_Background_IRfcommInboundConnectionInformation<D>::SdpRecord(Windows::Storage::Streams::IBuffer const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Background::IRfcommInboundConnectionInformation)->put_SdpRecord(get_abi(value)));
}

template <typename D> Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId consume_Windows_Devices_Bluetooth_Background_IRfcommInboundConnectionInformation<D>::LocalServiceId() const
{
    Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Background::IRfcommInboundConnectionInformation)->get_LocalServiceId(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Bluetooth_Background_IRfcommInboundConnectionInformation<D>::LocalServiceId(Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Background::IRfcommInboundConnectionInformation)->put_LocalServiceId(get_abi(value)));
}

template <typename D> Windows::Devices::Bluetooth::BluetoothServiceCapabilities consume_Windows_Devices_Bluetooth_Background_IRfcommInboundConnectionInformation<D>::ServiceCapabilities() const
{
    Windows::Devices::Bluetooth::BluetoothServiceCapabilities value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Background::IRfcommInboundConnectionInformation)->get_ServiceCapabilities(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Bluetooth_Background_IRfcommInboundConnectionInformation<D>::ServiceCapabilities(Windows::Devices::Bluetooth::BluetoothServiceCapabilities const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Background::IRfcommInboundConnectionInformation)->put_ServiceCapabilities(get_abi(value)));
}

template <typename D> Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId consume_Windows_Devices_Bluetooth_Background_IRfcommOutboundConnectionInformation<D>::RemoteServiceId() const
{
    Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Background::IRfcommOutboundConnectionInformation)->get_RemoteServiceId(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Bluetooth_Background_IRfcommOutboundConnectionInformation<D>::RemoteServiceId(Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Background::IRfcommOutboundConnectionInformation)->put_RemoteServiceId(get_abi(value)));
}

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::Background::IBluetoothLEAdvertisementPublisherTriggerDetails> : produce_base<D, Windows::Devices::Bluetooth::Background::IBluetoothLEAdvertisementPublisherTriggerDetails>
{
    int32_t WINRT_CALL get_Status(Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementPublisherStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementPublisherStatus));
            *value = detach_from<Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementPublisherStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Error(Windows::Devices::Bluetooth::BluetoothError* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Error, WINRT_WRAP(Windows::Devices::Bluetooth::BluetoothError));
            *value = detach_from<Windows::Devices::Bluetooth::BluetoothError>(this->shim().Error());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::Background::IBluetoothLEAdvertisementWatcherTriggerDetails> : produce_base<D, Windows::Devices::Bluetooth::Background::IBluetoothLEAdvertisementWatcherTriggerDetails>
{
    int32_t WINRT_CALL get_Error(Windows::Devices::Bluetooth::BluetoothError* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Error, WINRT_WRAP(Windows::Devices::Bluetooth::BluetoothError));
            *value = detach_from<Windows::Devices::Bluetooth::BluetoothError>(this->shim().Error());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Advertisements(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Advertisements, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementReceivedEventArgs>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::Advertisement::BluetoothLEAdvertisementReceivedEventArgs>>(this->shim().Advertisements());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SignalStrengthFilter(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SignalStrengthFilter, WINRT_WRAP(Windows::Devices::Bluetooth::BluetoothSignalStrengthFilter));
            *value = detach_from<Windows::Devices::Bluetooth::BluetoothSignalStrengthFilter>(this->shim().SignalStrengthFilter());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::Background::IGattCharacteristicNotificationTriggerDetails> : produce_base<D, Windows::Devices::Bluetooth::Background::IGattCharacteristicNotificationTriggerDetails>
{
    int32_t WINRT_CALL get_Characteristic(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Characteristic, WINRT_WRAP(Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristic));
            *value = detach_from<Windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristic>(this->shim().Characteristic());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Value(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Value, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().Value());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::Background::IGattCharacteristicNotificationTriggerDetails2> : produce_base<D, Windows::Devices::Bluetooth::Background::IGattCharacteristicNotificationTriggerDetails2>
{
    int32_t WINRT_CALL get_Error(Windows::Devices::Bluetooth::BluetoothError* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Error, WINRT_WRAP(Windows::Devices::Bluetooth::BluetoothError));
            *value = detach_from<Windows::Devices::Bluetooth::BluetoothError>(this->shim().Error());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EventTriggeringMode(Windows::Devices::Bluetooth::Background::BluetoothEventTriggeringMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EventTriggeringMode, WINRT_WRAP(Windows::Devices::Bluetooth::Background::BluetoothEventTriggeringMode));
            *value = detach_from<Windows::Devices::Bluetooth::Background::BluetoothEventTriggeringMode>(this->shim().EventTriggeringMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ValueChangedEvents(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ValueChangedEvents, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattValueChangedEventArgs>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattValueChangedEventArgs>>(this->shim().ValueChangedEvents());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::Background::IGattServiceProviderConnection> : produce_base<D, Windows::Devices::Bluetooth::Background::IGattServiceProviderConnection>
{
    int32_t WINRT_CALL get_TriggerId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TriggerId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().TriggerId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Service(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Service, WINRT_WRAP(Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalService));
            *value = detach_from<Windows::Devices::Bluetooth::GenericAttributeProfile::GattLocalService>(this->shim().Service());
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
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::Background::IGattServiceProviderConnectionStatics> : produce_base<D, Windows::Devices::Bluetooth::Background::IGattServiceProviderConnectionStatics>
{
    int32_t WINRT_CALL get_AllServices(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllServices, WINRT_WRAP(Windows::Foundation::Collections::IMapView<hstring, Windows::Devices::Bluetooth::Background::GattServiceProviderConnection>));
            *value = detach_from<Windows::Foundation::Collections::IMapView<hstring, Windows::Devices::Bluetooth::Background::GattServiceProviderConnection>>(this->shim().AllServices());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::Background::IGattServiceProviderTriggerDetails> : produce_base<D, Windows::Devices::Bluetooth::Background::IGattServiceProviderTriggerDetails>
{
    int32_t WINRT_CALL get_Connection(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Connection, WINRT_WRAP(Windows::Devices::Bluetooth::Background::GattServiceProviderConnection));
            *value = detach_from<Windows::Devices::Bluetooth::Background::GattServiceProviderConnection>(this->shim().Connection());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::Background::IRfcommConnectionTriggerDetails> : produce_base<D, Windows::Devices::Bluetooth::Background::IRfcommConnectionTriggerDetails>
{
    int32_t WINRT_CALL get_Socket(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Socket, WINRT_WRAP(Windows::Networking::Sockets::StreamSocket));
            *value = detach_from<Windows::Networking::Sockets::StreamSocket>(this->shim().Socket());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Incoming(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Incoming, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Incoming());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RemoteDevice(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoteDevice, WINRT_WRAP(Windows::Devices::Bluetooth::BluetoothDevice));
            *value = detach_from<Windows::Devices::Bluetooth::BluetoothDevice>(this->shim().RemoteDevice());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::Background::IRfcommInboundConnectionInformation> : produce_base<D, Windows::Devices::Bluetooth::Background::IRfcommInboundConnectionInformation>
{
    int32_t WINRT_CALL get_SdpRecord(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SdpRecord, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().SdpRecord());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SdpRecord(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SdpRecord, WINRT_WRAP(void), Windows::Storage::Streams::IBuffer const&);
            this->shim().SdpRecord(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LocalServiceId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LocalServiceId, WINRT_WRAP(Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId));
            *value = detach_from<Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId>(this->shim().LocalServiceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_LocalServiceId(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LocalServiceId, WINRT_WRAP(void), Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId const&);
            this->shim().LocalServiceId(*reinterpret_cast<Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ServiceCapabilities(Windows::Devices::Bluetooth::BluetoothServiceCapabilities* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServiceCapabilities, WINRT_WRAP(Windows::Devices::Bluetooth::BluetoothServiceCapabilities));
            *value = detach_from<Windows::Devices::Bluetooth::BluetoothServiceCapabilities>(this->shim().ServiceCapabilities());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ServiceCapabilities(Windows::Devices::Bluetooth::BluetoothServiceCapabilities value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServiceCapabilities, WINRT_WRAP(void), Windows::Devices::Bluetooth::BluetoothServiceCapabilities const&);
            this->shim().ServiceCapabilities(*reinterpret_cast<Windows::Devices::Bluetooth::BluetoothServiceCapabilities const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::Background::IRfcommOutboundConnectionInformation> : produce_base<D, Windows::Devices::Bluetooth::Background::IRfcommOutboundConnectionInformation>
{
    int32_t WINRT_CALL get_RemoteServiceId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoteServiceId, WINRT_WRAP(Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId));
            *value = detach_from<Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId>(this->shim().RemoteServiceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RemoteServiceId(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoteServiceId, WINRT_WRAP(void), Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId const&);
            this->shim().RemoteServiceId(*reinterpret_cast<Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Devices::Bluetooth::Background {

inline Windows::Foundation::Collections::IMapView<hstring, Windows::Devices::Bluetooth::Background::GattServiceProviderConnection> GattServiceProviderConnection::AllServices()
{
    return impl::call_factory<GattServiceProviderConnection, Windows::Devices::Bluetooth::Background::IGattServiceProviderConnectionStatics>([&](auto&& f) { return f.AllServices(); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Devices::Bluetooth::Background::IBluetoothLEAdvertisementPublisherTriggerDetails> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::Background::IBluetoothLEAdvertisementPublisherTriggerDetails> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::Background::IBluetoothLEAdvertisementWatcherTriggerDetails> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::Background::IBluetoothLEAdvertisementWatcherTriggerDetails> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::Background::IGattCharacteristicNotificationTriggerDetails> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::Background::IGattCharacteristicNotificationTriggerDetails> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::Background::IGattCharacteristicNotificationTriggerDetails2> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::Background::IGattCharacteristicNotificationTriggerDetails2> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::Background::IGattServiceProviderConnection> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::Background::IGattServiceProviderConnection> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::Background::IGattServiceProviderConnectionStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::Background::IGattServiceProviderConnectionStatics> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::Background::IGattServiceProviderTriggerDetails> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::Background::IGattServiceProviderTriggerDetails> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::Background::IRfcommConnectionTriggerDetails> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::Background::IRfcommConnectionTriggerDetails> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::Background::IRfcommInboundConnectionInformation> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::Background::IRfcommInboundConnectionInformation> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::Background::IRfcommOutboundConnectionInformation> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::Background::IRfcommOutboundConnectionInformation> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::Background::BluetoothLEAdvertisementPublisherTriggerDetails> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::Background::BluetoothLEAdvertisementPublisherTriggerDetails> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::Background::BluetoothLEAdvertisementWatcherTriggerDetails> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::Background::BluetoothLEAdvertisementWatcherTriggerDetails> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::Background::GattCharacteristicNotificationTriggerDetails> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::Background::GattCharacteristicNotificationTriggerDetails> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::Background::GattServiceProviderConnection> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::Background::GattServiceProviderConnection> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::Background::GattServiceProviderTriggerDetails> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::Background::GattServiceProviderTriggerDetails> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::Background::RfcommConnectionTriggerDetails> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::Background::RfcommConnectionTriggerDetails> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::Background::RfcommInboundConnectionInformation> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::Background::RfcommInboundConnectionInformation> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::Background::RfcommOutboundConnectionInformation> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::Background::RfcommOutboundConnectionInformation> {};

}
