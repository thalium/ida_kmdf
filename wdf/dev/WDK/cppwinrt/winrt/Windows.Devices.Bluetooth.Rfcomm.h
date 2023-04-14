// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Devices.Bluetooth.2.h"
#include "winrt/impl/Windows.Devices.Enumeration.2.h"
#include "winrt/impl/Windows.Networking.2.h"
#include "winrt/impl/Windows.Networking.Sockets.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Devices.Bluetooth.Rfcomm.2.h"
#include "winrt/Windows.Devices.Bluetooth.h"

namespace winrt::impl {

template <typename D> Windows::Networking::HostName consume_Windows_Devices_Bluetooth_Rfcomm_IRfcommDeviceService<D>::ConnectionHostName() const
{
    Windows::Networking::HostName value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Rfcomm::IRfcommDeviceService)->get_ConnectionHostName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Bluetooth_Rfcomm_IRfcommDeviceService<D>::ConnectionServiceName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Rfcomm::IRfcommDeviceService)->get_ConnectionServiceName(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId consume_Windows_Devices_Bluetooth_Rfcomm_IRfcommDeviceService<D>::ServiceId() const
{
    Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Rfcomm::IRfcommDeviceService)->get_ServiceId(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::Sockets::SocketProtectionLevel consume_Windows_Devices_Bluetooth_Rfcomm_IRfcommDeviceService<D>::ProtectionLevel() const
{
    Windows::Networking::Sockets::SocketProtectionLevel value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Rfcomm::IRfcommDeviceService)->get_ProtectionLevel(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::Sockets::SocketProtectionLevel consume_Windows_Devices_Bluetooth_Rfcomm_IRfcommDeviceService<D>::MaxProtectionLevel() const
{
    Windows::Networking::Sockets::SocketProtectionLevel value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Rfcomm::IRfcommDeviceService)->get_MaxProtectionLevel(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IMapView<uint32_t, Windows::Storage::Streams::IBuffer>> consume_Windows_Devices_Bluetooth_Rfcomm_IRfcommDeviceService<D>::GetSdpRawAttributesAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IMapView<uint32_t, Windows::Storage::Streams::IBuffer>> asyncOp{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Rfcomm::IRfcommDeviceService)->GetSdpRawAttributesAsync(put_abi(asyncOp)));
    return asyncOp;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IMapView<uint32_t, Windows::Storage::Streams::IBuffer>> consume_Windows_Devices_Bluetooth_Rfcomm_IRfcommDeviceService<D>::GetSdpRawAttributesAsync(Windows::Devices::Bluetooth::BluetoothCacheMode const& cacheMode) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IMapView<uint32_t, Windows::Storage::Streams::IBuffer>> asyncOp{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Rfcomm::IRfcommDeviceService)->GetSdpRawAttributesWithCacheModeAsync(get_abi(cacheMode), put_abi(asyncOp)));
    return asyncOp;
}

template <typename D> Windows::Devices::Bluetooth::BluetoothDevice consume_Windows_Devices_Bluetooth_Rfcomm_IRfcommDeviceService2<D>::Device() const
{
    Windows::Devices::Bluetooth::BluetoothDevice value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Rfcomm::IRfcommDeviceService2)->get_Device(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Enumeration::DeviceAccessInformation consume_Windows_Devices_Bluetooth_Rfcomm_IRfcommDeviceService3<D>::DeviceAccessInformation() const
{
    Windows::Devices::Enumeration::DeviceAccessInformation value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Rfcomm::IRfcommDeviceService3)->get_DeviceAccessInformation(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceAccessStatus> consume_Windows_Devices_Bluetooth_Rfcomm_IRfcommDeviceService3<D>::RequestAccessAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceAccessStatus> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Rfcomm::IRfcommDeviceService3)->RequestAccessAsync(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::Rfcomm::RfcommDeviceService> consume_Windows_Devices_Bluetooth_Rfcomm_IRfcommDeviceServiceStatics<D>::FromIdAsync(param::hstring const& deviceId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::Rfcomm::RfcommDeviceService> asyncOp{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Rfcomm::IRfcommDeviceServiceStatics)->FromIdAsync(get_abi(deviceId), put_abi(asyncOp)));
    return asyncOp;
}

template <typename D> hstring consume_Windows_Devices_Bluetooth_Rfcomm_IRfcommDeviceServiceStatics<D>::GetDeviceSelector(Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId const& serviceId) const
{
    hstring selector{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Rfcomm::IRfcommDeviceServiceStatics)->GetDeviceSelector(get_abi(serviceId), put_abi(selector)));
    return selector;
}

template <typename D> hstring consume_Windows_Devices_Bluetooth_Rfcomm_IRfcommDeviceServiceStatics2<D>::GetDeviceSelectorForBluetoothDevice(Windows::Devices::Bluetooth::BluetoothDevice const& bluetoothDevice) const
{
    hstring selector{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Rfcomm::IRfcommDeviceServiceStatics2)->GetDeviceSelectorForBluetoothDevice(get_abi(bluetoothDevice), put_abi(selector)));
    return selector;
}

template <typename D> hstring consume_Windows_Devices_Bluetooth_Rfcomm_IRfcommDeviceServiceStatics2<D>::GetDeviceSelectorForBluetoothDevice(Windows::Devices::Bluetooth::BluetoothDevice const& bluetoothDevice, Windows::Devices::Bluetooth::BluetoothCacheMode const& cacheMode) const
{
    hstring selector{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Rfcomm::IRfcommDeviceServiceStatics2)->GetDeviceSelectorForBluetoothDeviceWithCacheMode(get_abi(bluetoothDevice), get_abi(cacheMode), put_abi(selector)));
    return selector;
}

template <typename D> hstring consume_Windows_Devices_Bluetooth_Rfcomm_IRfcommDeviceServiceStatics2<D>::GetDeviceSelectorForBluetoothDeviceAndServiceId(Windows::Devices::Bluetooth::BluetoothDevice const& bluetoothDevice, Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId const& serviceId) const
{
    hstring selector{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Rfcomm::IRfcommDeviceServiceStatics2)->GetDeviceSelectorForBluetoothDeviceAndServiceId(get_abi(bluetoothDevice), get_abi(serviceId), put_abi(selector)));
    return selector;
}

template <typename D> hstring consume_Windows_Devices_Bluetooth_Rfcomm_IRfcommDeviceServiceStatics2<D>::GetDeviceSelectorForBluetoothDeviceAndServiceId(Windows::Devices::Bluetooth::BluetoothDevice const& bluetoothDevice, Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId const& serviceId, Windows::Devices::Bluetooth::BluetoothCacheMode const& cacheMode) const
{
    hstring selector{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Rfcomm::IRfcommDeviceServiceStatics2)->GetDeviceSelectorForBluetoothDeviceAndServiceIdWithCacheMode(get_abi(bluetoothDevice), get_abi(serviceId), get_abi(cacheMode), put_abi(selector)));
    return selector;
}

template <typename D> Windows::Devices::Bluetooth::BluetoothError consume_Windows_Devices_Bluetooth_Rfcomm_IRfcommDeviceServicesResult<D>::Error() const
{
    Windows::Devices::Bluetooth::BluetoothError value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Rfcomm::IRfcommDeviceServicesResult)->get_Error(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::Rfcomm::RfcommDeviceService> consume_Windows_Devices_Bluetooth_Rfcomm_IRfcommDeviceServicesResult<D>::Services() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::Rfcomm::RfcommDeviceService> services{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Rfcomm::IRfcommDeviceServicesResult)->get_Services(put_abi(services)));
    return services;
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_Rfcomm_IRfcommServiceId<D>::Uuid() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Rfcomm::IRfcommServiceId)->get_Uuid(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_Bluetooth_Rfcomm_IRfcommServiceId<D>::AsShortId() const
{
    uint32_t shortId{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Rfcomm::IRfcommServiceId)->AsShortId(&shortId));
    return shortId;
}

template <typename D> hstring consume_Windows_Devices_Bluetooth_Rfcomm_IRfcommServiceId<D>::AsString() const
{
    hstring id{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Rfcomm::IRfcommServiceId)->AsString(put_abi(id)));
    return id;
}

template <typename D> Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId consume_Windows_Devices_Bluetooth_Rfcomm_IRfcommServiceIdStatics<D>::FromUuid(winrt::guid const& uuid) const
{
    Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId serviceId{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Rfcomm::IRfcommServiceIdStatics)->FromUuid(get_abi(uuid), put_abi(serviceId)));
    return serviceId;
}

template <typename D> Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId consume_Windows_Devices_Bluetooth_Rfcomm_IRfcommServiceIdStatics<D>::FromShortId(uint32_t shortId) const
{
    Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId serviceId{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Rfcomm::IRfcommServiceIdStatics)->FromShortId(shortId, put_abi(serviceId)));
    return serviceId;
}

template <typename D> Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId consume_Windows_Devices_Bluetooth_Rfcomm_IRfcommServiceIdStatics<D>::SerialPort() const
{
    Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId serviceId{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Rfcomm::IRfcommServiceIdStatics)->get_SerialPort(put_abi(serviceId)));
    return serviceId;
}

template <typename D> Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId consume_Windows_Devices_Bluetooth_Rfcomm_IRfcommServiceIdStatics<D>::ObexObjectPush() const
{
    Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId serviceId{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Rfcomm::IRfcommServiceIdStatics)->get_ObexObjectPush(put_abi(serviceId)));
    return serviceId;
}

template <typename D> Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId consume_Windows_Devices_Bluetooth_Rfcomm_IRfcommServiceIdStatics<D>::ObexFileTransfer() const
{
    Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId serviceId{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Rfcomm::IRfcommServiceIdStatics)->get_ObexFileTransfer(put_abi(serviceId)));
    return serviceId;
}

template <typename D> Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId consume_Windows_Devices_Bluetooth_Rfcomm_IRfcommServiceIdStatics<D>::PhoneBookAccessPce() const
{
    Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId serviceId{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Rfcomm::IRfcommServiceIdStatics)->get_PhoneBookAccessPce(put_abi(serviceId)));
    return serviceId;
}

template <typename D> Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId consume_Windows_Devices_Bluetooth_Rfcomm_IRfcommServiceIdStatics<D>::PhoneBookAccessPse() const
{
    Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId serviceId{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Rfcomm::IRfcommServiceIdStatics)->get_PhoneBookAccessPse(put_abi(serviceId)));
    return serviceId;
}

template <typename D> Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId consume_Windows_Devices_Bluetooth_Rfcomm_IRfcommServiceIdStatics<D>::GenericFileTransfer() const
{
    Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId serviceId{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Rfcomm::IRfcommServiceIdStatics)->get_GenericFileTransfer(put_abi(serviceId)));
    return serviceId;
}

template <typename D> Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId consume_Windows_Devices_Bluetooth_Rfcomm_IRfcommServiceProvider<D>::ServiceId() const
{
    Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Rfcomm::IRfcommServiceProvider)->get_ServiceId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IMap<uint32_t, Windows::Storage::Streams::IBuffer> consume_Windows_Devices_Bluetooth_Rfcomm_IRfcommServiceProvider<D>::SdpRawAttributes() const
{
    Windows::Foundation::Collections::IMap<uint32_t, Windows::Storage::Streams::IBuffer> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Rfcomm::IRfcommServiceProvider)->get_SdpRawAttributes(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Bluetooth_Rfcomm_IRfcommServiceProvider<D>::StartAdvertising(Windows::Networking::Sockets::StreamSocketListener const& listener) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Rfcomm::IRfcommServiceProvider)->StartAdvertising(get_abi(listener)));
}

template <typename D> void consume_Windows_Devices_Bluetooth_Rfcomm_IRfcommServiceProvider<D>::StopAdvertising() const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Rfcomm::IRfcommServiceProvider)->StopAdvertising());
}

template <typename D> void consume_Windows_Devices_Bluetooth_Rfcomm_IRfcommServiceProvider2<D>::StartAdvertising(Windows::Networking::Sockets::StreamSocketListener const& listener, bool radioDiscoverable) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Rfcomm::IRfcommServiceProvider2)->StartAdvertisingWithRadioDiscoverability(get_abi(listener), radioDiscoverable));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::Rfcomm::RfcommServiceProvider> consume_Windows_Devices_Bluetooth_Rfcomm_IRfcommServiceProviderStatics<D>::CreateAsync(Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId const& serviceId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::Rfcomm::RfcommServiceProvider> asyncOp{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::Rfcomm::IRfcommServiceProviderStatics)->CreateAsync(get_abi(serviceId), put_abi(asyncOp)));
    return asyncOp;
}

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::Rfcomm::IRfcommDeviceService> : produce_base<D, Windows::Devices::Bluetooth::Rfcomm::IRfcommDeviceService>
{
    int32_t WINRT_CALL get_ConnectionHostName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConnectionHostName, WINRT_WRAP(Windows::Networking::HostName));
            *value = detach_from<Windows::Networking::HostName>(this->shim().ConnectionHostName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ConnectionServiceName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConnectionServiceName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ConnectionServiceName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ServiceId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServiceId, WINRT_WRAP(Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId));
            *value = detach_from<Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId>(this->shim().ServiceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProtectionLevel(Windows::Networking::Sockets::SocketProtectionLevel* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProtectionLevel, WINRT_WRAP(Windows::Networking::Sockets::SocketProtectionLevel));
            *value = detach_from<Windows::Networking::Sockets::SocketProtectionLevel>(this->shim().ProtectionLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxProtectionLevel(Windows::Networking::Sockets::SocketProtectionLevel* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxProtectionLevel, WINRT_WRAP(Windows::Networking::Sockets::SocketProtectionLevel));
            *value = detach_from<Windows::Networking::Sockets::SocketProtectionLevel>(this->shim().MaxProtectionLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetSdpRawAttributesAsync(void** asyncOp) noexcept final
    {
        try
        {
            *asyncOp = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetSdpRawAttributesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IMapView<uint32_t, Windows::Storage::Streams::IBuffer>>));
            *asyncOp = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IMapView<uint32_t, Windows::Storage::Streams::IBuffer>>>(this->shim().GetSdpRawAttributesAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetSdpRawAttributesWithCacheModeAsync(Windows::Devices::Bluetooth::BluetoothCacheMode cacheMode, void** asyncOp) noexcept final
    {
        try
        {
            *asyncOp = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetSdpRawAttributesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IMapView<uint32_t, Windows::Storage::Streams::IBuffer>>), Windows::Devices::Bluetooth::BluetoothCacheMode const);
            *asyncOp = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IMapView<uint32_t, Windows::Storage::Streams::IBuffer>>>(this->shim().GetSdpRawAttributesAsync(*reinterpret_cast<Windows::Devices::Bluetooth::BluetoothCacheMode const*>(&cacheMode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::Rfcomm::IRfcommDeviceService2> : produce_base<D, Windows::Devices::Bluetooth::Rfcomm::IRfcommDeviceService2>
{
    int32_t WINRT_CALL get_Device(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Device, WINRT_WRAP(Windows::Devices::Bluetooth::BluetoothDevice));
            *value = detach_from<Windows::Devices::Bluetooth::BluetoothDevice>(this->shim().Device());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::Rfcomm::IRfcommDeviceService3> : produce_base<D, Windows::Devices::Bluetooth::Rfcomm::IRfcommDeviceService3>
{
    int32_t WINRT_CALL get_DeviceAccessInformation(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceAccessInformation, WINRT_WRAP(Windows::Devices::Enumeration::DeviceAccessInformation));
            *value = detach_from<Windows::Devices::Enumeration::DeviceAccessInformation>(this->shim().DeviceAccessInformation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestAccessAsync(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestAccessAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceAccessStatus>));
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceAccessStatus>>(this->shim().RequestAccessAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::Rfcomm::IRfcommDeviceServiceStatics> : produce_base<D, Windows::Devices::Bluetooth::Rfcomm::IRfcommDeviceServiceStatics>
{
    int32_t WINRT_CALL FromIdAsync(void* deviceId, void** asyncOp) noexcept final
    {
        try
        {
            *asyncOp = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::Rfcomm::RfcommDeviceService>), hstring const);
            *asyncOp = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::Rfcomm::RfcommDeviceService>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeviceSelector(void* serviceId, void** selector) noexcept final
    {
        try
        {
            *selector = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelector, WINRT_WRAP(hstring), Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId const&);
            *selector = detach_from<hstring>(this->shim().GetDeviceSelector(*reinterpret_cast<Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId const*>(&serviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::Rfcomm::IRfcommDeviceServiceStatics2> : produce_base<D, Windows::Devices::Bluetooth::Rfcomm::IRfcommDeviceServiceStatics2>
{
    int32_t WINRT_CALL GetDeviceSelectorForBluetoothDevice(void* bluetoothDevice, void** selector) noexcept final
    {
        try
        {
            *selector = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelectorForBluetoothDevice, WINRT_WRAP(hstring), Windows::Devices::Bluetooth::BluetoothDevice const&);
            *selector = detach_from<hstring>(this->shim().GetDeviceSelectorForBluetoothDevice(*reinterpret_cast<Windows::Devices::Bluetooth::BluetoothDevice const*>(&bluetoothDevice)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeviceSelectorForBluetoothDeviceWithCacheMode(void* bluetoothDevice, Windows::Devices::Bluetooth::BluetoothCacheMode cacheMode, void** selector) noexcept final
    {
        try
        {
            *selector = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelectorForBluetoothDevice, WINRT_WRAP(hstring), Windows::Devices::Bluetooth::BluetoothDevice const&, Windows::Devices::Bluetooth::BluetoothCacheMode const&);
            *selector = detach_from<hstring>(this->shim().GetDeviceSelectorForBluetoothDevice(*reinterpret_cast<Windows::Devices::Bluetooth::BluetoothDevice const*>(&bluetoothDevice), *reinterpret_cast<Windows::Devices::Bluetooth::BluetoothCacheMode const*>(&cacheMode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeviceSelectorForBluetoothDeviceAndServiceId(void* bluetoothDevice, void* serviceId, void** selector) noexcept final
    {
        try
        {
            *selector = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelectorForBluetoothDeviceAndServiceId, WINRT_WRAP(hstring), Windows::Devices::Bluetooth::BluetoothDevice const&, Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId const&);
            *selector = detach_from<hstring>(this->shim().GetDeviceSelectorForBluetoothDeviceAndServiceId(*reinterpret_cast<Windows::Devices::Bluetooth::BluetoothDevice const*>(&bluetoothDevice), *reinterpret_cast<Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId const*>(&serviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeviceSelectorForBluetoothDeviceAndServiceIdWithCacheMode(void* bluetoothDevice, void* serviceId, Windows::Devices::Bluetooth::BluetoothCacheMode cacheMode, void** selector) noexcept final
    {
        try
        {
            *selector = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelectorForBluetoothDeviceAndServiceId, WINRT_WRAP(hstring), Windows::Devices::Bluetooth::BluetoothDevice const&, Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId const&, Windows::Devices::Bluetooth::BluetoothCacheMode const&);
            *selector = detach_from<hstring>(this->shim().GetDeviceSelectorForBluetoothDeviceAndServiceId(*reinterpret_cast<Windows::Devices::Bluetooth::BluetoothDevice const*>(&bluetoothDevice), *reinterpret_cast<Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId const*>(&serviceId), *reinterpret_cast<Windows::Devices::Bluetooth::BluetoothCacheMode const*>(&cacheMode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::Rfcomm::IRfcommDeviceServicesResult> : produce_base<D, Windows::Devices::Bluetooth::Rfcomm::IRfcommDeviceServicesResult>
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

    int32_t WINRT_CALL get_Services(void** services) noexcept final
    {
        try
        {
            *services = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Services, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::Rfcomm::RfcommDeviceService>));
            *services = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::Rfcomm::RfcommDeviceService>>(this->shim().Services());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::Rfcomm::IRfcommServiceId> : produce_base<D, Windows::Devices::Bluetooth::Rfcomm::IRfcommServiceId>
{
    int32_t WINRT_CALL get_Uuid(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Uuid, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().Uuid());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AsShortId(uint32_t* shortId) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AsShortId, WINRT_WRAP(uint32_t));
            *shortId = detach_from<uint32_t>(this->shim().AsShortId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AsString(void** id) noexcept final
    {
        try
        {
            *id = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AsString, WINRT_WRAP(hstring));
            *id = detach_from<hstring>(this->shim().AsString());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::Rfcomm::IRfcommServiceIdStatics> : produce_base<D, Windows::Devices::Bluetooth::Rfcomm::IRfcommServiceIdStatics>
{
    int32_t WINRT_CALL FromUuid(winrt::guid uuid, void** serviceId) noexcept final
    {
        try
        {
            *serviceId = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromUuid, WINRT_WRAP(Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId), winrt::guid const&);
            *serviceId = detach_from<Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId>(this->shim().FromUuid(*reinterpret_cast<winrt::guid const*>(&uuid)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FromShortId(uint32_t shortId, void** serviceId) noexcept final
    {
        try
        {
            *serviceId = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromShortId, WINRT_WRAP(Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId), uint32_t);
            *serviceId = detach_from<Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId>(this->shim().FromShortId(shortId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SerialPort(void** serviceId) noexcept final
    {
        try
        {
            *serviceId = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SerialPort, WINRT_WRAP(Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId));
            *serviceId = detach_from<Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId>(this->shim().SerialPort());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ObexObjectPush(void** serviceId) noexcept final
    {
        try
        {
            *serviceId = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ObexObjectPush, WINRT_WRAP(Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId));
            *serviceId = detach_from<Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId>(this->shim().ObexObjectPush());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ObexFileTransfer(void** serviceId) noexcept final
    {
        try
        {
            *serviceId = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ObexFileTransfer, WINRT_WRAP(Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId));
            *serviceId = detach_from<Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId>(this->shim().ObexFileTransfer());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PhoneBookAccessPce(void** serviceId) noexcept final
    {
        try
        {
            *serviceId = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PhoneBookAccessPce, WINRT_WRAP(Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId));
            *serviceId = detach_from<Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId>(this->shim().PhoneBookAccessPce());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PhoneBookAccessPse(void** serviceId) noexcept final
    {
        try
        {
            *serviceId = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PhoneBookAccessPse, WINRT_WRAP(Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId));
            *serviceId = detach_from<Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId>(this->shim().PhoneBookAccessPse());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_GenericFileTransfer(void** serviceId) noexcept final
    {
        try
        {
            *serviceId = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GenericFileTransfer, WINRT_WRAP(Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId));
            *serviceId = detach_from<Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId>(this->shim().GenericFileTransfer());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::Rfcomm::IRfcommServiceProvider> : produce_base<D, Windows::Devices::Bluetooth::Rfcomm::IRfcommServiceProvider>
{
    int32_t WINRT_CALL get_ServiceId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServiceId, WINRT_WRAP(Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId));
            *value = detach_from<Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId>(this->shim().ServiceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SdpRawAttributes(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SdpRawAttributes, WINRT_WRAP(Windows::Foundation::Collections::IMap<uint32_t, Windows::Storage::Streams::IBuffer>));
            *value = detach_from<Windows::Foundation::Collections::IMap<uint32_t, Windows::Storage::Streams::IBuffer>>(this->shim().SdpRawAttributes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StartAdvertising(void* listener) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartAdvertising, WINRT_WRAP(void), Windows::Networking::Sockets::StreamSocketListener const&);
            this->shim().StartAdvertising(*reinterpret_cast<Windows::Networking::Sockets::StreamSocketListener const*>(&listener));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StopAdvertising() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StopAdvertising, WINRT_WRAP(void));
            this->shim().StopAdvertising();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::Rfcomm::IRfcommServiceProvider2> : produce_base<D, Windows::Devices::Bluetooth::Rfcomm::IRfcommServiceProvider2>
{
    int32_t WINRT_CALL StartAdvertisingWithRadioDiscoverability(void* listener, bool radioDiscoverable) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartAdvertising, WINRT_WRAP(void), Windows::Networking::Sockets::StreamSocketListener const&, bool);
            this->shim().StartAdvertising(*reinterpret_cast<Windows::Networking::Sockets::StreamSocketListener const*>(&listener), radioDiscoverable);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::Rfcomm::IRfcommServiceProviderStatics> : produce_base<D, Windows::Devices::Bluetooth::Rfcomm::IRfcommServiceProviderStatics>
{
    int32_t WINRT_CALL CreateAsync(void* serviceId, void** asyncOp) noexcept final
    {
        try
        {
            *asyncOp = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::Rfcomm::RfcommServiceProvider>), Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId const);
            *asyncOp = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::Rfcomm::RfcommServiceProvider>>(this->shim().CreateAsync(*reinterpret_cast<Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId const*>(&serviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Devices::Bluetooth::Rfcomm {

inline Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::Rfcomm::RfcommDeviceService> RfcommDeviceService::FromIdAsync(param::hstring const& deviceId)
{
    return impl::call_factory<RfcommDeviceService, Windows::Devices::Bluetooth::Rfcomm::IRfcommDeviceServiceStatics>([&](auto&& f) { return f.FromIdAsync(deviceId); });
}

inline hstring RfcommDeviceService::GetDeviceSelector(Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId const& serviceId)
{
    return impl::call_factory<RfcommDeviceService, Windows::Devices::Bluetooth::Rfcomm::IRfcommDeviceServiceStatics>([&](auto&& f) { return f.GetDeviceSelector(serviceId); });
}

inline hstring RfcommDeviceService::GetDeviceSelectorForBluetoothDevice(Windows::Devices::Bluetooth::BluetoothDevice const& bluetoothDevice)
{
    return impl::call_factory<RfcommDeviceService, Windows::Devices::Bluetooth::Rfcomm::IRfcommDeviceServiceStatics2>([&](auto&& f) { return f.GetDeviceSelectorForBluetoothDevice(bluetoothDevice); });
}

inline hstring RfcommDeviceService::GetDeviceSelectorForBluetoothDevice(Windows::Devices::Bluetooth::BluetoothDevice const& bluetoothDevice, Windows::Devices::Bluetooth::BluetoothCacheMode const& cacheMode)
{
    return impl::call_factory<RfcommDeviceService, Windows::Devices::Bluetooth::Rfcomm::IRfcommDeviceServiceStatics2>([&](auto&& f) { return f.GetDeviceSelectorForBluetoothDevice(bluetoothDevice, cacheMode); });
}

inline hstring RfcommDeviceService::GetDeviceSelectorForBluetoothDeviceAndServiceId(Windows::Devices::Bluetooth::BluetoothDevice const& bluetoothDevice, Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId const& serviceId)
{
    return impl::call_factory<RfcommDeviceService, Windows::Devices::Bluetooth::Rfcomm::IRfcommDeviceServiceStatics2>([&](auto&& f) { return f.GetDeviceSelectorForBluetoothDeviceAndServiceId(bluetoothDevice, serviceId); });
}

inline hstring RfcommDeviceService::GetDeviceSelectorForBluetoothDeviceAndServiceId(Windows::Devices::Bluetooth::BluetoothDevice const& bluetoothDevice, Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId const& serviceId, Windows::Devices::Bluetooth::BluetoothCacheMode const& cacheMode)
{
    return impl::call_factory<RfcommDeviceService, Windows::Devices::Bluetooth::Rfcomm::IRfcommDeviceServiceStatics2>([&](auto&& f) { return f.GetDeviceSelectorForBluetoothDeviceAndServiceId(bluetoothDevice, serviceId, cacheMode); });
}

inline Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId RfcommServiceId::FromUuid(winrt::guid const& uuid)
{
    return impl::call_factory<RfcommServiceId, Windows::Devices::Bluetooth::Rfcomm::IRfcommServiceIdStatics>([&](auto&& f) { return f.FromUuid(uuid); });
}

inline Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId RfcommServiceId::FromShortId(uint32_t shortId)
{
    return impl::call_factory<RfcommServiceId, Windows::Devices::Bluetooth::Rfcomm::IRfcommServiceIdStatics>([&](auto&& f) { return f.FromShortId(shortId); });
}

inline Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId RfcommServiceId::SerialPort()
{
    return impl::call_factory<RfcommServiceId, Windows::Devices::Bluetooth::Rfcomm::IRfcommServiceIdStatics>([&](auto&& f) { return f.SerialPort(); });
}

inline Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId RfcommServiceId::ObexObjectPush()
{
    return impl::call_factory<RfcommServiceId, Windows::Devices::Bluetooth::Rfcomm::IRfcommServiceIdStatics>([&](auto&& f) { return f.ObexObjectPush(); });
}

inline Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId RfcommServiceId::ObexFileTransfer()
{
    return impl::call_factory<RfcommServiceId, Windows::Devices::Bluetooth::Rfcomm::IRfcommServiceIdStatics>([&](auto&& f) { return f.ObexFileTransfer(); });
}

inline Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId RfcommServiceId::PhoneBookAccessPce()
{
    return impl::call_factory<RfcommServiceId, Windows::Devices::Bluetooth::Rfcomm::IRfcommServiceIdStatics>([&](auto&& f) { return f.PhoneBookAccessPce(); });
}

inline Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId RfcommServiceId::PhoneBookAccessPse()
{
    return impl::call_factory<RfcommServiceId, Windows::Devices::Bluetooth::Rfcomm::IRfcommServiceIdStatics>([&](auto&& f) { return f.PhoneBookAccessPse(); });
}

inline Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId RfcommServiceId::GenericFileTransfer()
{
    return impl::call_factory<RfcommServiceId, Windows::Devices::Bluetooth::Rfcomm::IRfcommServiceIdStatics>([&](auto&& f) { return f.GenericFileTransfer(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::Rfcomm::RfcommServiceProvider> RfcommServiceProvider::CreateAsync(Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId const& serviceId)
{
    return impl::call_factory<RfcommServiceProvider, Windows::Devices::Bluetooth::Rfcomm::IRfcommServiceProviderStatics>([&](auto&& f) { return f.CreateAsync(serviceId); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Devices::Bluetooth::Rfcomm::IRfcommDeviceService> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::Rfcomm::IRfcommDeviceService> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::Rfcomm::IRfcommDeviceService2> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::Rfcomm::IRfcommDeviceService2> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::Rfcomm::IRfcommDeviceService3> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::Rfcomm::IRfcommDeviceService3> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::Rfcomm::IRfcommDeviceServiceStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::Rfcomm::IRfcommDeviceServiceStatics> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::Rfcomm::IRfcommDeviceServiceStatics2> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::Rfcomm::IRfcommDeviceServiceStatics2> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::Rfcomm::IRfcommDeviceServicesResult> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::Rfcomm::IRfcommDeviceServicesResult> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::Rfcomm::IRfcommServiceId> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::Rfcomm::IRfcommServiceId> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::Rfcomm::IRfcommServiceIdStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::Rfcomm::IRfcommServiceIdStatics> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::Rfcomm::IRfcommServiceProvider> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::Rfcomm::IRfcommServiceProvider> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::Rfcomm::IRfcommServiceProvider2> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::Rfcomm::IRfcommServiceProvider2> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::Rfcomm::IRfcommServiceProviderStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::Rfcomm::IRfcommServiceProviderStatics> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::Rfcomm::RfcommDeviceService> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::Rfcomm::RfcommDeviceService> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::Rfcomm::RfcommDeviceServicesResult> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::Rfcomm::RfcommDeviceServicesResult> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::Rfcomm::RfcommServiceProvider> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::Rfcomm::RfcommServiceProvider> {};

}
