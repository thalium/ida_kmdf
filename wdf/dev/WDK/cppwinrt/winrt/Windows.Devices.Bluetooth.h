// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Devices.Bluetooth.GenericAttributeProfile.2.h"
#include "winrt/impl/Windows.Devices.Bluetooth.Rfcomm.2.h"
#include "winrt/impl/Windows.Devices.Enumeration.2.h"
#include "winrt/impl/Windows.Devices.Radios.2.h"
#include "winrt/impl/Windows.Networking.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Devices.Bluetooth.2.h"
#include "winrt/Windows.Devices.h"

namespace winrt::impl {

template <typename D> hstring consume_Windows_Devices_Bluetooth_IBluetoothAdapter<D>::DeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothAdapter)->get_DeviceId(put_abi(value)));
    return value;
}

template <typename D> uint64_t consume_Windows_Devices_Bluetooth_IBluetoothAdapter<D>::BluetoothAddress() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothAdapter)->get_BluetoothAddress(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_Bluetooth_IBluetoothAdapter<D>::IsClassicSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothAdapter)->get_IsClassicSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_Bluetooth_IBluetoothAdapter<D>::IsLowEnergySupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothAdapter)->get_IsLowEnergySupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_Bluetooth_IBluetoothAdapter<D>::IsPeripheralRoleSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothAdapter)->get_IsPeripheralRoleSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_Bluetooth_IBluetoothAdapter<D>::IsCentralRoleSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothAdapter)->get_IsCentralRoleSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_Bluetooth_IBluetoothAdapter<D>::IsAdvertisementOffloadSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothAdapter)->get_IsAdvertisementOffloadSupported(&value));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Radios::Radio> consume_Windows_Devices_Bluetooth_IBluetoothAdapter<D>::GetRadioAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Radios::Radio> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothAdapter)->GetRadioAsync(put_abi(operation)));
    return operation;
}

template <typename D> bool consume_Windows_Devices_Bluetooth_IBluetoothAdapter2<D>::AreClassicSecureConnectionsSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothAdapter2)->get_AreClassicSecureConnectionsSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_Bluetooth_IBluetoothAdapter2<D>::AreLowEnergySecureConnectionsSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothAdapter2)->get_AreLowEnergySecureConnectionsSupported(&value));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Bluetooth_IBluetoothAdapterStatics<D>::GetDeviceSelector() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothAdapterStatics)->GetDeviceSelector(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::BluetoothAdapter> consume_Windows_Devices_Bluetooth_IBluetoothAdapterStatics<D>::FromIdAsync(param::hstring const& deviceId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::BluetoothAdapter> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothAdapterStatics)->FromIdAsync(get_abi(deviceId), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::BluetoothAdapter> consume_Windows_Devices_Bluetooth_IBluetoothAdapterStatics<D>::GetDefaultAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::BluetoothAdapter> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothAdapterStatics)->GetDefaultAsync(put_abi(operation)));
    return operation;
}

template <typename D> uint32_t consume_Windows_Devices_Bluetooth_IBluetoothClassOfDevice<D>::RawValue() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothClassOfDevice)->get_RawValue(&value));
    return value;
}

template <typename D> Windows::Devices::Bluetooth::BluetoothMajorClass consume_Windows_Devices_Bluetooth_IBluetoothClassOfDevice<D>::MajorClass() const
{
    Windows::Devices::Bluetooth::BluetoothMajorClass value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothClassOfDevice)->get_MajorClass(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Bluetooth::BluetoothMinorClass consume_Windows_Devices_Bluetooth_IBluetoothClassOfDevice<D>::MinorClass() const
{
    Windows::Devices::Bluetooth::BluetoothMinorClass value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothClassOfDevice)->get_MinorClass(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Bluetooth::BluetoothServiceCapabilities consume_Windows_Devices_Bluetooth_IBluetoothClassOfDevice<D>::ServiceCapabilities() const
{
    Windows::Devices::Bluetooth::BluetoothServiceCapabilities value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothClassOfDevice)->get_ServiceCapabilities(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Bluetooth::BluetoothClassOfDevice consume_Windows_Devices_Bluetooth_IBluetoothClassOfDeviceStatics<D>::FromRawValue(uint32_t rawValue) const
{
    Windows::Devices::Bluetooth::BluetoothClassOfDevice classOfDevice{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothClassOfDeviceStatics)->FromRawValue(rawValue, put_abi(classOfDevice)));
    return classOfDevice;
}

template <typename D> Windows::Devices::Bluetooth::BluetoothClassOfDevice consume_Windows_Devices_Bluetooth_IBluetoothClassOfDeviceStatics<D>::FromParts(Windows::Devices::Bluetooth::BluetoothMajorClass const& majorClass, Windows::Devices::Bluetooth::BluetoothMinorClass const& minorClass, Windows::Devices::Bluetooth::BluetoothServiceCapabilities const& serviceCapabilities) const
{
    Windows::Devices::Bluetooth::BluetoothClassOfDevice classOfDevice{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothClassOfDeviceStatics)->FromParts(get_abi(majorClass), get_abi(minorClass), get_abi(serviceCapabilities), put_abi(classOfDevice)));
    return classOfDevice;
}

template <typename D> hstring consume_Windows_Devices_Bluetooth_IBluetoothDevice<D>::DeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothDevice)->get_DeviceId(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::HostName consume_Windows_Devices_Bluetooth_IBluetoothDevice<D>::HostName() const
{
    Windows::Networking::HostName value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothDevice)->get_HostName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Bluetooth_IBluetoothDevice<D>::Name() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothDevice)->get_Name(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Bluetooth::BluetoothClassOfDevice consume_Windows_Devices_Bluetooth_IBluetoothDevice<D>::ClassOfDevice() const
{
    Windows::Devices::Bluetooth::BluetoothClassOfDevice value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothDevice)->get_ClassOfDevice(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Storage::Streams::IBuffer> consume_Windows_Devices_Bluetooth_IBluetoothDevice<D>::SdpRecords() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Storage::Streams::IBuffer> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothDevice)->get_SdpRecords(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::Rfcomm::RfcommDeviceService> consume_Windows_Devices_Bluetooth_IBluetoothDevice<D>::RfcommServices() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::Rfcomm::RfcommDeviceService> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothDevice)->get_RfcommServices(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Bluetooth::BluetoothConnectionStatus consume_Windows_Devices_Bluetooth_IBluetoothDevice<D>::ConnectionStatus() const
{
    Windows::Devices::Bluetooth::BluetoothConnectionStatus value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothDevice)->get_ConnectionStatus(put_abi(value)));
    return value;
}

template <typename D> uint64_t consume_Windows_Devices_Bluetooth_IBluetoothDevice<D>::BluetoothAddress() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothDevice)->get_BluetoothAddress(&value));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Devices_Bluetooth_IBluetoothDevice<D>::NameChanged(Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::BluetoothDevice, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothDevice)->add_NameChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Bluetooth_IBluetoothDevice<D>::NameChanged_revoker consume_Windows_Devices_Bluetooth_IBluetoothDevice<D>::NameChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::BluetoothDevice, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, NameChanged_revoker>(this, NameChanged(handler));
}

template <typename D> void consume_Windows_Devices_Bluetooth_IBluetoothDevice<D>::NameChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothDevice)->remove_NameChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Devices_Bluetooth_IBluetoothDevice<D>::SdpRecordsChanged(Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::BluetoothDevice, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothDevice)->add_SdpRecordsChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Bluetooth_IBluetoothDevice<D>::SdpRecordsChanged_revoker consume_Windows_Devices_Bluetooth_IBluetoothDevice<D>::SdpRecordsChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::BluetoothDevice, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, SdpRecordsChanged_revoker>(this, SdpRecordsChanged(handler));
}

template <typename D> void consume_Windows_Devices_Bluetooth_IBluetoothDevice<D>::SdpRecordsChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothDevice)->remove_SdpRecordsChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Devices_Bluetooth_IBluetoothDevice<D>::ConnectionStatusChanged(Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::BluetoothDevice, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothDevice)->add_ConnectionStatusChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Bluetooth_IBluetoothDevice<D>::ConnectionStatusChanged_revoker consume_Windows_Devices_Bluetooth_IBluetoothDevice<D>::ConnectionStatusChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::BluetoothDevice, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, ConnectionStatusChanged_revoker>(this, ConnectionStatusChanged(handler));
}

template <typename D> void consume_Windows_Devices_Bluetooth_IBluetoothDevice<D>::ConnectionStatusChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothDevice)->remove_ConnectionStatusChanged(get_abi(token)));
}

template <typename D> Windows::Devices::Enumeration::DeviceInformation consume_Windows_Devices_Bluetooth_IBluetoothDevice2<D>::DeviceInformation() const
{
    Windows::Devices::Enumeration::DeviceInformation value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothDevice2)->get_DeviceInformation(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Enumeration::DeviceAccessInformation consume_Windows_Devices_Bluetooth_IBluetoothDevice3<D>::DeviceAccessInformation() const
{
    Windows::Devices::Enumeration::DeviceAccessInformation value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothDevice3)->get_DeviceAccessInformation(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceAccessStatus> consume_Windows_Devices_Bluetooth_IBluetoothDevice3<D>::RequestAccessAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceAccessStatus> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothDevice3)->RequestAccessAsync(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::Rfcomm::RfcommDeviceServicesResult> consume_Windows_Devices_Bluetooth_IBluetoothDevice3<D>::GetRfcommServicesAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::Rfcomm::RfcommDeviceServicesResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothDevice3)->GetRfcommServicesAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::Rfcomm::RfcommDeviceServicesResult> consume_Windows_Devices_Bluetooth_IBluetoothDevice3<D>::GetRfcommServicesAsync(Windows::Devices::Bluetooth::BluetoothCacheMode const& cacheMode) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::Rfcomm::RfcommDeviceServicesResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothDevice3)->GetRfcommServicesWithCacheModeAsync(get_abi(cacheMode), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::Rfcomm::RfcommDeviceServicesResult> consume_Windows_Devices_Bluetooth_IBluetoothDevice3<D>::GetRfcommServicesForIdAsync(Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId const& serviceId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::Rfcomm::RfcommDeviceServicesResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothDevice3)->GetRfcommServicesForIdAsync(get_abi(serviceId), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::Rfcomm::RfcommDeviceServicesResult> consume_Windows_Devices_Bluetooth_IBluetoothDevice3<D>::GetRfcommServicesForIdAsync(Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId const& serviceId, Windows::Devices::Bluetooth::BluetoothCacheMode const& cacheMode) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::Rfcomm::RfcommDeviceServicesResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothDevice3)->GetRfcommServicesForIdWithCacheModeAsync(get_abi(serviceId), get_abi(cacheMode), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Devices::Bluetooth::BluetoothDeviceId consume_Windows_Devices_Bluetooth_IBluetoothDevice4<D>::BluetoothDeviceId() const
{
    Windows::Devices::Bluetooth::BluetoothDeviceId value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothDevice4)->get_BluetoothDeviceId(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Devices_Bluetooth_IBluetoothDevice5<D>::WasSecureConnectionUsedForPairing() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothDevice5)->get_WasSecureConnectionUsedForPairing(&value));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Bluetooth_IBluetoothDeviceId<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothDeviceId)->get_Id(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Devices_Bluetooth_IBluetoothDeviceId<D>::IsClassicDevice() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothDeviceId)->get_IsClassicDevice(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_Bluetooth_IBluetoothDeviceId<D>::IsLowEnergyDevice() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothDeviceId)->get_IsLowEnergyDevice(&value));
    return value;
}

template <typename D> Windows::Devices::Bluetooth::BluetoothDeviceId consume_Windows_Devices_Bluetooth_IBluetoothDeviceIdStatics<D>::FromId(param::hstring const& deviceId) const
{
    Windows::Devices::Bluetooth::BluetoothDeviceId result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothDeviceIdStatics)->FromId(get_abi(deviceId), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::BluetoothDevice> consume_Windows_Devices_Bluetooth_IBluetoothDeviceStatics<D>::FromIdAsync(param::hstring const& deviceId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::BluetoothDevice> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothDeviceStatics)->FromIdAsync(get_abi(deviceId), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::BluetoothDevice> consume_Windows_Devices_Bluetooth_IBluetoothDeviceStatics<D>::FromHostNameAsync(Windows::Networking::HostName const& hostName) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::BluetoothDevice> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothDeviceStatics)->FromHostNameAsync(get_abi(hostName), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::BluetoothDevice> consume_Windows_Devices_Bluetooth_IBluetoothDeviceStatics<D>::FromBluetoothAddressAsync(uint64_t address) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::BluetoothDevice> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothDeviceStatics)->FromBluetoothAddressAsync(address, put_abi(operation)));
    return operation;
}

template <typename D> hstring consume_Windows_Devices_Bluetooth_IBluetoothDeviceStatics<D>::GetDeviceSelector() const
{
    hstring deviceSelector{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothDeviceStatics)->GetDeviceSelector(put_abi(deviceSelector)));
    return deviceSelector;
}

template <typename D> hstring consume_Windows_Devices_Bluetooth_IBluetoothDeviceStatics2<D>::GetDeviceSelectorFromPairingState(bool pairingState) const
{
    hstring deviceSelector{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothDeviceStatics2)->GetDeviceSelectorFromPairingState(pairingState, put_abi(deviceSelector)));
    return deviceSelector;
}

template <typename D> hstring consume_Windows_Devices_Bluetooth_IBluetoothDeviceStatics2<D>::GetDeviceSelectorFromConnectionStatus(Windows::Devices::Bluetooth::BluetoothConnectionStatus const& connectionStatus) const
{
    hstring deviceSelector{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothDeviceStatics2)->GetDeviceSelectorFromConnectionStatus(get_abi(connectionStatus), put_abi(deviceSelector)));
    return deviceSelector;
}

template <typename D> hstring consume_Windows_Devices_Bluetooth_IBluetoothDeviceStatics2<D>::GetDeviceSelectorFromDeviceName(param::hstring const& deviceName) const
{
    hstring deviceSelector{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothDeviceStatics2)->GetDeviceSelectorFromDeviceName(get_abi(deviceName), put_abi(deviceSelector)));
    return deviceSelector;
}

template <typename D> hstring consume_Windows_Devices_Bluetooth_IBluetoothDeviceStatics2<D>::GetDeviceSelectorFromBluetoothAddress(uint64_t bluetoothAddress) const
{
    hstring deviceSelector{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothDeviceStatics2)->GetDeviceSelectorFromBluetoothAddress(bluetoothAddress, put_abi(deviceSelector)));
    return deviceSelector;
}

template <typename D> hstring consume_Windows_Devices_Bluetooth_IBluetoothDeviceStatics2<D>::GetDeviceSelectorFromClassOfDevice(Windows::Devices::Bluetooth::BluetoothClassOfDevice const& classOfDevice) const
{
    hstring deviceSelector{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothDeviceStatics2)->GetDeviceSelectorFromClassOfDevice(get_abi(classOfDevice), put_abi(deviceSelector)));
    return deviceSelector;
}

template <typename D> uint16_t consume_Windows_Devices_Bluetooth_IBluetoothLEAppearance<D>::RawValue() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEAppearance)->get_RawValue(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_Bluetooth_IBluetoothLEAppearance<D>::Category() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEAppearance)->get_Category(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_Bluetooth_IBluetoothLEAppearance<D>::SubCategory() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEAppearance)->get_SubCategory(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceCategoriesStatics<D>::Uncategorized() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics)->get_Uncategorized(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceCategoriesStatics<D>::Phone() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics)->get_Phone(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceCategoriesStatics<D>::Computer() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics)->get_Computer(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceCategoriesStatics<D>::Watch() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics)->get_Watch(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceCategoriesStatics<D>::Clock() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics)->get_Clock(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceCategoriesStatics<D>::Display() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics)->get_Display(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceCategoriesStatics<D>::RemoteControl() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics)->get_RemoteControl(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceCategoriesStatics<D>::EyeGlasses() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics)->get_EyeGlasses(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceCategoriesStatics<D>::Tag() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics)->get_Tag(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceCategoriesStatics<D>::Keyring() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics)->get_Keyring(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceCategoriesStatics<D>::MediaPlayer() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics)->get_MediaPlayer(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceCategoriesStatics<D>::BarcodeScanner() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics)->get_BarcodeScanner(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceCategoriesStatics<D>::Thermometer() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics)->get_Thermometer(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceCategoriesStatics<D>::HeartRate() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics)->get_HeartRate(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceCategoriesStatics<D>::BloodPressure() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics)->get_BloodPressure(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceCategoriesStatics<D>::HumanInterfaceDevice() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics)->get_HumanInterfaceDevice(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceCategoriesStatics<D>::GlucoseMeter() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics)->get_GlucoseMeter(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceCategoriesStatics<D>::RunningWalking() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics)->get_RunningWalking(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceCategoriesStatics<D>::Cycling() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics)->get_Cycling(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceCategoriesStatics<D>::PulseOximeter() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics)->get_PulseOximeter(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceCategoriesStatics<D>::WeightScale() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics)->get_WeightScale(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceCategoriesStatics<D>::OutdoorSportActivity() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics)->get_OutdoorSportActivity(&value));
    return value;
}

template <typename D> Windows::Devices::Bluetooth::BluetoothLEAppearance consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceStatics<D>::FromRawValue(uint16_t rawValue) const
{
    Windows::Devices::Bluetooth::BluetoothLEAppearance appearance{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEAppearanceStatics)->FromRawValue(rawValue, put_abi(appearance)));
    return appearance;
}

template <typename D> Windows::Devices::Bluetooth::BluetoothLEAppearance consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceStatics<D>::FromParts(uint16_t appearanceCategory, uint16_t appearanceSubCategory) const
{
    Windows::Devices::Bluetooth::BluetoothLEAppearance appearance{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEAppearanceStatics)->FromParts(appearanceCategory, appearanceSubCategory, put_abi(appearance)));
    return appearance;
}

template <typename D> uint16_t consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceSubcategoriesStatics<D>::Generic() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics)->get_Generic(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceSubcategoriesStatics<D>::SportsWatch() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics)->get_SportsWatch(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceSubcategoriesStatics<D>::ThermometerEar() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics)->get_ThermometerEar(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceSubcategoriesStatics<D>::HeartRateBelt() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics)->get_HeartRateBelt(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceSubcategoriesStatics<D>::BloodPressureArm() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics)->get_BloodPressureArm(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceSubcategoriesStatics<D>::BloodPressureWrist() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics)->get_BloodPressureWrist(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceSubcategoriesStatics<D>::Keyboard() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics)->get_Keyboard(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceSubcategoriesStatics<D>::Mouse() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics)->get_Mouse(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceSubcategoriesStatics<D>::Joystick() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics)->get_Joystick(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceSubcategoriesStatics<D>::Gamepad() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics)->get_Gamepad(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceSubcategoriesStatics<D>::DigitizerTablet() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics)->get_DigitizerTablet(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceSubcategoriesStatics<D>::CardReader() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics)->get_CardReader(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceSubcategoriesStatics<D>::DigitalPen() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics)->get_DigitalPen(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceSubcategoriesStatics<D>::BarcodeScanner() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics)->get_BarcodeScanner(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceSubcategoriesStatics<D>::RunningWalkingInShoe() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics)->get_RunningWalkingInShoe(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceSubcategoriesStatics<D>::RunningWalkingOnShoe() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics)->get_RunningWalkingOnShoe(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceSubcategoriesStatics<D>::RunningWalkingOnHip() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics)->get_RunningWalkingOnHip(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceSubcategoriesStatics<D>::CyclingComputer() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics)->get_CyclingComputer(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceSubcategoriesStatics<D>::CyclingSpeedSensor() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics)->get_CyclingSpeedSensor(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceSubcategoriesStatics<D>::CyclingCadenceSensor() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics)->get_CyclingCadenceSensor(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceSubcategoriesStatics<D>::CyclingPowerSensor() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics)->get_CyclingPowerSensor(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceSubcategoriesStatics<D>::CyclingSpeedCadenceSensor() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics)->get_CyclingSpeedCadenceSensor(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceSubcategoriesStatics<D>::OximeterFingertip() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics)->get_OximeterFingertip(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceSubcategoriesStatics<D>::OximeterWristWorn() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics)->get_OximeterWristWorn(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceSubcategoriesStatics<D>::LocationDisplay() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics)->get_LocationDisplay(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceSubcategoriesStatics<D>::LocationNavigationDisplay() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics)->get_LocationNavigationDisplay(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceSubcategoriesStatics<D>::LocationPod() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics)->get_LocationPod(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceSubcategoriesStatics<D>::LocationNavigationPod() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics)->get_LocationNavigationPod(&value));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Bluetooth_IBluetoothLEDevice<D>::DeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEDevice)->get_DeviceId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Bluetooth_IBluetoothLEDevice<D>::Name() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEDevice)->get_Name(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceService> consume_Windows_Devices_Bluetooth_IBluetoothLEDevice<D>::GattServices() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceService> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEDevice)->get_GattServices(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Bluetooth::BluetoothConnectionStatus consume_Windows_Devices_Bluetooth_IBluetoothLEDevice<D>::ConnectionStatus() const
{
    Windows::Devices::Bluetooth::BluetoothConnectionStatus value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEDevice)->get_ConnectionStatus(put_abi(value)));
    return value;
}

template <typename D> uint64_t consume_Windows_Devices_Bluetooth_IBluetoothLEDevice<D>::BluetoothAddress() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEDevice)->get_BluetoothAddress(&value));
    return value;
}

template <typename D> Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceService consume_Windows_Devices_Bluetooth_IBluetoothLEDevice<D>::GetGattService(winrt::guid const& serviceUuid) const
{
    Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceService service{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEDevice)->GetGattService(get_abi(serviceUuid), put_abi(service)));
    return service;
}

template <typename D> winrt::event_token consume_Windows_Devices_Bluetooth_IBluetoothLEDevice<D>::NameChanged(Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::BluetoothLEDevice, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEDevice)->add_NameChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Bluetooth_IBluetoothLEDevice<D>::NameChanged_revoker consume_Windows_Devices_Bluetooth_IBluetoothLEDevice<D>::NameChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::BluetoothLEDevice, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, NameChanged_revoker>(this, NameChanged(handler));
}

template <typename D> void consume_Windows_Devices_Bluetooth_IBluetoothLEDevice<D>::NameChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEDevice)->remove_NameChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Devices_Bluetooth_IBluetoothLEDevice<D>::GattServicesChanged(Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::BluetoothLEDevice, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEDevice)->add_GattServicesChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Bluetooth_IBluetoothLEDevice<D>::GattServicesChanged_revoker consume_Windows_Devices_Bluetooth_IBluetoothLEDevice<D>::GattServicesChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::BluetoothLEDevice, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, GattServicesChanged_revoker>(this, GattServicesChanged(handler));
}

template <typename D> void consume_Windows_Devices_Bluetooth_IBluetoothLEDevice<D>::GattServicesChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEDevice)->remove_GattServicesChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Devices_Bluetooth_IBluetoothLEDevice<D>::ConnectionStatusChanged(Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::BluetoothLEDevice, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEDevice)->add_ConnectionStatusChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Bluetooth_IBluetoothLEDevice<D>::ConnectionStatusChanged_revoker consume_Windows_Devices_Bluetooth_IBluetoothLEDevice<D>::ConnectionStatusChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::BluetoothLEDevice, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, ConnectionStatusChanged_revoker>(this, ConnectionStatusChanged(handler));
}

template <typename D> void consume_Windows_Devices_Bluetooth_IBluetoothLEDevice<D>::ConnectionStatusChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEDevice)->remove_ConnectionStatusChanged(get_abi(token)));
}

template <typename D> Windows::Devices::Enumeration::DeviceInformation consume_Windows_Devices_Bluetooth_IBluetoothLEDevice2<D>::DeviceInformation() const
{
    Windows::Devices::Enumeration::DeviceInformation value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEDevice2)->get_DeviceInformation(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Bluetooth::BluetoothLEAppearance consume_Windows_Devices_Bluetooth_IBluetoothLEDevice2<D>::Appearance() const
{
    Windows::Devices::Bluetooth::BluetoothLEAppearance value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEDevice2)->get_Appearance(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Bluetooth::BluetoothAddressType consume_Windows_Devices_Bluetooth_IBluetoothLEDevice2<D>::BluetoothAddressType() const
{
    Windows::Devices::Bluetooth::BluetoothAddressType value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEDevice2)->get_BluetoothAddressType(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Enumeration::DeviceAccessInformation consume_Windows_Devices_Bluetooth_IBluetoothLEDevice3<D>::DeviceAccessInformation() const
{
    Windows::Devices::Enumeration::DeviceAccessInformation value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEDevice3)->get_DeviceAccessInformation(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceAccessStatus> consume_Windows_Devices_Bluetooth_IBluetoothLEDevice3<D>::RequestAccessAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceAccessStatus> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEDevice3)->RequestAccessAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceServicesResult> consume_Windows_Devices_Bluetooth_IBluetoothLEDevice3<D>::GetGattServicesAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceServicesResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEDevice3)->GetGattServicesAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceServicesResult> consume_Windows_Devices_Bluetooth_IBluetoothLEDevice3<D>::GetGattServicesAsync(Windows::Devices::Bluetooth::BluetoothCacheMode const& cacheMode) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceServicesResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEDevice3)->GetGattServicesWithCacheModeAsync(get_abi(cacheMode), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceServicesResult> consume_Windows_Devices_Bluetooth_IBluetoothLEDevice3<D>::GetGattServicesForUuidAsync(winrt::guid const& serviceUuid) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceServicesResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEDevice3)->GetGattServicesForUuidAsync(get_abi(serviceUuid), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceServicesResult> consume_Windows_Devices_Bluetooth_IBluetoothLEDevice3<D>::GetGattServicesForUuidAsync(winrt::guid const& serviceUuid, Windows::Devices::Bluetooth::BluetoothCacheMode const& cacheMode) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceServicesResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEDevice3)->GetGattServicesForUuidWithCacheModeAsync(get_abi(serviceUuid), get_abi(cacheMode), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Devices::Bluetooth::BluetoothDeviceId consume_Windows_Devices_Bluetooth_IBluetoothLEDevice4<D>::BluetoothDeviceId() const
{
    Windows::Devices::Bluetooth::BluetoothDeviceId value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEDevice4)->get_BluetoothDeviceId(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Devices_Bluetooth_IBluetoothLEDevice5<D>::WasSecureConnectionUsedForPairing() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEDevice5)->get_WasSecureConnectionUsedForPairing(&value));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::BluetoothLEDevice> consume_Windows_Devices_Bluetooth_IBluetoothLEDeviceStatics<D>::FromIdAsync(param::hstring const& deviceId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::BluetoothLEDevice> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEDeviceStatics)->FromIdAsync(get_abi(deviceId), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::BluetoothLEDevice> consume_Windows_Devices_Bluetooth_IBluetoothLEDeviceStatics<D>::FromBluetoothAddressAsync(uint64_t bluetoothAddress) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::BluetoothLEDevice> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEDeviceStatics)->FromBluetoothAddressAsync(bluetoothAddress, put_abi(operation)));
    return operation;
}

template <typename D> hstring consume_Windows_Devices_Bluetooth_IBluetoothLEDeviceStatics<D>::GetDeviceSelector() const
{
    hstring deviceSelector{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEDeviceStatics)->GetDeviceSelector(put_abi(deviceSelector)));
    return deviceSelector;
}

template <typename D> hstring consume_Windows_Devices_Bluetooth_IBluetoothLEDeviceStatics2<D>::GetDeviceSelectorFromPairingState(bool pairingState) const
{
    hstring deviceSelector{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEDeviceStatics2)->GetDeviceSelectorFromPairingState(pairingState, put_abi(deviceSelector)));
    return deviceSelector;
}

template <typename D> hstring consume_Windows_Devices_Bluetooth_IBluetoothLEDeviceStatics2<D>::GetDeviceSelectorFromConnectionStatus(Windows::Devices::Bluetooth::BluetoothConnectionStatus const& connectionStatus) const
{
    hstring deviceSelector{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEDeviceStatics2)->GetDeviceSelectorFromConnectionStatus(get_abi(connectionStatus), put_abi(deviceSelector)));
    return deviceSelector;
}

template <typename D> hstring consume_Windows_Devices_Bluetooth_IBluetoothLEDeviceStatics2<D>::GetDeviceSelectorFromDeviceName(param::hstring const& deviceName) const
{
    hstring deviceSelector{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEDeviceStatics2)->GetDeviceSelectorFromDeviceName(get_abi(deviceName), put_abi(deviceSelector)));
    return deviceSelector;
}

template <typename D> hstring consume_Windows_Devices_Bluetooth_IBluetoothLEDeviceStatics2<D>::GetDeviceSelectorFromBluetoothAddress(uint64_t bluetoothAddress) const
{
    hstring deviceSelector{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEDeviceStatics2)->GetDeviceSelectorFromBluetoothAddress(bluetoothAddress, put_abi(deviceSelector)));
    return deviceSelector;
}

template <typename D> hstring consume_Windows_Devices_Bluetooth_IBluetoothLEDeviceStatics2<D>::GetDeviceSelectorFromBluetoothAddress(uint64_t bluetoothAddress, Windows::Devices::Bluetooth::BluetoothAddressType const& bluetoothAddressType) const
{
    hstring deviceSelector{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEDeviceStatics2)->GetDeviceSelectorFromBluetoothAddressWithBluetoothAddressType(bluetoothAddress, get_abi(bluetoothAddressType), put_abi(deviceSelector)));
    return deviceSelector;
}

template <typename D> hstring consume_Windows_Devices_Bluetooth_IBluetoothLEDeviceStatics2<D>::GetDeviceSelectorFromAppearance(Windows::Devices::Bluetooth::BluetoothLEAppearance const& appearance) const
{
    hstring deviceSelector{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEDeviceStatics2)->GetDeviceSelectorFromAppearance(get_abi(appearance), put_abi(deviceSelector)));
    return deviceSelector;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::BluetoothLEDevice> consume_Windows_Devices_Bluetooth_IBluetoothLEDeviceStatics2<D>::FromBluetoothAddressAsync(uint64_t bluetoothAddress, Windows::Devices::Bluetooth::BluetoothAddressType const& bluetoothAddressType) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::BluetoothLEDevice> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothLEDeviceStatics2)->FromBluetoothAddressWithBluetoothAddressTypeAsync(bluetoothAddress, get_abi(bluetoothAddressType), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IReference<int16_t> consume_Windows_Devices_Bluetooth_IBluetoothSignalStrengthFilter<D>::InRangeThresholdInDBm() const
{
    Windows::Foundation::IReference<int16_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothSignalStrengthFilter)->get_InRangeThresholdInDBm(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Bluetooth_IBluetoothSignalStrengthFilter<D>::InRangeThresholdInDBm(optional<int16_t> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothSignalStrengthFilter)->put_InRangeThresholdInDBm(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<int16_t> consume_Windows_Devices_Bluetooth_IBluetoothSignalStrengthFilter<D>::OutOfRangeThresholdInDBm() const
{
    Windows::Foundation::IReference<int16_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothSignalStrengthFilter)->get_OutOfRangeThresholdInDBm(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Bluetooth_IBluetoothSignalStrengthFilter<D>::OutOfRangeThresholdInDBm(optional<int16_t> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothSignalStrengthFilter)->put_OutOfRangeThresholdInDBm(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::TimeSpan> consume_Windows_Devices_Bluetooth_IBluetoothSignalStrengthFilter<D>::OutOfRangeTimeout() const
{
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothSignalStrengthFilter)->get_OutOfRangeTimeout(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Bluetooth_IBluetoothSignalStrengthFilter<D>::OutOfRangeTimeout(optional<Windows::Foundation::TimeSpan> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothSignalStrengthFilter)->put_OutOfRangeTimeout(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::TimeSpan> consume_Windows_Devices_Bluetooth_IBluetoothSignalStrengthFilter<D>::SamplingInterval() const
{
    Windows::Foundation::IReference<Windows::Foundation::TimeSpan> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothSignalStrengthFilter)->get_SamplingInterval(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Bluetooth_IBluetoothSignalStrengthFilter<D>::SamplingInterval(optional<Windows::Foundation::TimeSpan> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothSignalStrengthFilter)->put_SamplingInterval(get_abi(value)));
}

template <typename D> winrt::guid consume_Windows_Devices_Bluetooth_IBluetoothUuidHelperStatics<D>::FromShortId(uint32_t shortId) const
{
    winrt::guid result{};
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothUuidHelperStatics)->FromShortId(shortId, put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IReference<uint32_t> consume_Windows_Devices_Bluetooth_IBluetoothUuidHelperStatics<D>::TryGetShortId(winrt::guid const& uuid) const
{
    Windows::Foundation::IReference<uint32_t> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Bluetooth::IBluetoothUuidHelperStatics)->TryGetShortId(get_abi(uuid), put_abi(result)));
    return result;
}

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::IBluetoothAdapter> : produce_base<D, Windows::Devices::Bluetooth::IBluetoothAdapter>
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

    int32_t WINRT_CALL get_BluetoothAddress(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BluetoothAddress, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().BluetoothAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsClassicSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsClassicSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsClassicSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsLowEnergySupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsLowEnergySupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsLowEnergySupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsPeripheralRoleSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsPeripheralRoleSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsPeripheralRoleSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsCentralRoleSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsCentralRoleSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsCentralRoleSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsAdvertisementOffloadSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsAdvertisementOffloadSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsAdvertisementOffloadSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetRadioAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetRadioAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Radios::Radio>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Radios::Radio>>(this->shim().GetRadioAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::IBluetoothAdapter2> : produce_base<D, Windows::Devices::Bluetooth::IBluetoothAdapter2>
{
    int32_t WINRT_CALL get_AreClassicSecureConnectionsSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AreClassicSecureConnectionsSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AreClassicSecureConnectionsSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AreLowEnergySecureConnectionsSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AreLowEnergySecureConnectionsSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AreLowEnergySecureConnectionsSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::IBluetoothAdapterStatics> : produce_base<D, Windows::Devices::Bluetooth::IBluetoothAdapterStatics>
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

    int32_t WINRT_CALL FromIdAsync(void* deviceId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::BluetoothAdapter>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::BluetoothAdapter>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
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
            WINRT_ASSERT_DECLARATION(GetDefaultAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::BluetoothAdapter>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::BluetoothAdapter>>(this->shim().GetDefaultAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::IBluetoothClassOfDevice> : produce_base<D, Windows::Devices::Bluetooth::IBluetoothClassOfDevice>
{
    int32_t WINRT_CALL get_RawValue(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RawValue, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().RawValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MajorClass(Windows::Devices::Bluetooth::BluetoothMajorClass* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MajorClass, WINRT_WRAP(Windows::Devices::Bluetooth::BluetoothMajorClass));
            *value = detach_from<Windows::Devices::Bluetooth::BluetoothMajorClass>(this->shim().MajorClass());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MinorClass(Windows::Devices::Bluetooth::BluetoothMinorClass* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinorClass, WINRT_WRAP(Windows::Devices::Bluetooth::BluetoothMinorClass));
            *value = detach_from<Windows::Devices::Bluetooth::BluetoothMinorClass>(this->shim().MinorClass());
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
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::IBluetoothClassOfDeviceStatics> : produce_base<D, Windows::Devices::Bluetooth::IBluetoothClassOfDeviceStatics>
{
    int32_t WINRT_CALL FromRawValue(uint32_t rawValue, void** classOfDevice) noexcept final
    {
        try
        {
            *classOfDevice = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromRawValue, WINRT_WRAP(Windows::Devices::Bluetooth::BluetoothClassOfDevice), uint32_t);
            *classOfDevice = detach_from<Windows::Devices::Bluetooth::BluetoothClassOfDevice>(this->shim().FromRawValue(rawValue));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FromParts(Windows::Devices::Bluetooth::BluetoothMajorClass majorClass, Windows::Devices::Bluetooth::BluetoothMinorClass minorClass, Windows::Devices::Bluetooth::BluetoothServiceCapabilities serviceCapabilities, void** classOfDevice) noexcept final
    {
        try
        {
            *classOfDevice = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromParts, WINRT_WRAP(Windows::Devices::Bluetooth::BluetoothClassOfDevice), Windows::Devices::Bluetooth::BluetoothMajorClass const&, Windows::Devices::Bluetooth::BluetoothMinorClass const&, Windows::Devices::Bluetooth::BluetoothServiceCapabilities const&);
            *classOfDevice = detach_from<Windows::Devices::Bluetooth::BluetoothClassOfDevice>(this->shim().FromParts(*reinterpret_cast<Windows::Devices::Bluetooth::BluetoothMajorClass const*>(&majorClass), *reinterpret_cast<Windows::Devices::Bluetooth::BluetoothMinorClass const*>(&minorClass), *reinterpret_cast<Windows::Devices::Bluetooth::BluetoothServiceCapabilities const*>(&serviceCapabilities)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::IBluetoothDevice> : produce_base<D, Windows::Devices::Bluetooth::IBluetoothDevice>
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

    int32_t WINRT_CALL get_HostName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HostName, WINRT_WRAP(Windows::Networking::HostName));
            *value = detach_from<Windows::Networking::HostName>(this->shim().HostName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Name(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Name, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ClassOfDevice(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClassOfDevice, WINRT_WRAP(Windows::Devices::Bluetooth::BluetoothClassOfDevice));
            *value = detach_from<Windows::Devices::Bluetooth::BluetoothClassOfDevice>(this->shim().ClassOfDevice());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SdpRecords(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SdpRecords, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Storage::Streams::IBuffer>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Storage::Streams::IBuffer>>(this->shim().SdpRecords());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RfcommServices(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RfcommServices, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::Rfcomm::RfcommDeviceService>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::Rfcomm::RfcommDeviceService>>(this->shim().RfcommServices());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ConnectionStatus(Windows::Devices::Bluetooth::BluetoothConnectionStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConnectionStatus, WINRT_WRAP(Windows::Devices::Bluetooth::BluetoothConnectionStatus));
            *value = detach_from<Windows::Devices::Bluetooth::BluetoothConnectionStatus>(this->shim().ConnectionStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BluetoothAddress(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BluetoothAddress, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().BluetoothAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_NameChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NameChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::BluetoothDevice, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().NameChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::BluetoothDevice, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_NameChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(NameChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().NameChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_SdpRecordsChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SdpRecordsChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::BluetoothDevice, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().SdpRecordsChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::BluetoothDevice, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_SdpRecordsChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(SdpRecordsChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().SdpRecordsChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_ConnectionStatusChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConnectionStatusChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::BluetoothDevice, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().ConnectionStatusChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::BluetoothDevice, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ConnectionStatusChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ConnectionStatusChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ConnectionStatusChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::IBluetoothDevice2> : produce_base<D, Windows::Devices::Bluetooth::IBluetoothDevice2>
{
    int32_t WINRT_CALL get_DeviceInformation(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceInformation, WINRT_WRAP(Windows::Devices::Enumeration::DeviceInformation));
            *value = detach_from<Windows::Devices::Enumeration::DeviceInformation>(this->shim().DeviceInformation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::IBluetoothDevice3> : produce_base<D, Windows::Devices::Bluetooth::IBluetoothDevice3>
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

    int32_t WINRT_CALL GetRfcommServicesAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetRfcommServicesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::Rfcomm::RfcommDeviceServicesResult>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::Rfcomm::RfcommDeviceServicesResult>>(this->shim().GetRfcommServicesAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetRfcommServicesWithCacheModeAsync(Windows::Devices::Bluetooth::BluetoothCacheMode cacheMode, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetRfcommServicesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::Rfcomm::RfcommDeviceServicesResult>), Windows::Devices::Bluetooth::BluetoothCacheMode const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::Rfcomm::RfcommDeviceServicesResult>>(this->shim().GetRfcommServicesAsync(*reinterpret_cast<Windows::Devices::Bluetooth::BluetoothCacheMode const*>(&cacheMode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetRfcommServicesForIdAsync(void* serviceId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetRfcommServicesForIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::Rfcomm::RfcommDeviceServicesResult>), Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::Rfcomm::RfcommDeviceServicesResult>>(this->shim().GetRfcommServicesForIdAsync(*reinterpret_cast<Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId const*>(&serviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetRfcommServicesForIdWithCacheModeAsync(void* serviceId, Windows::Devices::Bluetooth::BluetoothCacheMode cacheMode, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetRfcommServicesForIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::Rfcomm::RfcommDeviceServicesResult>), Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId const, Windows::Devices::Bluetooth::BluetoothCacheMode const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::Rfcomm::RfcommDeviceServicesResult>>(this->shim().GetRfcommServicesForIdAsync(*reinterpret_cast<Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId const*>(&serviceId), *reinterpret_cast<Windows::Devices::Bluetooth::BluetoothCacheMode const*>(&cacheMode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::IBluetoothDevice4> : produce_base<D, Windows::Devices::Bluetooth::IBluetoothDevice4>
{
    int32_t WINRT_CALL get_BluetoothDeviceId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BluetoothDeviceId, WINRT_WRAP(Windows::Devices::Bluetooth::BluetoothDeviceId));
            *value = detach_from<Windows::Devices::Bluetooth::BluetoothDeviceId>(this->shim().BluetoothDeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::IBluetoothDevice5> : produce_base<D, Windows::Devices::Bluetooth::IBluetoothDevice5>
{
    int32_t WINRT_CALL get_WasSecureConnectionUsedForPairing(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WasSecureConnectionUsedForPairing, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().WasSecureConnectionUsedForPairing());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::IBluetoothDeviceId> : produce_base<D, Windows::Devices::Bluetooth::IBluetoothDeviceId>
{
    int32_t WINRT_CALL get_Id(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Id, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsClassicDevice(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsClassicDevice, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsClassicDevice());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsLowEnergyDevice(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsLowEnergyDevice, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsLowEnergyDevice());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::IBluetoothDeviceIdStatics> : produce_base<D, Windows::Devices::Bluetooth::IBluetoothDeviceIdStatics>
{
    int32_t WINRT_CALL FromId(void* deviceId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromId, WINRT_WRAP(Windows::Devices::Bluetooth::BluetoothDeviceId), hstring const&);
            *result = detach_from<Windows::Devices::Bluetooth::BluetoothDeviceId>(this->shim().FromId(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::IBluetoothDeviceStatics> : produce_base<D, Windows::Devices::Bluetooth::IBluetoothDeviceStatics>
{
    int32_t WINRT_CALL FromIdAsync(void* deviceId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::BluetoothDevice>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::BluetoothDevice>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FromHostNameAsync(void* hostName, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromHostNameAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::BluetoothDevice>), Windows::Networking::HostName const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::BluetoothDevice>>(this->shim().FromHostNameAsync(*reinterpret_cast<Windows::Networking::HostName const*>(&hostName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FromBluetoothAddressAsync(uint64_t address, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromBluetoothAddressAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::BluetoothDevice>), uint64_t);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::BluetoothDevice>>(this->shim().FromBluetoothAddressAsync(address));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeviceSelector(void** deviceSelector) noexcept final
    {
        try
        {
            *deviceSelector = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelector, WINRT_WRAP(hstring));
            *deviceSelector = detach_from<hstring>(this->shim().GetDeviceSelector());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::IBluetoothDeviceStatics2> : produce_base<D, Windows::Devices::Bluetooth::IBluetoothDeviceStatics2>
{
    int32_t WINRT_CALL GetDeviceSelectorFromPairingState(bool pairingState, void** deviceSelector) noexcept final
    {
        try
        {
            *deviceSelector = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelectorFromPairingState, WINRT_WRAP(hstring), bool);
            *deviceSelector = detach_from<hstring>(this->shim().GetDeviceSelectorFromPairingState(pairingState));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeviceSelectorFromConnectionStatus(Windows::Devices::Bluetooth::BluetoothConnectionStatus connectionStatus, void** deviceSelector) noexcept final
    {
        try
        {
            *deviceSelector = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelectorFromConnectionStatus, WINRT_WRAP(hstring), Windows::Devices::Bluetooth::BluetoothConnectionStatus const&);
            *deviceSelector = detach_from<hstring>(this->shim().GetDeviceSelectorFromConnectionStatus(*reinterpret_cast<Windows::Devices::Bluetooth::BluetoothConnectionStatus const*>(&connectionStatus)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeviceSelectorFromDeviceName(void* deviceName, void** deviceSelector) noexcept final
    {
        try
        {
            *deviceSelector = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelectorFromDeviceName, WINRT_WRAP(hstring), hstring const&);
            *deviceSelector = detach_from<hstring>(this->shim().GetDeviceSelectorFromDeviceName(*reinterpret_cast<hstring const*>(&deviceName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeviceSelectorFromBluetoothAddress(uint64_t bluetoothAddress, void** deviceSelector) noexcept final
    {
        try
        {
            *deviceSelector = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelectorFromBluetoothAddress, WINRT_WRAP(hstring), uint64_t);
            *deviceSelector = detach_from<hstring>(this->shim().GetDeviceSelectorFromBluetoothAddress(bluetoothAddress));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeviceSelectorFromClassOfDevice(void* classOfDevice, void** deviceSelector) noexcept final
    {
        try
        {
            *deviceSelector = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelectorFromClassOfDevice, WINRT_WRAP(hstring), Windows::Devices::Bluetooth::BluetoothClassOfDevice const&);
            *deviceSelector = detach_from<hstring>(this->shim().GetDeviceSelectorFromClassOfDevice(*reinterpret_cast<Windows::Devices::Bluetooth::BluetoothClassOfDevice const*>(&classOfDevice)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::IBluetoothLEAppearance> : produce_base<D, Windows::Devices::Bluetooth::IBluetoothLEAppearance>
{
    int32_t WINRT_CALL get_RawValue(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RawValue, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().RawValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Category(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Category, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().Category());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SubCategory(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SubCategory, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().SubCategory());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics> : produce_base<D, Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics>
{
    int32_t WINRT_CALL get_Uncategorized(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Uncategorized, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().Uncategorized());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Phone(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Phone, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().Phone());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Computer(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Computer, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().Computer());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Watch(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Watch, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().Watch());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Clock(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Clock, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().Clock());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Display(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Display, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().Display());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RemoteControl(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoteControl, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().RemoteControl());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EyeGlasses(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EyeGlasses, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().EyeGlasses());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Tag(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Tag, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().Tag());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Keyring(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Keyring, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().Keyring());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MediaPlayer(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MediaPlayer, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().MediaPlayer());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BarcodeScanner(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BarcodeScanner, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().BarcodeScanner());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Thermometer(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Thermometer, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().Thermometer());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HeartRate(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HeartRate, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().HeartRate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BloodPressure(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BloodPressure, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().BloodPressure());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HumanInterfaceDevice(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HumanInterfaceDevice, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().HumanInterfaceDevice());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_GlucoseMeter(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GlucoseMeter, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().GlucoseMeter());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RunningWalking(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RunningWalking, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().RunningWalking());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Cycling(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Cycling, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().Cycling());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PulseOximeter(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PulseOximeter, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().PulseOximeter());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WeightScale(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WeightScale, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().WeightScale());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OutdoorSportActivity(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OutdoorSportActivity, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().OutdoorSportActivity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::IBluetoothLEAppearanceStatics> : produce_base<D, Windows::Devices::Bluetooth::IBluetoothLEAppearanceStatics>
{
    int32_t WINRT_CALL FromRawValue(uint16_t rawValue, void** appearance) noexcept final
    {
        try
        {
            *appearance = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromRawValue, WINRT_WRAP(Windows::Devices::Bluetooth::BluetoothLEAppearance), uint16_t);
            *appearance = detach_from<Windows::Devices::Bluetooth::BluetoothLEAppearance>(this->shim().FromRawValue(rawValue));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FromParts(uint16_t appearanceCategory, uint16_t appearanceSubCategory, void** appearance) noexcept final
    {
        try
        {
            *appearance = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromParts, WINRT_WRAP(Windows::Devices::Bluetooth::BluetoothLEAppearance), uint16_t, uint16_t);
            *appearance = detach_from<Windows::Devices::Bluetooth::BluetoothLEAppearance>(this->shim().FromParts(appearanceCategory, appearanceSubCategory));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics> : produce_base<D, Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics>
{
    int32_t WINRT_CALL get_Generic(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Generic, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().Generic());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SportsWatch(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SportsWatch, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().SportsWatch());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ThermometerEar(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ThermometerEar, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().ThermometerEar());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HeartRateBelt(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HeartRateBelt, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().HeartRateBelt());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BloodPressureArm(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BloodPressureArm, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().BloodPressureArm());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BloodPressureWrist(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BloodPressureWrist, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().BloodPressureWrist());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Keyboard(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Keyboard, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().Keyboard());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Mouse(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Mouse, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().Mouse());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Joystick(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Joystick, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().Joystick());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Gamepad(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Gamepad, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().Gamepad());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DigitizerTablet(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DigitizerTablet, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().DigitizerTablet());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CardReader(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CardReader, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().CardReader());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DigitalPen(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DigitalPen, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().DigitalPen());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BarcodeScanner(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BarcodeScanner, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().BarcodeScanner());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RunningWalkingInShoe(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RunningWalkingInShoe, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().RunningWalkingInShoe());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RunningWalkingOnShoe(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RunningWalkingOnShoe, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().RunningWalkingOnShoe());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RunningWalkingOnHip(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RunningWalkingOnHip, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().RunningWalkingOnHip());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CyclingComputer(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CyclingComputer, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().CyclingComputer());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CyclingSpeedSensor(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CyclingSpeedSensor, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().CyclingSpeedSensor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CyclingCadenceSensor(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CyclingCadenceSensor, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().CyclingCadenceSensor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CyclingPowerSensor(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CyclingPowerSensor, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().CyclingPowerSensor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CyclingSpeedCadenceSensor(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CyclingSpeedCadenceSensor, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().CyclingSpeedCadenceSensor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OximeterFingertip(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OximeterFingertip, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().OximeterFingertip());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OximeterWristWorn(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OximeterWristWorn, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().OximeterWristWorn());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LocationDisplay(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LocationDisplay, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().LocationDisplay());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LocationNavigationDisplay(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LocationNavigationDisplay, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().LocationNavigationDisplay());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LocationPod(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LocationPod, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().LocationPod());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LocationNavigationPod(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LocationNavigationPod, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().LocationNavigationPod());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::IBluetoothLEDevice> : produce_base<D, Windows::Devices::Bluetooth::IBluetoothLEDevice>
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

    int32_t WINRT_CALL get_Name(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Name, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_GattServices(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GattServices, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceService>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceService>>(this->shim().GattServices());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ConnectionStatus(Windows::Devices::Bluetooth::BluetoothConnectionStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConnectionStatus, WINRT_WRAP(Windows::Devices::Bluetooth::BluetoothConnectionStatus));
            *value = detach_from<Windows::Devices::Bluetooth::BluetoothConnectionStatus>(this->shim().ConnectionStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BluetoothAddress(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BluetoothAddress, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().BluetoothAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetGattService(winrt::guid serviceUuid, void** service) noexcept final
    {
        try
        {
            *service = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetGattService, WINRT_WRAP(Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceService), winrt::guid const&);
            *service = detach_from<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceService>(this->shim().GetGattService(*reinterpret_cast<winrt::guid const*>(&serviceUuid)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_NameChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NameChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::BluetoothLEDevice, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().NameChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::BluetoothLEDevice, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_NameChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(NameChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().NameChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_GattServicesChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GattServicesChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::BluetoothLEDevice, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().GattServicesChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::BluetoothLEDevice, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_GattServicesChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(GattServicesChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().GattServicesChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_ConnectionStatusChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConnectionStatusChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::BluetoothLEDevice, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().ConnectionStatusChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Bluetooth::BluetoothLEDevice, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ConnectionStatusChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ConnectionStatusChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ConnectionStatusChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::IBluetoothLEDevice2> : produce_base<D, Windows::Devices::Bluetooth::IBluetoothLEDevice2>
{
    int32_t WINRT_CALL get_DeviceInformation(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceInformation, WINRT_WRAP(Windows::Devices::Enumeration::DeviceInformation));
            *value = detach_from<Windows::Devices::Enumeration::DeviceInformation>(this->shim().DeviceInformation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Appearance(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Appearance, WINRT_WRAP(Windows::Devices::Bluetooth::BluetoothLEAppearance));
            *value = detach_from<Windows::Devices::Bluetooth::BluetoothLEAppearance>(this->shim().Appearance());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BluetoothAddressType(Windows::Devices::Bluetooth::BluetoothAddressType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BluetoothAddressType, WINRT_WRAP(Windows::Devices::Bluetooth::BluetoothAddressType));
            *value = detach_from<Windows::Devices::Bluetooth::BluetoothAddressType>(this->shim().BluetoothAddressType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::IBluetoothLEDevice3> : produce_base<D, Windows::Devices::Bluetooth::IBluetoothLEDevice3>
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

    int32_t WINRT_CALL RequestAccessAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestAccessAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceAccessStatus>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Enumeration::DeviceAccessStatus>>(this->shim().RequestAccessAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetGattServicesAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetGattServicesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceServicesResult>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceServicesResult>>(this->shim().GetGattServicesAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetGattServicesWithCacheModeAsync(Windows::Devices::Bluetooth::BluetoothCacheMode cacheMode, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetGattServicesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceServicesResult>), Windows::Devices::Bluetooth::BluetoothCacheMode const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceServicesResult>>(this->shim().GetGattServicesAsync(*reinterpret_cast<Windows::Devices::Bluetooth::BluetoothCacheMode const*>(&cacheMode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetGattServicesForUuidAsync(winrt::guid serviceUuid, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetGattServicesForUuidAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceServicesResult>), winrt::guid const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceServicesResult>>(this->shim().GetGattServicesForUuidAsync(*reinterpret_cast<winrt::guid const*>(&serviceUuid)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetGattServicesForUuidWithCacheModeAsync(winrt::guid serviceUuid, Windows::Devices::Bluetooth::BluetoothCacheMode cacheMode, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetGattServicesForUuidAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceServicesResult>), winrt::guid const, Windows::Devices::Bluetooth::BluetoothCacheMode const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceServicesResult>>(this->shim().GetGattServicesForUuidAsync(*reinterpret_cast<winrt::guid const*>(&serviceUuid), *reinterpret_cast<Windows::Devices::Bluetooth::BluetoothCacheMode const*>(&cacheMode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::IBluetoothLEDevice4> : produce_base<D, Windows::Devices::Bluetooth::IBluetoothLEDevice4>
{
    int32_t WINRT_CALL get_BluetoothDeviceId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BluetoothDeviceId, WINRT_WRAP(Windows::Devices::Bluetooth::BluetoothDeviceId));
            *value = detach_from<Windows::Devices::Bluetooth::BluetoothDeviceId>(this->shim().BluetoothDeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::IBluetoothLEDevice5> : produce_base<D, Windows::Devices::Bluetooth::IBluetoothLEDevice5>
{
    int32_t WINRT_CALL get_WasSecureConnectionUsedForPairing(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WasSecureConnectionUsedForPairing, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().WasSecureConnectionUsedForPairing());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::IBluetoothLEDeviceStatics> : produce_base<D, Windows::Devices::Bluetooth::IBluetoothLEDeviceStatics>
{
    int32_t WINRT_CALL FromIdAsync(void* deviceId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::BluetoothLEDevice>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::BluetoothLEDevice>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FromBluetoothAddressAsync(uint64_t bluetoothAddress, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromBluetoothAddressAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::BluetoothLEDevice>), uint64_t);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::BluetoothLEDevice>>(this->shim().FromBluetoothAddressAsync(bluetoothAddress));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeviceSelector(void** deviceSelector) noexcept final
    {
        try
        {
            *deviceSelector = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelector, WINRT_WRAP(hstring));
            *deviceSelector = detach_from<hstring>(this->shim().GetDeviceSelector());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::IBluetoothLEDeviceStatics2> : produce_base<D, Windows::Devices::Bluetooth::IBluetoothLEDeviceStatics2>
{
    int32_t WINRT_CALL GetDeviceSelectorFromPairingState(bool pairingState, void** deviceSelector) noexcept final
    {
        try
        {
            *deviceSelector = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelectorFromPairingState, WINRT_WRAP(hstring), bool);
            *deviceSelector = detach_from<hstring>(this->shim().GetDeviceSelectorFromPairingState(pairingState));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeviceSelectorFromConnectionStatus(Windows::Devices::Bluetooth::BluetoothConnectionStatus connectionStatus, void** deviceSelector) noexcept final
    {
        try
        {
            *deviceSelector = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelectorFromConnectionStatus, WINRT_WRAP(hstring), Windows::Devices::Bluetooth::BluetoothConnectionStatus const&);
            *deviceSelector = detach_from<hstring>(this->shim().GetDeviceSelectorFromConnectionStatus(*reinterpret_cast<Windows::Devices::Bluetooth::BluetoothConnectionStatus const*>(&connectionStatus)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeviceSelectorFromDeviceName(void* deviceName, void** deviceSelector) noexcept final
    {
        try
        {
            *deviceSelector = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelectorFromDeviceName, WINRT_WRAP(hstring), hstring const&);
            *deviceSelector = detach_from<hstring>(this->shim().GetDeviceSelectorFromDeviceName(*reinterpret_cast<hstring const*>(&deviceName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeviceSelectorFromBluetoothAddress(uint64_t bluetoothAddress, void** deviceSelector) noexcept final
    {
        try
        {
            *deviceSelector = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelectorFromBluetoothAddress, WINRT_WRAP(hstring), uint64_t);
            *deviceSelector = detach_from<hstring>(this->shim().GetDeviceSelectorFromBluetoothAddress(bluetoothAddress));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeviceSelectorFromBluetoothAddressWithBluetoothAddressType(uint64_t bluetoothAddress, Windows::Devices::Bluetooth::BluetoothAddressType bluetoothAddressType, void** deviceSelector) noexcept final
    {
        try
        {
            *deviceSelector = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelectorFromBluetoothAddress, WINRT_WRAP(hstring), uint64_t, Windows::Devices::Bluetooth::BluetoothAddressType const&);
            *deviceSelector = detach_from<hstring>(this->shim().GetDeviceSelectorFromBluetoothAddress(bluetoothAddress, *reinterpret_cast<Windows::Devices::Bluetooth::BluetoothAddressType const*>(&bluetoothAddressType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeviceSelectorFromAppearance(void* appearance, void** deviceSelector) noexcept final
    {
        try
        {
            *deviceSelector = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelectorFromAppearance, WINRT_WRAP(hstring), Windows::Devices::Bluetooth::BluetoothLEAppearance const&);
            *deviceSelector = detach_from<hstring>(this->shim().GetDeviceSelectorFromAppearance(*reinterpret_cast<Windows::Devices::Bluetooth::BluetoothLEAppearance const*>(&appearance)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FromBluetoothAddressWithBluetoothAddressTypeAsync(uint64_t bluetoothAddress, Windows::Devices::Bluetooth::BluetoothAddressType bluetoothAddressType, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromBluetoothAddressAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::BluetoothLEDevice>), uint64_t, Windows::Devices::Bluetooth::BluetoothAddressType const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::BluetoothLEDevice>>(this->shim().FromBluetoothAddressAsync(bluetoothAddress, *reinterpret_cast<Windows::Devices::Bluetooth::BluetoothAddressType const*>(&bluetoothAddressType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::IBluetoothSignalStrengthFilter> : produce_base<D, Windows::Devices::Bluetooth::IBluetoothSignalStrengthFilter>
{
    int32_t WINRT_CALL get_InRangeThresholdInDBm(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InRangeThresholdInDBm, WINRT_WRAP(Windows::Foundation::IReference<int16_t>));
            *value = detach_from<Windows::Foundation::IReference<int16_t>>(this->shim().InRangeThresholdInDBm());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_InRangeThresholdInDBm(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InRangeThresholdInDBm, WINRT_WRAP(void), Windows::Foundation::IReference<int16_t> const&);
            this->shim().InRangeThresholdInDBm(*reinterpret_cast<Windows::Foundation::IReference<int16_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OutOfRangeThresholdInDBm(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OutOfRangeThresholdInDBm, WINRT_WRAP(Windows::Foundation::IReference<int16_t>));
            *value = detach_from<Windows::Foundation::IReference<int16_t>>(this->shim().OutOfRangeThresholdInDBm());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_OutOfRangeThresholdInDBm(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OutOfRangeThresholdInDBm, WINRT_WRAP(void), Windows::Foundation::IReference<int16_t> const&);
            this->shim().OutOfRangeThresholdInDBm(*reinterpret_cast<Windows::Foundation::IReference<int16_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OutOfRangeTimeout(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OutOfRangeTimeout, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::TimeSpan>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::TimeSpan>>(this->shim().OutOfRangeTimeout());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_OutOfRangeTimeout(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OutOfRangeTimeout, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Foundation::TimeSpan> const&);
            this->shim().OutOfRangeTimeout(*reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::TimeSpan> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SamplingInterval(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SamplingInterval, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::TimeSpan>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::TimeSpan>>(this->shim().SamplingInterval());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SamplingInterval(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SamplingInterval, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Foundation::TimeSpan> const&);
            this->shim().SamplingInterval(*reinterpret_cast<Windows::Foundation::IReference<Windows::Foundation::TimeSpan> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Bluetooth::IBluetoothUuidHelperStatics> : produce_base<D, Windows::Devices::Bluetooth::IBluetoothUuidHelperStatics>
{
    int32_t WINRT_CALL FromShortId(uint32_t shortId, winrt::guid* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromShortId, WINRT_WRAP(winrt::guid), uint32_t);
            *result = detach_from<winrt::guid>(this->shim().FromShortId(shortId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryGetShortId(winrt::guid uuid, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryGetShortId, WINRT_WRAP(Windows::Foundation::IReference<uint32_t>), winrt::guid const&);
            *result = detach_from<Windows::Foundation::IReference<uint32_t>>(this->shim().TryGetShortId(*reinterpret_cast<winrt::guid const*>(&uuid)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Devices::Bluetooth {

inline hstring BluetoothAdapter::GetDeviceSelector()
{
    return impl::call_factory<BluetoothAdapter, Windows::Devices::Bluetooth::IBluetoothAdapterStatics>([&](auto&& f) { return f.GetDeviceSelector(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::BluetoothAdapter> BluetoothAdapter::FromIdAsync(param::hstring const& deviceId)
{
    return impl::call_factory<BluetoothAdapter, Windows::Devices::Bluetooth::IBluetoothAdapterStatics>([&](auto&& f) { return f.FromIdAsync(deviceId); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::BluetoothAdapter> BluetoothAdapter::GetDefaultAsync()
{
    return impl::call_factory<BluetoothAdapter, Windows::Devices::Bluetooth::IBluetoothAdapterStatics>([&](auto&& f) { return f.GetDefaultAsync(); });
}

inline Windows::Devices::Bluetooth::BluetoothClassOfDevice BluetoothClassOfDevice::FromRawValue(uint32_t rawValue)
{
    return impl::call_factory<BluetoothClassOfDevice, Windows::Devices::Bluetooth::IBluetoothClassOfDeviceStatics>([&](auto&& f) { return f.FromRawValue(rawValue); });
}

inline Windows::Devices::Bluetooth::BluetoothClassOfDevice BluetoothClassOfDevice::FromParts(Windows::Devices::Bluetooth::BluetoothMajorClass const& majorClass, Windows::Devices::Bluetooth::BluetoothMinorClass const& minorClass, Windows::Devices::Bluetooth::BluetoothServiceCapabilities const& serviceCapabilities)
{
    return impl::call_factory<BluetoothClassOfDevice, Windows::Devices::Bluetooth::IBluetoothClassOfDeviceStatics>([&](auto&& f) { return f.FromParts(majorClass, minorClass, serviceCapabilities); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::BluetoothDevice> BluetoothDevice::FromIdAsync(param::hstring const& deviceId)
{
    return impl::call_factory<BluetoothDevice, Windows::Devices::Bluetooth::IBluetoothDeviceStatics>([&](auto&& f) { return f.FromIdAsync(deviceId); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::BluetoothDevice> BluetoothDevice::FromHostNameAsync(Windows::Networking::HostName const& hostName)
{
    return impl::call_factory<BluetoothDevice, Windows::Devices::Bluetooth::IBluetoothDeviceStatics>([&](auto&& f) { return f.FromHostNameAsync(hostName); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::BluetoothDevice> BluetoothDevice::FromBluetoothAddressAsync(uint64_t address)
{
    return impl::call_factory<BluetoothDevice, Windows::Devices::Bluetooth::IBluetoothDeviceStatics>([&](auto&& f) { return f.FromBluetoothAddressAsync(address); });
}

inline hstring BluetoothDevice::GetDeviceSelector()
{
    return impl::call_factory<BluetoothDevice, Windows::Devices::Bluetooth::IBluetoothDeviceStatics>([&](auto&& f) { return f.GetDeviceSelector(); });
}

inline hstring BluetoothDevice::GetDeviceSelectorFromPairingState(bool pairingState)
{
    return impl::call_factory<BluetoothDevice, Windows::Devices::Bluetooth::IBluetoothDeviceStatics2>([&](auto&& f) { return f.GetDeviceSelectorFromPairingState(pairingState); });
}

inline hstring BluetoothDevice::GetDeviceSelectorFromConnectionStatus(Windows::Devices::Bluetooth::BluetoothConnectionStatus const& connectionStatus)
{
    return impl::call_factory<BluetoothDevice, Windows::Devices::Bluetooth::IBluetoothDeviceStatics2>([&](auto&& f) { return f.GetDeviceSelectorFromConnectionStatus(connectionStatus); });
}

inline hstring BluetoothDevice::GetDeviceSelectorFromDeviceName(param::hstring const& deviceName)
{
    return impl::call_factory<BluetoothDevice, Windows::Devices::Bluetooth::IBluetoothDeviceStatics2>([&](auto&& f) { return f.GetDeviceSelectorFromDeviceName(deviceName); });
}

inline hstring BluetoothDevice::GetDeviceSelectorFromBluetoothAddress(uint64_t bluetoothAddress)
{
    return impl::call_factory<BluetoothDevice, Windows::Devices::Bluetooth::IBluetoothDeviceStatics2>([&](auto&& f) { return f.GetDeviceSelectorFromBluetoothAddress(bluetoothAddress); });
}

inline hstring BluetoothDevice::GetDeviceSelectorFromClassOfDevice(Windows::Devices::Bluetooth::BluetoothClassOfDevice const& classOfDevice)
{
    return impl::call_factory<BluetoothDevice, Windows::Devices::Bluetooth::IBluetoothDeviceStatics2>([&](auto&& f) { return f.GetDeviceSelectorFromClassOfDevice(classOfDevice); });
}

inline Windows::Devices::Bluetooth::BluetoothDeviceId BluetoothDeviceId::FromId(param::hstring const& deviceId)
{
    return impl::call_factory<BluetoothDeviceId, Windows::Devices::Bluetooth::IBluetoothDeviceIdStatics>([&](auto&& f) { return f.FromId(deviceId); });
}

inline Windows::Devices::Bluetooth::BluetoothLEAppearance BluetoothLEAppearance::FromRawValue(uint16_t rawValue)
{
    return impl::call_factory<BluetoothLEAppearance, Windows::Devices::Bluetooth::IBluetoothLEAppearanceStatics>([&](auto&& f) { return f.FromRawValue(rawValue); });
}

inline Windows::Devices::Bluetooth::BluetoothLEAppearance BluetoothLEAppearance::FromParts(uint16_t appearanceCategory, uint16_t appearanceSubCategory)
{
    return impl::call_factory<BluetoothLEAppearance, Windows::Devices::Bluetooth::IBluetoothLEAppearanceStatics>([&](auto&& f) { return f.FromParts(appearanceCategory, appearanceSubCategory); });
}

inline uint16_t BluetoothLEAppearanceCategories::Uncategorized()
{
    return impl::call_factory<BluetoothLEAppearanceCategories, Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics>([&](auto&& f) { return f.Uncategorized(); });
}

inline uint16_t BluetoothLEAppearanceCategories::Phone()
{
    return impl::call_factory<BluetoothLEAppearanceCategories, Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics>([&](auto&& f) { return f.Phone(); });
}

inline uint16_t BluetoothLEAppearanceCategories::Computer()
{
    return impl::call_factory<BluetoothLEAppearanceCategories, Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics>([&](auto&& f) { return f.Computer(); });
}

inline uint16_t BluetoothLEAppearanceCategories::Watch()
{
    return impl::call_factory<BluetoothLEAppearanceCategories, Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics>([&](auto&& f) { return f.Watch(); });
}

inline uint16_t BluetoothLEAppearanceCategories::Clock()
{
    return impl::call_factory<BluetoothLEAppearanceCategories, Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics>([&](auto&& f) { return f.Clock(); });
}

inline uint16_t BluetoothLEAppearanceCategories::Display()
{
    return impl::call_factory<BluetoothLEAppearanceCategories, Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics>([&](auto&& f) { return f.Display(); });
}

inline uint16_t BluetoothLEAppearanceCategories::RemoteControl()
{
    return impl::call_factory<BluetoothLEAppearanceCategories, Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics>([&](auto&& f) { return f.RemoteControl(); });
}

inline uint16_t BluetoothLEAppearanceCategories::EyeGlasses()
{
    return impl::call_factory<BluetoothLEAppearanceCategories, Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics>([&](auto&& f) { return f.EyeGlasses(); });
}

inline uint16_t BluetoothLEAppearanceCategories::Tag()
{
    return impl::call_factory<BluetoothLEAppearanceCategories, Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics>([&](auto&& f) { return f.Tag(); });
}

inline uint16_t BluetoothLEAppearanceCategories::Keyring()
{
    return impl::call_factory<BluetoothLEAppearanceCategories, Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics>([&](auto&& f) { return f.Keyring(); });
}

inline uint16_t BluetoothLEAppearanceCategories::MediaPlayer()
{
    return impl::call_factory<BluetoothLEAppearanceCategories, Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics>([&](auto&& f) { return f.MediaPlayer(); });
}

inline uint16_t BluetoothLEAppearanceCategories::BarcodeScanner()
{
    return impl::call_factory<BluetoothLEAppearanceCategories, Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics>([&](auto&& f) { return f.BarcodeScanner(); });
}

inline uint16_t BluetoothLEAppearanceCategories::Thermometer()
{
    return impl::call_factory<BluetoothLEAppearanceCategories, Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics>([&](auto&& f) { return f.Thermometer(); });
}

inline uint16_t BluetoothLEAppearanceCategories::HeartRate()
{
    return impl::call_factory<BluetoothLEAppearanceCategories, Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics>([&](auto&& f) { return f.HeartRate(); });
}

inline uint16_t BluetoothLEAppearanceCategories::BloodPressure()
{
    return impl::call_factory<BluetoothLEAppearanceCategories, Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics>([&](auto&& f) { return f.BloodPressure(); });
}

inline uint16_t BluetoothLEAppearanceCategories::HumanInterfaceDevice()
{
    return impl::call_factory<BluetoothLEAppearanceCategories, Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics>([&](auto&& f) { return f.HumanInterfaceDevice(); });
}

inline uint16_t BluetoothLEAppearanceCategories::GlucoseMeter()
{
    return impl::call_factory<BluetoothLEAppearanceCategories, Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics>([&](auto&& f) { return f.GlucoseMeter(); });
}

inline uint16_t BluetoothLEAppearanceCategories::RunningWalking()
{
    return impl::call_factory<BluetoothLEAppearanceCategories, Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics>([&](auto&& f) { return f.RunningWalking(); });
}

inline uint16_t BluetoothLEAppearanceCategories::Cycling()
{
    return impl::call_factory<BluetoothLEAppearanceCategories, Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics>([&](auto&& f) { return f.Cycling(); });
}

inline uint16_t BluetoothLEAppearanceCategories::PulseOximeter()
{
    return impl::call_factory<BluetoothLEAppearanceCategories, Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics>([&](auto&& f) { return f.PulseOximeter(); });
}

inline uint16_t BluetoothLEAppearanceCategories::WeightScale()
{
    return impl::call_factory<BluetoothLEAppearanceCategories, Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics>([&](auto&& f) { return f.WeightScale(); });
}

inline uint16_t BluetoothLEAppearanceCategories::OutdoorSportActivity()
{
    return impl::call_factory<BluetoothLEAppearanceCategories, Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics>([&](auto&& f) { return f.OutdoorSportActivity(); });
}

inline uint16_t BluetoothLEAppearanceSubcategories::Generic()
{
    return impl::call_factory<BluetoothLEAppearanceSubcategories, Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics>([&](auto&& f) { return f.Generic(); });
}

inline uint16_t BluetoothLEAppearanceSubcategories::SportsWatch()
{
    return impl::call_factory<BluetoothLEAppearanceSubcategories, Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics>([&](auto&& f) { return f.SportsWatch(); });
}

inline uint16_t BluetoothLEAppearanceSubcategories::ThermometerEar()
{
    return impl::call_factory<BluetoothLEAppearanceSubcategories, Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics>([&](auto&& f) { return f.ThermometerEar(); });
}

inline uint16_t BluetoothLEAppearanceSubcategories::HeartRateBelt()
{
    return impl::call_factory<BluetoothLEAppearanceSubcategories, Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics>([&](auto&& f) { return f.HeartRateBelt(); });
}

inline uint16_t BluetoothLEAppearanceSubcategories::BloodPressureArm()
{
    return impl::call_factory<BluetoothLEAppearanceSubcategories, Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics>([&](auto&& f) { return f.BloodPressureArm(); });
}

inline uint16_t BluetoothLEAppearanceSubcategories::BloodPressureWrist()
{
    return impl::call_factory<BluetoothLEAppearanceSubcategories, Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics>([&](auto&& f) { return f.BloodPressureWrist(); });
}

inline uint16_t BluetoothLEAppearanceSubcategories::Keyboard()
{
    return impl::call_factory<BluetoothLEAppearanceSubcategories, Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics>([&](auto&& f) { return f.Keyboard(); });
}

inline uint16_t BluetoothLEAppearanceSubcategories::Mouse()
{
    return impl::call_factory<BluetoothLEAppearanceSubcategories, Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics>([&](auto&& f) { return f.Mouse(); });
}

inline uint16_t BluetoothLEAppearanceSubcategories::Joystick()
{
    return impl::call_factory<BluetoothLEAppearanceSubcategories, Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics>([&](auto&& f) { return f.Joystick(); });
}

inline uint16_t BluetoothLEAppearanceSubcategories::Gamepad()
{
    return impl::call_factory<BluetoothLEAppearanceSubcategories, Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics>([&](auto&& f) { return f.Gamepad(); });
}

inline uint16_t BluetoothLEAppearanceSubcategories::DigitizerTablet()
{
    return impl::call_factory<BluetoothLEAppearanceSubcategories, Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics>([&](auto&& f) { return f.DigitizerTablet(); });
}

inline uint16_t BluetoothLEAppearanceSubcategories::CardReader()
{
    return impl::call_factory<BluetoothLEAppearanceSubcategories, Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics>([&](auto&& f) { return f.CardReader(); });
}

inline uint16_t BluetoothLEAppearanceSubcategories::DigitalPen()
{
    return impl::call_factory<BluetoothLEAppearanceSubcategories, Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics>([&](auto&& f) { return f.DigitalPen(); });
}

inline uint16_t BluetoothLEAppearanceSubcategories::BarcodeScanner()
{
    return impl::call_factory<BluetoothLEAppearanceSubcategories, Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics>([&](auto&& f) { return f.BarcodeScanner(); });
}

inline uint16_t BluetoothLEAppearanceSubcategories::RunningWalkingInShoe()
{
    return impl::call_factory<BluetoothLEAppearanceSubcategories, Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics>([&](auto&& f) { return f.RunningWalkingInShoe(); });
}

inline uint16_t BluetoothLEAppearanceSubcategories::RunningWalkingOnShoe()
{
    return impl::call_factory<BluetoothLEAppearanceSubcategories, Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics>([&](auto&& f) { return f.RunningWalkingOnShoe(); });
}

inline uint16_t BluetoothLEAppearanceSubcategories::RunningWalkingOnHip()
{
    return impl::call_factory<BluetoothLEAppearanceSubcategories, Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics>([&](auto&& f) { return f.RunningWalkingOnHip(); });
}

inline uint16_t BluetoothLEAppearanceSubcategories::CyclingComputer()
{
    return impl::call_factory<BluetoothLEAppearanceSubcategories, Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics>([&](auto&& f) { return f.CyclingComputer(); });
}

inline uint16_t BluetoothLEAppearanceSubcategories::CyclingSpeedSensor()
{
    return impl::call_factory<BluetoothLEAppearanceSubcategories, Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics>([&](auto&& f) { return f.CyclingSpeedSensor(); });
}

inline uint16_t BluetoothLEAppearanceSubcategories::CyclingCadenceSensor()
{
    return impl::call_factory<BluetoothLEAppearanceSubcategories, Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics>([&](auto&& f) { return f.CyclingCadenceSensor(); });
}

inline uint16_t BluetoothLEAppearanceSubcategories::CyclingPowerSensor()
{
    return impl::call_factory<BluetoothLEAppearanceSubcategories, Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics>([&](auto&& f) { return f.CyclingPowerSensor(); });
}

inline uint16_t BluetoothLEAppearanceSubcategories::CyclingSpeedCadenceSensor()
{
    return impl::call_factory<BluetoothLEAppearanceSubcategories, Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics>([&](auto&& f) { return f.CyclingSpeedCadenceSensor(); });
}

inline uint16_t BluetoothLEAppearanceSubcategories::OximeterFingertip()
{
    return impl::call_factory<BluetoothLEAppearanceSubcategories, Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics>([&](auto&& f) { return f.OximeterFingertip(); });
}

inline uint16_t BluetoothLEAppearanceSubcategories::OximeterWristWorn()
{
    return impl::call_factory<BluetoothLEAppearanceSubcategories, Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics>([&](auto&& f) { return f.OximeterWristWorn(); });
}

inline uint16_t BluetoothLEAppearanceSubcategories::LocationDisplay()
{
    return impl::call_factory<BluetoothLEAppearanceSubcategories, Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics>([&](auto&& f) { return f.LocationDisplay(); });
}

inline uint16_t BluetoothLEAppearanceSubcategories::LocationNavigationDisplay()
{
    return impl::call_factory<BluetoothLEAppearanceSubcategories, Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics>([&](auto&& f) { return f.LocationNavigationDisplay(); });
}

inline uint16_t BluetoothLEAppearanceSubcategories::LocationPod()
{
    return impl::call_factory<BluetoothLEAppearanceSubcategories, Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics>([&](auto&& f) { return f.LocationPod(); });
}

inline uint16_t BluetoothLEAppearanceSubcategories::LocationNavigationPod()
{
    return impl::call_factory<BluetoothLEAppearanceSubcategories, Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics>([&](auto&& f) { return f.LocationNavigationPod(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::BluetoothLEDevice> BluetoothLEDevice::FromIdAsync(param::hstring const& deviceId)
{
    return impl::call_factory<BluetoothLEDevice, Windows::Devices::Bluetooth::IBluetoothLEDeviceStatics>([&](auto&& f) { return f.FromIdAsync(deviceId); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::BluetoothLEDevice> BluetoothLEDevice::FromBluetoothAddressAsync(uint64_t bluetoothAddress)
{
    return impl::call_factory<BluetoothLEDevice, Windows::Devices::Bluetooth::IBluetoothLEDeviceStatics>([&](auto&& f) { return f.FromBluetoothAddressAsync(bluetoothAddress); });
}

inline hstring BluetoothLEDevice::GetDeviceSelector()
{
    return impl::call_factory<BluetoothLEDevice, Windows::Devices::Bluetooth::IBluetoothLEDeviceStatics>([&](auto&& f) { return f.GetDeviceSelector(); });
}

inline hstring BluetoothLEDevice::GetDeviceSelectorFromPairingState(bool pairingState)
{
    return impl::call_factory<BluetoothLEDevice, Windows::Devices::Bluetooth::IBluetoothLEDeviceStatics2>([&](auto&& f) { return f.GetDeviceSelectorFromPairingState(pairingState); });
}

inline hstring BluetoothLEDevice::GetDeviceSelectorFromConnectionStatus(Windows::Devices::Bluetooth::BluetoothConnectionStatus const& connectionStatus)
{
    return impl::call_factory<BluetoothLEDevice, Windows::Devices::Bluetooth::IBluetoothLEDeviceStatics2>([&](auto&& f) { return f.GetDeviceSelectorFromConnectionStatus(connectionStatus); });
}

inline hstring BluetoothLEDevice::GetDeviceSelectorFromDeviceName(param::hstring const& deviceName)
{
    return impl::call_factory<BluetoothLEDevice, Windows::Devices::Bluetooth::IBluetoothLEDeviceStatics2>([&](auto&& f) { return f.GetDeviceSelectorFromDeviceName(deviceName); });
}

inline hstring BluetoothLEDevice::GetDeviceSelectorFromBluetoothAddress(uint64_t bluetoothAddress)
{
    return impl::call_factory<BluetoothLEDevice, Windows::Devices::Bluetooth::IBluetoothLEDeviceStatics2>([&](auto&& f) { return f.GetDeviceSelectorFromBluetoothAddress(bluetoothAddress); });
}

inline hstring BluetoothLEDevice::GetDeviceSelectorFromBluetoothAddress(uint64_t bluetoothAddress, Windows::Devices::Bluetooth::BluetoothAddressType const& bluetoothAddressType)
{
    return impl::call_factory<BluetoothLEDevice, Windows::Devices::Bluetooth::IBluetoothLEDeviceStatics2>([&](auto&& f) { return f.GetDeviceSelectorFromBluetoothAddress(bluetoothAddress, bluetoothAddressType); });
}

inline hstring BluetoothLEDevice::GetDeviceSelectorFromAppearance(Windows::Devices::Bluetooth::BluetoothLEAppearance const& appearance)
{
    return impl::call_factory<BluetoothLEDevice, Windows::Devices::Bluetooth::IBluetoothLEDeviceStatics2>([&](auto&& f) { return f.GetDeviceSelectorFromAppearance(appearance); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::Bluetooth::BluetoothLEDevice> BluetoothLEDevice::FromBluetoothAddressAsync(uint64_t bluetoothAddress, Windows::Devices::Bluetooth::BluetoothAddressType const& bluetoothAddressType)
{
    return impl::call_factory<BluetoothLEDevice, Windows::Devices::Bluetooth::IBluetoothLEDeviceStatics2>([&](auto&& f) { return f.FromBluetoothAddressAsync(bluetoothAddress, bluetoothAddressType); });
}

inline BluetoothSignalStrengthFilter::BluetoothSignalStrengthFilter() :
    BluetoothSignalStrengthFilter(impl::call_factory<BluetoothSignalStrengthFilter>([](auto&& f) { return f.template ActivateInstance<BluetoothSignalStrengthFilter>(); }))
{}

inline winrt::guid BluetoothUuidHelper::FromShortId(uint32_t shortId)
{
    return impl::call_factory<BluetoothUuidHelper, Windows::Devices::Bluetooth::IBluetoothUuidHelperStatics>([&](auto&& f) { return f.FromShortId(shortId); });
}

inline Windows::Foundation::IReference<uint32_t> BluetoothUuidHelper::TryGetShortId(winrt::guid const& uuid)
{
    return impl::call_factory<BluetoothUuidHelper, Windows::Devices::Bluetooth::IBluetoothUuidHelperStatics>([&](auto&& f) { return f.TryGetShortId(uuid); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Devices::Bluetooth::IBluetoothAdapter> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::IBluetoothAdapter> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::IBluetoothAdapter2> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::IBluetoothAdapter2> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::IBluetoothAdapterStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::IBluetoothAdapterStatics> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::IBluetoothClassOfDevice> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::IBluetoothClassOfDevice> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::IBluetoothClassOfDeviceStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::IBluetoothClassOfDeviceStatics> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::IBluetoothDevice> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::IBluetoothDevice> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::IBluetoothDevice2> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::IBluetoothDevice2> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::IBluetoothDevice3> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::IBluetoothDevice3> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::IBluetoothDevice4> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::IBluetoothDevice4> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::IBluetoothDevice5> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::IBluetoothDevice5> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::IBluetoothDeviceId> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::IBluetoothDeviceId> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::IBluetoothDeviceIdStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::IBluetoothDeviceIdStatics> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::IBluetoothDeviceStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::IBluetoothDeviceStatics> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::IBluetoothDeviceStatics2> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::IBluetoothDeviceStatics2> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearance> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearance> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceStatics> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice2> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice2> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice3> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice3> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice4> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice4> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice5> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice5> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::IBluetoothLEDeviceStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::IBluetoothLEDeviceStatics> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::IBluetoothLEDeviceStatics2> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::IBluetoothLEDeviceStatics2> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::IBluetoothSignalStrengthFilter> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::IBluetoothSignalStrengthFilter> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::IBluetoothUuidHelperStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::IBluetoothUuidHelperStatics> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::BluetoothAdapter> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::BluetoothAdapter> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::BluetoothClassOfDevice> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::BluetoothClassOfDevice> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::BluetoothDevice> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::BluetoothDevice> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::BluetoothDeviceId> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::BluetoothDeviceId> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::BluetoothLEAppearance> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::BluetoothLEAppearance> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::BluetoothLEAppearanceCategories> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::BluetoothLEAppearanceCategories> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::BluetoothLEAppearanceSubcategories> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::BluetoothLEAppearanceSubcategories> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::BluetoothLEDevice> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::BluetoothLEDevice> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::BluetoothSignalStrengthFilter> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::BluetoothSignalStrengthFilter> {};
template<> struct hash<winrt::Windows::Devices::Bluetooth::BluetoothUuidHelper> : winrt::impl::hash_base<winrt::Windows::Devices::Bluetooth::BluetoothUuidHelper> {};

}
