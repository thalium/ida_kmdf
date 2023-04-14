// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Devices.Usb.2.h"
#include "winrt/Windows.Devices.h"

namespace winrt::impl {

template <typename D> uint32_t consume_Windows_Devices_Usb_IUsbBulkInEndpointDescriptor<D>::MaxPacketSize() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbBulkInEndpointDescriptor)->get_MaxPacketSize(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Usb_IUsbBulkInEndpointDescriptor<D>::EndpointNumber() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbBulkInEndpointDescriptor)->get_EndpointNumber(&value));
    return value;
}

template <typename D> Windows::Devices::Usb::UsbBulkInPipe consume_Windows_Devices_Usb_IUsbBulkInEndpointDescriptor<D>::Pipe() const
{
    Windows::Devices::Usb::UsbBulkInPipe value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbBulkInEndpointDescriptor)->get_Pipe(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_Usb_IUsbBulkInPipe<D>::MaxTransferSizeBytes() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbBulkInPipe)->get_MaxTransferSizeBytes(&value));
    return value;
}

template <typename D> Windows::Devices::Usb::UsbBulkInEndpointDescriptor consume_Windows_Devices_Usb_IUsbBulkInPipe<D>::EndpointDescriptor() const
{
    Windows::Devices::Usb::UsbBulkInEndpointDescriptor value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbBulkInPipe)->get_EndpointDescriptor(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Devices_Usb_IUsbBulkInPipe<D>::ClearStallAsync() const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbBulkInPipe)->ClearStallAsync(put_abi(operation)));
    return operation;
}

template <typename D> void consume_Windows_Devices_Usb_IUsbBulkInPipe<D>::ReadOptions(Windows::Devices::Usb::UsbReadOptions const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbBulkInPipe)->put_ReadOptions(get_abi(value)));
}

template <typename D> Windows::Devices::Usb::UsbReadOptions consume_Windows_Devices_Usb_IUsbBulkInPipe<D>::ReadOptions() const
{
    Windows::Devices::Usb::UsbReadOptions value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbBulkInPipe)->get_ReadOptions(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Usb_IUsbBulkInPipe<D>::FlushBuffer() const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbBulkInPipe)->FlushBuffer());
}

template <typename D> Windows::Storage::Streams::IInputStream consume_Windows_Devices_Usb_IUsbBulkInPipe<D>::InputStream() const
{
    Windows::Storage::Streams::IInputStream value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbBulkInPipe)->get_InputStream(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_Usb_IUsbBulkOutEndpointDescriptor<D>::MaxPacketSize() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbBulkOutEndpointDescriptor)->get_MaxPacketSize(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Usb_IUsbBulkOutEndpointDescriptor<D>::EndpointNumber() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbBulkOutEndpointDescriptor)->get_EndpointNumber(&value));
    return value;
}

template <typename D> Windows::Devices::Usb::UsbBulkOutPipe consume_Windows_Devices_Usb_IUsbBulkOutEndpointDescriptor<D>::Pipe() const
{
    Windows::Devices::Usb::UsbBulkOutPipe value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbBulkOutEndpointDescriptor)->get_Pipe(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Usb::UsbBulkOutEndpointDescriptor consume_Windows_Devices_Usb_IUsbBulkOutPipe<D>::EndpointDescriptor() const
{
    Windows::Devices::Usb::UsbBulkOutEndpointDescriptor value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbBulkOutPipe)->get_EndpointDescriptor(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Devices_Usb_IUsbBulkOutPipe<D>::ClearStallAsync() const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbBulkOutPipe)->ClearStallAsync(put_abi(operation)));
    return operation;
}

template <typename D> void consume_Windows_Devices_Usb_IUsbBulkOutPipe<D>::WriteOptions(Windows::Devices::Usb::UsbWriteOptions const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbBulkOutPipe)->put_WriteOptions(get_abi(value)));
}

template <typename D> Windows::Devices::Usb::UsbWriteOptions consume_Windows_Devices_Usb_IUsbBulkOutPipe<D>::WriteOptions() const
{
    Windows::Devices::Usb::UsbWriteOptions value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbBulkOutPipe)->get_WriteOptions(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IOutputStream consume_Windows_Devices_Usb_IUsbBulkOutPipe<D>::OutputStream() const
{
    Windows::Storage::Streams::IOutputStream value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbBulkOutPipe)->get_OutputStream(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::Usb::UsbInterface> consume_Windows_Devices_Usb_IUsbConfiguration<D>::UsbInterfaces() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Usb::UsbInterface> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbConfiguration)->get_UsbInterfaces(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Usb::UsbConfigurationDescriptor consume_Windows_Devices_Usb_IUsbConfiguration<D>::ConfigurationDescriptor() const
{
    Windows::Devices::Usb::UsbConfigurationDescriptor value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbConfiguration)->get_ConfigurationDescriptor(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::Usb::UsbDescriptor> consume_Windows_Devices_Usb_IUsbConfiguration<D>::Descriptors() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Usb::UsbDescriptor> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbConfiguration)->get_Descriptors(put_abi(value)));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Usb_IUsbConfigurationDescriptor<D>::ConfigurationValue() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbConfigurationDescriptor)->get_ConfigurationValue(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_Usb_IUsbConfigurationDescriptor<D>::MaxPowerMilliamps() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbConfigurationDescriptor)->get_MaxPowerMilliamps(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_Usb_IUsbConfigurationDescriptor<D>::SelfPowered() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbConfigurationDescriptor)->get_SelfPowered(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_Usb_IUsbConfigurationDescriptor<D>::RemoteWakeup() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbConfigurationDescriptor)->get_RemoteWakeup(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_Usb_IUsbConfigurationDescriptorStatics<D>::TryParse(Windows::Devices::Usb::UsbDescriptor const& descriptor, Windows::Devices::Usb::UsbConfigurationDescriptor& parsed) const
{
    bool success{};
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbConfigurationDescriptorStatics)->TryParse(get_abi(descriptor), put_abi(parsed), &success));
    return success;
}

template <typename D> Windows::Devices::Usb::UsbConfigurationDescriptor consume_Windows_Devices_Usb_IUsbConfigurationDescriptorStatics<D>::Parse(Windows::Devices::Usb::UsbDescriptor const& descriptor) const
{
    Windows::Devices::Usb::UsbConfigurationDescriptor parsed{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbConfigurationDescriptorStatics)->Parse(get_abi(descriptor), put_abi(parsed)));
    return parsed;
}

template <typename D> Windows::Devices::Usb::UsbTransferDirection consume_Windows_Devices_Usb_IUsbControlRequestType<D>::Direction() const
{
    Windows::Devices::Usb::UsbTransferDirection value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbControlRequestType)->get_Direction(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Usb_IUsbControlRequestType<D>::Direction(Windows::Devices::Usb::UsbTransferDirection const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbControlRequestType)->put_Direction(get_abi(value)));
}

template <typename D> Windows::Devices::Usb::UsbControlTransferType consume_Windows_Devices_Usb_IUsbControlRequestType<D>::ControlTransferType() const
{
    Windows::Devices::Usb::UsbControlTransferType value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbControlRequestType)->get_ControlTransferType(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Usb_IUsbControlRequestType<D>::ControlTransferType(Windows::Devices::Usb::UsbControlTransferType const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbControlRequestType)->put_ControlTransferType(get_abi(value)));
}

template <typename D> Windows::Devices::Usb::UsbControlRecipient consume_Windows_Devices_Usb_IUsbControlRequestType<D>::Recipient() const
{
    Windows::Devices::Usb::UsbControlRecipient value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbControlRequestType)->get_Recipient(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Usb_IUsbControlRequestType<D>::Recipient(Windows::Devices::Usb::UsbControlRecipient const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbControlRequestType)->put_Recipient(get_abi(value)));
}

template <typename D> uint8_t consume_Windows_Devices_Usb_IUsbControlRequestType<D>::AsByte() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbControlRequestType)->get_AsByte(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_Usb_IUsbControlRequestType<D>::AsByte(uint8_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbControlRequestType)->put_AsByte(value));
}

template <typename D> uint8_t consume_Windows_Devices_Usb_IUsbDescriptor<D>::Length() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbDescriptor)->get_Length(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Usb_IUsbDescriptor<D>::DescriptorType() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbDescriptor)->get_DescriptorType(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_Usb_IUsbDescriptor<D>::ReadDescriptorBuffer(Windows::Storage::Streams::IBuffer const& buffer) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbDescriptor)->ReadDescriptorBuffer(get_abi(buffer)));
}

template <typename D> Windows::Foundation::IAsyncOperation<uint32_t> consume_Windows_Devices_Usb_IUsbDevice<D>::SendControlOutTransferAsync(Windows::Devices::Usb::UsbSetupPacket const& setupPacket, Windows::Storage::Streams::IBuffer const& buffer) const
{
    Windows::Foundation::IAsyncOperation<uint32_t> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbDevice)->SendControlOutTransferAsync(get_abi(setupPacket), get_abi(buffer), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<uint32_t> consume_Windows_Devices_Usb_IUsbDevice<D>::SendControlOutTransferAsync(Windows::Devices::Usb::UsbSetupPacket const& setupPacket) const
{
    Windows::Foundation::IAsyncOperation<uint32_t> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbDevice)->SendControlOutTransferAsyncNoBuffer(get_abi(setupPacket), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer> consume_Windows_Devices_Usb_IUsbDevice<D>::SendControlInTransferAsync(Windows::Devices::Usb::UsbSetupPacket const& setupPacket, Windows::Storage::Streams::IBuffer const& buffer) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbDevice)->SendControlInTransferAsync(get_abi(setupPacket), get_abi(buffer), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer> consume_Windows_Devices_Usb_IUsbDevice<D>::SendControlInTransferAsync(Windows::Devices::Usb::UsbSetupPacket const& setupPacket) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbDevice)->SendControlInTransferAsyncNoBuffer(get_abi(setupPacket), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Devices::Usb::UsbInterface consume_Windows_Devices_Usb_IUsbDevice<D>::DefaultInterface() const
{
    Windows::Devices::Usb::UsbInterface value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbDevice)->get_DefaultInterface(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Usb::UsbDeviceDescriptor consume_Windows_Devices_Usb_IUsbDevice<D>::DeviceDescriptor() const
{
    Windows::Devices::Usb::UsbDeviceDescriptor value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbDevice)->get_DeviceDescriptor(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Usb::UsbConfiguration consume_Windows_Devices_Usb_IUsbDevice<D>::Configuration() const
{
    Windows::Devices::Usb::UsbConfiguration value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbDevice)->get_Configuration(put_abi(value)));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Usb_IUsbDeviceClass<D>::ClassCode() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbDeviceClass)->get_ClassCode(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_Usb_IUsbDeviceClass<D>::ClassCode(uint8_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbDeviceClass)->put_ClassCode(value));
}

template <typename D> Windows::Foundation::IReference<uint8_t> consume_Windows_Devices_Usb_IUsbDeviceClass<D>::SubclassCode() const
{
    Windows::Foundation::IReference<uint8_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbDeviceClass)->get_SubclassCode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Usb_IUsbDeviceClass<D>::SubclassCode(optional<uint8_t> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbDeviceClass)->put_SubclassCode(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<uint8_t> consume_Windows_Devices_Usb_IUsbDeviceClass<D>::ProtocolCode() const
{
    Windows::Foundation::IReference<uint8_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbDeviceClass)->get_ProtocolCode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Usb_IUsbDeviceClass<D>::ProtocolCode(optional<uint8_t> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbDeviceClass)->put_ProtocolCode(get_abi(value)));
}

template <typename D> Windows::Devices::Usb::UsbDeviceClass consume_Windows_Devices_Usb_IUsbDeviceClassesStatics<D>::CdcControl() const
{
    Windows::Devices::Usb::UsbDeviceClass value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbDeviceClassesStatics)->get_CdcControl(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Usb::UsbDeviceClass consume_Windows_Devices_Usb_IUsbDeviceClassesStatics<D>::Physical() const
{
    Windows::Devices::Usb::UsbDeviceClass value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbDeviceClassesStatics)->get_Physical(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Usb::UsbDeviceClass consume_Windows_Devices_Usb_IUsbDeviceClassesStatics<D>::PersonalHealthcare() const
{
    Windows::Devices::Usb::UsbDeviceClass value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbDeviceClassesStatics)->get_PersonalHealthcare(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Usb::UsbDeviceClass consume_Windows_Devices_Usb_IUsbDeviceClassesStatics<D>::ActiveSync() const
{
    Windows::Devices::Usb::UsbDeviceClass value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbDeviceClassesStatics)->get_ActiveSync(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Usb::UsbDeviceClass consume_Windows_Devices_Usb_IUsbDeviceClassesStatics<D>::PalmSync() const
{
    Windows::Devices::Usb::UsbDeviceClass value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbDeviceClassesStatics)->get_PalmSync(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Usb::UsbDeviceClass consume_Windows_Devices_Usb_IUsbDeviceClassesStatics<D>::DeviceFirmwareUpdate() const
{
    Windows::Devices::Usb::UsbDeviceClass value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbDeviceClassesStatics)->get_DeviceFirmwareUpdate(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Usb::UsbDeviceClass consume_Windows_Devices_Usb_IUsbDeviceClassesStatics<D>::Irda() const
{
    Windows::Devices::Usb::UsbDeviceClass value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbDeviceClassesStatics)->get_Irda(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Usb::UsbDeviceClass consume_Windows_Devices_Usb_IUsbDeviceClassesStatics<D>::Measurement() const
{
    Windows::Devices::Usb::UsbDeviceClass value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbDeviceClassesStatics)->get_Measurement(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Usb::UsbDeviceClass consume_Windows_Devices_Usb_IUsbDeviceClassesStatics<D>::VendorSpecific() const
{
    Windows::Devices::Usb::UsbDeviceClass value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbDeviceClassesStatics)->get_VendorSpecific(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_Usb_IUsbDeviceDescriptor<D>::BcdUsb() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbDeviceDescriptor)->get_BcdUsb(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Usb_IUsbDeviceDescriptor<D>::MaxPacketSize0() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbDeviceDescriptor)->get_MaxPacketSize0(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_Usb_IUsbDeviceDescriptor<D>::VendorId() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbDeviceDescriptor)->get_VendorId(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_Usb_IUsbDeviceDescriptor<D>::ProductId() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbDeviceDescriptor)->get_ProductId(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_Usb_IUsbDeviceDescriptor<D>::BcdDeviceRevision() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbDeviceDescriptor)->get_BcdDeviceRevision(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Usb_IUsbDeviceDescriptor<D>::NumberOfConfigurations() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbDeviceDescriptor)->get_NumberOfConfigurations(&value));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Usb_IUsbDeviceStatics<D>::GetDeviceSelector(uint32_t vendorId, uint32_t productId, winrt::guid const& winUsbInterfaceClass) const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbDeviceStatics)->GetDeviceSelector(vendorId, productId, get_abi(winUsbInterfaceClass), put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Usb_IUsbDeviceStatics<D>::GetDeviceSelector(winrt::guid const& winUsbInterfaceClass) const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbDeviceStatics)->GetDeviceSelectorGuidOnly(get_abi(winUsbInterfaceClass), put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Usb_IUsbDeviceStatics<D>::GetDeviceSelector(uint32_t vendorId, uint32_t productId) const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbDeviceStatics)->GetDeviceSelectorVidPidOnly(vendorId, productId, put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Usb_IUsbDeviceStatics<D>::GetDeviceClassSelector(Windows::Devices::Usb::UsbDeviceClass const& usbClass) const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbDeviceStatics)->GetDeviceClassSelector(get_abi(usbClass), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Usb::UsbDevice> consume_Windows_Devices_Usb_IUsbDeviceStatics<D>::FromIdAsync(param::hstring const& deviceId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Usb::UsbDevice> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbDeviceStatics)->FromIdAsync(get_abi(deviceId), put_abi(operation)));
    return operation;
}

template <typename D> uint8_t consume_Windows_Devices_Usb_IUsbEndpointDescriptor<D>::EndpointNumber() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbEndpointDescriptor)->get_EndpointNumber(&value));
    return value;
}

template <typename D> Windows::Devices::Usb::UsbTransferDirection consume_Windows_Devices_Usb_IUsbEndpointDescriptor<D>::Direction() const
{
    Windows::Devices::Usb::UsbTransferDirection value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbEndpointDescriptor)->get_Direction(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Usb::UsbEndpointType consume_Windows_Devices_Usb_IUsbEndpointDescriptor<D>::EndpointType() const
{
    Windows::Devices::Usb::UsbEndpointType value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbEndpointDescriptor)->get_EndpointType(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Usb::UsbBulkInEndpointDescriptor consume_Windows_Devices_Usb_IUsbEndpointDescriptor<D>::AsBulkInEndpointDescriptor() const
{
    Windows::Devices::Usb::UsbBulkInEndpointDescriptor value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbEndpointDescriptor)->get_AsBulkInEndpointDescriptor(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Usb::UsbInterruptInEndpointDescriptor consume_Windows_Devices_Usb_IUsbEndpointDescriptor<D>::AsInterruptInEndpointDescriptor() const
{
    Windows::Devices::Usb::UsbInterruptInEndpointDescriptor value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbEndpointDescriptor)->get_AsInterruptInEndpointDescriptor(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Usb::UsbBulkOutEndpointDescriptor consume_Windows_Devices_Usb_IUsbEndpointDescriptor<D>::AsBulkOutEndpointDescriptor() const
{
    Windows::Devices::Usb::UsbBulkOutEndpointDescriptor value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbEndpointDescriptor)->get_AsBulkOutEndpointDescriptor(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Usb::UsbInterruptOutEndpointDescriptor consume_Windows_Devices_Usb_IUsbEndpointDescriptor<D>::AsInterruptOutEndpointDescriptor() const
{
    Windows::Devices::Usb::UsbInterruptOutEndpointDescriptor value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbEndpointDescriptor)->get_AsInterruptOutEndpointDescriptor(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Devices_Usb_IUsbEndpointDescriptorStatics<D>::TryParse(Windows::Devices::Usb::UsbDescriptor const& descriptor, Windows::Devices::Usb::UsbEndpointDescriptor& parsed) const
{
    bool success{};
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbEndpointDescriptorStatics)->TryParse(get_abi(descriptor), put_abi(parsed), &success));
    return success;
}

template <typename D> Windows::Devices::Usb::UsbEndpointDescriptor consume_Windows_Devices_Usb_IUsbEndpointDescriptorStatics<D>::Parse(Windows::Devices::Usb::UsbDescriptor const& descriptor) const
{
    Windows::Devices::Usb::UsbEndpointDescriptor parsed{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbEndpointDescriptorStatics)->Parse(get_abi(descriptor), put_abi(parsed)));
    return parsed;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::Usb::UsbBulkInPipe> consume_Windows_Devices_Usb_IUsbInterface<D>::BulkInPipes() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Usb::UsbBulkInPipe> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbInterface)->get_BulkInPipes(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::Usb::UsbInterruptInPipe> consume_Windows_Devices_Usb_IUsbInterface<D>::InterruptInPipes() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Usb::UsbInterruptInPipe> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbInterface)->get_InterruptInPipes(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::Usb::UsbBulkOutPipe> consume_Windows_Devices_Usb_IUsbInterface<D>::BulkOutPipes() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Usb::UsbBulkOutPipe> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbInterface)->get_BulkOutPipes(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::Usb::UsbInterruptOutPipe> consume_Windows_Devices_Usb_IUsbInterface<D>::InterruptOutPipes() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Usb::UsbInterruptOutPipe> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbInterface)->get_InterruptOutPipes(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::Usb::UsbInterfaceSetting> consume_Windows_Devices_Usb_IUsbInterface<D>::InterfaceSettings() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Usb::UsbInterfaceSetting> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbInterface)->get_InterfaceSettings(put_abi(value)));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Usb_IUsbInterface<D>::InterfaceNumber() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbInterface)->get_InterfaceNumber(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::Usb::UsbDescriptor> consume_Windows_Devices_Usb_IUsbInterface<D>::Descriptors() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Usb::UsbDescriptor> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbInterface)->get_Descriptors(put_abi(value)));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Usb_IUsbInterfaceDescriptor<D>::ClassCode() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbInterfaceDescriptor)->get_ClassCode(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Usb_IUsbInterfaceDescriptor<D>::SubclassCode() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbInterfaceDescriptor)->get_SubclassCode(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Usb_IUsbInterfaceDescriptor<D>::ProtocolCode() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbInterfaceDescriptor)->get_ProtocolCode(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Usb_IUsbInterfaceDescriptor<D>::AlternateSettingNumber() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbInterfaceDescriptor)->get_AlternateSettingNumber(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Usb_IUsbInterfaceDescriptor<D>::InterfaceNumber() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbInterfaceDescriptor)->get_InterfaceNumber(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_Usb_IUsbInterfaceDescriptorStatics<D>::TryParse(Windows::Devices::Usb::UsbDescriptor const& descriptor, Windows::Devices::Usb::UsbInterfaceDescriptor& parsed) const
{
    bool success{};
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbInterfaceDescriptorStatics)->TryParse(get_abi(descriptor), put_abi(parsed), &success));
    return success;
}

template <typename D> Windows::Devices::Usb::UsbInterfaceDescriptor consume_Windows_Devices_Usb_IUsbInterfaceDescriptorStatics<D>::Parse(Windows::Devices::Usb::UsbDescriptor const& descriptor) const
{
    Windows::Devices::Usb::UsbInterfaceDescriptor parsed{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbInterfaceDescriptorStatics)->Parse(get_abi(descriptor), put_abi(parsed)));
    return parsed;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::Usb::UsbBulkInEndpointDescriptor> consume_Windows_Devices_Usb_IUsbInterfaceSetting<D>::BulkInEndpoints() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Usb::UsbBulkInEndpointDescriptor> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbInterfaceSetting)->get_BulkInEndpoints(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::Usb::UsbInterruptInEndpointDescriptor> consume_Windows_Devices_Usb_IUsbInterfaceSetting<D>::InterruptInEndpoints() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Usb::UsbInterruptInEndpointDescriptor> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbInterfaceSetting)->get_InterruptInEndpoints(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::Usb::UsbBulkOutEndpointDescriptor> consume_Windows_Devices_Usb_IUsbInterfaceSetting<D>::BulkOutEndpoints() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Usb::UsbBulkOutEndpointDescriptor> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbInterfaceSetting)->get_BulkOutEndpoints(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::Usb::UsbInterruptOutEndpointDescriptor> consume_Windows_Devices_Usb_IUsbInterfaceSetting<D>::InterruptOutEndpoints() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Usb::UsbInterruptOutEndpointDescriptor> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbInterfaceSetting)->get_InterruptOutEndpoints(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Devices_Usb_IUsbInterfaceSetting<D>::Selected() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbInterfaceSetting)->get_Selected(&value));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Devices_Usb_IUsbInterfaceSetting<D>::SelectSettingAsync() const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbInterfaceSetting)->SelectSettingAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Devices::Usb::UsbInterfaceDescriptor consume_Windows_Devices_Usb_IUsbInterfaceSetting<D>::InterfaceDescriptor() const
{
    Windows::Devices::Usb::UsbInterfaceDescriptor value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbInterfaceSetting)->get_InterfaceDescriptor(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::Usb::UsbDescriptor> consume_Windows_Devices_Usb_IUsbInterfaceSetting<D>::Descriptors() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Usb::UsbDescriptor> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbInterfaceSetting)->get_Descriptors(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_Usb_IUsbInterruptInEndpointDescriptor<D>::MaxPacketSize() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbInterruptInEndpointDescriptor)->get_MaxPacketSize(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Usb_IUsbInterruptInEndpointDescriptor<D>::EndpointNumber() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbInterruptInEndpointDescriptor)->get_EndpointNumber(&value));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Devices_Usb_IUsbInterruptInEndpointDescriptor<D>::Interval() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbInterruptInEndpointDescriptor)->get_Interval(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Usb::UsbInterruptInPipe consume_Windows_Devices_Usb_IUsbInterruptInEndpointDescriptor<D>::Pipe() const
{
    Windows::Devices::Usb::UsbInterruptInPipe value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbInterruptInEndpointDescriptor)->get_Pipe(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Devices_Usb_IUsbInterruptInEventArgs<D>::InterruptData() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbInterruptInEventArgs)->get_InterruptData(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Usb::UsbInterruptInEndpointDescriptor consume_Windows_Devices_Usb_IUsbInterruptInPipe<D>::EndpointDescriptor() const
{
    Windows::Devices::Usb::UsbInterruptInEndpointDescriptor value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbInterruptInPipe)->get_EndpointDescriptor(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Devices_Usb_IUsbInterruptInPipe<D>::ClearStallAsync() const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbInterruptInPipe)->ClearStallAsync(put_abi(operation)));
    return operation;
}

template <typename D> winrt::event_token consume_Windows_Devices_Usb_IUsbInterruptInPipe<D>::DataReceived(Windows::Foundation::TypedEventHandler<Windows::Devices::Usb::UsbInterruptInPipe, Windows::Devices::Usb::UsbInterruptInEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbInterruptInPipe)->add_DataReceived(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Usb_IUsbInterruptInPipe<D>::DataReceived_revoker consume_Windows_Devices_Usb_IUsbInterruptInPipe<D>::DataReceived(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Usb::UsbInterruptInPipe, Windows::Devices::Usb::UsbInterruptInEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, DataReceived_revoker>(this, DataReceived(handler));
}

template <typename D> void consume_Windows_Devices_Usb_IUsbInterruptInPipe<D>::DataReceived(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Usb::IUsbInterruptInPipe)->remove_DataReceived(get_abi(token)));
}

template <typename D> uint32_t consume_Windows_Devices_Usb_IUsbInterruptOutEndpointDescriptor<D>::MaxPacketSize() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbInterruptOutEndpointDescriptor)->get_MaxPacketSize(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_Usb_IUsbInterruptOutEndpointDescriptor<D>::EndpointNumber() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbInterruptOutEndpointDescriptor)->get_EndpointNumber(&value));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Devices_Usb_IUsbInterruptOutEndpointDescriptor<D>::Interval() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbInterruptOutEndpointDescriptor)->get_Interval(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Usb::UsbInterruptOutPipe consume_Windows_Devices_Usb_IUsbInterruptOutEndpointDescriptor<D>::Pipe() const
{
    Windows::Devices::Usb::UsbInterruptOutPipe value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbInterruptOutEndpointDescriptor)->get_Pipe(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Usb::UsbInterruptOutEndpointDescriptor consume_Windows_Devices_Usb_IUsbInterruptOutPipe<D>::EndpointDescriptor() const
{
    Windows::Devices::Usb::UsbInterruptOutEndpointDescriptor value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbInterruptOutPipe)->get_EndpointDescriptor(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Devices_Usb_IUsbInterruptOutPipe<D>::ClearStallAsync() const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbInterruptOutPipe)->ClearStallAsync(put_abi(operation)));
    return operation;
}

template <typename D> void consume_Windows_Devices_Usb_IUsbInterruptOutPipe<D>::WriteOptions(Windows::Devices::Usb::UsbWriteOptions const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbInterruptOutPipe)->put_WriteOptions(get_abi(value)));
}

template <typename D> Windows::Devices::Usb::UsbWriteOptions consume_Windows_Devices_Usb_IUsbInterruptOutPipe<D>::WriteOptions() const
{
    Windows::Devices::Usb::UsbWriteOptions value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbInterruptOutPipe)->get_WriteOptions(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IOutputStream consume_Windows_Devices_Usb_IUsbInterruptOutPipe<D>::OutputStream() const
{
    Windows::Storage::Streams::IOutputStream value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbInterruptOutPipe)->get_OutputStream(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Usb::UsbControlRequestType consume_Windows_Devices_Usb_IUsbSetupPacket<D>::RequestType() const
{
    Windows::Devices::Usb::UsbControlRequestType value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbSetupPacket)->get_RequestType(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Usb_IUsbSetupPacket<D>::RequestType(Windows::Devices::Usb::UsbControlRequestType const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbSetupPacket)->put_RequestType(get_abi(value)));
}

template <typename D> uint8_t consume_Windows_Devices_Usb_IUsbSetupPacket<D>::Request() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbSetupPacket)->get_Request(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_Usb_IUsbSetupPacket<D>::Request(uint8_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbSetupPacket)->put_Request(value));
}

template <typename D> uint32_t consume_Windows_Devices_Usb_IUsbSetupPacket<D>::Value() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbSetupPacket)->get_Value(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_Usb_IUsbSetupPacket<D>::Value(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbSetupPacket)->put_Value(value));
}

template <typename D> uint32_t consume_Windows_Devices_Usb_IUsbSetupPacket<D>::Index() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbSetupPacket)->get_Index(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_Usb_IUsbSetupPacket<D>::Index(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbSetupPacket)->put_Index(value));
}

template <typename D> uint32_t consume_Windows_Devices_Usb_IUsbSetupPacket<D>::Length() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbSetupPacket)->get_Length(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_Usb_IUsbSetupPacket<D>::Length(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbSetupPacket)->put_Length(value));
}

template <typename D> Windows::Devices::Usb::UsbSetupPacket consume_Windows_Devices_Usb_IUsbSetupPacketFactory<D>::CreateWithEightByteBuffer(Windows::Storage::Streams::IBuffer const& eightByteBuffer) const
{
    Windows::Devices::Usb::UsbSetupPacket value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Usb::IUsbSetupPacketFactory)->CreateWithEightByteBuffer(get_abi(eightByteBuffer), put_abi(value)));
    return value;
}

template <typename D>
struct produce<D, Windows::Devices::Usb::IUsbBulkInEndpointDescriptor> : produce_base<D, Windows::Devices::Usb::IUsbBulkInEndpointDescriptor>
{
    int32_t WINRT_CALL get_MaxPacketSize(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxPacketSize, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().MaxPacketSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EndpointNumber(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EndpointNumber, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().EndpointNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Pipe(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Pipe, WINRT_WRAP(Windows::Devices::Usb::UsbBulkInPipe));
            *value = detach_from<Windows::Devices::Usb::UsbBulkInPipe>(this->shim().Pipe());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Usb::IUsbBulkInPipe> : produce_base<D, Windows::Devices::Usb::IUsbBulkInPipe>
{
    int32_t WINRT_CALL get_MaxTransferSizeBytes(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxTransferSizeBytes, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().MaxTransferSizeBytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EndpointDescriptor(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EndpointDescriptor, WINRT_WRAP(Windows::Devices::Usb::UsbBulkInEndpointDescriptor));
            *value = detach_from<Windows::Devices::Usb::UsbBulkInEndpointDescriptor>(this->shim().EndpointDescriptor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ClearStallAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClearStallAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ClearStallAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ReadOptions(Windows::Devices::Usb::UsbReadOptions value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadOptions, WINRT_WRAP(void), Windows::Devices::Usb::UsbReadOptions const&);
            this->shim().ReadOptions(*reinterpret_cast<Windows::Devices::Usb::UsbReadOptions const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ReadOptions(Windows::Devices::Usb::UsbReadOptions* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadOptions, WINRT_WRAP(Windows::Devices::Usb::UsbReadOptions));
            *value = detach_from<Windows::Devices::Usb::UsbReadOptions>(this->shim().ReadOptions());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FlushBuffer() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FlushBuffer, WINRT_WRAP(void));
            this->shim().FlushBuffer();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InputStream(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InputStream, WINRT_WRAP(Windows::Storage::Streams::IInputStream));
            *value = detach_from<Windows::Storage::Streams::IInputStream>(this->shim().InputStream());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Usb::IUsbBulkOutEndpointDescriptor> : produce_base<D, Windows::Devices::Usb::IUsbBulkOutEndpointDescriptor>
{
    int32_t WINRT_CALL get_MaxPacketSize(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxPacketSize, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().MaxPacketSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EndpointNumber(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EndpointNumber, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().EndpointNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Pipe(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Pipe, WINRT_WRAP(Windows::Devices::Usb::UsbBulkOutPipe));
            *value = detach_from<Windows::Devices::Usb::UsbBulkOutPipe>(this->shim().Pipe());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Usb::IUsbBulkOutPipe> : produce_base<D, Windows::Devices::Usb::IUsbBulkOutPipe>
{
    int32_t WINRT_CALL get_EndpointDescriptor(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EndpointDescriptor, WINRT_WRAP(Windows::Devices::Usb::UsbBulkOutEndpointDescriptor));
            *value = detach_from<Windows::Devices::Usb::UsbBulkOutEndpointDescriptor>(this->shim().EndpointDescriptor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ClearStallAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClearStallAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ClearStallAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_WriteOptions(Windows::Devices::Usb::UsbWriteOptions value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WriteOptions, WINRT_WRAP(void), Windows::Devices::Usb::UsbWriteOptions const&);
            this->shim().WriteOptions(*reinterpret_cast<Windows::Devices::Usb::UsbWriteOptions const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WriteOptions(Windows::Devices::Usb::UsbWriteOptions* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WriteOptions, WINRT_WRAP(Windows::Devices::Usb::UsbWriteOptions));
            *value = detach_from<Windows::Devices::Usb::UsbWriteOptions>(this->shim().WriteOptions());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OutputStream(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OutputStream, WINRT_WRAP(Windows::Storage::Streams::IOutputStream));
            *value = detach_from<Windows::Storage::Streams::IOutputStream>(this->shim().OutputStream());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Usb::IUsbConfiguration> : produce_base<D, Windows::Devices::Usb::IUsbConfiguration>
{
    int32_t WINRT_CALL get_UsbInterfaces(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UsbInterfaces, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::Usb::UsbInterface>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::Usb::UsbInterface>>(this->shim().UsbInterfaces());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ConfigurationDescriptor(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConfigurationDescriptor, WINRT_WRAP(Windows::Devices::Usb::UsbConfigurationDescriptor));
            *value = detach_from<Windows::Devices::Usb::UsbConfigurationDescriptor>(this->shim().ConfigurationDescriptor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Descriptors(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Descriptors, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::Usb::UsbDescriptor>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::Usb::UsbDescriptor>>(this->shim().Descriptors());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Usb::IUsbConfigurationDescriptor> : produce_base<D, Windows::Devices::Usb::IUsbConfigurationDescriptor>
{
    int32_t WINRT_CALL get_ConfigurationValue(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConfigurationValue, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().ConfigurationValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxPowerMilliamps(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxPowerMilliamps, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().MaxPowerMilliamps());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SelfPowered(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelfPowered, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().SelfPowered());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RemoteWakeup(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoteWakeup, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().RemoteWakeup());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Usb::IUsbConfigurationDescriptorStatics> : produce_base<D, Windows::Devices::Usb::IUsbConfigurationDescriptorStatics>
{
    int32_t WINRT_CALL TryParse(void* descriptor, void** parsed, bool* success) noexcept final
    {
        try
        {
            *parsed = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryParse, WINRT_WRAP(bool), Windows::Devices::Usb::UsbDescriptor const&, Windows::Devices::Usb::UsbConfigurationDescriptor&);
            *success = detach_from<bool>(this->shim().TryParse(*reinterpret_cast<Windows::Devices::Usb::UsbDescriptor const*>(&descriptor), *reinterpret_cast<Windows::Devices::Usb::UsbConfigurationDescriptor*>(parsed)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Parse(void* descriptor, void** parsed) noexcept final
    {
        try
        {
            *parsed = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Parse, WINRT_WRAP(Windows::Devices::Usb::UsbConfigurationDescriptor), Windows::Devices::Usb::UsbDescriptor const&);
            *parsed = detach_from<Windows::Devices::Usb::UsbConfigurationDescriptor>(this->shim().Parse(*reinterpret_cast<Windows::Devices::Usb::UsbDescriptor const*>(&descriptor)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Usb::IUsbControlRequestType> : produce_base<D, Windows::Devices::Usb::IUsbControlRequestType>
{
    int32_t WINRT_CALL get_Direction(Windows::Devices::Usb::UsbTransferDirection* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Direction, WINRT_WRAP(Windows::Devices::Usb::UsbTransferDirection));
            *value = detach_from<Windows::Devices::Usb::UsbTransferDirection>(this->shim().Direction());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Direction(Windows::Devices::Usb::UsbTransferDirection value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Direction, WINRT_WRAP(void), Windows::Devices::Usb::UsbTransferDirection const&);
            this->shim().Direction(*reinterpret_cast<Windows::Devices::Usb::UsbTransferDirection const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ControlTransferType(Windows::Devices::Usb::UsbControlTransferType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ControlTransferType, WINRT_WRAP(Windows::Devices::Usb::UsbControlTransferType));
            *value = detach_from<Windows::Devices::Usb::UsbControlTransferType>(this->shim().ControlTransferType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ControlTransferType(Windows::Devices::Usb::UsbControlTransferType value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ControlTransferType, WINRT_WRAP(void), Windows::Devices::Usb::UsbControlTransferType const&);
            this->shim().ControlTransferType(*reinterpret_cast<Windows::Devices::Usb::UsbControlTransferType const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Recipient(Windows::Devices::Usb::UsbControlRecipient* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Recipient, WINRT_WRAP(Windows::Devices::Usb::UsbControlRecipient));
            *value = detach_from<Windows::Devices::Usb::UsbControlRecipient>(this->shim().Recipient());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Recipient(Windows::Devices::Usb::UsbControlRecipient value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Recipient, WINRT_WRAP(void), Windows::Devices::Usb::UsbControlRecipient const&);
            this->shim().Recipient(*reinterpret_cast<Windows::Devices::Usb::UsbControlRecipient const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AsByte(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AsByte, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().AsByte());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AsByte(uint8_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AsByte, WINRT_WRAP(void), uint8_t);
            this->shim().AsByte(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Usb::IUsbDescriptor> : produce_base<D, Windows::Devices::Usb::IUsbDescriptor>
{
    int32_t WINRT_CALL get_Length(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Length, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().Length());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DescriptorType(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DescriptorType, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().DescriptorType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReadDescriptorBuffer(void* buffer) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReadDescriptorBuffer, WINRT_WRAP(void), Windows::Storage::Streams::IBuffer const&);
            this->shim().ReadDescriptorBuffer(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&buffer));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Usb::IUsbDevice> : produce_base<D, Windows::Devices::Usb::IUsbDevice>
{
    int32_t WINRT_CALL SendControlOutTransferAsync(void* setupPacket, void* buffer, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SendControlOutTransferAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<uint32_t>), Windows::Devices::Usb::UsbSetupPacket const, Windows::Storage::Streams::IBuffer const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<uint32_t>>(this->shim().SendControlOutTransferAsync(*reinterpret_cast<Windows::Devices::Usb::UsbSetupPacket const*>(&setupPacket), *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&buffer)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SendControlOutTransferAsyncNoBuffer(void* setupPacket, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SendControlOutTransferAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<uint32_t>), Windows::Devices::Usb::UsbSetupPacket const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<uint32_t>>(this->shim().SendControlOutTransferAsync(*reinterpret_cast<Windows::Devices::Usb::UsbSetupPacket const*>(&setupPacket)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SendControlInTransferAsync(void* setupPacket, void* buffer, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SendControlInTransferAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer>), Windows::Devices::Usb::UsbSetupPacket const, Windows::Storage::Streams::IBuffer const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer>>(this->shim().SendControlInTransferAsync(*reinterpret_cast<Windows::Devices::Usb::UsbSetupPacket const*>(&setupPacket), *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&buffer)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SendControlInTransferAsyncNoBuffer(void* setupPacket, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SendControlInTransferAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer>), Windows::Devices::Usb::UsbSetupPacket const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer>>(this->shim().SendControlInTransferAsync(*reinterpret_cast<Windows::Devices::Usb::UsbSetupPacket const*>(&setupPacket)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DefaultInterface(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DefaultInterface, WINRT_WRAP(Windows::Devices::Usb::UsbInterface));
            *value = detach_from<Windows::Devices::Usb::UsbInterface>(this->shim().DefaultInterface());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DeviceDescriptor(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceDescriptor, WINRT_WRAP(Windows::Devices::Usb::UsbDeviceDescriptor));
            *value = detach_from<Windows::Devices::Usb::UsbDeviceDescriptor>(this->shim().DeviceDescriptor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Configuration(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Configuration, WINRT_WRAP(Windows::Devices::Usb::UsbConfiguration));
            *value = detach_from<Windows::Devices::Usb::UsbConfiguration>(this->shim().Configuration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Usb::IUsbDeviceClass> : produce_base<D, Windows::Devices::Usb::IUsbDeviceClass>
{
    int32_t WINRT_CALL get_ClassCode(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClassCode, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().ClassCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ClassCode(uint8_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClassCode, WINRT_WRAP(void), uint8_t);
            this->shim().ClassCode(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SubclassCode(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SubclassCode, WINRT_WRAP(Windows::Foundation::IReference<uint8_t>));
            *value = detach_from<Windows::Foundation::IReference<uint8_t>>(this->shim().SubclassCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SubclassCode(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SubclassCode, WINRT_WRAP(void), Windows::Foundation::IReference<uint8_t> const&);
            this->shim().SubclassCode(*reinterpret_cast<Windows::Foundation::IReference<uint8_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProtocolCode(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProtocolCode, WINRT_WRAP(Windows::Foundation::IReference<uint8_t>));
            *value = detach_from<Windows::Foundation::IReference<uint8_t>>(this->shim().ProtocolCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ProtocolCode(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProtocolCode, WINRT_WRAP(void), Windows::Foundation::IReference<uint8_t> const&);
            this->shim().ProtocolCode(*reinterpret_cast<Windows::Foundation::IReference<uint8_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Usb::IUsbDeviceClasses> : produce_base<D, Windows::Devices::Usb::IUsbDeviceClasses>
{};

template <typename D>
struct produce<D, Windows::Devices::Usb::IUsbDeviceClassesStatics> : produce_base<D, Windows::Devices::Usb::IUsbDeviceClassesStatics>
{
    int32_t WINRT_CALL get_CdcControl(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CdcControl, WINRT_WRAP(Windows::Devices::Usb::UsbDeviceClass));
            *value = detach_from<Windows::Devices::Usb::UsbDeviceClass>(this->shim().CdcControl());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Physical(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Physical, WINRT_WRAP(Windows::Devices::Usb::UsbDeviceClass));
            *value = detach_from<Windows::Devices::Usb::UsbDeviceClass>(this->shim().Physical());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PersonalHealthcare(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PersonalHealthcare, WINRT_WRAP(Windows::Devices::Usb::UsbDeviceClass));
            *value = detach_from<Windows::Devices::Usb::UsbDeviceClass>(this->shim().PersonalHealthcare());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ActiveSync(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ActiveSync, WINRT_WRAP(Windows::Devices::Usb::UsbDeviceClass));
            *value = detach_from<Windows::Devices::Usb::UsbDeviceClass>(this->shim().ActiveSync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PalmSync(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PalmSync, WINRT_WRAP(Windows::Devices::Usb::UsbDeviceClass));
            *value = detach_from<Windows::Devices::Usb::UsbDeviceClass>(this->shim().PalmSync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DeviceFirmwareUpdate(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceFirmwareUpdate, WINRT_WRAP(Windows::Devices::Usb::UsbDeviceClass));
            *value = detach_from<Windows::Devices::Usb::UsbDeviceClass>(this->shim().DeviceFirmwareUpdate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Irda(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Irda, WINRT_WRAP(Windows::Devices::Usb::UsbDeviceClass));
            *value = detach_from<Windows::Devices::Usb::UsbDeviceClass>(this->shim().Irda());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Measurement(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Measurement, WINRT_WRAP(Windows::Devices::Usb::UsbDeviceClass));
            *value = detach_from<Windows::Devices::Usb::UsbDeviceClass>(this->shim().Measurement());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VendorSpecific(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VendorSpecific, WINRT_WRAP(Windows::Devices::Usb::UsbDeviceClass));
            *value = detach_from<Windows::Devices::Usb::UsbDeviceClass>(this->shim().VendorSpecific());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Usb::IUsbDeviceDescriptor> : produce_base<D, Windows::Devices::Usb::IUsbDeviceDescriptor>
{
    int32_t WINRT_CALL get_BcdUsb(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BcdUsb, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().BcdUsb());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxPacketSize0(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxPacketSize0, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().MaxPacketSize0());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VendorId(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VendorId, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().VendorId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProductId(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProductId, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().ProductId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BcdDeviceRevision(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BcdDeviceRevision, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().BcdDeviceRevision());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NumberOfConfigurations(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NumberOfConfigurations, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().NumberOfConfigurations());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Usb::IUsbDeviceStatics> : produce_base<D, Windows::Devices::Usb::IUsbDeviceStatics>
{
    int32_t WINRT_CALL GetDeviceSelector(uint32_t vendorId, uint32_t productId, winrt::guid winUsbInterfaceClass, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelector, WINRT_WRAP(hstring), uint32_t, uint32_t, winrt::guid const&);
            *value = detach_from<hstring>(this->shim().GetDeviceSelector(vendorId, productId, *reinterpret_cast<winrt::guid const*>(&winUsbInterfaceClass)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeviceSelectorGuidOnly(winrt::guid winUsbInterfaceClass, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelector, WINRT_WRAP(hstring), winrt::guid const&);
            *value = detach_from<hstring>(this->shim().GetDeviceSelector(*reinterpret_cast<winrt::guid const*>(&winUsbInterfaceClass)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeviceSelectorVidPidOnly(uint32_t vendorId, uint32_t productId, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelector, WINRT_WRAP(hstring), uint32_t, uint32_t);
            *value = detach_from<hstring>(this->shim().GetDeviceSelector(vendorId, productId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeviceClassSelector(void* usbClass, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceClassSelector, WINRT_WRAP(hstring), Windows::Devices::Usb::UsbDeviceClass const&);
            *value = detach_from<hstring>(this->shim().GetDeviceClassSelector(*reinterpret_cast<Windows::Devices::Usb::UsbDeviceClass const*>(&usbClass)));
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
            WINRT_ASSERT_DECLARATION(FromIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Usb::UsbDevice>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Usb::UsbDevice>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Usb::IUsbEndpointDescriptor> : produce_base<D, Windows::Devices::Usb::IUsbEndpointDescriptor>
{
    int32_t WINRT_CALL get_EndpointNumber(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EndpointNumber, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().EndpointNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Direction(Windows::Devices::Usb::UsbTransferDirection* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Direction, WINRT_WRAP(Windows::Devices::Usb::UsbTransferDirection));
            *value = detach_from<Windows::Devices::Usb::UsbTransferDirection>(this->shim().Direction());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EndpointType(Windows::Devices::Usb::UsbEndpointType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EndpointType, WINRT_WRAP(Windows::Devices::Usb::UsbEndpointType));
            *value = detach_from<Windows::Devices::Usb::UsbEndpointType>(this->shim().EndpointType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AsBulkInEndpointDescriptor(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AsBulkInEndpointDescriptor, WINRT_WRAP(Windows::Devices::Usb::UsbBulkInEndpointDescriptor));
            *value = detach_from<Windows::Devices::Usb::UsbBulkInEndpointDescriptor>(this->shim().AsBulkInEndpointDescriptor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AsInterruptInEndpointDescriptor(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AsInterruptInEndpointDescriptor, WINRT_WRAP(Windows::Devices::Usb::UsbInterruptInEndpointDescriptor));
            *value = detach_from<Windows::Devices::Usb::UsbInterruptInEndpointDescriptor>(this->shim().AsInterruptInEndpointDescriptor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AsBulkOutEndpointDescriptor(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AsBulkOutEndpointDescriptor, WINRT_WRAP(Windows::Devices::Usb::UsbBulkOutEndpointDescriptor));
            *value = detach_from<Windows::Devices::Usb::UsbBulkOutEndpointDescriptor>(this->shim().AsBulkOutEndpointDescriptor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AsInterruptOutEndpointDescriptor(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AsInterruptOutEndpointDescriptor, WINRT_WRAP(Windows::Devices::Usb::UsbInterruptOutEndpointDescriptor));
            *value = detach_from<Windows::Devices::Usb::UsbInterruptOutEndpointDescriptor>(this->shim().AsInterruptOutEndpointDescriptor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Usb::IUsbEndpointDescriptorStatics> : produce_base<D, Windows::Devices::Usb::IUsbEndpointDescriptorStatics>
{
    int32_t WINRT_CALL TryParse(void* descriptor, void** parsed, bool* success) noexcept final
    {
        try
        {
            *parsed = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryParse, WINRT_WRAP(bool), Windows::Devices::Usb::UsbDescriptor const&, Windows::Devices::Usb::UsbEndpointDescriptor&);
            *success = detach_from<bool>(this->shim().TryParse(*reinterpret_cast<Windows::Devices::Usb::UsbDescriptor const*>(&descriptor), *reinterpret_cast<Windows::Devices::Usb::UsbEndpointDescriptor*>(parsed)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Parse(void* descriptor, void** parsed) noexcept final
    {
        try
        {
            *parsed = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Parse, WINRT_WRAP(Windows::Devices::Usb::UsbEndpointDescriptor), Windows::Devices::Usb::UsbDescriptor const&);
            *parsed = detach_from<Windows::Devices::Usb::UsbEndpointDescriptor>(this->shim().Parse(*reinterpret_cast<Windows::Devices::Usb::UsbDescriptor const*>(&descriptor)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Usb::IUsbInterface> : produce_base<D, Windows::Devices::Usb::IUsbInterface>
{
    int32_t WINRT_CALL get_BulkInPipes(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BulkInPipes, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::Usb::UsbBulkInPipe>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::Usb::UsbBulkInPipe>>(this->shim().BulkInPipes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InterruptInPipes(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InterruptInPipes, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::Usb::UsbInterruptInPipe>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::Usb::UsbInterruptInPipe>>(this->shim().InterruptInPipes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BulkOutPipes(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BulkOutPipes, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::Usb::UsbBulkOutPipe>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::Usb::UsbBulkOutPipe>>(this->shim().BulkOutPipes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InterruptOutPipes(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InterruptOutPipes, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::Usb::UsbInterruptOutPipe>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::Usb::UsbInterruptOutPipe>>(this->shim().InterruptOutPipes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InterfaceSettings(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InterfaceSettings, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::Usb::UsbInterfaceSetting>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::Usb::UsbInterfaceSetting>>(this->shim().InterfaceSettings());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InterfaceNumber(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InterfaceNumber, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().InterfaceNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Descriptors(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Descriptors, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::Usb::UsbDescriptor>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::Usb::UsbDescriptor>>(this->shim().Descriptors());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Usb::IUsbInterfaceDescriptor> : produce_base<D, Windows::Devices::Usb::IUsbInterfaceDescriptor>
{
    int32_t WINRT_CALL get_ClassCode(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClassCode, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().ClassCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SubclassCode(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SubclassCode, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().SubclassCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProtocolCode(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProtocolCode, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().ProtocolCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AlternateSettingNumber(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AlternateSettingNumber, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().AlternateSettingNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InterfaceNumber(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InterfaceNumber, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().InterfaceNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Usb::IUsbInterfaceDescriptorStatics> : produce_base<D, Windows::Devices::Usb::IUsbInterfaceDescriptorStatics>
{
    int32_t WINRT_CALL TryParse(void* descriptor, void** parsed, bool* success) noexcept final
    {
        try
        {
            *parsed = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryParse, WINRT_WRAP(bool), Windows::Devices::Usb::UsbDescriptor const&, Windows::Devices::Usb::UsbInterfaceDescriptor&);
            *success = detach_from<bool>(this->shim().TryParse(*reinterpret_cast<Windows::Devices::Usb::UsbDescriptor const*>(&descriptor), *reinterpret_cast<Windows::Devices::Usb::UsbInterfaceDescriptor*>(parsed)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Parse(void* descriptor, void** parsed) noexcept final
    {
        try
        {
            *parsed = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Parse, WINRT_WRAP(Windows::Devices::Usb::UsbInterfaceDescriptor), Windows::Devices::Usb::UsbDescriptor const&);
            *parsed = detach_from<Windows::Devices::Usb::UsbInterfaceDescriptor>(this->shim().Parse(*reinterpret_cast<Windows::Devices::Usb::UsbDescriptor const*>(&descriptor)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Usb::IUsbInterfaceSetting> : produce_base<D, Windows::Devices::Usb::IUsbInterfaceSetting>
{
    int32_t WINRT_CALL get_BulkInEndpoints(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BulkInEndpoints, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::Usb::UsbBulkInEndpointDescriptor>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::Usb::UsbBulkInEndpointDescriptor>>(this->shim().BulkInEndpoints());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InterruptInEndpoints(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InterruptInEndpoints, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::Usb::UsbInterruptInEndpointDescriptor>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::Usb::UsbInterruptInEndpointDescriptor>>(this->shim().InterruptInEndpoints());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BulkOutEndpoints(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BulkOutEndpoints, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::Usb::UsbBulkOutEndpointDescriptor>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::Usb::UsbBulkOutEndpointDescriptor>>(this->shim().BulkOutEndpoints());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InterruptOutEndpoints(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InterruptOutEndpoints, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::Usb::UsbInterruptOutEndpointDescriptor>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::Usb::UsbInterruptOutEndpointDescriptor>>(this->shim().InterruptOutEndpoints());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Selected(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Selected, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Selected());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SelectSettingAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectSettingAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SelectSettingAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InterfaceDescriptor(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InterfaceDescriptor, WINRT_WRAP(Windows::Devices::Usb::UsbInterfaceDescriptor));
            *value = detach_from<Windows::Devices::Usb::UsbInterfaceDescriptor>(this->shim().InterfaceDescriptor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Descriptors(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Descriptors, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::Usb::UsbDescriptor>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::Usb::UsbDescriptor>>(this->shim().Descriptors());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Usb::IUsbInterruptInEndpointDescriptor> : produce_base<D, Windows::Devices::Usb::IUsbInterruptInEndpointDescriptor>
{
    int32_t WINRT_CALL get_MaxPacketSize(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxPacketSize, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().MaxPacketSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EndpointNumber(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EndpointNumber, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().EndpointNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Interval(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Interval, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().Interval());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Pipe(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Pipe, WINRT_WRAP(Windows::Devices::Usb::UsbInterruptInPipe));
            *value = detach_from<Windows::Devices::Usb::UsbInterruptInPipe>(this->shim().Pipe());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Usb::IUsbInterruptInEventArgs> : produce_base<D, Windows::Devices::Usb::IUsbInterruptInEventArgs>
{
    int32_t WINRT_CALL get_InterruptData(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InterruptData, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().InterruptData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Usb::IUsbInterruptInPipe> : produce_base<D, Windows::Devices::Usb::IUsbInterruptInPipe>
{
    int32_t WINRT_CALL get_EndpointDescriptor(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EndpointDescriptor, WINRT_WRAP(Windows::Devices::Usb::UsbInterruptInEndpointDescriptor));
            *value = detach_from<Windows::Devices::Usb::UsbInterruptInEndpointDescriptor>(this->shim().EndpointDescriptor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ClearStallAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClearStallAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ClearStallAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_DataReceived(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DataReceived, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Usb::UsbInterruptInPipe, Windows::Devices::Usb::UsbInterruptInEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().DataReceived(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Usb::UsbInterruptInPipe, Windows::Devices::Usb::UsbInterruptInEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_DataReceived(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(DataReceived, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().DataReceived(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Devices::Usb::IUsbInterruptOutEndpointDescriptor> : produce_base<D, Windows::Devices::Usb::IUsbInterruptOutEndpointDescriptor>
{
    int32_t WINRT_CALL get_MaxPacketSize(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxPacketSize, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().MaxPacketSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EndpointNumber(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EndpointNumber, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().EndpointNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Interval(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Interval, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().Interval());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Pipe(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Pipe, WINRT_WRAP(Windows::Devices::Usb::UsbInterruptOutPipe));
            *value = detach_from<Windows::Devices::Usb::UsbInterruptOutPipe>(this->shim().Pipe());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Usb::IUsbInterruptOutPipe> : produce_base<D, Windows::Devices::Usb::IUsbInterruptOutPipe>
{
    int32_t WINRT_CALL get_EndpointDescriptor(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EndpointDescriptor, WINRT_WRAP(Windows::Devices::Usb::UsbInterruptOutEndpointDescriptor));
            *value = detach_from<Windows::Devices::Usb::UsbInterruptOutEndpointDescriptor>(this->shim().EndpointDescriptor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ClearStallAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClearStallAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ClearStallAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_WriteOptions(Windows::Devices::Usb::UsbWriteOptions value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WriteOptions, WINRT_WRAP(void), Windows::Devices::Usb::UsbWriteOptions const&);
            this->shim().WriteOptions(*reinterpret_cast<Windows::Devices::Usb::UsbWriteOptions const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WriteOptions(Windows::Devices::Usb::UsbWriteOptions* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WriteOptions, WINRT_WRAP(Windows::Devices::Usb::UsbWriteOptions));
            *value = detach_from<Windows::Devices::Usb::UsbWriteOptions>(this->shim().WriteOptions());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OutputStream(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OutputStream, WINRT_WRAP(Windows::Storage::Streams::IOutputStream));
            *value = detach_from<Windows::Storage::Streams::IOutputStream>(this->shim().OutputStream());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Usb::IUsbSetupPacket> : produce_base<D, Windows::Devices::Usb::IUsbSetupPacket>
{
    int32_t WINRT_CALL get_RequestType(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestType, WINRT_WRAP(Windows::Devices::Usb::UsbControlRequestType));
            *value = detach_from<Windows::Devices::Usb::UsbControlRequestType>(this->shim().RequestType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RequestType(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestType, WINRT_WRAP(void), Windows::Devices::Usb::UsbControlRequestType const&);
            this->shim().RequestType(*reinterpret_cast<Windows::Devices::Usb::UsbControlRequestType const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Request(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Request, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().Request());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Request(uint8_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Request, WINRT_WRAP(void), uint8_t);
            this->shim().Request(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Value(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Value, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Value());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Value(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Value, WINRT_WRAP(void), uint32_t);
            this->shim().Value(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Index(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Index, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Index());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Index(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Index, WINRT_WRAP(void), uint32_t);
            this->shim().Index(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Length(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Length, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Length());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Length(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Length, WINRT_WRAP(void), uint32_t);
            this->shim().Length(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Usb::IUsbSetupPacketFactory> : produce_base<D, Windows::Devices::Usb::IUsbSetupPacketFactory>
{
    int32_t WINRT_CALL CreateWithEightByteBuffer(void* eightByteBuffer, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithEightByteBuffer, WINRT_WRAP(Windows::Devices::Usb::UsbSetupPacket), Windows::Storage::Streams::IBuffer const&);
            *value = detach_from<Windows::Devices::Usb::UsbSetupPacket>(this->shim().CreateWithEightByteBuffer(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&eightByteBuffer)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Devices::Usb {

inline bool UsbConfigurationDescriptor::TryParse(Windows::Devices::Usb::UsbDescriptor const& descriptor, Windows::Devices::Usb::UsbConfigurationDescriptor& parsed)
{
    return impl::call_factory<UsbConfigurationDescriptor, Windows::Devices::Usb::IUsbConfigurationDescriptorStatics>([&](auto&& f) { return f.TryParse(descriptor, parsed); });
}

inline Windows::Devices::Usb::UsbConfigurationDescriptor UsbConfigurationDescriptor::Parse(Windows::Devices::Usb::UsbDescriptor const& descriptor)
{
    return impl::call_factory<UsbConfigurationDescriptor, Windows::Devices::Usb::IUsbConfigurationDescriptorStatics>([&](auto&& f) { return f.Parse(descriptor); });
}

inline UsbControlRequestType::UsbControlRequestType() :
    UsbControlRequestType(impl::call_factory<UsbControlRequestType>([](auto&& f) { return f.template ActivateInstance<UsbControlRequestType>(); }))
{}

inline hstring UsbDevice::GetDeviceSelector(uint32_t vendorId, uint32_t productId, winrt::guid const& winUsbInterfaceClass)
{
    return impl::call_factory<UsbDevice, Windows::Devices::Usb::IUsbDeviceStatics>([&](auto&& f) { return f.GetDeviceSelector(vendorId, productId, winUsbInterfaceClass); });
}

inline hstring UsbDevice::GetDeviceSelector(winrt::guid const& winUsbInterfaceClass)
{
    return impl::call_factory<UsbDevice, Windows::Devices::Usb::IUsbDeviceStatics>([&](auto&& f) { return f.GetDeviceSelector(winUsbInterfaceClass); });
}

inline hstring UsbDevice::GetDeviceSelector(uint32_t vendorId, uint32_t productId)
{
    return impl::call_factory<UsbDevice, Windows::Devices::Usb::IUsbDeviceStatics>([&](auto&& f) { return f.GetDeviceSelector(vendorId, productId); });
}

inline hstring UsbDevice::GetDeviceClassSelector(Windows::Devices::Usb::UsbDeviceClass const& usbClass)
{
    return impl::call_factory<UsbDevice, Windows::Devices::Usb::IUsbDeviceStatics>([&](auto&& f) { return f.GetDeviceClassSelector(usbClass); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::Usb::UsbDevice> UsbDevice::FromIdAsync(param::hstring const& deviceId)
{
    return impl::call_factory<UsbDevice, Windows::Devices::Usb::IUsbDeviceStatics>([&](auto&& f) { return f.FromIdAsync(deviceId); });
}

inline UsbDeviceClass::UsbDeviceClass() :
    UsbDeviceClass(impl::call_factory<UsbDeviceClass>([](auto&& f) { return f.template ActivateInstance<UsbDeviceClass>(); }))
{}

inline Windows::Devices::Usb::UsbDeviceClass UsbDeviceClasses::CdcControl()
{
    return impl::call_factory<UsbDeviceClasses, Windows::Devices::Usb::IUsbDeviceClassesStatics>([&](auto&& f) { return f.CdcControl(); });
}

inline Windows::Devices::Usb::UsbDeviceClass UsbDeviceClasses::Physical()
{
    return impl::call_factory<UsbDeviceClasses, Windows::Devices::Usb::IUsbDeviceClassesStatics>([&](auto&& f) { return f.Physical(); });
}

inline Windows::Devices::Usb::UsbDeviceClass UsbDeviceClasses::PersonalHealthcare()
{
    return impl::call_factory<UsbDeviceClasses, Windows::Devices::Usb::IUsbDeviceClassesStatics>([&](auto&& f) { return f.PersonalHealthcare(); });
}

inline Windows::Devices::Usb::UsbDeviceClass UsbDeviceClasses::ActiveSync()
{
    return impl::call_factory<UsbDeviceClasses, Windows::Devices::Usb::IUsbDeviceClassesStatics>([&](auto&& f) { return f.ActiveSync(); });
}

inline Windows::Devices::Usb::UsbDeviceClass UsbDeviceClasses::PalmSync()
{
    return impl::call_factory<UsbDeviceClasses, Windows::Devices::Usb::IUsbDeviceClassesStatics>([&](auto&& f) { return f.PalmSync(); });
}

inline Windows::Devices::Usb::UsbDeviceClass UsbDeviceClasses::DeviceFirmwareUpdate()
{
    return impl::call_factory<UsbDeviceClasses, Windows::Devices::Usb::IUsbDeviceClassesStatics>([&](auto&& f) { return f.DeviceFirmwareUpdate(); });
}

inline Windows::Devices::Usb::UsbDeviceClass UsbDeviceClasses::Irda()
{
    return impl::call_factory<UsbDeviceClasses, Windows::Devices::Usb::IUsbDeviceClassesStatics>([&](auto&& f) { return f.Irda(); });
}

inline Windows::Devices::Usb::UsbDeviceClass UsbDeviceClasses::Measurement()
{
    return impl::call_factory<UsbDeviceClasses, Windows::Devices::Usb::IUsbDeviceClassesStatics>([&](auto&& f) { return f.Measurement(); });
}

inline Windows::Devices::Usb::UsbDeviceClass UsbDeviceClasses::VendorSpecific()
{
    return impl::call_factory<UsbDeviceClasses, Windows::Devices::Usb::IUsbDeviceClassesStatics>([&](auto&& f) { return f.VendorSpecific(); });
}

inline bool UsbEndpointDescriptor::TryParse(Windows::Devices::Usb::UsbDescriptor const& descriptor, Windows::Devices::Usb::UsbEndpointDescriptor& parsed)
{
    return impl::call_factory<UsbEndpointDescriptor, Windows::Devices::Usb::IUsbEndpointDescriptorStatics>([&](auto&& f) { return f.TryParse(descriptor, parsed); });
}

inline Windows::Devices::Usb::UsbEndpointDescriptor UsbEndpointDescriptor::Parse(Windows::Devices::Usb::UsbDescriptor const& descriptor)
{
    return impl::call_factory<UsbEndpointDescriptor, Windows::Devices::Usb::IUsbEndpointDescriptorStatics>([&](auto&& f) { return f.Parse(descriptor); });
}

inline bool UsbInterfaceDescriptor::TryParse(Windows::Devices::Usb::UsbDescriptor const& descriptor, Windows::Devices::Usb::UsbInterfaceDescriptor& parsed)
{
    return impl::call_factory<UsbInterfaceDescriptor, Windows::Devices::Usb::IUsbInterfaceDescriptorStatics>([&](auto&& f) { return f.TryParse(descriptor, parsed); });
}

inline Windows::Devices::Usb::UsbInterfaceDescriptor UsbInterfaceDescriptor::Parse(Windows::Devices::Usb::UsbDescriptor const& descriptor)
{
    return impl::call_factory<UsbInterfaceDescriptor, Windows::Devices::Usb::IUsbInterfaceDescriptorStatics>([&](auto&& f) { return f.Parse(descriptor); });
}

inline UsbSetupPacket::UsbSetupPacket() :
    UsbSetupPacket(impl::call_factory<UsbSetupPacket>([](auto&& f) { return f.template ActivateInstance<UsbSetupPacket>(); }))
{}

inline UsbSetupPacket::UsbSetupPacket(Windows::Storage::Streams::IBuffer const& eightByteBuffer) :
    UsbSetupPacket(impl::call_factory<UsbSetupPacket, Windows::Devices::Usb::IUsbSetupPacketFactory>([&](auto&& f) { return f.CreateWithEightByteBuffer(eightByteBuffer); }))
{}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Devices::Usb::IUsbBulkInEndpointDescriptor> : winrt::impl::hash_base<winrt::Windows::Devices::Usb::IUsbBulkInEndpointDescriptor> {};
template<> struct hash<winrt::Windows::Devices::Usb::IUsbBulkInPipe> : winrt::impl::hash_base<winrt::Windows::Devices::Usb::IUsbBulkInPipe> {};
template<> struct hash<winrt::Windows::Devices::Usb::IUsbBulkOutEndpointDescriptor> : winrt::impl::hash_base<winrt::Windows::Devices::Usb::IUsbBulkOutEndpointDescriptor> {};
template<> struct hash<winrt::Windows::Devices::Usb::IUsbBulkOutPipe> : winrt::impl::hash_base<winrt::Windows::Devices::Usb::IUsbBulkOutPipe> {};
template<> struct hash<winrt::Windows::Devices::Usb::IUsbConfiguration> : winrt::impl::hash_base<winrt::Windows::Devices::Usb::IUsbConfiguration> {};
template<> struct hash<winrt::Windows::Devices::Usb::IUsbConfigurationDescriptor> : winrt::impl::hash_base<winrt::Windows::Devices::Usb::IUsbConfigurationDescriptor> {};
template<> struct hash<winrt::Windows::Devices::Usb::IUsbConfigurationDescriptorStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Usb::IUsbConfigurationDescriptorStatics> {};
template<> struct hash<winrt::Windows::Devices::Usb::IUsbControlRequestType> : winrt::impl::hash_base<winrt::Windows::Devices::Usb::IUsbControlRequestType> {};
template<> struct hash<winrt::Windows::Devices::Usb::IUsbDescriptor> : winrt::impl::hash_base<winrt::Windows::Devices::Usb::IUsbDescriptor> {};
template<> struct hash<winrt::Windows::Devices::Usb::IUsbDevice> : winrt::impl::hash_base<winrt::Windows::Devices::Usb::IUsbDevice> {};
template<> struct hash<winrt::Windows::Devices::Usb::IUsbDeviceClass> : winrt::impl::hash_base<winrt::Windows::Devices::Usb::IUsbDeviceClass> {};
template<> struct hash<winrt::Windows::Devices::Usb::IUsbDeviceClasses> : winrt::impl::hash_base<winrt::Windows::Devices::Usb::IUsbDeviceClasses> {};
template<> struct hash<winrt::Windows::Devices::Usb::IUsbDeviceClassesStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Usb::IUsbDeviceClassesStatics> {};
template<> struct hash<winrt::Windows::Devices::Usb::IUsbDeviceDescriptor> : winrt::impl::hash_base<winrt::Windows::Devices::Usb::IUsbDeviceDescriptor> {};
template<> struct hash<winrt::Windows::Devices::Usb::IUsbDeviceStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Usb::IUsbDeviceStatics> {};
template<> struct hash<winrt::Windows::Devices::Usb::IUsbEndpointDescriptor> : winrt::impl::hash_base<winrt::Windows::Devices::Usb::IUsbEndpointDescriptor> {};
template<> struct hash<winrt::Windows::Devices::Usb::IUsbEndpointDescriptorStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Usb::IUsbEndpointDescriptorStatics> {};
template<> struct hash<winrt::Windows::Devices::Usb::IUsbInterface> : winrt::impl::hash_base<winrt::Windows::Devices::Usb::IUsbInterface> {};
template<> struct hash<winrt::Windows::Devices::Usb::IUsbInterfaceDescriptor> : winrt::impl::hash_base<winrt::Windows::Devices::Usb::IUsbInterfaceDescriptor> {};
template<> struct hash<winrt::Windows::Devices::Usb::IUsbInterfaceDescriptorStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Usb::IUsbInterfaceDescriptorStatics> {};
template<> struct hash<winrt::Windows::Devices::Usb::IUsbInterfaceSetting> : winrt::impl::hash_base<winrt::Windows::Devices::Usb::IUsbInterfaceSetting> {};
template<> struct hash<winrt::Windows::Devices::Usb::IUsbInterruptInEndpointDescriptor> : winrt::impl::hash_base<winrt::Windows::Devices::Usb::IUsbInterruptInEndpointDescriptor> {};
template<> struct hash<winrt::Windows::Devices::Usb::IUsbInterruptInEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Usb::IUsbInterruptInEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Usb::IUsbInterruptInPipe> : winrt::impl::hash_base<winrt::Windows::Devices::Usb::IUsbInterruptInPipe> {};
template<> struct hash<winrt::Windows::Devices::Usb::IUsbInterruptOutEndpointDescriptor> : winrt::impl::hash_base<winrt::Windows::Devices::Usb::IUsbInterruptOutEndpointDescriptor> {};
template<> struct hash<winrt::Windows::Devices::Usb::IUsbInterruptOutPipe> : winrt::impl::hash_base<winrt::Windows::Devices::Usb::IUsbInterruptOutPipe> {};
template<> struct hash<winrt::Windows::Devices::Usb::IUsbSetupPacket> : winrt::impl::hash_base<winrt::Windows::Devices::Usb::IUsbSetupPacket> {};
template<> struct hash<winrt::Windows::Devices::Usb::IUsbSetupPacketFactory> : winrt::impl::hash_base<winrt::Windows::Devices::Usb::IUsbSetupPacketFactory> {};
template<> struct hash<winrt::Windows::Devices::Usb::UsbBulkInEndpointDescriptor> : winrt::impl::hash_base<winrt::Windows::Devices::Usb::UsbBulkInEndpointDescriptor> {};
template<> struct hash<winrt::Windows::Devices::Usb::UsbBulkInPipe> : winrt::impl::hash_base<winrt::Windows::Devices::Usb::UsbBulkInPipe> {};
template<> struct hash<winrt::Windows::Devices::Usb::UsbBulkOutEndpointDescriptor> : winrt::impl::hash_base<winrt::Windows::Devices::Usb::UsbBulkOutEndpointDescriptor> {};
template<> struct hash<winrt::Windows::Devices::Usb::UsbBulkOutPipe> : winrt::impl::hash_base<winrt::Windows::Devices::Usb::UsbBulkOutPipe> {};
template<> struct hash<winrt::Windows::Devices::Usb::UsbConfiguration> : winrt::impl::hash_base<winrt::Windows::Devices::Usb::UsbConfiguration> {};
template<> struct hash<winrt::Windows::Devices::Usb::UsbConfigurationDescriptor> : winrt::impl::hash_base<winrt::Windows::Devices::Usb::UsbConfigurationDescriptor> {};
template<> struct hash<winrt::Windows::Devices::Usb::UsbControlRequestType> : winrt::impl::hash_base<winrt::Windows::Devices::Usb::UsbControlRequestType> {};
template<> struct hash<winrt::Windows::Devices::Usb::UsbDescriptor> : winrt::impl::hash_base<winrt::Windows::Devices::Usb::UsbDescriptor> {};
template<> struct hash<winrt::Windows::Devices::Usb::UsbDevice> : winrt::impl::hash_base<winrt::Windows::Devices::Usb::UsbDevice> {};
template<> struct hash<winrt::Windows::Devices::Usb::UsbDeviceClass> : winrt::impl::hash_base<winrt::Windows::Devices::Usb::UsbDeviceClass> {};
template<> struct hash<winrt::Windows::Devices::Usb::UsbDeviceClasses> : winrt::impl::hash_base<winrt::Windows::Devices::Usb::UsbDeviceClasses> {};
template<> struct hash<winrt::Windows::Devices::Usb::UsbDeviceDescriptor> : winrt::impl::hash_base<winrt::Windows::Devices::Usb::UsbDeviceDescriptor> {};
template<> struct hash<winrt::Windows::Devices::Usb::UsbEndpointDescriptor> : winrt::impl::hash_base<winrt::Windows::Devices::Usb::UsbEndpointDescriptor> {};
template<> struct hash<winrt::Windows::Devices::Usb::UsbInterface> : winrt::impl::hash_base<winrt::Windows::Devices::Usb::UsbInterface> {};
template<> struct hash<winrt::Windows::Devices::Usb::UsbInterfaceDescriptor> : winrt::impl::hash_base<winrt::Windows::Devices::Usb::UsbInterfaceDescriptor> {};
template<> struct hash<winrt::Windows::Devices::Usb::UsbInterfaceSetting> : winrt::impl::hash_base<winrt::Windows::Devices::Usb::UsbInterfaceSetting> {};
template<> struct hash<winrt::Windows::Devices::Usb::UsbInterruptInEndpointDescriptor> : winrt::impl::hash_base<winrt::Windows::Devices::Usb::UsbInterruptInEndpointDescriptor> {};
template<> struct hash<winrt::Windows::Devices::Usb::UsbInterruptInEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Usb::UsbInterruptInEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Usb::UsbInterruptInPipe> : winrt::impl::hash_base<winrt::Windows::Devices::Usb::UsbInterruptInPipe> {};
template<> struct hash<winrt::Windows::Devices::Usb::UsbInterruptOutEndpointDescriptor> : winrt::impl::hash_base<winrt::Windows::Devices::Usb::UsbInterruptOutEndpointDescriptor> {};
template<> struct hash<winrt::Windows::Devices::Usb::UsbInterruptOutPipe> : winrt::impl::hash_base<winrt::Windows::Devices::Usb::UsbInterruptOutPipe> {};
template<> struct hash<winrt::Windows::Devices::Usb::UsbSetupPacket> : winrt::impl::hash_base<winrt::Windows::Devices::Usb::UsbSetupPacket> {};

}
