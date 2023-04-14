// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Storage::Streams {

struct IInputStream;
struct IOutputStream;

}

WINRT_EXPORT namespace winrt::Windows::Devices::SerialCommunication {

enum class SerialError : int32_t
{
    Frame = 0,
    BufferOverrun = 1,
    ReceiveFull = 2,
    ReceiveParity = 3,
    TransmitFull = 4,
};

enum class SerialHandshake : int32_t
{
    None = 0,
    RequestToSend = 1,
    XOnXOff = 2,
    RequestToSendXOnXOff = 3,
};

enum class SerialParity : int32_t
{
    None = 0,
    Odd = 1,
    Even = 2,
    Mark = 3,
    Space = 4,
};

enum class SerialPinChange : int32_t
{
    BreakSignal = 0,
    CarrierDetect = 1,
    ClearToSend = 2,
    DataSetReady = 3,
    RingIndicator = 4,
};

enum class SerialStopBitCount : int32_t
{
    One = 0,
    OnePointFive = 1,
    Two = 2,
};

struct IErrorReceivedEventArgs;
struct IPinChangedEventArgs;
struct ISerialDevice;
struct ISerialDeviceStatics;
struct ErrorReceivedEventArgs;
struct PinChangedEventArgs;
struct SerialDevice;

}

namespace winrt::impl {

template <> struct category<Windows::Devices::SerialCommunication::IErrorReceivedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Devices::SerialCommunication::IPinChangedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Devices::SerialCommunication::ISerialDevice>{ using type = interface_category; };
template <> struct category<Windows::Devices::SerialCommunication::ISerialDeviceStatics>{ using type = interface_category; };
template <> struct category<Windows::Devices::SerialCommunication::ErrorReceivedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Devices::SerialCommunication::PinChangedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Devices::SerialCommunication::SerialDevice>{ using type = class_category; };
template <> struct category<Windows::Devices::SerialCommunication::SerialError>{ using type = enum_category; };
template <> struct category<Windows::Devices::SerialCommunication::SerialHandshake>{ using type = enum_category; };
template <> struct category<Windows::Devices::SerialCommunication::SerialParity>{ using type = enum_category; };
template <> struct category<Windows::Devices::SerialCommunication::SerialPinChange>{ using type = enum_category; };
template <> struct category<Windows::Devices::SerialCommunication::SerialStopBitCount>{ using type = enum_category; };
template <> struct name<Windows::Devices::SerialCommunication::IErrorReceivedEventArgs>{ static constexpr auto & value{ L"Windows.Devices.SerialCommunication.IErrorReceivedEventArgs" }; };
template <> struct name<Windows::Devices::SerialCommunication::IPinChangedEventArgs>{ static constexpr auto & value{ L"Windows.Devices.SerialCommunication.IPinChangedEventArgs" }; };
template <> struct name<Windows::Devices::SerialCommunication::ISerialDevice>{ static constexpr auto & value{ L"Windows.Devices.SerialCommunication.ISerialDevice" }; };
template <> struct name<Windows::Devices::SerialCommunication::ISerialDeviceStatics>{ static constexpr auto & value{ L"Windows.Devices.SerialCommunication.ISerialDeviceStatics" }; };
template <> struct name<Windows::Devices::SerialCommunication::ErrorReceivedEventArgs>{ static constexpr auto & value{ L"Windows.Devices.SerialCommunication.ErrorReceivedEventArgs" }; };
template <> struct name<Windows::Devices::SerialCommunication::PinChangedEventArgs>{ static constexpr auto & value{ L"Windows.Devices.SerialCommunication.PinChangedEventArgs" }; };
template <> struct name<Windows::Devices::SerialCommunication::SerialDevice>{ static constexpr auto & value{ L"Windows.Devices.SerialCommunication.SerialDevice" }; };
template <> struct name<Windows::Devices::SerialCommunication::SerialError>{ static constexpr auto & value{ L"Windows.Devices.SerialCommunication.SerialError" }; };
template <> struct name<Windows::Devices::SerialCommunication::SerialHandshake>{ static constexpr auto & value{ L"Windows.Devices.SerialCommunication.SerialHandshake" }; };
template <> struct name<Windows::Devices::SerialCommunication::SerialParity>{ static constexpr auto & value{ L"Windows.Devices.SerialCommunication.SerialParity" }; };
template <> struct name<Windows::Devices::SerialCommunication::SerialPinChange>{ static constexpr auto & value{ L"Windows.Devices.SerialCommunication.SerialPinChange" }; };
template <> struct name<Windows::Devices::SerialCommunication::SerialStopBitCount>{ static constexpr auto & value{ L"Windows.Devices.SerialCommunication.SerialStopBitCount" }; };
template <> struct guid_storage<Windows::Devices::SerialCommunication::IErrorReceivedEventArgs>{ static constexpr guid value{ 0xFCC6BF59,0x1283,0x4D8A,{ 0xBF,0xDF,0x56,0x6B,0x33,0xDD,0xB2,0x8F } }; };
template <> struct guid_storage<Windows::Devices::SerialCommunication::IPinChangedEventArgs>{ static constexpr guid value{ 0xA2BF1DB0,0xFC9C,0x4607,{ 0x93,0xD0,0xFA,0x5E,0x83,0x43,0xEE,0x22 } }; };
template <> struct guid_storage<Windows::Devices::SerialCommunication::ISerialDevice>{ static constexpr guid value{ 0xE187CCC6,0x2210,0x414F,{ 0xB6,0x5A,0xF5,0x55,0x3A,0x03,0x37,0x2A } }; };
template <> struct guid_storage<Windows::Devices::SerialCommunication::ISerialDeviceStatics>{ static constexpr guid value{ 0x058C4A70,0x0836,0x4993,{ 0xAE,0x1A,0xB6,0x1A,0xE3,0xBE,0x05,0x6B } }; };
template <> struct default_interface<Windows::Devices::SerialCommunication::ErrorReceivedEventArgs>{ using type = Windows::Devices::SerialCommunication::IErrorReceivedEventArgs; };
template <> struct default_interface<Windows::Devices::SerialCommunication::PinChangedEventArgs>{ using type = Windows::Devices::SerialCommunication::IPinChangedEventArgs; };
template <> struct default_interface<Windows::Devices::SerialCommunication::SerialDevice>{ using type = Windows::Devices::SerialCommunication::ISerialDevice; };

template <> struct abi<Windows::Devices::SerialCommunication::IErrorReceivedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Error(Windows::Devices::SerialCommunication::SerialError* value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::SerialCommunication::IPinChangedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_PinChange(Windows::Devices::SerialCommunication::SerialPinChange* value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::SerialCommunication::ISerialDevice>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_BaudRate(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_BaudRate(uint32_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BreakSignalState(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_BreakSignalState(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BytesReceived(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_CarrierDetectState(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ClearToSendState(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DataBits(uint16_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_DataBits(uint16_t value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DataSetReadyState(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Handshake(Windows::Devices::SerialCommunication::SerialHandshake* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Handshake(Windows::Devices::SerialCommunication::SerialHandshake value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsDataTerminalReadyEnabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IsDataTerminalReadyEnabled(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsRequestToSendEnabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IsRequestToSendEnabled(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Parity(Windows::Devices::SerialCommunication::SerialParity* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Parity(Windows::Devices::SerialCommunication::SerialParity value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PortName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ReadTimeout(Windows::Foundation::TimeSpan* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_ReadTimeout(Windows::Foundation::TimeSpan value) noexcept = 0;
    virtual int32_t WINRT_CALL get_StopBits(Windows::Devices::SerialCommunication::SerialStopBitCount* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_StopBits(Windows::Devices::SerialCommunication::SerialStopBitCount value) noexcept = 0;
    virtual int32_t WINRT_CALL get_UsbVendorId(uint16_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_UsbProductId(uint16_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_WriteTimeout(Windows::Foundation::TimeSpan* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_WriteTimeout(Windows::Foundation::TimeSpan value) noexcept = 0;
    virtual int32_t WINRT_CALL get_InputStream(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_OutputStream(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL add_ErrorReceived(void* reportHandler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_ErrorReceived(winrt::event_token token) noexcept = 0;
    virtual int32_t WINRT_CALL add_PinChanged(void* reportHandler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_PinChanged(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::Devices::SerialCommunication::ISerialDeviceStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetDeviceSelector(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetDeviceSelectorFromPortName(void* portName, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL GetDeviceSelectorFromUsbVidPid(uint16_t vendorId, uint16_t productId, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL FromIdAsync(void* deviceId, void** result) noexcept = 0;
};};

template <typename D>
struct consume_Windows_Devices_SerialCommunication_IErrorReceivedEventArgs
{
    Windows::Devices::SerialCommunication::SerialError Error() const;
};
template <> struct consume<Windows::Devices::SerialCommunication::IErrorReceivedEventArgs> { template <typename D> using type = consume_Windows_Devices_SerialCommunication_IErrorReceivedEventArgs<D>; };

template <typename D>
struct consume_Windows_Devices_SerialCommunication_IPinChangedEventArgs
{
    Windows::Devices::SerialCommunication::SerialPinChange PinChange() const;
};
template <> struct consume<Windows::Devices::SerialCommunication::IPinChangedEventArgs> { template <typename D> using type = consume_Windows_Devices_SerialCommunication_IPinChangedEventArgs<D>; };

template <typename D>
struct consume_Windows_Devices_SerialCommunication_ISerialDevice
{
    uint32_t BaudRate() const;
    void BaudRate(uint32_t value) const;
    bool BreakSignalState() const;
    void BreakSignalState(bool value) const;
    uint32_t BytesReceived() const;
    bool CarrierDetectState() const;
    bool ClearToSendState() const;
    uint16_t DataBits() const;
    void DataBits(uint16_t value) const;
    bool DataSetReadyState() const;
    Windows::Devices::SerialCommunication::SerialHandshake Handshake() const;
    void Handshake(Windows::Devices::SerialCommunication::SerialHandshake const& value) const;
    bool IsDataTerminalReadyEnabled() const;
    void IsDataTerminalReadyEnabled(bool value) const;
    bool IsRequestToSendEnabled() const;
    void IsRequestToSendEnabled(bool value) const;
    Windows::Devices::SerialCommunication::SerialParity Parity() const;
    void Parity(Windows::Devices::SerialCommunication::SerialParity const& value) const;
    hstring PortName() const;
    Windows::Foundation::TimeSpan ReadTimeout() const;
    void ReadTimeout(Windows::Foundation::TimeSpan const& value) const;
    Windows::Devices::SerialCommunication::SerialStopBitCount StopBits() const;
    void StopBits(Windows::Devices::SerialCommunication::SerialStopBitCount const& value) const;
    uint16_t UsbVendorId() const;
    uint16_t UsbProductId() const;
    Windows::Foundation::TimeSpan WriteTimeout() const;
    void WriteTimeout(Windows::Foundation::TimeSpan const& value) const;
    Windows::Storage::Streams::IInputStream InputStream() const;
    Windows::Storage::Streams::IOutputStream OutputStream() const;
    winrt::event_token ErrorReceived(Windows::Foundation::TypedEventHandler<Windows::Devices::SerialCommunication::SerialDevice, Windows::Devices::SerialCommunication::ErrorReceivedEventArgs> const& reportHandler) const;
    using ErrorReceived_revoker = impl::event_revoker<Windows::Devices::SerialCommunication::ISerialDevice, &impl::abi_t<Windows::Devices::SerialCommunication::ISerialDevice>::remove_ErrorReceived>;
    ErrorReceived_revoker ErrorReceived(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::SerialCommunication::SerialDevice, Windows::Devices::SerialCommunication::ErrorReceivedEventArgs> const& reportHandler) const;
    void ErrorReceived(winrt::event_token const& token) const noexcept;
    winrt::event_token PinChanged(Windows::Foundation::TypedEventHandler<Windows::Devices::SerialCommunication::SerialDevice, Windows::Devices::SerialCommunication::PinChangedEventArgs> const& reportHandler) const;
    using PinChanged_revoker = impl::event_revoker<Windows::Devices::SerialCommunication::ISerialDevice, &impl::abi_t<Windows::Devices::SerialCommunication::ISerialDevice>::remove_PinChanged>;
    PinChanged_revoker PinChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::SerialCommunication::SerialDevice, Windows::Devices::SerialCommunication::PinChangedEventArgs> const& reportHandler) const;
    void PinChanged(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::Devices::SerialCommunication::ISerialDevice> { template <typename D> using type = consume_Windows_Devices_SerialCommunication_ISerialDevice<D>; };

template <typename D>
struct consume_Windows_Devices_SerialCommunication_ISerialDeviceStatics
{
    hstring GetDeviceSelector() const;
    hstring GetDeviceSelector(param::hstring const& portName) const;
    hstring GetDeviceSelectorFromUsbVidPid(uint16_t vendorId, uint16_t productId) const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::SerialCommunication::SerialDevice> FromIdAsync(param::hstring const& deviceId) const;
};
template <> struct consume<Windows::Devices::SerialCommunication::ISerialDeviceStatics> { template <typename D> using type = consume_Windows_Devices_SerialCommunication_ISerialDeviceStatics<D>; };

}
