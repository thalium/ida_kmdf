// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Graphics {

struct DisplayAdapterId;
struct SizeInt32;

}

WINRT_EXPORT namespace winrt::Windows::Devices::Display {

enum class DisplayMonitorConnectionKind : int32_t
{
    Internal = 0,
    Wired = 1,
    Wireless = 2,
    Virtual = 3,
};

enum class DisplayMonitorDescriptorKind : int32_t
{
    Edid = 0,
    DisplayId = 1,
};

enum class DisplayMonitorPhysicalConnectorKind : int32_t
{
    Unknown = 0,
    HD15 = 1,
    AnalogTV = 2,
    Dvi = 3,
    Hdmi = 4,
    Lvds = 5,
    Sdi = 6,
    DisplayPort = 7,
};

enum class DisplayMonitorUsageKind : int32_t
{
    Standard = 0,
    HeadMounted = 1,
    SpecialPurpose = 2,
};

struct IDisplayMonitor;
struct IDisplayMonitorStatics;
struct DisplayMonitor;

}

namespace winrt::impl {

template <> struct category<Windows::Devices::Display::IDisplayMonitor>{ using type = interface_category; };
template <> struct category<Windows::Devices::Display::IDisplayMonitorStatics>{ using type = interface_category; };
template <> struct category<Windows::Devices::Display::DisplayMonitor>{ using type = class_category; };
template <> struct category<Windows::Devices::Display::DisplayMonitorConnectionKind>{ using type = enum_category; };
template <> struct category<Windows::Devices::Display::DisplayMonitorDescriptorKind>{ using type = enum_category; };
template <> struct category<Windows::Devices::Display::DisplayMonitorPhysicalConnectorKind>{ using type = enum_category; };
template <> struct category<Windows::Devices::Display::DisplayMonitorUsageKind>{ using type = enum_category; };
template <> struct name<Windows::Devices::Display::IDisplayMonitor>{ static constexpr auto & value{ L"Windows.Devices.Display.IDisplayMonitor" }; };
template <> struct name<Windows::Devices::Display::IDisplayMonitorStatics>{ static constexpr auto & value{ L"Windows.Devices.Display.IDisplayMonitorStatics" }; };
template <> struct name<Windows::Devices::Display::DisplayMonitor>{ static constexpr auto & value{ L"Windows.Devices.Display.DisplayMonitor" }; };
template <> struct name<Windows::Devices::Display::DisplayMonitorConnectionKind>{ static constexpr auto & value{ L"Windows.Devices.Display.DisplayMonitorConnectionKind" }; };
template <> struct name<Windows::Devices::Display::DisplayMonitorDescriptorKind>{ static constexpr auto & value{ L"Windows.Devices.Display.DisplayMonitorDescriptorKind" }; };
template <> struct name<Windows::Devices::Display::DisplayMonitorPhysicalConnectorKind>{ static constexpr auto & value{ L"Windows.Devices.Display.DisplayMonitorPhysicalConnectorKind" }; };
template <> struct name<Windows::Devices::Display::DisplayMonitorUsageKind>{ static constexpr auto & value{ L"Windows.Devices.Display.DisplayMonitorUsageKind" }; };
template <> struct guid_storage<Windows::Devices::Display::IDisplayMonitor>{ static constexpr guid value{ 0x1F6B15D4,0x1D01,0x4C51,{ 0x87,0xE2,0x6F,0x95,0x4A,0x77,0x2B,0x59 } }; };
template <> struct guid_storage<Windows::Devices::Display::IDisplayMonitorStatics>{ static constexpr guid value{ 0x6EAE698F,0xA228,0x4C05,{ 0x82,0x1D,0xB6,0x95,0xD6,0x67,0xDE,0x8E } }; };
template <> struct default_interface<Windows::Devices::Display::DisplayMonitor>{ using type = Windows::Devices::Display::IDisplayMonitor; };

template <> struct abi<Windows::Devices::Display::IDisplayMonitor>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_DeviceId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DisplayName(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_ConnectionKind(Windows::Devices::Display::DisplayMonitorConnectionKind* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PhysicalConnector(Windows::Devices::Display::DisplayMonitorPhysicalConnectorKind* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DisplayAdapterDeviceId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DisplayAdapterId(struct struct_Windows_Graphics_DisplayAdapterId* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_DisplayAdapterTargetId(uint32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_UsageKind(Windows::Devices::Display::DisplayMonitorUsageKind* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_NativeResolutionInRawPixels(struct struct_Windows_Graphics_SizeInt32* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_PhysicalSizeInInches(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RawDpiX(float* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RawDpiY(float* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RedPrimary(Windows::Foundation::Point* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_GreenPrimary(Windows::Foundation::Point* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BluePrimary(Windows::Foundation::Point* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_WhitePoint(Windows::Foundation::Point* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MaxLuminanceInNits(float* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MinLuminanceInNits(float* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MaxAverageFullFrameLuminanceInNits(float* value) noexcept = 0;
    virtual int32_t WINRT_CALL GetDescriptor(Windows::Devices::Display::DisplayMonitorDescriptorKind descriptorKind, uint32_t* __resultSize, uint8_t** result) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Display::IDisplayMonitorStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetDeviceSelector(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL FromIdAsync(void* deviceId, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL FromInterfaceIdAsync(void* deviceInterfaceId, void** operation) noexcept = 0;
};};

template <typename D>
struct consume_Windows_Devices_Display_IDisplayMonitor
{
    hstring DeviceId() const;
    hstring DisplayName() const;
    Windows::Devices::Display::DisplayMonitorConnectionKind ConnectionKind() const;
    Windows::Devices::Display::DisplayMonitorPhysicalConnectorKind PhysicalConnector() const;
    hstring DisplayAdapterDeviceId() const;
    Windows::Graphics::DisplayAdapterId DisplayAdapterId() const;
    uint32_t DisplayAdapterTargetId() const;
    Windows::Devices::Display::DisplayMonitorUsageKind UsageKind() const;
    Windows::Graphics::SizeInt32 NativeResolutionInRawPixels() const;
    Windows::Foundation::IReference<Windows::Foundation::Size> PhysicalSizeInInches() const;
    float RawDpiX() const;
    float RawDpiY() const;
    Windows::Foundation::Point RedPrimary() const;
    Windows::Foundation::Point GreenPrimary() const;
    Windows::Foundation::Point BluePrimary() const;
    Windows::Foundation::Point WhitePoint() const;
    float MaxLuminanceInNits() const;
    float MinLuminanceInNits() const;
    float MaxAverageFullFrameLuminanceInNits() const;
    com_array<uint8_t> GetDescriptor(Windows::Devices::Display::DisplayMonitorDescriptorKind const& descriptorKind) const;
};
template <> struct consume<Windows::Devices::Display::IDisplayMonitor> { template <typename D> using type = consume_Windows_Devices_Display_IDisplayMonitor<D>; };

template <typename D>
struct consume_Windows_Devices_Display_IDisplayMonitorStatics
{
    hstring GetDeviceSelector() const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::Display::DisplayMonitor> FromIdAsync(param::hstring const& deviceId) const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::Display::DisplayMonitor> FromInterfaceIdAsync(param::hstring const& deviceInterfaceId) const;
};
template <> struct consume<Windows::Devices::Display::IDisplayMonitorStatics> { template <typename D> using type = consume_Windows_Devices_Display_IDisplayMonitorStatics<D>; };

}
