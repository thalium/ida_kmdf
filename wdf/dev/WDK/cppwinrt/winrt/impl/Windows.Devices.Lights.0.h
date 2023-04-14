// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Storage::Streams {

struct IBuffer;

}

WINRT_EXPORT namespace winrt::Windows::System {

enum class VirtualKey;

}

WINRT_EXPORT namespace winrt::Windows::UI {

struct Color;

}

WINRT_EXPORT namespace winrt::Windows::Devices::Lights {

enum class LampArrayKind : int32_t
{
    Undefined = 0,
    Keyboard = 1,
    Mouse = 2,
    GameController = 3,
    Peripheral = 4,
    Scene = 5,
    Notification = 6,
    Chassis = 7,
    Wearable = 8,
    Furniture = 9,
    Art = 10,
};

enum class LampPurposes : uint32_t
{
    Undefined = 0x0,
    Control = 0x1,
    Accent = 0x2,
    Branding = 0x4,
    Status = 0x8,
    Illumination = 0x10,
    Presentation = 0x20,
};

struct ILamp;
struct ILampArray;
struct ILampArrayStatics;
struct ILampAvailabilityChangedEventArgs;
struct ILampInfo;
struct ILampStatics;
struct Lamp;
struct LampArray;
struct LampAvailabilityChangedEventArgs;
struct LampInfo;

}

namespace winrt::impl {

template<> struct is_enum_flag<Windows::Devices::Lights::LampPurposes> : std::true_type {};
template <> struct category<Windows::Devices::Lights::ILamp>{ using type = interface_category; };
template <> struct category<Windows::Devices::Lights::ILampArray>{ using type = interface_category; };
template <> struct category<Windows::Devices::Lights::ILampArrayStatics>{ using type = interface_category; };
template <> struct category<Windows::Devices::Lights::ILampAvailabilityChangedEventArgs>{ using type = interface_category; };
template <> struct category<Windows::Devices::Lights::ILampInfo>{ using type = interface_category; };
template <> struct category<Windows::Devices::Lights::ILampStatics>{ using type = interface_category; };
template <> struct category<Windows::Devices::Lights::Lamp>{ using type = class_category; };
template <> struct category<Windows::Devices::Lights::LampArray>{ using type = class_category; };
template <> struct category<Windows::Devices::Lights::LampAvailabilityChangedEventArgs>{ using type = class_category; };
template <> struct category<Windows::Devices::Lights::LampInfo>{ using type = class_category; };
template <> struct category<Windows::Devices::Lights::LampArrayKind>{ using type = enum_category; };
template <> struct category<Windows::Devices::Lights::LampPurposes>{ using type = enum_category; };
template <> struct name<Windows::Devices::Lights::ILamp>{ static constexpr auto & value{ L"Windows.Devices.Lights.ILamp" }; };
template <> struct name<Windows::Devices::Lights::ILampArray>{ static constexpr auto & value{ L"Windows.Devices.Lights.ILampArray" }; };
template <> struct name<Windows::Devices::Lights::ILampArrayStatics>{ static constexpr auto & value{ L"Windows.Devices.Lights.ILampArrayStatics" }; };
template <> struct name<Windows::Devices::Lights::ILampAvailabilityChangedEventArgs>{ static constexpr auto & value{ L"Windows.Devices.Lights.ILampAvailabilityChangedEventArgs" }; };
template <> struct name<Windows::Devices::Lights::ILampInfo>{ static constexpr auto & value{ L"Windows.Devices.Lights.ILampInfo" }; };
template <> struct name<Windows::Devices::Lights::ILampStatics>{ static constexpr auto & value{ L"Windows.Devices.Lights.ILampStatics" }; };
template <> struct name<Windows::Devices::Lights::Lamp>{ static constexpr auto & value{ L"Windows.Devices.Lights.Lamp" }; };
template <> struct name<Windows::Devices::Lights::LampArray>{ static constexpr auto & value{ L"Windows.Devices.Lights.LampArray" }; };
template <> struct name<Windows::Devices::Lights::LampAvailabilityChangedEventArgs>{ static constexpr auto & value{ L"Windows.Devices.Lights.LampAvailabilityChangedEventArgs" }; };
template <> struct name<Windows::Devices::Lights::LampInfo>{ static constexpr auto & value{ L"Windows.Devices.Lights.LampInfo" }; };
template <> struct name<Windows::Devices::Lights::LampArrayKind>{ static constexpr auto & value{ L"Windows.Devices.Lights.LampArrayKind" }; };
template <> struct name<Windows::Devices::Lights::LampPurposes>{ static constexpr auto & value{ L"Windows.Devices.Lights.LampPurposes" }; };
template <> struct guid_storage<Windows::Devices::Lights::ILamp>{ static constexpr guid value{ 0x047D5B9A,0xEA45,0x4B2B,{ 0xB1,0xA2,0x14,0xDF,0xF0,0x0B,0xDE,0x7B } }; };
template <> struct guid_storage<Windows::Devices::Lights::ILampArray>{ static constexpr guid value{ 0x7ACE9787,0xC8A0,0x4E95,{ 0xA1,0xE0,0xD5,0x86,0x76,0x53,0x86,0x49 } }; };
template <> struct guid_storage<Windows::Devices::Lights::ILampArrayStatics>{ static constexpr guid value{ 0x7BB8C98D,0x5FC1,0x452D,{ 0xBB,0x1F,0x4A,0xD4,0x10,0xD3,0x98,0xFF } }; };
template <> struct guid_storage<Windows::Devices::Lights::ILampAvailabilityChangedEventArgs>{ static constexpr guid value{ 0x4F6E3DED,0x07A2,0x499D,{ 0x92,0x60,0x67,0xE3,0x04,0x53,0x2B,0xA4 } }; };
template <> struct guid_storage<Windows::Devices::Lights::ILampInfo>{ static constexpr guid value{ 0x30BB521C,0x0ACF,0x49DA,{ 0x8C,0x10,0x15,0x0B,0x9C,0xF6,0x27,0x13 } }; };
template <> struct guid_storage<Windows::Devices::Lights::ILampStatics>{ static constexpr guid value{ 0xA822416C,0x8885,0x401E,{ 0xB8,0x21,0x8E,0x8B,0x38,0xA8,0xE8,0xEC } }; };
template <> struct default_interface<Windows::Devices::Lights::Lamp>{ using type = Windows::Devices::Lights::ILamp; };
template <> struct default_interface<Windows::Devices::Lights::LampArray>{ using type = Windows::Devices::Lights::ILampArray; };
template <> struct default_interface<Windows::Devices::Lights::LampAvailabilityChangedEventArgs>{ using type = Windows::Devices::Lights::ILampAvailabilityChangedEventArgs; };
template <> struct default_interface<Windows::Devices::Lights::LampInfo>{ using type = Windows::Devices::Lights::ILampInfo; };

template <> struct abi<Windows::Devices::Lights::ILamp>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_DeviceId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsEnabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IsEnabled(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BrightnessLevel(float* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_BrightnessLevel(float value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsColorSettable(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Color(struct struct_Windows_UI_Color* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_Color(struct struct_Windows_UI_Color value) noexcept = 0;
    virtual int32_t WINRT_CALL add_AvailabilityChanged(void* handler, winrt::event_token* token) noexcept = 0;
    virtual int32_t WINRT_CALL remove_AvailabilityChanged(winrt::event_token token) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Lights::ILampArray>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_DeviceId(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HardwareVendorId(uint16_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HardwareProductId(uint16_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_HardwareVersion(uint16_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LampArrayKind(Windows::Devices::Lights::LampArrayKind* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_LampCount(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_MinUpdateInterval(Windows::Foundation::TimeSpan* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BoundingBox(Windows::Foundation::Numerics::float3* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsEnabled(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_IsEnabled(bool value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BrightnessLevel(double* value) noexcept = 0;
    virtual int32_t WINRT_CALL put_BrightnessLevel(double value) noexcept = 0;
    virtual int32_t WINRT_CALL get_IsConnected(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_SupportsVirtualKeys(bool* value) noexcept = 0;
    virtual int32_t WINRT_CALL GetLampInfo(int32_t lampIndex, void** result) noexcept = 0;
    virtual int32_t WINRT_CALL GetIndicesForKey(Windows::System::VirtualKey key, uint32_t* __resultSize, int32_t** result) noexcept = 0;
    virtual int32_t WINRT_CALL GetIndicesForPurposes(Windows::Devices::Lights::LampPurposes purposes, uint32_t* __resultSize, int32_t** result) noexcept = 0;
    virtual int32_t WINRT_CALL SetColor(struct struct_Windows_UI_Color desiredColor) noexcept = 0;
    virtual int32_t WINRT_CALL SetColorForIndex(int32_t lampIndex, struct struct_Windows_UI_Color desiredColor) noexcept = 0;
    virtual int32_t WINRT_CALL SetSingleColorForIndices(struct struct_Windows_UI_Color desiredColor, uint32_t __lampIndexesSize, int32_t* lampIndexes) noexcept = 0;
    virtual int32_t WINRT_CALL SetColorsForIndices(uint32_t __desiredColorsSize, struct struct_Windows_UI_Color* desiredColors, uint32_t __lampIndexesSize, int32_t* lampIndexes) noexcept = 0;
    virtual int32_t WINRT_CALL SetColorsForKey(struct struct_Windows_UI_Color desiredColor, Windows::System::VirtualKey key) noexcept = 0;
    virtual int32_t WINRT_CALL SetColorsForKeys(uint32_t __desiredColorsSize, struct struct_Windows_UI_Color* desiredColors, uint32_t __keysSize, Windows::System::VirtualKey* keys) noexcept = 0;
    virtual int32_t WINRT_CALL SetColorsForPurposes(struct struct_Windows_UI_Color desiredColor, Windows::Devices::Lights::LampPurposes purposes) noexcept = 0;
    virtual int32_t WINRT_CALL SendMessageAsync(int32_t messageId, void* message, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL RequestMessageAsync(int32_t messageId, void** operation) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Lights::ILampArrayStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetDeviceSelector(void** result) noexcept = 0;
    virtual int32_t WINRT_CALL FromIdAsync(void* deviceId, void** operation) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Lights::ILampAvailabilityChangedEventArgs>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_IsAvailable(bool* value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Lights::ILampInfo>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL get_Index(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Purposes(Windows::Devices::Lights::LampPurposes* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Position(Windows::Foundation::Numerics::float3* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_RedLevelCount(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_GreenLevelCount(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_BlueLevelCount(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_GainLevelCount(int32_t* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_FixedColor(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetNearestSupportedColor(struct struct_Windows_UI_Color desiredColor, struct struct_Windows_UI_Color* result) noexcept = 0;
    virtual int32_t WINRT_CALL get_UpdateLatency(Windows::Foundation::TimeSpan* value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Lights::ILampStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetDeviceSelector(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL FromIdAsync(void* deviceId, void** operation) noexcept = 0;
    virtual int32_t WINRT_CALL GetDefaultAsync(void** operation) noexcept = 0;
};};

template <typename D>
struct consume_Windows_Devices_Lights_ILamp
{
    hstring DeviceId() const;
    bool IsEnabled() const;
    void IsEnabled(bool value) const;
    float BrightnessLevel() const;
    void BrightnessLevel(float value) const;
    bool IsColorSettable() const;
    Windows::UI::Color Color() const;
    void Color(Windows::UI::Color const& value) const;
    winrt::event_token AvailabilityChanged(Windows::Foundation::TypedEventHandler<Windows::Devices::Lights::Lamp, Windows::Devices::Lights::LampAvailabilityChangedEventArgs> const& handler) const;
    using AvailabilityChanged_revoker = impl::event_revoker<Windows::Devices::Lights::ILamp, &impl::abi_t<Windows::Devices::Lights::ILamp>::remove_AvailabilityChanged>;
    AvailabilityChanged_revoker AvailabilityChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Lights::Lamp, Windows::Devices::Lights::LampAvailabilityChangedEventArgs> const& handler) const;
    void AvailabilityChanged(winrt::event_token const& token) const noexcept;
};
template <> struct consume<Windows::Devices::Lights::ILamp> { template <typename D> using type = consume_Windows_Devices_Lights_ILamp<D>; };

template <typename D>
struct consume_Windows_Devices_Lights_ILampArray
{
    hstring DeviceId() const;
    uint16_t HardwareVendorId() const;
    uint16_t HardwareProductId() const;
    uint16_t HardwareVersion() const;
    Windows::Devices::Lights::LampArrayKind LampArrayKind() const;
    int32_t LampCount() const;
    Windows::Foundation::TimeSpan MinUpdateInterval() const;
    Windows::Foundation::Numerics::float3 BoundingBox() const;
    bool IsEnabled() const;
    void IsEnabled(bool value) const;
    double BrightnessLevel() const;
    void BrightnessLevel(double value) const;
    bool IsConnected() const;
    bool SupportsVirtualKeys() const;
    Windows::Devices::Lights::LampInfo GetLampInfo(int32_t lampIndex) const;
    com_array<int32_t> GetIndicesForKey(Windows::System::VirtualKey const& key) const;
    com_array<int32_t> GetIndicesForPurposes(Windows::Devices::Lights::LampPurposes const& purposes) const;
    void SetColor(Windows::UI::Color const& desiredColor) const;
    void SetColorForIndex(int32_t lampIndex, Windows::UI::Color const& desiredColor) const;
    void SetSingleColorForIndices(Windows::UI::Color const& desiredColor, array_view<int32_t const> lampIndexes) const;
    void SetColorsForIndices(array_view<Windows::UI::Color const> desiredColors, array_view<int32_t const> lampIndexes) const;
    void SetColorsForKey(Windows::UI::Color const& desiredColor, Windows::System::VirtualKey const& key) const;
    void SetColorsForKeys(array_view<Windows::UI::Color const> desiredColors, array_view<Windows::System::VirtualKey const> keys) const;
    void SetColorsForPurposes(Windows::UI::Color const& desiredColor, Windows::Devices::Lights::LampPurposes const& purposes) const;
    Windows::Foundation::IAsyncAction SendMessageAsync(int32_t messageId, Windows::Storage::Streams::IBuffer const& message) const;
    Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer> RequestMessageAsync(int32_t messageId) const;
};
template <> struct consume<Windows::Devices::Lights::ILampArray> { template <typename D> using type = consume_Windows_Devices_Lights_ILampArray<D>; };

template <typename D>
struct consume_Windows_Devices_Lights_ILampArrayStatics
{
    hstring GetDeviceSelector() const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::Lights::LampArray> FromIdAsync(param::hstring const& deviceId) const;
};
template <> struct consume<Windows::Devices::Lights::ILampArrayStatics> { template <typename D> using type = consume_Windows_Devices_Lights_ILampArrayStatics<D>; };

template <typename D>
struct consume_Windows_Devices_Lights_ILampAvailabilityChangedEventArgs
{
    bool IsAvailable() const;
};
template <> struct consume<Windows::Devices::Lights::ILampAvailabilityChangedEventArgs> { template <typename D> using type = consume_Windows_Devices_Lights_ILampAvailabilityChangedEventArgs<D>; };

template <typename D>
struct consume_Windows_Devices_Lights_ILampInfo
{
    int32_t Index() const;
    Windows::Devices::Lights::LampPurposes Purposes() const;
    Windows::Foundation::Numerics::float3 Position() const;
    int32_t RedLevelCount() const;
    int32_t GreenLevelCount() const;
    int32_t BlueLevelCount() const;
    int32_t GainLevelCount() const;
    Windows::Foundation::IReference<Windows::UI::Color> FixedColor() const;
    Windows::UI::Color GetNearestSupportedColor(Windows::UI::Color const& desiredColor) const;
    Windows::Foundation::TimeSpan UpdateLatency() const;
};
template <> struct consume<Windows::Devices::Lights::ILampInfo> { template <typename D> using type = consume_Windows_Devices_Lights_ILampInfo<D>; };

template <typename D>
struct consume_Windows_Devices_Lights_ILampStatics
{
    hstring GetDeviceSelector() const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::Lights::Lamp> FromIdAsync(param::hstring const& deviceId) const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::Lights::Lamp> GetDefaultAsync() const;
};
template <> struct consume<Windows::Devices::Lights::ILampStatics> { template <typename D> using type = consume_Windows_Devices_Lights_ILampStatics<D>; };

}
