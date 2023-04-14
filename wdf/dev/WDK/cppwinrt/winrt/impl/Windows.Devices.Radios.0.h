// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

WINRT_EXPORT namespace winrt::Windows::Devices::Radios {

enum class RadioAccessStatus : int32_t
{
    Unspecified = 0,
    Allowed = 1,
    DeniedByUser = 2,
    DeniedBySystem = 3,
};

enum class RadioKind : int32_t
{
    Other = 0,
    WiFi = 1,
    MobileBroadband = 2,
    Bluetooth = 3,
    FM = 4,
};

enum class RadioState : int32_t
{
    Unknown = 0,
    On = 1,
    Off = 2,
    Disabled = 3,
};

struct IRadio;
struct IRadioStatics;
struct Radio;

}

namespace winrt::impl {

template <> struct category<Windows::Devices::Radios::IRadio>{ using type = interface_category; };
template <> struct category<Windows::Devices::Radios::IRadioStatics>{ using type = interface_category; };
template <> struct category<Windows::Devices::Radios::Radio>{ using type = class_category; };
template <> struct category<Windows::Devices::Radios::RadioAccessStatus>{ using type = enum_category; };
template <> struct category<Windows::Devices::Radios::RadioKind>{ using type = enum_category; };
template <> struct category<Windows::Devices::Radios::RadioState>{ using type = enum_category; };
template <> struct name<Windows::Devices::Radios::IRadio>{ static constexpr auto & value{ L"Windows.Devices.Radios.IRadio" }; };
template <> struct name<Windows::Devices::Radios::IRadioStatics>{ static constexpr auto & value{ L"Windows.Devices.Radios.IRadioStatics" }; };
template <> struct name<Windows::Devices::Radios::Radio>{ static constexpr auto & value{ L"Windows.Devices.Radios.Radio" }; };
template <> struct name<Windows::Devices::Radios::RadioAccessStatus>{ static constexpr auto & value{ L"Windows.Devices.Radios.RadioAccessStatus" }; };
template <> struct name<Windows::Devices::Radios::RadioKind>{ static constexpr auto & value{ L"Windows.Devices.Radios.RadioKind" }; };
template <> struct name<Windows::Devices::Radios::RadioState>{ static constexpr auto & value{ L"Windows.Devices.Radios.RadioState" }; };
template <> struct guid_storage<Windows::Devices::Radios::IRadio>{ static constexpr guid value{ 0x252118DF,0xB33E,0x416A,{ 0x87,0x5F,0x1C,0xF3,0x8A,0xE2,0xD8,0x3E } }; };
template <> struct guid_storage<Windows::Devices::Radios::IRadioStatics>{ static constexpr guid value{ 0x5FB6A12E,0x67CB,0x46AE,{ 0xAA,0xE9,0x65,0x91,0x9F,0x86,0xEF,0xF4 } }; };
template <> struct default_interface<Windows::Devices::Radios::Radio>{ using type = Windows::Devices::Radios::IRadio; };

template <> struct abi<Windows::Devices::Radios::IRadio>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL SetStateAsync(Windows::Devices::Radios::RadioState value, void** retval) noexcept = 0;
    virtual int32_t WINRT_CALL add_StateChanged(void* handler, winrt::event_token* eventCookie) noexcept = 0;
    virtual int32_t WINRT_CALL remove_StateChanged(winrt::event_token eventCookie) noexcept = 0;
    virtual int32_t WINRT_CALL get_State(Windows::Devices::Radios::RadioState* value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Name(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL get_Kind(Windows::Devices::Radios::RadioKind* value) noexcept = 0;
};};

template <> struct abi<Windows::Devices::Radios::IRadioStatics>{ struct type : IInspectable
{
    virtual int32_t WINRT_CALL GetRadiosAsync(void** value) noexcept = 0;
    virtual int32_t WINRT_CALL GetDeviceSelector(void** deviceSelector) noexcept = 0;
    virtual int32_t WINRT_CALL FromIdAsync(void* deviceId, void** value) noexcept = 0;
    virtual int32_t WINRT_CALL RequestAccessAsync(void** value) noexcept = 0;
};};

template <typename D>
struct consume_Windows_Devices_Radios_IRadio
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Radios::RadioAccessStatus> SetStateAsync(Windows::Devices::Radios::RadioState const& value) const;
    winrt::event_token StateChanged(Windows::Foundation::TypedEventHandler<Windows::Devices::Radios::Radio, Windows::Foundation::IInspectable> const& handler) const;
    using StateChanged_revoker = impl::event_revoker<Windows::Devices::Radios::IRadio, &impl::abi_t<Windows::Devices::Radios::IRadio>::remove_StateChanged>;
    StateChanged_revoker StateChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Radios::Radio, Windows::Foundation::IInspectable> const& handler) const;
    void StateChanged(winrt::event_token const& eventCookie) const noexcept;
    Windows::Devices::Radios::RadioState State() const;
    hstring Name() const;
    Windows::Devices::Radios::RadioKind Kind() const;
};
template <> struct consume<Windows::Devices::Radios::IRadio> { template <typename D> using type = consume_Windows_Devices_Radios_IRadio<D>; };

template <typename D>
struct consume_Windows_Devices_Radios_IRadioStatics
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::Radios::Radio>> GetRadiosAsync() const;
    hstring GetDeviceSelector() const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::Radios::Radio> FromIdAsync(param::hstring const& deviceId) const;
    Windows::Foundation::IAsyncOperation<Windows::Devices::Radios::RadioAccessStatus> RequestAccessAsync() const;
};
template <> struct consume<Windows::Devices::Radios::IRadioStatics> { template <typename D> using type = consume_Windows_Devices_Radios_IRadioStatics<D>; };

}
