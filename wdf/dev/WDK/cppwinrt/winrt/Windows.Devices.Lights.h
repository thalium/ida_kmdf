// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.UI.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Devices.Lights.2.h"
#include "winrt/Windows.Devices.h"

namespace winrt::impl {

template <typename D> hstring consume_Windows_Devices_Lights_ILamp<D>::DeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::ILamp)->get_DeviceId(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Devices_Lights_ILamp<D>::IsEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::ILamp)->get_IsEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_Lights_ILamp<D>::IsEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::ILamp)->put_IsEnabled(value));
}

template <typename D> float consume_Windows_Devices_Lights_ILamp<D>::BrightnessLevel() const
{
    float value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::ILamp)->get_BrightnessLevel(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_Lights_ILamp<D>::BrightnessLevel(float value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::ILamp)->put_BrightnessLevel(value));
}

template <typename D> bool consume_Windows_Devices_Lights_ILamp<D>::IsColorSettable() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::ILamp)->get_IsColorSettable(&value));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_Devices_Lights_ILamp<D>::Color() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::ILamp)->get_Color(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Lights_ILamp<D>::Color(Windows::UI::Color const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::ILamp)->put_Color(get_abi(value)));
}

template <typename D> winrt::event_token consume_Windows_Devices_Lights_ILamp<D>::AvailabilityChanged(Windows::Foundation::TypedEventHandler<Windows::Devices::Lights::Lamp, Windows::Devices::Lights::LampAvailabilityChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::ILamp)->add_AvailabilityChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Lights_ILamp<D>::AvailabilityChanged_revoker consume_Windows_Devices_Lights_ILamp<D>::AvailabilityChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Lights::Lamp, Windows::Devices::Lights::LampAvailabilityChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, AvailabilityChanged_revoker>(this, AvailabilityChanged(handler));
}

template <typename D> void consume_Windows_Devices_Lights_ILamp<D>::AvailabilityChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Lights::ILamp)->remove_AvailabilityChanged(get_abi(token)));
}

template <typename D> hstring consume_Windows_Devices_Lights_ILampArray<D>::DeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::ILampArray)->get_DeviceId(put_abi(value)));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_Lights_ILampArray<D>::HardwareVendorId() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::ILampArray)->get_HardwareVendorId(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_Lights_ILampArray<D>::HardwareProductId() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::ILampArray)->get_HardwareProductId(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Devices_Lights_ILampArray<D>::HardwareVersion() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::ILampArray)->get_HardwareVersion(&value));
    return value;
}

template <typename D> Windows::Devices::Lights::LampArrayKind consume_Windows_Devices_Lights_ILampArray<D>::LampArrayKind() const
{
    Windows::Devices::Lights::LampArrayKind value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::ILampArray)->get_LampArrayKind(put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_Devices_Lights_ILampArray<D>::LampCount() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::ILampArray)->get_LampCount(&value));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Devices_Lights_ILampArray<D>::MinUpdateInterval() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::ILampArray)->get_MinUpdateInterval(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Numerics::float3 consume_Windows_Devices_Lights_ILampArray<D>::BoundingBox() const
{
    Windows::Foundation::Numerics::float3 value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::ILampArray)->get_BoundingBox(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Devices_Lights_ILampArray<D>::IsEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::ILampArray)->get_IsEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_Lights_ILampArray<D>::IsEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::ILampArray)->put_IsEnabled(value));
}

template <typename D> double consume_Windows_Devices_Lights_ILampArray<D>::BrightnessLevel() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::ILampArray)->get_BrightnessLevel(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_Lights_ILampArray<D>::BrightnessLevel(double value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::ILampArray)->put_BrightnessLevel(value));
}

template <typename D> bool consume_Windows_Devices_Lights_ILampArray<D>::IsConnected() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::ILampArray)->get_IsConnected(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_Lights_ILampArray<D>::SupportsVirtualKeys() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::ILampArray)->get_SupportsVirtualKeys(&value));
    return value;
}

template <typename D> Windows::Devices::Lights::LampInfo consume_Windows_Devices_Lights_ILampArray<D>::GetLampInfo(int32_t lampIndex) const
{
    Windows::Devices::Lights::LampInfo result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::ILampArray)->GetLampInfo(lampIndex, put_abi(result)));
    return result;
}

template <typename D> com_array<int32_t> consume_Windows_Devices_Lights_ILampArray<D>::GetIndicesForKey(Windows::System::VirtualKey const& key) const
{
    com_array<int32_t> result;
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::ILampArray)->GetIndicesForKey(get_abi(key), impl::put_size_abi(result), put_abi(result)));
    return result;
}

template <typename D> com_array<int32_t> consume_Windows_Devices_Lights_ILampArray<D>::GetIndicesForPurposes(Windows::Devices::Lights::LampPurposes const& purposes) const
{
    com_array<int32_t> result;
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::ILampArray)->GetIndicesForPurposes(get_abi(purposes), impl::put_size_abi(result), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_Devices_Lights_ILampArray<D>::SetColor(Windows::UI::Color const& desiredColor) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::ILampArray)->SetColor(get_abi(desiredColor)));
}

template <typename D> void consume_Windows_Devices_Lights_ILampArray<D>::SetColorForIndex(int32_t lampIndex, Windows::UI::Color const& desiredColor) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::ILampArray)->SetColorForIndex(lampIndex, get_abi(desiredColor)));
}

template <typename D> void consume_Windows_Devices_Lights_ILampArray<D>::SetSingleColorForIndices(Windows::UI::Color const& desiredColor, array_view<int32_t const> lampIndexes) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::ILampArray)->SetSingleColorForIndices(get_abi(desiredColor), lampIndexes.size(), get_abi(lampIndexes)));
}

template <typename D> void consume_Windows_Devices_Lights_ILampArray<D>::SetColorsForIndices(array_view<Windows::UI::Color const> desiredColors, array_view<int32_t const> lampIndexes) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::ILampArray)->SetColorsForIndices(desiredColors.size(), get_abi(desiredColors), lampIndexes.size(), get_abi(lampIndexes)));
}

template <typename D> void consume_Windows_Devices_Lights_ILampArray<D>::SetColorsForKey(Windows::UI::Color const& desiredColor, Windows::System::VirtualKey const& key) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::ILampArray)->SetColorsForKey(get_abi(desiredColor), get_abi(key)));
}

template <typename D> void consume_Windows_Devices_Lights_ILampArray<D>::SetColorsForKeys(array_view<Windows::UI::Color const> desiredColors, array_view<Windows::System::VirtualKey const> keys) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::ILampArray)->SetColorsForKeys(desiredColors.size(), get_abi(desiredColors), keys.size(), get_abi(keys)));
}

template <typename D> void consume_Windows_Devices_Lights_ILampArray<D>::SetColorsForPurposes(Windows::UI::Color const& desiredColor, Windows::Devices::Lights::LampPurposes const& purposes) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::ILampArray)->SetColorsForPurposes(get_abi(desiredColor), get_abi(purposes)));
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Devices_Lights_ILampArray<D>::SendMessageAsync(int32_t messageId, Windows::Storage::Streams::IBuffer const& message) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::ILampArray)->SendMessageAsync(messageId, get_abi(message), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer> consume_Windows_Devices_Lights_ILampArray<D>::RequestMessageAsync(int32_t messageId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::ILampArray)->RequestMessageAsync(messageId, put_abi(operation)));
    return operation;
}

template <typename D> hstring consume_Windows_Devices_Lights_ILampArrayStatics<D>::GetDeviceSelector() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::ILampArrayStatics)->GetDeviceSelector(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Lights::LampArray> consume_Windows_Devices_Lights_ILampArrayStatics<D>::FromIdAsync(param::hstring const& deviceId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Lights::LampArray> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::ILampArrayStatics)->FromIdAsync(get_abi(deviceId), put_abi(operation)));
    return operation;
}

template <typename D> bool consume_Windows_Devices_Lights_ILampAvailabilityChangedEventArgs<D>::IsAvailable() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::ILampAvailabilityChangedEventArgs)->get_IsAvailable(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Devices_Lights_ILampInfo<D>::Index() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::ILampInfo)->get_Index(&value));
    return value;
}

template <typename D> Windows::Devices::Lights::LampPurposes consume_Windows_Devices_Lights_ILampInfo<D>::Purposes() const
{
    Windows::Devices::Lights::LampPurposes value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::ILampInfo)->get_Purposes(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Numerics::float3 consume_Windows_Devices_Lights_ILampInfo<D>::Position() const
{
    Windows::Foundation::Numerics::float3 value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::ILampInfo)->get_Position(put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_Devices_Lights_ILampInfo<D>::RedLevelCount() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::ILampInfo)->get_RedLevelCount(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Devices_Lights_ILampInfo<D>::GreenLevelCount() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::ILampInfo)->get_GreenLevelCount(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Devices_Lights_ILampInfo<D>::BlueLevelCount() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::ILampInfo)->get_BlueLevelCount(&value));
    return value;
}

template <typename D> int32_t consume_Windows_Devices_Lights_ILampInfo<D>::GainLevelCount() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::ILampInfo)->get_GainLevelCount(&value));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::UI::Color> consume_Windows_Devices_Lights_ILampInfo<D>::FixedColor() const
{
    Windows::Foundation::IReference<Windows::UI::Color> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::ILampInfo)->get_FixedColor(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_Devices_Lights_ILampInfo<D>::GetNearestSupportedColor(Windows::UI::Color const& desiredColor) const
{
    Windows::UI::Color result{};
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::ILampInfo)->GetNearestSupportedColor(get_abi(desiredColor), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Devices_Lights_ILampInfo<D>::UpdateLatency() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::ILampInfo)->get_UpdateLatency(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Lights_ILampStatics<D>::GetDeviceSelector() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::ILampStatics)->GetDeviceSelector(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Lights::Lamp> consume_Windows_Devices_Lights_ILampStatics<D>::FromIdAsync(param::hstring const& deviceId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Lights::Lamp> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::ILampStatics)->FromIdAsync(get_abi(deviceId), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::Lights::Lamp> consume_Windows_Devices_Lights_ILampStatics<D>::GetDefaultAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::Lights::Lamp> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Lights::ILampStatics)->GetDefaultAsync(put_abi(operation)));
    return operation;
}

template <typename D>
struct produce<D, Windows::Devices::Lights::ILamp> : produce_base<D, Windows::Devices::Lights::ILamp>
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

    int32_t WINRT_CALL get_IsEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsEnabled, WINRT_WRAP(void), bool);
            this->shim().IsEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BrightnessLevel(float* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BrightnessLevel, WINRT_WRAP(float));
            *value = detach_from<float>(this->shim().BrightnessLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_BrightnessLevel(float value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BrightnessLevel, WINRT_WRAP(void), float);
            this->shim().BrightnessLevel(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsColorSettable(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsColorSettable, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsColorSettable());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Color(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Color, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Color());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Color(struct struct_Windows_UI_Color value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Color, WINRT_WRAP(void), Windows::UI::Color const&);
            this->shim().Color(*reinterpret_cast<Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_AvailabilityChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AvailabilityChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Lights::Lamp, Windows::Devices::Lights::LampAvailabilityChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().AvailabilityChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Lights::Lamp, Windows::Devices::Lights::LampAvailabilityChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_AvailabilityChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(AvailabilityChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().AvailabilityChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Devices::Lights::ILampArray> : produce_base<D, Windows::Devices::Lights::ILampArray>
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

    int32_t WINRT_CALL get_HardwareVendorId(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HardwareVendorId, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().HardwareVendorId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HardwareProductId(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HardwareProductId, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().HardwareProductId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HardwareVersion(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HardwareVersion, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().HardwareVersion());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LampArrayKind(Windows::Devices::Lights::LampArrayKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LampArrayKind, WINRT_WRAP(Windows::Devices::Lights::LampArrayKind));
            *value = detach_from<Windows::Devices::Lights::LampArrayKind>(this->shim().LampArrayKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LampCount(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LampCount, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().LampCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MinUpdateInterval(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinUpdateInterval, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().MinUpdateInterval());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BoundingBox(Windows::Foundation::Numerics::float3* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BoundingBox, WINRT_WRAP(Windows::Foundation::Numerics::float3));
            *value = detach_from<Windows::Foundation::Numerics::float3>(this->shim().BoundingBox());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsEnabled, WINRT_WRAP(void), bool);
            this->shim().IsEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BrightnessLevel(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BrightnessLevel, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().BrightnessLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_BrightnessLevel(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BrightnessLevel, WINRT_WRAP(void), double);
            this->shim().BrightnessLevel(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsConnected(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsConnected, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsConnected());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportsVirtualKeys(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportsVirtualKeys, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().SupportsVirtualKeys());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetLampInfo(int32_t lampIndex, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetLampInfo, WINRT_WRAP(Windows::Devices::Lights::LampInfo), int32_t);
            *result = detach_from<Windows::Devices::Lights::LampInfo>(this->shim().GetLampInfo(lampIndex));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetIndicesForKey(Windows::System::VirtualKey key, uint32_t* __resultSize, int32_t** result) noexcept final
    {
        try
        {
            *__resultSize = 0;
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetIndicesForKey, WINRT_WRAP(com_array<int32_t>), Windows::System::VirtualKey const&);
            std::tie(*__resultSize, *result) = detach_abi(this->shim().GetIndicesForKey(*reinterpret_cast<Windows::System::VirtualKey const*>(&key)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetIndicesForPurposes(Windows::Devices::Lights::LampPurposes purposes, uint32_t* __resultSize, int32_t** result) noexcept final
    {
        try
        {
            *__resultSize = 0;
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetIndicesForPurposes, WINRT_WRAP(com_array<int32_t>), Windows::Devices::Lights::LampPurposes const&);
            std::tie(*__resultSize, *result) = detach_abi(this->shim().GetIndicesForPurposes(*reinterpret_cast<Windows::Devices::Lights::LampPurposes const*>(&purposes)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetColor(struct struct_Windows_UI_Color desiredColor) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetColor, WINRT_WRAP(void), Windows::UI::Color const&);
            this->shim().SetColor(*reinterpret_cast<Windows::UI::Color const*>(&desiredColor));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetColorForIndex(int32_t lampIndex, struct struct_Windows_UI_Color desiredColor) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetColorForIndex, WINRT_WRAP(void), int32_t, Windows::UI::Color const&);
            this->shim().SetColorForIndex(lampIndex, *reinterpret_cast<Windows::UI::Color const*>(&desiredColor));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetSingleColorForIndices(struct struct_Windows_UI_Color desiredColor, uint32_t __lampIndexesSize, int32_t* lampIndexes) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetSingleColorForIndices, WINRT_WRAP(void), Windows::UI::Color const&, array_view<int32_t const>);
            this->shim().SetSingleColorForIndices(*reinterpret_cast<Windows::UI::Color const*>(&desiredColor), array_view<int32_t const>(reinterpret_cast<int32_t const *>(lampIndexes), reinterpret_cast<int32_t const *>(lampIndexes) + __lampIndexesSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetColorsForIndices(uint32_t __desiredColorsSize, struct struct_Windows_UI_Color* desiredColors, uint32_t __lampIndexesSize, int32_t* lampIndexes) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetColorsForIndices, WINRT_WRAP(void), array_view<Windows::UI::Color const>, array_view<int32_t const>);
            this->shim().SetColorsForIndices(array_view<Windows::UI::Color const>(reinterpret_cast<Windows::UI::Color const *>(desiredColors), reinterpret_cast<Windows::UI::Color const *>(desiredColors) + __desiredColorsSize), array_view<int32_t const>(reinterpret_cast<int32_t const *>(lampIndexes), reinterpret_cast<int32_t const *>(lampIndexes) + __lampIndexesSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetColorsForKey(struct struct_Windows_UI_Color desiredColor, Windows::System::VirtualKey key) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetColorsForKey, WINRT_WRAP(void), Windows::UI::Color const&, Windows::System::VirtualKey const&);
            this->shim().SetColorsForKey(*reinterpret_cast<Windows::UI::Color const*>(&desiredColor), *reinterpret_cast<Windows::System::VirtualKey const*>(&key));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetColorsForKeys(uint32_t __desiredColorsSize, struct struct_Windows_UI_Color* desiredColors, uint32_t __keysSize, Windows::System::VirtualKey* keys) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetColorsForKeys, WINRT_WRAP(void), array_view<Windows::UI::Color const>, array_view<Windows::System::VirtualKey const>);
            this->shim().SetColorsForKeys(array_view<Windows::UI::Color const>(reinterpret_cast<Windows::UI::Color const *>(desiredColors), reinterpret_cast<Windows::UI::Color const *>(desiredColors) + __desiredColorsSize), array_view<Windows::System::VirtualKey const>(reinterpret_cast<Windows::System::VirtualKey const *>(keys), reinterpret_cast<Windows::System::VirtualKey const *>(keys) + __keysSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetColorsForPurposes(struct struct_Windows_UI_Color desiredColor, Windows::Devices::Lights::LampPurposes purposes) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetColorsForPurposes, WINRT_WRAP(void), Windows::UI::Color const&, Windows::Devices::Lights::LampPurposes const&);
            this->shim().SetColorsForPurposes(*reinterpret_cast<Windows::UI::Color const*>(&desiredColor), *reinterpret_cast<Windows::Devices::Lights::LampPurposes const*>(&purposes));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SendMessageAsync(int32_t messageId, void* message, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SendMessageAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), int32_t, Windows::Storage::Streams::IBuffer const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SendMessageAsync(messageId, *reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&message)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestMessageAsync(int32_t messageId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestMessageAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer>), int32_t);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IBuffer>>(this->shim().RequestMessageAsync(messageId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Lights::ILampArrayStatics> : produce_base<D, Windows::Devices::Lights::ILampArrayStatics>
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
            WINRT_ASSERT_DECLARATION(FromIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Lights::LampArray>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Lights::LampArray>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Lights::ILampAvailabilityChangedEventArgs> : produce_base<D, Windows::Devices::Lights::ILampAvailabilityChangedEventArgs>
{
    int32_t WINRT_CALL get_IsAvailable(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsAvailable, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsAvailable());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Lights::ILampInfo> : produce_base<D, Windows::Devices::Lights::ILampInfo>
{
    int32_t WINRT_CALL get_Index(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Index, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().Index());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Purposes(Windows::Devices::Lights::LampPurposes* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Purposes, WINRT_WRAP(Windows::Devices::Lights::LampPurposes));
            *value = detach_from<Windows::Devices::Lights::LampPurposes>(this->shim().Purposes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Position(Windows::Foundation::Numerics::float3* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Position, WINRT_WRAP(Windows::Foundation::Numerics::float3));
            *value = detach_from<Windows::Foundation::Numerics::float3>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RedLevelCount(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RedLevelCount, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().RedLevelCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_GreenLevelCount(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GreenLevelCount, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().GreenLevelCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BlueLevelCount(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BlueLevelCount, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().BlueLevelCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_GainLevelCount(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GainLevelCount, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().GainLevelCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FixedColor(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FixedColor, WINRT_WRAP(Windows::Foundation::IReference<Windows::UI::Color>));
            *value = detach_from<Windows::Foundation::IReference<Windows::UI::Color>>(this->shim().FixedColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetNearestSupportedColor(struct struct_Windows_UI_Color desiredColor, struct struct_Windows_UI_Color* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetNearestSupportedColor, WINRT_WRAP(Windows::UI::Color), Windows::UI::Color const&);
            *result = detach_from<Windows::UI::Color>(this->shim().GetNearestSupportedColor(*reinterpret_cast<Windows::UI::Color const*>(&desiredColor)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UpdateLatency(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpdateLatency, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().UpdateLatency());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Lights::ILampStatics> : produce_base<D, Windows::Devices::Lights::ILampStatics>
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

    int32_t WINRT_CALL FromIdAsync(void* deviceId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Lights::Lamp>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Lights::Lamp>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
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
            WINRT_ASSERT_DECLARATION(GetDefaultAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::Lights::Lamp>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::Lights::Lamp>>(this->shim().GetDefaultAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Devices::Lights {

inline hstring Lamp::GetDeviceSelector()
{
    return impl::call_factory<Lamp, Windows::Devices::Lights::ILampStatics>([&](auto&& f) { return f.GetDeviceSelector(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::Lights::Lamp> Lamp::FromIdAsync(param::hstring const& deviceId)
{
    return impl::call_factory<Lamp, Windows::Devices::Lights::ILampStatics>([&](auto&& f) { return f.FromIdAsync(deviceId); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::Lights::Lamp> Lamp::GetDefaultAsync()
{
    return impl::call_factory<Lamp, Windows::Devices::Lights::ILampStatics>([&](auto&& f) { return f.GetDefaultAsync(); });
}

inline hstring LampArray::GetDeviceSelector()
{
    return impl::call_factory<LampArray, Windows::Devices::Lights::ILampArrayStatics>([&](auto&& f) { return f.GetDeviceSelector(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::Lights::LampArray> LampArray::FromIdAsync(param::hstring const& deviceId)
{
    return impl::call_factory<LampArray, Windows::Devices::Lights::ILampArrayStatics>([&](auto&& f) { return f.FromIdAsync(deviceId); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Devices::Lights::ILamp> : winrt::impl::hash_base<winrt::Windows::Devices::Lights::ILamp> {};
template<> struct hash<winrt::Windows::Devices::Lights::ILampArray> : winrt::impl::hash_base<winrt::Windows::Devices::Lights::ILampArray> {};
template<> struct hash<winrt::Windows::Devices::Lights::ILampArrayStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Lights::ILampArrayStatics> {};
template<> struct hash<winrt::Windows::Devices::Lights::ILampAvailabilityChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Lights::ILampAvailabilityChangedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Lights::ILampInfo> : winrt::impl::hash_base<winrt::Windows::Devices::Lights::ILampInfo> {};
template<> struct hash<winrt::Windows::Devices::Lights::ILampStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Lights::ILampStatics> {};
template<> struct hash<winrt::Windows::Devices::Lights::Lamp> : winrt::impl::hash_base<winrt::Windows::Devices::Lights::Lamp> {};
template<> struct hash<winrt::Windows::Devices::Lights::LampArray> : winrt::impl::hash_base<winrt::Windows::Devices::Lights::LampArray> {};
template<> struct hash<winrt::Windows::Devices::Lights::LampAvailabilityChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Lights::LampAvailabilityChangedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Lights::LampInfo> : winrt::impl::hash_base<winrt::Windows::Devices::Lights::LampInfo> {};

}
