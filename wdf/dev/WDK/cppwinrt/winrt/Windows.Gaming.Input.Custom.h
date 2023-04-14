// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Gaming.Input.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Gaming.Input.Custom.2.h"
#include "winrt/Windows.Gaming.Input.h"

namespace winrt::impl {

template <typename D> Windows::Foundation::IInspectable consume_Windows_Gaming_Input_Custom_ICustomGameControllerFactory<D>::CreateGameController(Windows::Gaming::Input::Custom::IGameControllerProvider const& provider) const
{
    Windows::Foundation::IInspectable value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::Custom::ICustomGameControllerFactory)->CreateGameController(get_abi(provider), put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Gaming_Input_Custom_ICustomGameControllerFactory<D>::OnGameControllerAdded(Windows::Gaming::Input::IGameController const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::Custom::ICustomGameControllerFactory)->OnGameControllerAdded(get_abi(value)));
}

template <typename D> void consume_Windows_Gaming_Input_Custom_ICustomGameControllerFactory<D>::OnGameControllerRemoved(Windows::Gaming::Input::IGameController const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::Custom::ICustomGameControllerFactory)->OnGameControllerRemoved(get_abi(value)));
}

template <typename D> void consume_Windows_Gaming_Input_Custom_IGameControllerFactoryManagerStatics<D>::RegisterCustomFactoryForGipInterface(Windows::Gaming::Input::Custom::ICustomGameControllerFactory const& factory, winrt::guid const& interfaceId) const
{
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::Custom::IGameControllerFactoryManagerStatics)->RegisterCustomFactoryForGipInterface(get_abi(factory), get_abi(interfaceId)));
}

template <typename D> void consume_Windows_Gaming_Input_Custom_IGameControllerFactoryManagerStatics<D>::RegisterCustomFactoryForHardwareId(Windows::Gaming::Input::Custom::ICustomGameControllerFactory const& factory, uint16_t hardwareVendorId, uint16_t hardwareProductId) const
{
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::Custom::IGameControllerFactoryManagerStatics)->RegisterCustomFactoryForHardwareId(get_abi(factory), hardwareVendorId, hardwareProductId));
}

template <typename D> void consume_Windows_Gaming_Input_Custom_IGameControllerFactoryManagerStatics<D>::RegisterCustomFactoryForXusbType(Windows::Gaming::Input::Custom::ICustomGameControllerFactory const& factory, Windows::Gaming::Input::Custom::XusbDeviceType const& xusbType, Windows::Gaming::Input::Custom::XusbDeviceSubtype const& xusbSubtype) const
{
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::Custom::IGameControllerFactoryManagerStatics)->RegisterCustomFactoryForXusbType(get_abi(factory), get_abi(xusbType), get_abi(xusbSubtype)));
}

template <typename D> Windows::Gaming::Input::IGameController consume_Windows_Gaming_Input_Custom_IGameControllerFactoryManagerStatics2<D>::TryGetFactoryControllerFromGameController(Windows::Gaming::Input::Custom::ICustomGameControllerFactory const& factory, Windows::Gaming::Input::IGameController const& gameController) const
{
    Windows::Gaming::Input::IGameController factoryController{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::Custom::IGameControllerFactoryManagerStatics2)->TryGetFactoryControllerFromGameController(get_abi(factory), get_abi(gameController), put_abi(factoryController)));
    return factoryController;
}

template <typename D> void consume_Windows_Gaming_Input_Custom_IGameControllerInputSink<D>::OnInputResumed(uint64_t timestamp) const
{
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::Custom::IGameControllerInputSink)->OnInputResumed(timestamp));
}

template <typename D> void consume_Windows_Gaming_Input_Custom_IGameControllerInputSink<D>::OnInputSuspended(uint64_t timestamp) const
{
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::Custom::IGameControllerInputSink)->OnInputSuspended(timestamp));
}

template <typename D> Windows::Gaming::Input::Custom::GameControllerVersionInfo consume_Windows_Gaming_Input_Custom_IGameControllerProvider<D>::FirmwareVersionInfo() const
{
    Windows::Gaming::Input::Custom::GameControllerVersionInfo value{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::Custom::IGameControllerProvider)->get_FirmwareVersionInfo(put_abi(value)));
    return value;
}

template <typename D> uint16_t consume_Windows_Gaming_Input_Custom_IGameControllerProvider<D>::HardwareProductId() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::Custom::IGameControllerProvider)->get_HardwareProductId(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Gaming_Input_Custom_IGameControllerProvider<D>::HardwareVendorId() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::Custom::IGameControllerProvider)->get_HardwareVendorId(&value));
    return value;
}

template <typename D> Windows::Gaming::Input::Custom::GameControllerVersionInfo consume_Windows_Gaming_Input_Custom_IGameControllerProvider<D>::HardwareVersionInfo() const
{
    Windows::Gaming::Input::Custom::GameControllerVersionInfo value{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::Custom::IGameControllerProvider)->get_HardwareVersionInfo(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Gaming_Input_Custom_IGameControllerProvider<D>::IsConnected() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::Custom::IGameControllerProvider)->get_IsConnected(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Gaming_Input_Custom_IGipFirmwareUpdateResult<D>::ExtendedErrorCode() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::Custom::IGipFirmwareUpdateResult)->get_ExtendedErrorCode(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Gaming_Input_Custom_IGipFirmwareUpdateResult<D>::FinalComponentId() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::Custom::IGipFirmwareUpdateResult)->get_FinalComponentId(&value));
    return value;
}

template <typename D> Windows::Gaming::Input::Custom::GipFirmwareUpdateStatus consume_Windows_Gaming_Input_Custom_IGipFirmwareUpdateResult<D>::Status() const
{
    Windows::Gaming::Input::Custom::GipFirmwareUpdateStatus value{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::Custom::IGipFirmwareUpdateResult)->get_Status(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Gaming_Input_Custom_IGipGameControllerInputSink<D>::OnKeyReceived(uint64_t timestamp, uint8_t keyCode, bool isPressed) const
{
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::Custom::IGipGameControllerInputSink)->OnKeyReceived(timestamp, keyCode, isPressed));
}

template <typename D> void consume_Windows_Gaming_Input_Custom_IGipGameControllerInputSink<D>::OnMessageReceived(uint64_t timestamp, Windows::Gaming::Input::Custom::GipMessageClass const& messageClass, uint8_t messageId, uint8_t sequenceId, array_view<uint8_t const> messageBuffer) const
{
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::Custom::IGipGameControllerInputSink)->OnMessageReceived(timestamp, get_abi(messageClass), messageId, sequenceId, messageBuffer.size(), get_abi(messageBuffer)));
}

template <typename D> void consume_Windows_Gaming_Input_Custom_IGipGameControllerProvider<D>::SendMessage(Windows::Gaming::Input::Custom::GipMessageClass const& messageClass, uint8_t messageId, array_view<uint8_t const> messageBuffer) const
{
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::Custom::IGipGameControllerProvider)->SendMessage(get_abi(messageClass), messageId, messageBuffer.size(), get_abi(messageBuffer)));
}

template <typename D> void consume_Windows_Gaming_Input_Custom_IGipGameControllerProvider<D>::SendReceiveMessage(Windows::Gaming::Input::Custom::GipMessageClass const& messageClass, uint8_t messageId, array_view<uint8_t const> requestMessageBuffer, array_view<uint8_t> responseMessageBuffer) const
{
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::Custom::IGipGameControllerProvider)->SendReceiveMessage(get_abi(messageClass), messageId, requestMessageBuffer.size(), get_abi(requestMessageBuffer), responseMessageBuffer.size(), get_abi(responseMessageBuffer)));
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<Windows::Gaming::Input::Custom::GipFirmwareUpdateResult, Windows::Gaming::Input::Custom::GipFirmwareUpdateProgress> consume_Windows_Gaming_Input_Custom_IGipGameControllerProvider<D>::UpdateFirmwareAsync(Windows::Storage::Streams::IInputStream const& firmwareImage) const
{
    Windows::Foundation::IAsyncOperationWithProgress<Windows::Gaming::Input::Custom::GipFirmwareUpdateResult, Windows::Gaming::Input::Custom::GipFirmwareUpdateProgress> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::Custom::IGipGameControllerProvider)->UpdateFirmwareAsync(get_abi(firmwareImage), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_Gaming_Input_Custom_IHidGameControllerInputSink<D>::OnInputReportReceived(uint64_t timestamp, uint8_t reportId, array_view<uint8_t const> reportBuffer) const
{
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::Custom::IHidGameControllerInputSink)->OnInputReportReceived(timestamp, reportId, reportBuffer.size(), get_abi(reportBuffer)));
}

template <typename D> uint16_t consume_Windows_Gaming_Input_Custom_IHidGameControllerProvider<D>::UsageId() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::Custom::IHidGameControllerProvider)->get_UsageId(&value));
    return value;
}

template <typename D> uint16_t consume_Windows_Gaming_Input_Custom_IHidGameControllerProvider<D>::UsagePage() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::Custom::IHidGameControllerProvider)->get_UsagePage(&value));
    return value;
}

template <typename D> void consume_Windows_Gaming_Input_Custom_IHidGameControllerProvider<D>::GetFeatureReport(uint8_t reportId, array_view<uint8_t> reportBuffer) const
{
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::Custom::IHidGameControllerProvider)->GetFeatureReport(reportId, reportBuffer.size(), get_abi(reportBuffer)));
}

template <typename D> void consume_Windows_Gaming_Input_Custom_IHidGameControllerProvider<D>::SendFeatureReport(uint8_t reportId, array_view<uint8_t const> reportBuffer) const
{
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::Custom::IHidGameControllerProvider)->SendFeatureReport(reportId, reportBuffer.size(), get_abi(reportBuffer)));
}

template <typename D> void consume_Windows_Gaming_Input_Custom_IHidGameControllerProvider<D>::SendOutputReport(uint8_t reportId, array_view<uint8_t const> reportBuffer) const
{
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::Custom::IHidGameControllerProvider)->SendOutputReport(reportId, reportBuffer.size(), get_abi(reportBuffer)));
}

template <typename D> void consume_Windows_Gaming_Input_Custom_IXusbGameControllerInputSink<D>::OnInputReceived(uint64_t timestamp, uint8_t reportId, array_view<uint8_t const> inputBuffer) const
{
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::Custom::IXusbGameControllerInputSink)->OnInputReceived(timestamp, reportId, inputBuffer.size(), get_abi(inputBuffer)));
}

template <typename D> void consume_Windows_Gaming_Input_Custom_IXusbGameControllerProvider<D>::SetVibration(double lowFrequencyMotorSpeed, double highFrequencyMotorSpeed) const
{
    check_hresult(WINRT_SHIM(Windows::Gaming::Input::Custom::IXusbGameControllerProvider)->SetVibration(lowFrequencyMotorSpeed, highFrequencyMotorSpeed));
}

template <typename D>
struct produce<D, Windows::Gaming::Input::Custom::ICustomGameControllerFactory> : produce_base<D, Windows::Gaming::Input::Custom::ICustomGameControllerFactory>
{
    int32_t WINRT_CALL CreateGameController(void* provider, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateGameController, WINRT_WRAP(Windows::Foundation::IInspectable), Windows::Gaming::Input::Custom::IGameControllerProvider const&);
            *value = detach_from<Windows::Foundation::IInspectable>(this->shim().CreateGameController(*reinterpret_cast<Windows::Gaming::Input::Custom::IGameControllerProvider const*>(&provider)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL OnGameControllerAdded(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OnGameControllerAdded, WINRT_WRAP(void), Windows::Gaming::Input::IGameController const&);
            this->shim().OnGameControllerAdded(*reinterpret_cast<Windows::Gaming::Input::IGameController const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL OnGameControllerRemoved(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OnGameControllerRemoved, WINRT_WRAP(void), Windows::Gaming::Input::IGameController const&);
            this->shim().OnGameControllerRemoved(*reinterpret_cast<Windows::Gaming::Input::IGameController const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Gaming::Input::Custom::IGameControllerFactoryManagerStatics> : produce_base<D, Windows::Gaming::Input::Custom::IGameControllerFactoryManagerStatics>
{
    int32_t WINRT_CALL RegisterCustomFactoryForGipInterface(void* factory, winrt::guid interfaceId) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RegisterCustomFactoryForGipInterface, WINRT_WRAP(void), Windows::Gaming::Input::Custom::ICustomGameControllerFactory const&, winrt::guid const&);
            this->shim().RegisterCustomFactoryForGipInterface(*reinterpret_cast<Windows::Gaming::Input::Custom::ICustomGameControllerFactory const*>(&factory), *reinterpret_cast<winrt::guid const*>(&interfaceId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RegisterCustomFactoryForHardwareId(void* factory, uint16_t hardwareVendorId, uint16_t hardwareProductId) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RegisterCustomFactoryForHardwareId, WINRT_WRAP(void), Windows::Gaming::Input::Custom::ICustomGameControllerFactory const&, uint16_t, uint16_t);
            this->shim().RegisterCustomFactoryForHardwareId(*reinterpret_cast<Windows::Gaming::Input::Custom::ICustomGameControllerFactory const*>(&factory), hardwareVendorId, hardwareProductId);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RegisterCustomFactoryForXusbType(void* factory, Windows::Gaming::Input::Custom::XusbDeviceType xusbType, Windows::Gaming::Input::Custom::XusbDeviceSubtype xusbSubtype) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RegisterCustomFactoryForXusbType, WINRT_WRAP(void), Windows::Gaming::Input::Custom::ICustomGameControllerFactory const&, Windows::Gaming::Input::Custom::XusbDeviceType const&, Windows::Gaming::Input::Custom::XusbDeviceSubtype const&);
            this->shim().RegisterCustomFactoryForXusbType(*reinterpret_cast<Windows::Gaming::Input::Custom::ICustomGameControllerFactory const*>(&factory), *reinterpret_cast<Windows::Gaming::Input::Custom::XusbDeviceType const*>(&xusbType), *reinterpret_cast<Windows::Gaming::Input::Custom::XusbDeviceSubtype const*>(&xusbSubtype));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Gaming::Input::Custom::IGameControllerFactoryManagerStatics2> : produce_base<D, Windows::Gaming::Input::Custom::IGameControllerFactoryManagerStatics2>
{
    int32_t WINRT_CALL TryGetFactoryControllerFromGameController(void* factory, void* gameController, void** factoryController) noexcept final
    {
        try
        {
            *factoryController = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryGetFactoryControllerFromGameController, WINRT_WRAP(Windows::Gaming::Input::IGameController), Windows::Gaming::Input::Custom::ICustomGameControllerFactory const&, Windows::Gaming::Input::IGameController const&);
            *factoryController = detach_from<Windows::Gaming::Input::IGameController>(this->shim().TryGetFactoryControllerFromGameController(*reinterpret_cast<Windows::Gaming::Input::Custom::ICustomGameControllerFactory const*>(&factory), *reinterpret_cast<Windows::Gaming::Input::IGameController const*>(&gameController)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Gaming::Input::Custom::IGameControllerInputSink> : produce_base<D, Windows::Gaming::Input::Custom::IGameControllerInputSink>
{
    int32_t WINRT_CALL OnInputResumed(uint64_t timestamp) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OnInputResumed, WINRT_WRAP(void), uint64_t);
            this->shim().OnInputResumed(timestamp);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL OnInputSuspended(uint64_t timestamp) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OnInputSuspended, WINRT_WRAP(void), uint64_t);
            this->shim().OnInputSuspended(timestamp);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Gaming::Input::Custom::IGameControllerProvider> : produce_base<D, Windows::Gaming::Input::Custom::IGameControllerProvider>
{
    int32_t WINRT_CALL get_FirmwareVersionInfo(struct struct_Windows_Gaming_Input_Custom_GameControllerVersionInfo* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FirmwareVersionInfo, WINRT_WRAP(Windows::Gaming::Input::Custom::GameControllerVersionInfo));
            *value = detach_from<Windows::Gaming::Input::Custom::GameControllerVersionInfo>(this->shim().FirmwareVersionInfo());
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

    int32_t WINRT_CALL get_HardwareVersionInfo(struct struct_Windows_Gaming_Input_Custom_GameControllerVersionInfo* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HardwareVersionInfo, WINRT_WRAP(Windows::Gaming::Input::Custom::GameControllerVersionInfo));
            *value = detach_from<Windows::Gaming::Input::Custom::GameControllerVersionInfo>(this->shim().HardwareVersionInfo());
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
};

template <typename D>
struct produce<D, Windows::Gaming::Input::Custom::IGipFirmwareUpdateResult> : produce_base<D, Windows::Gaming::Input::Custom::IGipFirmwareUpdateResult>
{
    int32_t WINRT_CALL get_ExtendedErrorCode(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExtendedErrorCode, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().ExtendedErrorCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FinalComponentId(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FinalComponentId, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().FinalComponentId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Status(Windows::Gaming::Input::Custom::GipFirmwareUpdateStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Gaming::Input::Custom::GipFirmwareUpdateStatus));
            *value = detach_from<Windows::Gaming::Input::Custom::GipFirmwareUpdateStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Gaming::Input::Custom::IGipGameControllerInputSink> : produce_base<D, Windows::Gaming::Input::Custom::IGipGameControllerInputSink>
{
    int32_t WINRT_CALL OnKeyReceived(uint64_t timestamp, uint8_t keyCode, bool isPressed) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OnKeyReceived, WINRT_WRAP(void), uint64_t, uint8_t, bool);
            this->shim().OnKeyReceived(timestamp, keyCode, isPressed);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL OnMessageReceived(uint64_t timestamp, Windows::Gaming::Input::Custom::GipMessageClass messageClass, uint8_t messageId, uint8_t sequenceId, uint32_t __messageBufferSize, uint8_t* messageBuffer) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OnMessageReceived, WINRT_WRAP(void), uint64_t, Windows::Gaming::Input::Custom::GipMessageClass const&, uint8_t, uint8_t, array_view<uint8_t const>);
            this->shim().OnMessageReceived(timestamp, *reinterpret_cast<Windows::Gaming::Input::Custom::GipMessageClass const*>(&messageClass), messageId, sequenceId, array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(messageBuffer), reinterpret_cast<uint8_t const *>(messageBuffer) + __messageBufferSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Gaming::Input::Custom::IGipGameControllerProvider> : produce_base<D, Windows::Gaming::Input::Custom::IGipGameControllerProvider>
{
    int32_t WINRT_CALL SendMessage(Windows::Gaming::Input::Custom::GipMessageClass messageClass, uint8_t messageId, uint32_t __messageBufferSize, uint8_t* messageBuffer) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SendMessage, WINRT_WRAP(void), Windows::Gaming::Input::Custom::GipMessageClass const&, uint8_t, array_view<uint8_t const>);
            this->shim().SendMessage(*reinterpret_cast<Windows::Gaming::Input::Custom::GipMessageClass const*>(&messageClass), messageId, array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(messageBuffer), reinterpret_cast<uint8_t const *>(messageBuffer) + __messageBufferSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SendReceiveMessage(Windows::Gaming::Input::Custom::GipMessageClass messageClass, uint8_t messageId, uint32_t __requestMessageBufferSize, uint8_t* requestMessageBuffer, uint32_t __responseMessageBufferSize, uint8_t* responseMessageBuffer) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SendReceiveMessage, WINRT_WRAP(void), Windows::Gaming::Input::Custom::GipMessageClass const&, uint8_t, array_view<uint8_t const>, array_view<uint8_t>);
            this->shim().SendReceiveMessage(*reinterpret_cast<Windows::Gaming::Input::Custom::GipMessageClass const*>(&messageClass), messageId, array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(requestMessageBuffer), reinterpret_cast<uint8_t const *>(requestMessageBuffer) + __requestMessageBufferSize), array_view<uint8_t>(reinterpret_cast<uint8_t*>(responseMessageBuffer), reinterpret_cast<uint8_t*>(responseMessageBuffer) + __responseMessageBufferSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UpdateFirmwareAsync(void* firmwareImage, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpdateFirmwareAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<Windows::Gaming::Input::Custom::GipFirmwareUpdateResult, Windows::Gaming::Input::Custom::GipFirmwareUpdateProgress>), Windows::Storage::Streams::IInputStream const);
            *result = detach_from<Windows::Foundation::IAsyncOperationWithProgress<Windows::Gaming::Input::Custom::GipFirmwareUpdateResult, Windows::Gaming::Input::Custom::GipFirmwareUpdateProgress>>(this->shim().UpdateFirmwareAsync(*reinterpret_cast<Windows::Storage::Streams::IInputStream const*>(&firmwareImage)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Gaming::Input::Custom::IHidGameControllerInputSink> : produce_base<D, Windows::Gaming::Input::Custom::IHidGameControllerInputSink>
{
    int32_t WINRT_CALL OnInputReportReceived(uint64_t timestamp, uint8_t reportId, uint32_t __reportBufferSize, uint8_t* reportBuffer) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OnInputReportReceived, WINRT_WRAP(void), uint64_t, uint8_t, array_view<uint8_t const>);
            this->shim().OnInputReportReceived(timestamp, reportId, array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(reportBuffer), reinterpret_cast<uint8_t const *>(reportBuffer) + __reportBufferSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Gaming::Input::Custom::IHidGameControllerProvider> : produce_base<D, Windows::Gaming::Input::Custom::IHidGameControllerProvider>
{
    int32_t WINRT_CALL get_UsageId(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UsageId, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().UsageId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UsagePage(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UsagePage, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().UsagePage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetFeatureReport(uint8_t reportId, uint32_t __reportBufferSize, uint8_t* reportBuffer) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetFeatureReport, WINRT_WRAP(void), uint8_t, array_view<uint8_t>);
            this->shim().GetFeatureReport(reportId, array_view<uint8_t>(reinterpret_cast<uint8_t*>(reportBuffer), reinterpret_cast<uint8_t*>(reportBuffer) + __reportBufferSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SendFeatureReport(uint8_t reportId, uint32_t __reportBufferSize, uint8_t* reportBuffer) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SendFeatureReport, WINRT_WRAP(void), uint8_t, array_view<uint8_t const>);
            this->shim().SendFeatureReport(reportId, array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(reportBuffer), reinterpret_cast<uint8_t const *>(reportBuffer) + __reportBufferSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SendOutputReport(uint8_t reportId, uint32_t __reportBufferSize, uint8_t* reportBuffer) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SendOutputReport, WINRT_WRAP(void), uint8_t, array_view<uint8_t const>);
            this->shim().SendOutputReport(reportId, array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(reportBuffer), reinterpret_cast<uint8_t const *>(reportBuffer) + __reportBufferSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Gaming::Input::Custom::IXusbGameControllerInputSink> : produce_base<D, Windows::Gaming::Input::Custom::IXusbGameControllerInputSink>
{
    int32_t WINRT_CALL OnInputReceived(uint64_t timestamp, uint8_t reportId, uint32_t __inputBufferSize, uint8_t* inputBuffer) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OnInputReceived, WINRT_WRAP(void), uint64_t, uint8_t, array_view<uint8_t const>);
            this->shim().OnInputReceived(timestamp, reportId, array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(inputBuffer), reinterpret_cast<uint8_t const *>(inputBuffer) + __inputBufferSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Gaming::Input::Custom::IXusbGameControllerProvider> : produce_base<D, Windows::Gaming::Input::Custom::IXusbGameControllerProvider>
{
    int32_t WINRT_CALL SetVibration(double lowFrequencyMotorSpeed, double highFrequencyMotorSpeed) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetVibration, WINRT_WRAP(void), double, double);
            this->shim().SetVibration(lowFrequencyMotorSpeed, highFrequencyMotorSpeed);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Gaming::Input::Custom {

inline void GameControllerFactoryManager::RegisterCustomFactoryForGipInterface(Windows::Gaming::Input::Custom::ICustomGameControllerFactory const& factory, winrt::guid const& interfaceId)
{
    impl::call_factory<GameControllerFactoryManager, Windows::Gaming::Input::Custom::IGameControllerFactoryManagerStatics>([&](auto&& f) { return f.RegisterCustomFactoryForGipInterface(factory, interfaceId); });
}

inline void GameControllerFactoryManager::RegisterCustomFactoryForHardwareId(Windows::Gaming::Input::Custom::ICustomGameControllerFactory const& factory, uint16_t hardwareVendorId, uint16_t hardwareProductId)
{
    impl::call_factory<GameControllerFactoryManager, Windows::Gaming::Input::Custom::IGameControllerFactoryManagerStatics>([&](auto&& f) { return f.RegisterCustomFactoryForHardwareId(factory, hardwareVendorId, hardwareProductId); });
}

inline void GameControllerFactoryManager::RegisterCustomFactoryForXusbType(Windows::Gaming::Input::Custom::ICustomGameControllerFactory const& factory, Windows::Gaming::Input::Custom::XusbDeviceType const& xusbType, Windows::Gaming::Input::Custom::XusbDeviceSubtype const& xusbSubtype)
{
    impl::call_factory<GameControllerFactoryManager, Windows::Gaming::Input::Custom::IGameControllerFactoryManagerStatics>([&](auto&& f) { return f.RegisterCustomFactoryForXusbType(factory, xusbType, xusbSubtype); });
}

inline Windows::Gaming::Input::IGameController GameControllerFactoryManager::TryGetFactoryControllerFromGameController(Windows::Gaming::Input::Custom::ICustomGameControllerFactory const& factory, Windows::Gaming::Input::IGameController const& gameController)
{
    return impl::call_factory<GameControllerFactoryManager, Windows::Gaming::Input::Custom::IGameControllerFactoryManagerStatics2>([&](auto&& f) { return f.TryGetFactoryControllerFromGameController(factory, gameController); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Gaming::Input::Custom::ICustomGameControllerFactory> : winrt::impl::hash_base<winrt::Windows::Gaming::Input::Custom::ICustomGameControllerFactory> {};
template<> struct hash<winrt::Windows::Gaming::Input::Custom::IGameControllerFactoryManagerStatics> : winrt::impl::hash_base<winrt::Windows::Gaming::Input::Custom::IGameControllerFactoryManagerStatics> {};
template<> struct hash<winrt::Windows::Gaming::Input::Custom::IGameControllerFactoryManagerStatics2> : winrt::impl::hash_base<winrt::Windows::Gaming::Input::Custom::IGameControllerFactoryManagerStatics2> {};
template<> struct hash<winrt::Windows::Gaming::Input::Custom::IGameControllerInputSink> : winrt::impl::hash_base<winrt::Windows::Gaming::Input::Custom::IGameControllerInputSink> {};
template<> struct hash<winrt::Windows::Gaming::Input::Custom::IGameControllerProvider> : winrt::impl::hash_base<winrt::Windows::Gaming::Input::Custom::IGameControllerProvider> {};
template<> struct hash<winrt::Windows::Gaming::Input::Custom::IGipFirmwareUpdateResult> : winrt::impl::hash_base<winrt::Windows::Gaming::Input::Custom::IGipFirmwareUpdateResult> {};
template<> struct hash<winrt::Windows::Gaming::Input::Custom::IGipGameControllerInputSink> : winrt::impl::hash_base<winrt::Windows::Gaming::Input::Custom::IGipGameControllerInputSink> {};
template<> struct hash<winrt::Windows::Gaming::Input::Custom::IGipGameControllerProvider> : winrt::impl::hash_base<winrt::Windows::Gaming::Input::Custom::IGipGameControllerProvider> {};
template<> struct hash<winrt::Windows::Gaming::Input::Custom::IHidGameControllerInputSink> : winrt::impl::hash_base<winrt::Windows::Gaming::Input::Custom::IHidGameControllerInputSink> {};
template<> struct hash<winrt::Windows::Gaming::Input::Custom::IHidGameControllerProvider> : winrt::impl::hash_base<winrt::Windows::Gaming::Input::Custom::IHidGameControllerProvider> {};
template<> struct hash<winrt::Windows::Gaming::Input::Custom::IXusbGameControllerInputSink> : winrt::impl::hash_base<winrt::Windows::Gaming::Input::Custom::IXusbGameControllerInputSink> {};
template<> struct hash<winrt::Windows::Gaming::Input::Custom::IXusbGameControllerProvider> : winrt::impl::hash_base<winrt::Windows::Gaming::Input::Custom::IXusbGameControllerProvider> {};
template<> struct hash<winrt::Windows::Gaming::Input::Custom::GameControllerFactoryManager> : winrt::impl::hash_base<winrt::Windows::Gaming::Input::Custom::GameControllerFactoryManager> {};
template<> struct hash<winrt::Windows::Gaming::Input::Custom::GipFirmwareUpdateResult> : winrt::impl::hash_base<winrt::Windows::Gaming::Input::Custom::GipFirmwareUpdateResult> {};
template<> struct hash<winrt::Windows::Gaming::Input::Custom::GipGameControllerProvider> : winrt::impl::hash_base<winrt::Windows::Gaming::Input::Custom::GipGameControllerProvider> {};
template<> struct hash<winrt::Windows::Gaming::Input::Custom::HidGameControllerProvider> : winrt::impl::hash_base<winrt::Windows::Gaming::Input::Custom::HidGameControllerProvider> {};
template<> struct hash<winrt::Windows::Gaming::Input::Custom::XusbGameControllerProvider> : winrt::impl::hash_base<winrt::Windows::Gaming::Input::Custom::XusbGameControllerProvider> {};

}
